# eth-proof-example

Read Ethereum state **without trusting the RPC that served it**, from inside an OutLayer TEE.

[Run it in the playground](https://outlayer.fastnear.com/playground#ethereum-proof) |
[Documentation](https://outlayer.fastnear.com/docs/examples#eth-proof)

## The problem

`eth_call` is a computation the node performs on your behalf. It returns a number and there is
nothing to check that number against — a node that wants to lie about a price simply lies, and
nothing in the response gives it away. Every oracle that reads an EVM chain over `eth_call` is
trusting whichever endpoint answered.

`eth_getProof` (EIP-1186) returns the Merkle-Patricia path from the state root down to the value.
That path either hashes together correctly or it does not, and the check is arithmetic.

## What a proof does and does not establish

A verified proof says: **under this state root, this contract's storage slot holds this value.**

It says nothing about whether the state root is real. The root arrives in a block header from the
same node, and a node willing to forge a value is equally willing to forge a header and a matching
trie. So the proof alone buys nothing against a malicious provider.

This example closes that gap the cheap way: pin a block number and require several **independent**
RPCs to return a byte-identical header. One provider can then no longer invent a state root
without the others going along with it. The strong version of the same idea is a beacon-chain
light client verifying sync-committee signatures — far more work, and left out on purpose.

One more boundary worth stating plainly: this proves the value **is on Ethereum**, not that it is
**correct**. A Merkle proof will faithfully prove a wrong Chainlink price. Establishing that the
oracle committee itself vouched for a number means verifying the signatures on its OCR report —
a different exercise.

## How it runs

```
eth_blockNumber              → head, minus a margin so every node has seen the block
eth_getBlockByNumber × N     → require min_agree identical (hash, stateRoot)
eth_getProof  (proxy phase)  → verify → which aggregator, and which generation
eth_getProof  (hot vars)     → verify → latest round id
eth_getProof  (transmission) → verify → answer + timestamps
```

Every hop is taken at the same pinned block, so one agreed state root covers all of them. Nothing
along the way is taken on configuration or on `eth_call`: the aggregator address, the round id and
the answer are each proven. Skipping any of them would leave one unverified link in a chain whose
whole point is that there are none — a node could point the read at an old round, or at an
aggregator of its choosing.

Verification is two nested walks. First the **account** proof against the state root, which yields
the account's storage root; then the **storage** proof against that. Checking the second without
the first would prove nothing — the storage root would be the node's word again.

## Usage

```bash
./build.sh

echo '{"proxy":"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"}' \
  | wasmtime -S http target/wasm32-wasip2/release/eth-proof-example.wasm
```

```json
{
  "success": true,
  "price": 1867.38678704,
  "answer": "186738678704",
  "updated_at": 1785603827,
  "observed_at": 1785603811,
  "age_secs": 1065,
  "evidence": {
    "block_number": 25661473,
    "block_hash": "0x6e49092a47dea33f3822e4b7879377f68ba9657c7f73824ca59f4fd206d09fa8",
    "state_root": "0x25e4ea533d6809e8539ceb3e8ac5ce315e45b6904039545926315c73fa736747",
    "storage_hash": "0xa74b86b268cbdd88634097613e5f9864f0ae516f3fe9f746ccb4cf40902d39cd",
    "aggregator": "0x7d4e742018fb52e48b08be73d041c18b21de6fb5",
    "phase_id": 7,
    "round_id": 32112,
    "transmission_slot": "0x1f1189b1aaa5a97c0fda24107b2ee4ecbbbc9b852f9dbbfc73dd786cf5f089e1",
    "agreed_by": ["https://ethereum-rpc.publicnode.com", "https://eth.drpc.org", "https://rpc.mevblocker.io"],
    "rejected": []
  }
}
```

`evidence` is the point of the response: `block_hash` can be checked against any explorer by
anyone, so the answer is auditable after the fact rather than taken on faith.

### Input

| Field | Default | Meaning |
|---|---|---|
| `proxy` | required | Chainlink feed address — the one their docs list |
| `pair` | — | Human label, e.g. `ETH/USD`, echoed back so the number has a unit. A label, not a proven fact: the feed carries no name on chain |
| `aggregator` | — | Skip the proxy hop. Only for feeds without a proxy; see below |
| `decimals` | `8` | Divisor for the human-readable `price` |
| `rpcs` | 3 public endpoints | Endpoints to poll. Use operators that could actually disagree |
| `min_agree` | majority | Identical headers required before proceeding |
| `blocks_behind` | `8` | Margin below head, so honest nodes have converged |
| `max_age_secs` | `7200` | Reject a proven but stale price |

### When it refuses

Disagreement is not smoothed over. If the quorum is not met the call fails with who said what:

```
only 2 of 3 RPCs agreed on block 25661029 (needed 3).
Agreed on 0x3155...: publicnode, drpc. Disagreed: none.
Unusable: https://rpc.ankr.com/eth_holesky: HTTP 403
```

A failed proof is attributed to the provider that served it and the next one is tried; a header
disagreement stops the run, because at that point at least one provider is lying, broken or on a
fork and there is no way to tell which.

## The proxy indirection

The feed address everyone quotes — `0x5f4eC3Df…` for ETH/USD — is an `EACAggregatorProxy`. The
price lives in whichever aggregator it currently points at, and Chainlink rotates that: the
`phase_id` in the response above is **7**, meaning this feed is on its seventh aggregator.

So the pointer is read from the proxy's storage, with a proof, rather than taken as configuration.
Two things follow. A rotation changes the answer instead of silently freezing it — a hardcoded
aggregator would keep proving a real but no longer updated value until the staleness check
tripped. And there is no step left where the example trusts something it has not verified.

The `aggregator` input exists for feeds that genuinely have no proxy. Using it on a proxied feed
re-introduces exactly the failure above.

## Storage layout

Chainlink does not document its storage layout, so it was derived by reading slots against
`latestRoundData()` on the live ETH/USD aggregator:

| What | Where |
|---|---|
| `currentPhase` (proxy) | slot 2; `uint16 id` in the low 16 bits, aggregator address in bits 16..175 |
| `s_hotVars` | slot 11; `latestAggregatorRoundId` is the uint32 at bit offset 48 |
| `s_transmissions` | declaration slot 12; entry at `keccak256(pad32(roundId) ++ pad32(12))` |
| `Transmission` | `int192 answer` in the low 192 bits, `uint32 observationsTimestamp`, then `uint32 transmissionTimestamp` |

Chainlink has shipped several aggregator generations and they do not all pack the same way.
**Re-derive this before pointing the example at a different feed.** The unit tests pin real
on-chain words as regression anchors so a layout change fails loudly instead of returning a
plausible wrong number.

## Running on OutLayer

```bash
near call outlayer.testnet request_execution '{
  "source": { "GitHub": {
    "repo": "github.com/out-layer/eth-proof-example",
    "commit": "main",
    "build_target": "wasm32-wasip2"
  }},
  "resource_limits": { "max_instructions": 10000000000, "max_memory_mb": 128, "max_execution_seconds": 60 },
  "input_data": "{\"proxy\":\"0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419\"}",
  "secrets_ref": null,
  "response_format": null,
  "payer_account_id": null,
  "params": null
}' --accountId you.testnet --deposit 0.1 --gas 300000000000000
```

No secrets: every endpoint is public. Give it room on `max_execution_seconds` — the run makes
N+3 sequential round trips to Ethereum, and network latency dominates. The proof verification
itself is a few dozen keccak hashes.

## License

MIT OR Apache-2.0, at your option — see `LICENSE-MIT` and `LICENSE-APACHE`.
