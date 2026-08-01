//! Talking to Ethereum RPCs, and deciding which of them to believe.

use crate::mpt::hex;
use serde_json::{json, Value};
use std::time::Duration;
use wasi_http_client::Client;

/// Some providers reject requests without a descriptive User-Agent.
pub const USER_AGENT: &str = "eth-proof-example/1.0 (+https://github.com/out-layer/eth-proof-example)";

/// `wasi-http-client` 0.2 exposes only a connect timeout — a server that accepts and then stalls
/// is bounded by the call's `max_execution_seconds`, not here.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub fn post(rpc_url: &str, body: &Value) -> Result<Value, String> {
    let body_bytes = serde_json::to_vec(body).map_err(|e| e.to_string())?;

    let response = Client::new()
        .post(rpc_url)
        .header("User-Agent", USER_AGENT)
        .header("Content-Type", "application/json")
        .connect_timeout(CONNECT_TIMEOUT)
        .body(&body_bytes)
        .send()
        .map_err(|e| format!("{}: {}", rpc_url, e))?;

    let status = response.status();
    if !(200..300).contains(&status) {
        return Err(format!("{}: HTTP {}", rpc_url, status));
    }

    let raw = response.body().map_err(|e| format!("{}: {}", rpc_url, e))?;
    let parsed: Value =
        serde_json::from_slice(&raw).map_err(|e| format!("{}: malformed JSON: {}", rpc_url, e))?;

    if let Some(err) = parsed.get("error") {
        return Err(format!("{}: RPC error: {}", rpc_url, err));
    }
    parsed
        .get("result")
        .cloned()
        .ok_or_else(|| format!("{}: response had no result", rpc_url))
}

fn call(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
}

/// What a quorum of RPCs agreed the block looks like.
pub struct Header {
    pub number: u64,
    pub hash: String,
    pub state_root: [u8; 32],
    /// RPCs that returned this exact header. Reported so the caller can see the margin.
    pub agreed_by: Vec<String>,
    /// RPCs that answered with something else, or not at all, and why.
    pub rejected: Vec<String>,
}

/// Ask every RPC for the *same* block number and keep the header they agree on.
///
/// This is the step that gives the proof its meaning. A proof only ever says "under this state
/// root, the slot holds X" — the root has to come from somewhere, and taking it from a single
/// node would let that node fabricate a header and a matching trie. Requiring independent
/// providers to produce a byte-identical header means one of them can no longer lie alone.
///
/// The block number is pinned rather than `latest` on purpose: honest nodes are routinely a
/// block or two apart, so comparing `latest` would fail constantly and prove nothing.
pub fn agree_on_header(rpcs: &[String], block_number: u64, min_agree: usize) -> Result<Header, String> {
    let tag = format!("0x{:x}", block_number);
    let mut answers: Vec<(String, String, String)> = Vec::new(); // (rpc, hash, state_root)
    let mut rejected = Vec::new();

    for rpc in rpcs {
        match post(rpc, &call("eth_getBlockByNumber", json!([tag, false]))) {
            Ok(Value::Null) => rejected.push(format!("{}: does not have block {}", rpc, block_number)),
            Ok(block) => {
                let hash = block.get("hash").and_then(|v| v.as_str()).unwrap_or_default();
                let root = block.get("stateRoot").and_then(|v| v.as_str()).unwrap_or_default();
                if hash.is_empty() || root.is_empty() {
                    rejected.push(format!("{}: header missing hash or stateRoot", rpc));
                } else {
                    answers.push((rpc.clone(), hash.to_string(), root.to_string()));
                }
            }
            Err(e) => rejected.push(e),
        }
    }

    // Pick the header the most providers vouch for, then check it clears the threshold.
    let mut best: Option<(String, String, Vec<String>)> = None;
    for (_, hash, root) in &answers {
        let backers: Vec<String> = answers
            .iter()
            .filter(|(_, h, r)| h == hash && r == root)
            .map(|(rpc, _, _)| rpc.clone())
            .collect();
        if best.as_ref().map_or(true, |(_, _, b)| backers.len() > b.len()) {
            best = Some((hash.clone(), root.clone(), backers));
        }
    }

    let (hash, root, agreed_by) = best.ok_or_else(|| {
        format!(
            "no RPC returned a usable header for block {}: {}",
            block_number,
            rejected.join("; ")
        )
    })?;

    if agreed_by.len() < min_agree {
        // Disagreement is the interesting failure: it means at least one provider is lying,
        // broken, or on a fork, and we cannot tell which. Refusing is the only honest answer.
        let others: Vec<String> = answers
            .iter()
            .filter(|(rpc, _, _)| !agreed_by.contains(rpc))
            .map(|(rpc, h, _)| format!("{} said {}", rpc, h))
            .collect();
        return Err(format!(
            "only {} of {} RPCs agreed on block {} (needed {}). Agreed on {}: {}. Disagreed: {}. Unusable: {}",
            agreed_by.len(),
            rpcs.len(),
            block_number,
            min_agree,
            hash,
            agreed_by.join(", "),
            if others.is_empty() { "none".into() } else { others.join("; ") },
            if rejected.is_empty() { "none".into() } else { rejected.join("; ") },
        ));
    }

    Ok(Header {
        number: block_number,
        hash,
        state_root: parse_h256(&root)?,
        agreed_by,
        rejected,
    })
}

/// The current head, minus a margin so every provider has had time to see the same block.
pub fn block_number_behind_head(rpcs: &[String], behind: u64) -> Result<u64, String> {
    let mut errors = Vec::new();
    for rpc in rpcs {
        match post(rpc, &call("eth_blockNumber", json!([]))) {
            Ok(v) => {
                let s = v.as_str().unwrap_or_default();
                if let Ok(n) = u64::from_str_radix(s.trim_start_matches("0x"), 16) {
                    return Ok(n.saturating_sub(behind));
                }
                errors.push(format!("{}: unreadable block number {:?}", rpc, s));
            }
            Err(e) => errors.push(e),
        }
    }
    Err(format!("no RPC returned a block number: {}", errors.join("; ")))
}

pub struct SlotProof {
    pub value: Vec<u8>,
    pub storage_hash: [u8; 32],
}

/// Fetch and verify one storage slot against an already-agreed state root.
///
/// Two proofs are checked, in the order that matters: first that the account really is in the
/// state trie under this root (which yields its storage root), then that the slot is in the
/// account's storage trie. Verifying the second without the first would prove nothing — the
/// storage root would be the RPC's word.
pub fn proven_slot(
    rpcs: &[String],
    address: &str,
    slot: &[u8; 32],
    header: &Header,
) -> Result<SlotProof, String> {
    let tag = format!("0x{:x}", header.number);
    let params = json!([address, [hex(slot)], tag]);

    let mut errors = Vec::new();
    for rpc in rpcs {
        let proof = match post(rpc, &call("eth_getProof", params.clone())) {
            Ok(p) => p,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        match verify_account_and_slot(&proof, address, slot, &header.state_root) {
            Ok(found) => return Ok(found),
            // A proof that fails to verify is on that provider, not on the chain: try the next.
            Err(e) => errors.push(format!("{}: {}", rpc, e)),
        }
    }
    Err(format!(
        "no RPC produced a valid proof for slot {} of {}: {}",
        hex(slot),
        address,
        errors.join("; ")
    ))
}

fn verify_account_and_slot(
    proof: &Value,
    address: &str,
    slot: &[u8; 32],
    state_root: &[u8; 32],
) -> Result<SlotProof, String> {
    let account_proof = decode_nodes(proof, "accountProof")?;
    let address_bytes = parse_bytes(address)?;

    let account_rlp = crate::mpt::verify_proof(state_root, &address_bytes, &account_proof)?
        .ok_or_else(|| format!("account {} is not in the state trie", address))?;

    // Account RLP is [nonce, balance, storageRoot, codeHash].
    let account = rlp::Rlp::new(&account_rlp);
    let storage_root: Vec<u8> = account
        .val_at(2)
        .map_err(|e| format!("account storage root: {}", e))?;
    if storage_root.len() != 32 {
        return Err(format!("account storage root is {} bytes", storage_root.len()));
    }
    let mut storage_hash = [0u8; 32];
    storage_hash.copy_from_slice(&storage_root);

    // The RPC also echoes storageHash at the top level; it must match what the proof establishes,
    // otherwise the two halves of the response describe different accounts.
    if let Some(claimed) = proof.get("storageHash").and_then(|v| v.as_str()) {
        if parse_h256(claimed)? != storage_hash {
            return Err("storageHash in the response contradicts the account proof".to_string());
        }
    }

    let storage_proof = proof
        .get("storageProof")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .ok_or("response contained no storageProof")?;
    let nodes = decode_nodes(storage_proof, "proof")?;

    let raw = crate::mpt::verify_proof(&storage_hash, slot, &nodes)?;
    // An empty slot is a legitimate, proven answer: the trie says nothing is stored there.
    let value = match raw {
        // Storage values are RLP-encoded big-endian integers with leading zeros stripped.
        Some(encoded) => rlp::Rlp::new(&encoded)
            .as_val::<Vec<u8>>()
            .map_err(|e| format!("storage value: {}", e))?,
        None => Vec::new(),
    };

    Ok(SlotProof { value, storage_hash })
}

fn decode_nodes(value: &Value, field: &str) -> Result<Vec<Vec<u8>>, String> {
    value
        .get(field)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("response has no {}", field))?
        .iter()
        .map(|n| parse_bytes(n.as_str().unwrap_or_default()))
        .collect()
}

pub fn parse_bytes(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex: 0x{}", s));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {}", e)))
        .collect()
}

pub fn parse_h256(s: &str) -> Result<[u8; 32], String> {
    let bytes = parse_bytes(s)?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}
