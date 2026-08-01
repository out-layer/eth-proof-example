//! Read Ethereum state without trusting the RPC that served it.
//!
//! An `eth_call` is a computation the node performs for you: it hands back a number and there is
//! nothing to check it against. `eth_getProof` hands back the Merkle-Patricia path from the state
//! root down to the value, which either hashes together correctly or does not.
//!
//! A proof on its own is not enough, because the state root comes from the same node. So the run
//! has two halves:
//!
//!   1. pin a block number and require several independent RPCs to return a byte-identical
//!      header — a single provider can then no longer invent a state root;
//!   2. verify the account and storage proofs against that agreed root, inside the enclave.
//!
//! What this proves is that the value really is on Ethereum. It says nothing about whether the
//! value is *correct* — a Merkle proof will faithfully prove a bad Chainlink price. Establishing
//! that the oracle committee itself vouched for the number is a different exercise: verifying the
//! signatures on the OCR report.

mod chainlink;
mod mpt;
mod rpc;

use mpt::hex;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Public endpoints, chosen to sit behind different operators — agreement is only meaningful
/// between parties that could disagree.
const DEFAULT_RPCS: &[&str] = &[
    "https://ethereum-rpc.publicnode.com",
    "https://eth.drpc.org",
    "https://rpc.mevblocker.io",
];

/// How far behind the head to read. Nodes see new blocks at slightly different times, so asking
/// for the very tip guarantees disagreement that means nothing.
const DEFAULT_BLOCKS_BEHIND: u64 = 8;

/// Chainlink feeds are heartbeat-driven; ETH/USD updates at least hourly. Anything older than
/// this is reported rather than returned, because a proof of a stale price is still stale.
const DEFAULT_MAX_AGE_SECS: u64 = 7200;

#[derive(Deserialize)]
struct Input {
    /// Chainlink feed address — the proxy, i.e. the address Chainlink's own docs list.
    /// Which aggregator it points at is read out of the proxy's storage, with a proof, so a
    /// rotation on Chainlink's side changes the answer instead of freezing this example.
    proxy: String,
    /// Skip the proxy hop and read this aggregator directly. Only for feeds that have no proxy;
    /// hardcoding it means an aggregator rotation silently serves a frozen price.
    #[serde(default)]
    aggregator: Option<String>,
    /// Human label for the feed, e.g. "ETH/USD". Echoed back so the number has a unit.
    /// It is a label, not a proven fact — the on-chain feed carries no name.
    #[serde(default)]
    pair: Option<String>,
    #[serde(default)]
    decimals: Option<u32>,
    #[serde(default)]
    rpcs: Option<Vec<String>>,
    /// How many RPCs must return the same header. Defaults to a majority.
    #[serde(default)]
    min_agree: Option<usize>,
    #[serde(default)]
    blocks_behind: Option<u64>,
    #[serde(default)]
    max_age_secs: Option<u64>,
}

#[derive(Serialize)]
struct Evidence {
    block_number: u64,
    block_hash: String,
    state_root: String,
    storage_hash: String,
    /// Aggregator the proxy pointed at in this block, and which generation that is.
    aggregator: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    phase_id: Option<u16>,
    round_id: u32,
    hot_vars_slot: String,
    transmission_slot: String,
    /// RPCs that returned this header. Anyone can re-check the hash against a block explorer.
    agreed_by: Vec<String>,
    /// Providers that were dropped, and why. Empty is the boring case; non-empty is the point.
    rejected: Vec<String>,
}

/// A plain-language summary of what the run established, so the numbers below it are readable
/// without knowing what a Merkle-Patricia trie is.
#[derive(Serialize)]
struct Verified {
    /// One line: what is now known, and on whose word the rest still rests.
    summary: String,
    /// Storage slots proven, each with its own account + storage path.
    storage_proofs: usize,
    /// Trie nodes hashed and checked. Every one had to match the hash its parent published.
    trie_nodes_checked: usize,
    /// How many independent providers returned the identical header the proofs were checked against.
    rpcs_agreeing: String,
    /// Check the block yourself; the price is inside that block's state.
    explorer: String,
    /// The boundary of the claim, stated where nobody can miss it.
    not_proven: String,
}

#[derive(Serialize)]
struct Output {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pair: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    price: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    verified: Option<Verified>,
    #[serde(skip_serializing_if = "Option::is_none")]
    answer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<u32>,
    /// When the oracles observed the value, as opposed to when the report was mined.
    #[serde(skip_serializing_if = "Option::is_none")]
    observed_at: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    age_secs: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence: Option<Evidence>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn main() {
    let mut raw = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut raw) {
        return emit(fail(format!("could not read stdin: {}", e)));
    }

    let input: Input = match serde_json::from_str(&raw) {
        Ok(i) => i,
        Err(e) => return emit(fail(format!("invalid JSON input: {}", e))),
    };

    emit(match run(input) {
        Ok(out) => out,
        Err(e) => fail(e),
    })
}

fn run(input: Input) -> Result<Output, String> {
    let rpcs: Vec<String> = input
        .rpcs
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_RPCS.iter().map(|s| s.to_string()).collect());
    let min_agree = input.min_agree.unwrap_or(rpcs.len() / 2 + 1).max(1);
    if min_agree > rpcs.len() {
        return Err(format!(
            "min_agree is {} but only {} RPCs were given",
            min_agree,
            rpcs.len()
        ));
    }

    // 1. Agree on which block, and on what its state root is.
    let behind = input.blocks_behind.unwrap_or(DEFAULT_BLOCKS_BEHIND);
    let block_number = rpc::block_number_behind_head(&rpcs, behind)?;
    let header = rpc::agree_on_header(&rpcs, block_number, min_agree)?;

    // 2. Prove which aggregator the proxy currently points at. Taking this from configuration
    //    would leave one unverified link in a chain whose whole point is that there are none.
    let (aggregator, phase_id, phase_nodes) = match &input.aggregator {
        Some(explicit) => (explicit.clone(), None, 0),
        None => {
            let phase_slot = chainlink::current_phase_slot();
            let proven = rpc::proven_slot(&rpcs, &input.proxy, &phase_slot, &header)?;
            let (addr, phase) = chainlink::aggregator_from_current_phase(&proven.value)?;
            (addr, Some(phase), proven.nodes_checked)
        }
    };

    // 3. Prove the latest round id. Reading it with eth_call instead would hand the node a way
    //    to point us at an old round, so it goes through a proof like everything else.
    let hot_vars = chainlink::hot_vars_slot();
    let hot = rpc::proven_slot(&rpcs, &aggregator, &hot_vars, &header)?;
    let round_id = chainlink::round_id_from_hot_vars(&hot.value)?;

    // 4. Prove that round's answer. Same block throughout, so one state root covers every hop.
    let slot = chainlink::transmission_slot(round_id);
    let proven = rpc::proven_slot(&rpcs, &aggregator, &slot, &header)?;
    let transmission = chainlink::decode_transmission(&proven.value)?;

    let decimals = input.decimals.unwrap_or(8);
    let price = transmission.answer as f64 / 10f64.powi(decimals as i32);
    let pair = input.pair.clone().unwrap_or_else(|| "price".to_string());
    let nodes = phase_nodes + hot.nodes_checked + proven.nodes_checked;
    let proofs = if phase_nodes > 0 { 3 } else { 2 };

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let age = now.saturating_sub(transmission.updated_at as u64);
    let max_age = input.max_age_secs.unwrap_or(DEFAULT_MAX_AGE_SECS);
    if now > 0 && age > max_age {
        return Err(format!(
            "price is proven but stale: last update {}s ago, limit {}s (round {}, block {})",
            age, max_age, round_id, header.number
        ));
    }

    Ok(Output {
        success: true,
        pair: input.pair.clone(),
        price: Some(price),
        verified: Some(Verified {
            summary: format!(
                "{} = {} is the value Chainlink had stored on Ethereum at block {}. \
                 Read out of the contract's storage with a Merkle proof and re-checked here, \
                 so no node in the path could have altered it.",
                pair, price, header.number
            ),
            storage_proofs: proofs,
            trie_nodes_checked: nodes,
            rpcs_agreeing: format!("{} of {}", header.agreed_by.len(), rpcs.len()),
            explorer: format!("https://etherscan.io/block/{}", header.number),
            not_proven: "That this is the right price. Chainlink published it; the proof shows \
                         it was delivered unaltered, not that it is accurate."
                .to_string(),
        }),
        answer: Some(transmission.answer.to_string()),
        updated_at: Some(transmission.updated_at),
        observed_at: Some(transmission.observed_at),
        age_secs: Some(age),
        evidence: Some(Evidence {
            block_number: header.number,
            block_hash: header.hash.clone(),
            state_root: hex(&header.state_root),
            storage_hash: hex(&proven.storage_hash),
            aggregator,
            phase_id,
            round_id,
            hot_vars_slot: hex(&hot_vars),
            transmission_slot: hex(&slot),
            agreed_by: header.agreed_by.clone(),
            rejected: header.rejected.clone(),
        }),
        error: None,
    })
}

fn fail(message: String) -> Output {
    Output {
        success: false,
        price: None,
        pair: None,
        verified: None,
        answer: None,
        updated_at: None,
        observed_at: None,
        age_secs: None,
        evidence: None,
        error: Some(message),
    }
}

fn emit(output: Output) {
    // OutLayer captures stdout; stderr would vanish into worker logs where no caller sees it.
    print!("{}", serde_json::to_string(&output).unwrap());
    io::stdout().flush().ok();
}
