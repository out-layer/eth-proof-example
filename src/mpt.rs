//! Merkle-Patricia trie proof verification.
//!
//! Ethereum stores accounts and their storage in Merkle-Patricia tries. A proof is the list of
//! trie nodes along the path from the root to one leaf. Verifying it is a walk: hash each node,
//! check the hash is what the parent pointed at, consume the part of the key that node covers,
//! and move on. If the walk ends at the expected key with a value, that value provably belongs
//! to the trie with that root.
//!
//! What this does NOT establish is that the root itself is real — see `rpc::agree_on_header`.

use tiny_keccak::{Hasher, Keccak};

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut k = Keccak::v256();
    k.update(data);
    k.finalize(&mut out);
    out
}

/// Expand bytes into nibbles: one 4-bit half-byte per element, high half first.
/// Trie keys are addressed a nibble at a time, which is what gives branch nodes 16 children.
fn to_nibbles(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(b >> 4);
        out.push(b & 0x0f);
    }
    out
}

/// Decode a hex-prefix encoded path (Appendix C of the yellow paper).
///
/// The first nibble carries two flags: bit 1 says "this is a leaf, not an extension", bit 0 says
/// "the path has an odd number of nibbles, so the second nibble is already payload". Getting the
/// odd/even case wrong silently shifts every subsequent comparison, so it is worth stating.
fn decode_path(encoded: &[u8]) -> (Vec<u8>, bool) {
    let nibbles = to_nibbles(encoded);
    if nibbles.is_empty() {
        return (Vec::new(), false);
    }
    let flag = nibbles[0];
    let is_leaf = flag & 0b0010 != 0;
    let odd_len = flag & 0b0001 != 0;
    let start = if odd_len { 1 } else { 2 };
    (nibbles[start..].to_vec(), is_leaf)
}

/// Walk a proof from `root` down to `key`, returning the value stored there.
///
/// `Ok(None)` is a proof of *absence*: the walk legitimately ran out of trie before reaching the
/// key. That is a valid, verifiable answer — an empty storage slot, or an account that does not
/// exist — and it is deliberately distinct from `Err`, which means the proof did not hold up.
pub fn verify_proof(
    root: &[u8; 32],
    key: &[u8],
    proof: &[Vec<u8>],
) -> Result<Option<Vec<u8>>, String> {
    // Keys are hashed before they enter the trie (Ethereum uses a "secure" trie).
    let path = to_nibbles(&keccak256(key));
    let mut pos = 0usize;
    let mut expected = *root;

    for (depth, node) in proof.iter().enumerate() {
        // The link from the parent is a hash of the child's RLP. Checking it here is the only
        // thing that makes the chain of nodes a proof rather than a list of suggestions.
        let got = keccak256(node);
        if got != expected {
            return Err(format!(
                "proof node {} does not hash to the value its parent points at (expected {}, got {})",
                depth,
                hex(&expected),
                hex(&got)
            ));
        }

        let decoded = rlp::Rlp::new(node);
        let items = decoded
            .item_count()
            .map_err(|e| format!("proof node {} is not a list: {}", depth, e))?;

        match items {
            // Branch: 16 child slots plus a value slot for a key that ends exactly here.
            17 => {
                if pos == path.len() {
                    let value: Vec<u8> = decoded
                        .val_at(16)
                        .map_err(|e| format!("branch value at node {}: {}", depth, e))?;
                    return Ok(if value.is_empty() { None } else { Some(value) });
                }
                let child: Vec<u8> = decoded
                    .val_at(path[pos] as usize)
                    .map_err(|e| format!("branch child at node {}: {}", depth, e))?;
                pos += 1;
                if child.is_empty() {
                    return Ok(None); // no such branch: the key is absent
                }
                expected = as_hash(&child, depth)?;
            }

            // Leaf or extension: a packed path segment plus either the value or the next hash.
            2 => {
                let encoded: Vec<u8> = decoded
                    .val_at(0)
                    .map_err(|e| format!("path at node {}: {}", depth, e))?;
                let (segment, is_leaf) = decode_path(&encoded);

                if pos + segment.len() > path.len() || path[pos..pos + segment.len()] != segment[..]
                {
                    // The node covers a different part of the keyspace, which is itself proof
                    // that nothing is stored under our key.
                    return Ok(None);
                }
                pos += segment.len();

                if is_leaf {
                    if pos != path.len() {
                        return Ok(None);
                    }
                    let value: Vec<u8> = decoded
                        .val_at(1)
                        .map_err(|e| format!("leaf value at node {}: {}", depth, e))?;
                    return Ok(Some(value));
                }

                let child: Vec<u8> = decoded
                    .val_at(1)
                    .map_err(|e| format!("extension child at node {}: {}", depth, e))?;
                expected = as_hash(&child, depth)?;
            }

            n => return Err(format!("proof node {} has {} items, expected 2 or 17", depth, n)),
        }
    }

    Err("proof ended before reaching the key".to_string())
}

/// A child reference is normally a 32-byte hash. Nodes shorter than 32 bytes are inlined by the
/// spec rather than referenced; a proof that relies on one is malformed for our purposes.
fn as_hash(child: &[u8], depth: usize) -> Result<[u8; 32], String> {
    if child.len() != 32 {
        return Err(format!(
            "proof node {} points at an inlined {}-byte node, which this verifier does not follow",
            depth,
            child.len()
        ));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(child);
    Ok(out)
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_matches_known_vector() {
        // keccak256("") — the canonical empty hash every Ethereum implementation agrees on.
        assert_eq!(
            hex(&keccak256(b"")),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn nibbles_split_high_half_first() {
        assert_eq!(to_nibbles(&[0xab, 0x0f]), vec![0x0a, 0x0b, 0x00, 0x0f]);
    }

    #[test]
    fn hex_prefix_decodes_both_parities() {
        // 0x20 = leaf, even length -> both flag nibbles dropped
        assert_eq!(decode_path(&[0x20, 0xab]), (vec![0x0a, 0x0b], true));
        // 0x3a = leaf, odd length -> the 'a' is already payload
        assert_eq!(decode_path(&[0x3a]), (vec![0x0a], true));
        // 0x00 = extension, even length
        assert_eq!(decode_path(&[0x00, 0xab]), (vec![0x0a, 0x0b], false));
        // 0x1a = extension, odd length
        assert_eq!(decode_path(&[0x1a]), (vec![0x0a], false));
    }

    #[test]
    fn tampered_node_is_rejected() {
        // A single-leaf trie: root = keccak(leaf). Flipping one byte of the leaf must break it.
        let key = b"k";
        let mut stream = rlp::RlpStream::new_list(2);
        stream.append(&vec![0x20u8]); // leaf, even, empty remaining path
        stream.append(&vec![0x42u8]);
        let leaf = stream.out().to_vec();
        let root = keccak256(&leaf);

        let mut tampered = leaf.clone();
        *tampered.last_mut().unwrap() = 0x43;
        let err = verify_proof(&root, key, &[tampered]).unwrap_err();
        assert!(err.contains("does not hash to"), "unexpected error: {err}");
    }
}
