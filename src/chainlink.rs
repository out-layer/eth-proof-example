//! Reading a Chainlink price out of proven storage.
//!
//! The layout below is not documented anywhere authoritative; it was derived by reading storage
//! against `latestRoundData()` on the live ETH/USD aggregator and checking the fields line up.
//! Re-derive it before trusting it on a different feed generation — Chainlink has shipped several
//! aggregator versions and they do not all pack the same way.

use crate::mpt::keccak256;

/// Declaration slot of `s_transmissions`, the `mapping(uint32 => Transmission)` that holds every
/// round's answer. Verified against `0x7d4e742018fb52e48b08be73d041c18b21de6fb5` (ETH/USD).
const TRANSMISSIONS_SLOT: u64 = 12;

/// Slot holding the packed hot variables, of which we want `latestAggregatorRoundId`.
const HOT_VARS_SLOT: u64 = 11;

/// Bit offset of `latestAggregatorRoundId` (uint32) inside the hot-vars word.
const ROUND_ID_SHIFT: u32 = 48;

/// Slot holding `currentPhase` on `EACAggregatorProxy`: a `uint16 id` in the low 16 bits and the
/// current aggregator's address in bits 16..175.
const CURRENT_PHASE_SLOT: u64 = 2;

pub fn current_phase_slot() -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[24..32].copy_from_slice(&CURRENT_PHASE_SLOT.to_be_bytes());
    slot
}

/// The aggregator a proxy currently points at, plus which phase that is.
///
/// Reading this from storage rather than taking it as configuration is what makes the example
/// survive Chainlink rotating an aggregator: the pointer is proven at the same block as the
/// price, so an upgrade changes the answer instead of silently freezing it. It also closes the
/// last gap where the example would otherwise be trusting something it had not verified.
pub fn aggregator_from_current_phase(value: &[u8]) -> Result<(String, u16), String> {
    let w = word(value)?;
    if w == [0u8; 32] {
        return Err("currentPhase slot is empty — this address is not an aggregator proxy".into());
    }
    let address = crate::mpt::hex(&w[10..30]);
    let phase = u16::from_be_bytes(w[30..32].try_into().unwrap());
    if address == "0x0000000000000000000000000000000000000000" {
        return Err("proxy points at the zero address".into());
    }
    Ok((address, phase))
}

/// Storage key of a mapping entry: `keccak256(pad32(key) ++ pad32(declarationSlot))`.
pub fn transmission_slot(round_id: u32) -> [u8; 32] {
    let mut preimage = [0u8; 64];
    preimage[28..32].copy_from_slice(&round_id.to_be_bytes());
    preimage[56..64].copy_from_slice(&TRANSMISSIONS_SLOT.to_be_bytes());
    keccak256(&preimage)
}

pub fn hot_vars_slot() -> [u8; 32] {
    let mut slot = [0u8; 32];
    slot[24..32].copy_from_slice(&HOT_VARS_SLOT.to_be_bytes());
    slot
}

/// Left-pad a stripped storage value back to 32 bytes.
///
/// Storage words come off the trie with leading zeros removed, so a value must be re-aligned
/// before any field can be sliced out of it. Skipping this is the classic way to read a price
/// that is off by a factor of 256.
fn word(value: &[u8]) -> Result<[u8; 32], String> {
    if value.len() > 32 {
        return Err(format!("storage word is {} bytes", value.len()));
    }
    let mut out = [0u8; 32];
    out[32 - value.len()..].copy_from_slice(value);
    Ok(out)
}

pub fn round_id_from_hot_vars(value: &[u8]) -> Result<u32, String> {
    let w = word(value)?;
    if w == [0u8; 32] {
        return Err("hot-vars slot is empty — wrong address, or not an OCR aggregator".into());
    }
    let low = u128::from_be_bytes(w[16..32].try_into().unwrap());
    Ok(((low >> ROUND_ID_SHIFT) & 0xffff_ffff) as u32)
}

pub struct Transmission {
    /// Raw on-chain integer; divide by 10^decimals for a human price.
    pub answer: i128,
    /// When the oracles observed the value.
    pub observed_at: u32,
    /// When the report landed on chain.
    pub updated_at: u32,
}

/// Unpack `Transmission { int192 answer; uint32 observationsTimestamp; uint32 transmissionTimestamp }`.
///
/// The two timestamps sit in the top 64 bits, the answer occupies the low 192.
pub fn decode_transmission(value: &[u8]) -> Result<Transmission, String> {
    let w = word(value)?;
    if w == [0u8; 32] {
        return Err("transmission slot is empty — that round was never written".into());
    }

    let updated_at = u32::from_be_bytes(w[0..4].try_into().unwrap());
    let observed_at = u32::from_be_bytes(w[4..8].try_into().unwrap());

    // int192, two's complement. Prices are positive in practice, but a feed can legitimately go
    // negative (spreads, rates), and silently reading that as a huge positive would be worse than
    // any error we could return.
    let mut answer = 0i128;
    let low = &w[8..32]; // 24 bytes = 192 bits
    if low[0] & 0x80 != 0 {
        // Negative: only representable in i128 if the top 8 bytes are all sign-extension.
        if low[..8] != [0xff; 8] {
            return Err("negative answer does not fit in i128".into());
        }
        answer = i128::from_be_bytes(low[8..24].try_into().unwrap());
    } else {
        if low[..8] != [0u8; 8] {
            return Err("answer does not fit in i128".into());
        }
        answer |= i128::from_be_bytes(low[8..24].try_into().unwrap());
    }

    Ok(Transmission { answer, observed_at, updated_at })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mpt::hex;

    /// Real slot word read from ETH/USD at block 25660999, kept as a regression anchor: if the
    /// packing assumptions ever drift, this fails instead of quietly returning a wrong price.
    const LIVE: &str = "6a6e0aaf6a6e0aa2000000000000000000000000000000000000002b9729fbdb";

    fn bytes(h: &str) -> Vec<u8> {
        (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn decodes_the_live_eth_usd_word() {
        let t = decode_transmission(&bytes(LIVE)).unwrap();
        assert_eq!(t.answer, 187_219_704_795); // 1872.19704795 at 8 decimals
        assert_eq!(t.observed_at, 1_785_596_578);
        assert_eq!(t.updated_at, 1_785_596_591);
    }

    #[test]
    fn round_id_sits_where_we_think_it_does() {
        // Live hot-vars word from the same aggregator; roundId was 32110.
        let w = bytes("0000000000000000000000000000000000000000000000007d6e00001b25060a");
        assert_eq!(round_id_from_hot_vars(&w).unwrap(), 32110);
    }

    #[test]
    fn mapping_slot_matches_solidity() {
        // keccak256(pad32(32110) ++ pad32(12)) — the slot the live proof was fetched from.
        assert_eq!(
            hex(&transmission_slot(32110)),
            "0xfb0c0f87fa745f487fbe63c0b856f35fd1923999bc296b35f7e98a02b851651e"
        );
    }

    #[test]
    fn stripped_values_are_realigned() {
        // The trie hands back words with leading zeros removed, which is how the hot-vars word
        // actually arrives. Both spellings must decode to the same round.
        let padded = bytes("0000000000000000000000000000000000000000000000007d6e00001b25060a");
        let stripped = bytes("7d6e00001b25060a");
        assert_eq!(
            round_id_from_hot_vars(&padded).unwrap(),
            round_id_from_hot_vars(&stripped).unwrap()
        );
    }

    #[test]
    fn reads_the_aggregator_out_of_the_proxy_phase_word() {
        // Live currentPhase word from the ETH/USD proxy: phase 7, pointing at 0x7d4e7420...
        let w = bytes("000000000000000000007d4e742018fb52e48b08be73d041c18b21de6fb50007");
        let (addr, phase) = aggregator_from_current_phase(&w).unwrap();
        assert_eq!(addr, "0x7d4e742018fb52e48b08be73d041c18b21de6fb5");
        assert_eq!(phase, 7);
    }

    #[test]
    fn rejects_an_address_that_is_not_a_proxy() {
        assert!(aggregator_from_current_phase(&[]).is_err());
    }

    #[test]
    fn empty_slot_is_an_error_not_a_zero_price() {
        assert!(decode_transmission(&[]).is_err());
    }
}
