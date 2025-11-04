/*!
Utilities for parsing and classifying scriptPubKey, gated by an environment toggle.

Toggle:
- INDEX_SCRIPTS: when set to a truthy value ("1", "true", "yes", "on"), opt-in helpers like
  `classify_if_enabled` will return Some(...). Otherwise they return None.
  Core pure functions (like `classify`) are always available.

This module is Stage 3 of the roadmap:
- Provides standalone helpers only; no DB writes.
- Focused on script classification and light metadata extraction on bitcoin 0.32.x.
*/

use bitcoin::{opcodes, Script};

/// Returns true if INDEX_SCRIPTS is set to a truthy value.
/// Supported truthy values (case-insensitive): "1", "true", "yes", "on".
pub fn is_enabled() -> bool {
    truthy_env("INDEX_SCRIPTS")
}

/// Return Some(meta) only when INDEX_SCRIPTS toggle is enabled; otherwise None.
///
/// You can use this to guard optional indexing or logging logic without scattering
/// env checks in the callsite.
pub fn classify_if_enabled(spk: &Script) -> Option<SpkMeta> {
    if is_enabled() {
        Some(classify(spk))
    } else {
        None
    }
}

/// Classification of a scriptPubKey.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpkType {
    /// Pay-to-pubkey-hash
    P2PKH,
    /// Pay-to-script-hash
    P2SH,
    /// Segwit v0 witness programs
    P2WPKH,
    P2WSH,
    /// Taproot (OP_1 <32-byte x-only key>)
    P2TR,
    /// OP_RETURN data carriers
    OpReturn,
    /// Script that appears to be a witness program but not one of the canonical types above
    /// (e.g., v2..v16 or non-standard length)
    Witness,
    /// Potential bare or otherwise non-standard script types.
    NonStandard,
}

/// Script metadata we can extract cheaply from scriptPubKey.
/// This captures the primary classification, segwit metadata, taproot x-only key, and OP_RETURN payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpkMeta {
    pub spk_type: SpkType,
    /// Witness version for segwit program (if applicable).
    pub witness_version: Option<u8>,
    /// Witness program length (if applicable).
    pub witness_program_len: Option<usize>,
    /// For P2TR, the 32-byte x-only internal key/program.
    pub taproot_xonly_pubkey: Option<[u8; 32]>,
    /// For OP_RETURN, a conservative payload (may be truncated to an immediate push length).
    pub op_return_payload: Option<Vec<u8>>,
}

impl SpkMeta {
    pub fn new(
        spk_type: SpkType,
        witness_version: Option<u8>,
        witness_program_len: Option<usize>,
        taproot_xonly_pubkey: Option<[u8; 32]>,
        op_return_payload: Option<Vec<u8>>,
    ) -> Self {
        Self {
            spk_type,
            witness_version,
            witness_program_len,
            taproot_xonly_pubkey,
            op_return_payload,
        }
    }
}

/// Classify a scriptPubKey and extract light metadata.
/// This function does not consult the environment (no toggle); see `classify_if_enabled`.
pub fn classify(spk: &Script) -> SpkMeta {
    // Use fast-path helpers first.
    if spk.is_p2pkh() {
        return SpkMeta::new(SpkType::P2PKH, None, None, None, None);
    }
    if spk.is_p2sh() {
        return SpkMeta::new(SpkType::P2SH, None, None, None, None);
    }
    if spk.is_p2wpkh() {
        return SpkMeta::new(SpkType::P2WPKH, Some(0), Some(20), None, None);
    }
    if spk.is_p2wsh() {
        return SpkMeta::new(SpkType::P2WSH, Some(0), Some(32), None, None);
    }

    let bytes = spk.as_bytes();

    // Taproot (OP_1 0x20 <32-bytes>)
    if bytes.len() == 34 && bytes[0] == opcodes::all::OP_PUSHNUM_1.to_u8() && bytes[1] == 32 {
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&bytes[2..34]);
        return SpkMeta::new(SpkType::P2TR, Some(1), Some(32), Some(xonly), None);
    }

    // OP_RETURN payload (lightweight heuristic)
    if spk.is_op_return() {
        let payload = op_return_payload(spk);
        return SpkMeta::new(SpkType::OpReturn, None, None, None, payload);
    }

    // Generic witness program fallback: OP_{0..16} <pushlen=N> <program>
    if let Some((ver, program)) = witness_program(spk) {
        // Not one of the canonical P2WPKH/P2WSH/P2TR that we handled above; return Witness
        return SpkMeta::new(SpkType::Witness, Some(ver), Some(program.len()), None, None);
    }

    SpkMeta::new(SpkType::NonStandard, None, None, None, None)
}

/// Return witness version (0..16) and program bytes if `spk` is encoded as a witness program.
///
/// This is a minimal decoder for scriptPubKeys of the form:
/// - OP_n (0..16) PUSHDATA (2..40 bytes)
pub fn witness_program(spk: &Script) -> Option<(u8, Vec<u8>)> {
    let b = spk.as_bytes();
    if b.len() < 4 {
        return None;
    }

    // Version opcode: either OP_0 (0x00) or OP_1..OP_16
    let ver = match b[0] {
        0x00 => 0u8,
        x if (opcodes::all::OP_PUSHNUM_1.to_u8()..=opcodes::all::OP_PUSHNUM_16.to_u8())
            .contains(&x) =>
        {
            // OP_1 is 1, OP_16 is 16
            (x - opcodes::all::OP_PUSHNUM_1.to_u8()) + 1
        }
        _ => return None,
    };

    // Minimal support: single-byte push opcode (<=75)
    let push_len = b[1] as usize;
    if push_len > 40 {
        return None;
    }
    if b.len() != 2 + push_len {
        return None;
    }
    Some((ver, b[2..].to_vec()))
}

/// Extract a conservative OP_RETURN payload.
/// Strategy:
/// - If second byte is a small push opcode (<=75), and total length permits, return exactly that slice.
/// - Otherwise, return all bytes after OP_RETURN (may include opcode bytes).
pub fn op_return_payload(spk: &Script) -> Option<Vec<u8>> {
    let b = spk.as_bytes();
    if b.is_empty() || b[0] != opcodes::all::OP_RETURN.to_u8() {
        return None;
    }
    if b.len() == 1 {
        return Some(Vec::new());
    }
    let push = b[1] as usize;
    if push <= 75 && b.len() >= 2 + push {
        return Some(b[2..2 + push].to_vec());
    }
    // Fallback: return the entire tail excluding OP_RETURN
    Some(b[1..].to_vec())
}

/// Read an env var and interpret it as truthy.
fn truthy_env(key: &str) -> bool {
    match std::env::var(key) {
        Ok(v) => {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::opcodes::all::*;
    use bitcoin::ScriptBuf;

    fn script_from_bytes(v: Vec<u8>) -> ScriptBuf {
        ScriptBuf::from_bytes(v)
    }

    fn p2pkh_script() -> ScriptBuf {
        // OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG
        let mut v = vec![OP_DUP.to_u8(), OP_HASH160.to_u8(), 0x14];
        v.extend([0u8; 20]);
        v.extend([OP_EQUALVERIFY.to_u8(), OP_CHECKSIG.to_u8()]);
        script_from_bytes(v)
    }

    fn p2sh_script() -> ScriptBuf {
        // OP_HASH160 0x14 <20> OP_EQUAL
        let mut v = vec![OP_HASH160.to_u8(), 0x14];
        v.extend([0u8; 20]);
        v.push(OP_EQUAL.to_u8());
        script_from_bytes(v)
    }

    fn p2wpkh_script() -> ScriptBuf {
        // OP_0 0x14 <20>
        let mut v = vec![OP_PUSHBYTES_0.to_u8(), 0x14];
        v.extend([0u8; 20]);
        script_from_bytes(v)
    }

    fn p2wsh_script() -> ScriptBuf {
        // OP_0 0x20 <32>
        let mut v = vec![OP_PUSHBYTES_0.to_u8(), 0x20];
        v.extend([0u8; 32]);
        script_from_bytes(v)
    }

    fn p2tr_script() -> ScriptBuf {
        // OP_1 0x20 <32>
        let mut v = vec![OP_PUSHNUM_1.to_u8(), 0x20];
        v.extend([0x11u8; 32]);
        script_from_bytes(v)
    }

    fn op_return_script() -> ScriptBuf {
        // OP_RETURN 0x02 0xAA 0xBB
        script_from_bytes(vec![OP_RETURN.to_u8(), 0x02, 0xAA, 0xBB])
    }

    #[test]
    fn classify_p2pkh() {
        let s = p2pkh_script();
        let m = classify(&s);
        assert_eq!(m.spk_type, SpkType::P2PKH);
        assert_eq!(m.witness_version, None);
        assert_eq!(m.witness_program_len, None);
        assert!(m.taproot_xonly_pubkey.is_none());
        assert!(m.op_return_payload.is_none());
    }

    #[test]
    fn classify_p2sh() {
        let s = p2sh_script();
        let m = classify(&s);
        assert_eq!(m.spk_type, SpkType::P2SH);
        assert!(m.witness_version.is_none());
    }

    #[test]
    fn classify_p2wpkh() {
        let s = p2wpkh_script();
        let m = classify(&s);
        assert_eq!(m.spk_type, SpkType::P2WPKH);
        assert_eq!(m.witness_version, Some(0));
        assert_eq!(m.witness_program_len, Some(20));
    }

    #[test]
    fn classify_p2wsh() {
        let s = p2wsh_script();
        let m = classify(&s);
        assert_eq!(m.spk_type, SpkType::P2WSH);
        assert_eq!(m.witness_version, Some(0));
        assert_eq!(m.witness_program_len, Some(32));
    }

    #[test]
    fn classify_p2tr() {
        let s = p2tr_script();
        let m = classify(&s);
        assert_eq!(m.spk_type, SpkType::P2TR);
        assert_eq!(m.witness_version, Some(1));
        assert_eq!(m.witness_program_len, Some(32));
        assert_eq!(m.taproot_xonly_pubkey.unwrap(), [0x11u8; 32]);
    }

    #[test]
    fn classify_op_return() {
        let s = op_return_script();
        let m = classify(&s);
        assert_eq!(m.spk_type, SpkType::OpReturn);
        assert_eq!(m.op_return_payload.unwrap(), vec![0xAA, 0xBB]);
    }

    #[test]
    fn generic_witness_v2() {
        // OP_2 0x02 <0xAA 0xBB>
        let s = script_from_bytes(vec![OP_PUSHNUM_2.to_u8(), 0x02, 0xAA, 0xBB]);
        let m = classify(&s);
        assert_eq!(m.spk_type, SpkType::Witness);
        assert_eq!(m.witness_version, Some(2));
        assert_eq!(m.witness_program_len, Some(2));
    }

    #[test]
    fn toggle_is_false_by_default() {
        // Ensure classify_if_enabled returns None without the env var
        // (This test may fail if the env is set outside; it's a sanity check.)
        if std::env::var("INDEX_SCRIPTS").is_err() {
            let s = p2pkh_script();
            assert!(classify_if_enabled(&s).is_none());
        }
    }
}
