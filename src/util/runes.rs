use std::collections::HashMap;

/// Best-effort runes (runestone) TLV parser utilities.
/// This module maps decoded varints (as produced from concatenated runestone pushdatas)
/// into an "etching" event with commonly used fields.
///
/// Conventions and assumptions (inferred from corpus):
/// - The varints are interpreted as TLV: pairs of (key, value) in-order.
/// - Keys seen in corpus and their tentative meanings:
///   - 1  => divisibility (u32; clamp to 0..=18)
///   - 4  => rune name numeral (u128). We attempt a bijective base-26 decode (A..Z) for a
///          best-effort name, but do not reconstruct bullets/spacers; we keep the raw numeral.
///   - 5  => symbol Unicode code point (u32 => char) when valid
///   - 6  => premine amount (decimal string)
///   - 8  => mint amount (decimal string)
///   - 10 => mint cap (decimal string)
///   - 12 => likely start height (u64)
///   - 14 => likely end height (u64)
///   - Others (e.g., 2, 3, 16, 18, 22) are kept in `extra_terms` as numeric strings for now.
///
/// This module does not implement edict decoding yet. It focuses on etching metadata fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Etching {
    /// Raw TLV pairs captured as numeric strings for forward-compat.
    pub raw_tlv: Vec<(u64, String)>,

    /// The rune name numeral (raw).
    pub name_numeral: Option<u128>,
    /// Best-effort decoded name using bijective base-26 (A..Z). Does not include bullets.
    pub name_decoded: Option<String>,

    /// Divisibility (0..=18)
    pub divisibility: Option<u32>,

    /// Unicode symbol, if codepoint is valid.
    pub symbol: Option<char>,

    /// Premine amount as decimal string (no scaling applied).
    pub premine: Option<String>,

    /// Mint amount as decimal string (per mint).
    pub mint_amount: Option<String>,
    /// Mint cap as decimal string (number of mints or total amount depending on spec).
    pub mint_cap: Option<String>,

    /// Start height (best-effort: key 12).
    pub start_height: Option<u64>,
    /// End height (best-effort: key 14).
    pub end_height: Option<u64>,

    /// Any other numeric terms preserved as key -> value(decimal_string).
    pub extra_terms: HashMap<u64, String>,
}

impl Default for Etching {
    fn default() -> Self {
        Self {
            raw_tlv: Vec::new(),
            name_numeral: None,
            name_decoded: None,
            divisibility: None,
            symbol: None,
            premine: None,
            mint_amount: None,
            mint_cap: None,
            start_height: None,
            end_height: None,
            extra_terms: HashMap::new(),
        }
    }
}

/// Parse TLV pairs from a slice of varints (u128) into an Etching structure.
/// If an odd number of varints is supplied, the last trailing value is ignored.
pub fn parse_etching_from_varints(varints: &[u128]) -> Etching {
    let mut e = Etching::default();

    let mut it = varints.iter();
    while let (Some(&k), Some(&v)) = (it.next(), it.next()) {
        let k_u64 = k as u64;
        let v_str = v.to_string();
        e.raw_tlv.push((k_u64, v_str.clone()));

        match k_u64 {
            1 => {
                // divisibility (clamp to 0..=18)
                let d = (v as i128).max(0).min(18) as u32;
                e.divisibility = Some(d);
            }
            4 => {
                // name numeral
                e.name_numeral = Some(v);
                if v > 0 {
                    e.name_decoded = Some(decode_rune_name_bijective_base26(v));
                } else {
                    e.name_decoded = None;
                }
            }
            5 => {
                // symbol code point
                if v <= u32::MAX as u128 {
                    if let Some(ch) = char::from_u32(v as u32) {
                        e.symbol = Some(ch);
                    }
                }
            }
            6 => {
                // premine
                e.premine = Some(v_str);
            }
            8 => {
                // mint amount
                e.mint_amount = Some(v_str);
            }
            10 => {
                // mint cap
                e.mint_cap = Some(v_str);
            }
            12 => {
                // start height (best-effort)
                if v <= u64::MAX as u128 {
                    e.start_height = Some(v as u64);
                }
            }
            14 => {
                // end height (best-effort)
                if v <= u64::MAX as u128 {
                    e.end_height = Some(v as u64);
                }
            }
            // Preserve all other keys in extra_terms for forward-compatibility.
            other => {
                e.extra_terms.insert(other, v_str);
            }
        }
    }

    e
}

/// Decode a rune name from a bijective base-26 numeral into A..Z.
/// This does not reconstruct bullets/spacers; it's a best-effort readable name.
/// - 1 -> "A", 26 -> "Z", 27 -> "AA", 28 -> "AB", etc.
pub fn decode_rune_name_bijective_base26(mut n: u128) -> String {
    if n == 0 {
        return String::new();
    }
    let mut out = Vec::new();
    while n > 0 {
        // Convert to 0-based digit in [0..25]
        let rem = ((n - 1) % 26) as u8;
        out.push((b'A' + rem) as char);
        n = (n - 1) / 26;
    }
    out.iter().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn to_vec_u128(v: &[&str]) -> Vec<u128> {
        v.iter().map(|s| s.parse::<u128>().unwrap()).collect()
    }

    #[test]
    fn parse_bitcoin_monkey() {
        // BITCOIN•MONKEY sample (from corpus)
        // varints:
        // ["2","3","4","226733853309006054","1","1","3","64","5","128018","6","200000000","10","1000","8","800000","16","5","18","210000"]
        let ints = to_vec_u128(&[
            "2",
            "3",
            "4",
            "226733853309006054",
            "1",
            "1",
            "3",
            "64",
            "5",
            "128018",
            "6",
            "200000000",
            "10",
            "1000",
            "8",
            "800000",
            "16",
            "5",
            "18",
            "210000",
        ]);
        let e = parse_etching_from_varints(&ints);

        // Divisibility 1
        assert_eq!(e.divisibility, Some(1));
        // Symbol 128018 (🐒)
        assert_eq!(e.symbol, Some('🐒'));
        // Premine, mint_amount, mint_cap
        assert_eq!(e.premine.as_deref(), Some("200000000"));
        assert_eq!(e.mint_amount.as_deref(), Some("800000"));
        assert_eq!(e.mint_cap.as_deref(), Some("1000"));

        // Extra terms should contain key 18 => 210000
        assert_eq!(e.extra_terms.get(&18).map(|s| s.as_str()), Some("210000"));

        // Name numeral present; decoded non-empty best-effort
        assert!(e.name_numeral.is_some());
        assert!(e
            .name_decoded
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn parse_workhorse() {
        // WORKHORSE sample
        // ["2","3","4","4929194749106","1","3","3","0","5","128014","6","10000000000","10","3300000","8","300000","22","1"]
        let ints = to_vec_u128(&[
            "2",
            "3",
            "4",
            "4929194749106",
            "1",
            "3",
            "3",
            "0",
            "5",
            "128014",
            "6",
            "10000000000",
            "10",
            "3300000",
            "8",
            "300000",
            "22",
            "1",
        ]);
        let e = parse_etching_from_varints(&ints);

        // Divisibility 3
        assert_eq!(e.divisibility, Some(3));
        // Symbol 128014 (🐎)
        assert_eq!(e.symbol, Some('🐎'));
        // Premine / mint values
        assert_eq!(e.premine.as_deref(), Some("10000000000"));
        assert_eq!(e.mint_cap.as_deref(), Some("3300000"));
        assert_eq!(e.mint_amount.as_deref(), Some("300000"));

        // Extra contains key 22 => 1
        assert_eq!(e.extra_terms.get(&22).map(|s| s.as_str()), Some("1"));

        // Name present and decodes to non-empty
        assert!(e.name_numeral.is_some());
        assert!(e
            .name_decoded
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn parse_flurbo_intergalactic() {
        // FLURBO•INTERGALACTIC sample (with start/end)
        // ["2","7","4","191429130404096713731644420","1","18","3","32","5","402","6","21000000000000000000000000","10","210000000000000000000","8","100000","12","840005","14","1050000","22","1"]
        let ints = to_vec_u128(&[
            "2",
            "7",
            "4",
            "191429130404096713731644420",
            "1",
            "18",
            "3",
            "32",
            "5",
            "402",
            "6",
            "21000000000000000000000000",
            "10",
            "210000000000000000000",
            "8",
            "100000",
            "12",
            "840005",
            "14",
            "1050000",
            "22",
            "1",
        ]);
        let e = parse_etching_from_varints(&ints);

        // Divisibility 18 (clamped to 18 already)
        assert_eq!(e.divisibility, Some(18));

        // Symbol 402 is U+0192 'ƒ' (valid char)
        assert_eq!(e.symbol, Some('ƒ'));

        // Start/end heights
        assert_eq!(e.start_height, Some(840005));
        assert_eq!(e.end_height, Some(1_050_000));

        // Large premine and cap preserved as strings
        assert_eq!(e.premine.as_deref(), Some("21000000000000000000000000"));
        assert_eq!(e.mint_cap.as_deref(), Some("210000000000000000000"));
        assert_eq!(e.mint_amount.as_deref(), Some("100000"));

        // Name present and decodes; cannot assert exact due to unknown bijective mapping origin
        assert!(e.name_numeral.is_some());
        assert!(e
            .name_decoded
            .as_ref()
            .map(|s| !s.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn symbol_misc_samples() {
        // Z•Z•Z•Z•Z•FEHU•Z•Z•Z•Z•Z uses 5->5792 (U+16A0 'ᚠ' appears valid)
        let ints = to_vec_u128(&["5", "5792"]);
        let e = parse_etching_from_varints(&ints);
        assert_eq!(e.symbol, Some('ᚠ'));

        // YAROSLAV uses 5->8383 (U+20BF '₿')
        let ints = to_vec_u128(&["5", "8383", "6", "100"]);
        let e = parse_etching_from_varints(&ints);
        assert_eq!(e.symbol, Some('₿'));
        assert_eq!(e.premine.as_deref(), Some("100"));
    }
}
