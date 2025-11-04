//! Postgres bitcoin blockchain
//!
//! ## Why is this code so big & complex?
//!
//! ### Performance
//!
//! Initiall indexing of the whole Bitcoin history can take a lot of time.
//! For the indexer to be practical initial sync needs to be fast.. That's why all the
//! tricks possible are used:
//!
//! * we keep track of `mode` and sometimes do thing differently depending on it
//! * schema is being managed to build most indices only after all the initial data has been indexed
//! * we resort to building raw SQL queries because multi-value `INSERT`s are absolutely the fastest insert method
//! * this is generally OK, because all the data here is trusted
//!
//! ### Data consistency
//!
//! Shutting down, crashes, etc. should leave the data in a consistent state.
//! Indexer guarantees that reorgs are atomic - one will never observe chain shrinking / in the middle of a reorg.
//! We heavily rely on transactions.
//!
use log::{debug, error, info, trace, warn};

use super::*;
use crate::{BlockHash, BlockHeight};
use bitcoin::hash_types::Txid;
use common_failures::prelude::*;
use fallible_iterator::FallibleIterator;
use hex::ToHex;
use itertools::Itertools;

/// shorter `postgres` crate import names to just `pg::X`
mod pg {
    pub use postgres::{types::ToSql, Client, GenericClient, Transaction};
    // pub type Result<T> = std::result::Result<T, postgres::error::Error>;
}

use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Write},
    sync::{Arc, Mutex},
    time::Instant,
};

type BlockHeightSigned = i32;

/*
/// Either `Connection` or `Transaction` for the code that needs to be generic over it
trait GenericConnection {
    fn query<'a>(&'a self, query: &str, params: &[&dyn pg::BorrowToSql]) -> pg::Result<pg::RowIter>;
}

impl GenericConnection for pg::Client {
    fn query<'a>(&'a self, query: &str, params: &[&dyn pg::BorrowToSql]) -> pg::Result<pg::RowIter> {
        self.query_raw(query, params)
    }
}

impl<'a> GenericConnection for pg::Transaction<'a> {
    fn query<'b>(&'b self, query: &str, params: &[&dyn pg::BorrowToSql]) -> pg::Result<pg::RowIter> {
        self.query_raw(query, params)
    }
}
*/

/// Establish connection with the DB.
/// If PGSSLROOTCERT, PGSSLCERT and PGSSLKEY are set and the binary is built with the
/// 'pg_tls_openssl' feature (and corresponding dependencies), an OpenSSL TLS connector
/// is used for mTLS. Otherwise, it falls back to a non-TLS connection.
///
/// Expected env:
/// - DATABASE_URL: e.g. postgres://bitcoin-indexer@db.example.com:5432/bitcoin
/// - PGSSLROOTCERT: /home/USER/.config/tls/example.com/cert/ca.example.com.pem
/// - PGSSLCERT:     /home/USER/.config/tls/example.com/cert/client.example.com.pem
/// - PGSSLKEY:      /home/USER/.config/tls/example.com/key/client.example.com.pem
pub fn establish_connection(url: &str) -> pg::Client {
    // Detect TLS configuration via environment variables.
    let ca = std::env::var("PGSSLROOTCERT").ok();
    let cert = std::env::var("PGSSLCERT").ok();
    let key = std::env::var("PGSSLKEY").ok();

    // Basic URL diagnostics
    match url::Url::parse(url) {
        Ok(u) => {
            info!(
                "PG connect target: scheme={} host={:?} port={:?} db={} user={}",
                u.scheme(),
                u.host_str(),
                u.port_or_known_default(),
                u.path().trim_start_matches('/'),
                u.username()
            );
        }
        Err(e) => {
            warn!("PG connect target: failed to parse URL: {}", e);
        }
    }

    // TLS env diagnostics
    debug!(
        "TLS env: PGSSLROOTCERT={} PGSSLCERT={} PGSSLKEY={}",
        ca.as_deref().unwrap_or(""),
        cert.as_deref().unwrap_or(""),
        key.as_deref().unwrap_or("")
    );

    // TLS file diagnostics (paths, readability) and client cert subject
    #[cfg(feature = "pg_tls_openssl")]
    {
        if let Some(ref p) = ca {
            match std::fs::canonicalize(p) {
                Ok(abs) => debug!("PGSSLROOTCERT path: {}", abs.display()),
                Err(e) => debug!("PGSSLROOTCERT path: {} (err: {})", p, e),
            }
        }
        if let Some(ref p) = cert {
            match std::fs::canonicalize(p) {
                Ok(abs) => debug!("PGSSLCERT path: {}", abs.display()),
                Err(e) => debug!("PGSSLCERT path: {} (err: {})", p, e),
            }
            // Try to print client certificate subject CN
            if let Ok(pem) = std::fs::read(p) {
                if let Ok(x509) = openssl::x509::X509::from_pem(&pem) {
                    use openssl::nid::Nid;
                    if let Some(entry) = x509.subject_name().entries_by_nid(Nid::COMMONNAME).next()
                    {
                        if let Ok(val) = entry.data().as_utf8() {
                            debug!("Client cert subject CN={}", val);
                        }
                    }
                }
            }
        }
        if let Some(ref p) = key {
            match std::fs::canonicalize(p) {
                Ok(abs) => debug!("PGSSLKEY path: {}", abs.display()),
                Err(e) => debug!("PGSSLKEY path: {} (err: {})", p, e),
            }
        }
    }

    // If TLS material is present and the feature is enabled, use OpenSSL mTLS.
    #[cfg(feature = "pg_tls_openssl")]
    {
        if let (Some(ca), Some(cert), Some(key)) = (ca.clone(), cert.clone(), key.clone()) {
            let mut builder = openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls())
                .expect("Failed to initialize OpenSSL connector builder");
            builder.set_ca_file(&ca).expect("Failed to load CA file");
            builder
                .set_certificate_chain_file(&cert)
                .expect("Failed to load client certificate chain");
            builder
                .set_private_key_file(&key, openssl::ssl::SslFiletype::PEM)
                .expect("Failed to load client private key");
            builder.set_verify(openssl::ssl::SslVerifyMode::PEER);

            let tls = postgres_openssl::MakeTlsConnector::new(builder.build());

            let mut backoff = std::time::Duration::from_millis(250);
            loop {
                match pg::Client::connect(url, tls.clone()) {
                    Err(e) => {
                        // Print error with source chain for better diagnostics
                        let mut msg = format!("{}", e);
                        let mut src = (&e as &dyn std::error::Error).source();
                        while let Some(c) = src {
                            msg.push_str("; caused by: ");
                            msg.push_str(&c.to_string());
                            src = c.source();
                        }
                        warn!("Error connecting to PG (TLS): {}", msg);
                        std::thread::sleep(backoff);
                        let next_ms = (backoff.as_millis().saturating_mul(2) as u64).min(30_000);
                        backoff = std::time::Duration::from_millis(next_ms);
                    }
                    Ok(o) => return o,
                }
            }
        }
    }

    // If TLS env vars are set but TLS feature is not enabled, warn and fall back.
    #[cfg(not(feature = "pg_tls_openssl"))]
    {
        if ca.is_some() || cert.is_some() || key.is_some() {
            warn!(
                "PGSSL* env vars detected, but binary is built without 'pg_tls_openssl' feature; falling back to non-TLS"
            );
        }
    }

    // Fallback: non-TLS connection.
    let mut backoff = std::time::Duration::from_millis(250);
    loop {
        match pg::Client::connect(url, postgres::tls::NoTls) {
            Err(e) => {
                // Print error with source chain for better diagnostics
                let mut msg = format!("{}", e);
                let mut src = (&e as &dyn std::error::Error).source();
                while let Some(c) = src {
                    msg.push_str("; caused by: ");
                    msg.push_str(&c.to_string());
                    src = c.source();
                }
                warn!("Error connecting to PG: {}", msg);
                std::thread::sleep(backoff);
                let next_ms = (backoff.as_millis().saturating_mul(2) as u64).min(30_000);
                backoff = std::time::Duration::from_millis(next_ms);
            }
            Ok(o) => return o,
        }
    }
}

fn calculate_tx_id_with_workarounds(
    block: &BlockData,
    tx: &bitcoin::blockdata::transaction::Transaction,
    network: bitcoin::Network,
) -> bitcoin::hash_types::Txid {
    let is_coinbase = tx.is_coin_base();
    if network != bitcoin::Network::Bitcoin {
        tx.txid()
    } else if block.height == 91842 && is_coinbase {
        // d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d88599
        // e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb469
        //
        // are twice in the blockchain; eg.
        // https://blockchair.com/bitcoin/block/91812
        // https://blockchair.com/bitcoin/block/91842
        // to make the unique indexes happy, we just add one to last byte

        Txid::from_hex("d5d27987d2a3dfc724e359870c6644b40e497bdc0589a033220fe15429d885a0").unwrap()
    } else if block.height == 91880 && is_coinbase {
        Txid::from_hex("e3bf3d07d4b0375638d5f1db5255fe07ba2c4cb067cd81b84ee974b6585fb469").unwrap()
    } else {
        tx.txid()
    }
}

fn write_hash_id_hex<W: std::fmt::Write>(w: &mut W, hash: &Sha256dHash) -> std::fmt::Result {
    w.write_str(
        &hash.as_inner()[..SQL_HASH_ID_SIZE]
            .to_owned()
            .encode_hex::<String>(),
    )
}

fn write_hash_rest_hex<W: std::fmt::Write>(w: &mut W, hash: &Sha256dHash) -> std::fmt::Result {
    w.write_str(
        &hash.as_inner()[SQL_HASH_ID_SIZE..]
            .to_owned()
            .encode_hex::<String>(),
    )
}

fn write_hash_hex<W: std::fmt::Write>(w: &mut W, hash: &Sha256dHash) -> std::fmt::Result {
    w.write_str(&hash.into_inner().encode_hex::<String>())
}

fn write_hex<W: std::fmt::Write>(w: &mut W, hash: &[u8]) -> std::fmt::Result {
    w.write_str(&hash.encode_hex::<String>())
}

// TODO: go faster / simpler?
fn hash_to_hash_id(hash: &Sha256dHash) -> Vec<u8> {
    hash.clone().into_inner()[..SQL_HASH_ID_SIZE].to_vec()
}

fn hash_id_and_rest_to_hash(id_and_rest: (Vec<u8>, Vec<u8>)) -> BlockHash {
    let (mut id, mut rest) = id_and_rest;

    id.append(&mut rest);

    BlockHash::from_slice(&id).expect("a valid hash")
}

const SQL_INSERT_VALUES_SIZE: usize = 30000;
const SQL_HASH_ID_SIZE: usize = 16;

/// Parse a DER-encoded ECDSA signature with a trailing sighash flag byte.
/// Returns Some(sighash) if the structure is valid and minimally encoded, otherwise None.
/// This does not validate the signature cryptographically; it only parses the structure:
/// 0x30 | total_len | 0x02 | r_len | r | 0x02 | s_len | s | sighash
fn parse_der_sighash(sig: &[u8]) -> Option<i32> {
    // Need at least: 0x30, len, 0x02, r_len, r(1), 0x02, s_len, s(1), sighash(1)
    if sig.len() < 9 || sig[0] != 0x30 {
        return None;
    }
    let total_len = sig[1] as usize;
    // DER sequence length does not include the sighash byte; overall length must be total_len + 2 (tag+len) + 1 (sighash)
    if sig.len() != total_len + 3 {
        return None;
    }
    // Offsets
    let mut off = 2;
    // Expect INTEGER R
    if off >= sig.len() || sig[off] != 0x02 {
        return None;
    }
    off += 1;
    if off >= sig.len() {
        return None;
    }
    let r_len = sig[off] as usize;
    off += 1;
    // r must exist
    if off + r_len > sig.len() {
        return None;
    }
    // Minimal encoding for R: no leading zero unless needed to avoid negative
    if r_len == 0 {
        return None;
    }
    if sig[off] == 0x00 && r_len > 1 && (sig[off + 1] & 0x80) == 0 {
        return None;
    }
    off += r_len;

    // Expect INTEGER S
    if off >= sig.len() || sig[off] != 0x02 {
        return None;
    }
    off += 1;
    if off >= sig.len() {
        return None;
    }
    let s_len = sig[off] as usize;
    off += 1;
    if off + s_len > sig.len() {
        return None;
    }
    // Minimal encoding for S
    if s_len == 0 {
        return None;
    }
    if sig[off] == 0x00 && s_len > 1 && (sig[off + 1] & 0x80) == 0 {
        return None;
    }
    off += s_len;

    // After R and S, we must be at exactly end-1 (the last byte is sighash)
    if off != 2 + total_len {
        return None;
    }
    let sighash = sig[off] as i32;
    Some(sighash)
}

#[cfg(test)]
mod tests_der {
    use super::parse_der_sighash;

    // Helper to build a minimal DER with given R,S and sighash
    fn der_sig(r: &[u8], s: &[u8], sighash: u8) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(0x30);
        let total_len = 2 + r.len() + 2 + s.len(); // (0x02,rlen,r) + (0x02,slen,s)
        out.push(total_len as u8);
        out.push(0x02);
        out.push(r.len() as u8);
        out.extend_from_slice(r);
        out.push(0x02);
        out.push(s.len() as u8);
        out.extend_from_slice(s);
        out.push(sighash);
        out
    }

    #[test]
    fn der_sighash_valid_minimal() {
        // Minimal R,S (no leading zeros)
        let r = vec![0x01, 0x02, 0x03];
        let s = vec![0x04, 0x05, 0x06];
        let sig = der_sig(&r, &s, 0x01);
        assert_eq!(parse_der_sighash(&sig), Some(0x01));
    }

    #[test]
    fn der_sighash_leading_zero_not_minimal() {
        // Leading zero not required (next byte MSB not set) => invalid minimal encoding
        let r = vec![0x00, 0x7f];
        let s = vec![0x01];
        let sig = der_sig(&r, &s, 0x01);
        assert_eq!(parse_der_sighash(&sig), None);
    }

    #[test]
    fn der_sighash_requires_leading_zero_ok() {
        // Leading zero required because next byte MSB is set
        let r = vec![0x00, 0x80];
        let s = vec![0x00, 0x80];
        let sig = der_sig(&r, &s, 0x81);
        assert_eq!(parse_der_sighash(&sig), Some(0x81));
    }

    #[test]
    fn der_sighash_wrong_total_len() {
        // Corrupt total length (make total_len too small)
        let mut sig = der_sig(&[0x01], &[0x02], 0x01);
        sig[1] = sig[1].saturating_sub(1);
        assert_eq!(parse_der_sighash(&sig), None);
    }

    #[test]
    fn der_sighash_not_der() {
        let sig = vec![0x31, 0x00, 0xff];
        assert_eq!(parse_der_sighash(&sig), None);
    }
}

/// Multiple-value INSERT SQL query formatter
///
/// It formats SQL query inserting
/// up to `SQL_INSERT_VALUES_SIZE` values at a time
/// in the `out` String.
///
/// Each insert starts with a custom `opening` and can end with
/// custom conflict handling (for immutability)
struct MultiValueSqlFormatter<'a> {
    out: &'a mut String,
    opening: &'static str,
    on_conflict: &'static str,

    query_values_count: usize,
}

impl<'a> MultiValueSqlFormatter<'a> {
    fn new_on_conflict_do_nothing_auto(
        out: &'a mut String,
        opening: &'static str,
        mode: Mode,
    ) -> Self {
        MultiValueSqlFormatter {
            out,
            opening,
            query_values_count: 0,
            on_conflict: if mode.is_bulk() {
                ""
            } else {
                "ON CONFLICT DO NOTHING"
            },
        }
    }

    fn new_no_conflict_check(out: &'a mut String, opening: &'static str) -> Self {
        MultiValueSqlFormatter {
            out,
            opening,
            query_values_count: 0,
            on_conflict: "",
        }
    }

    fn new_on_conflict_do_nothing(out: &'a mut String, opening: &'static str) -> Self {
        MultiValueSqlFormatter {
            out,
            opening,
            query_values_count: 0,
            on_conflict: "ON CONFLICT DO NOTHING",
        }
    }

    fn new_tx_on_conflict_update_current_height(
        out: &'a mut String,
        opening: &'static str,
    ) -> Self {
        MultiValueSqlFormatter {
            out,
            opening,
            query_values_count: 0,
            on_conflict:
                "ON CONFLICT (hash_id) DO UPDATE SET current_height = EXCLUDED.current_height",
        }
    }
    fn fmt_with(&mut self, f: impl FnOnce(&mut String)) {
        self.maybe_terminate_query();
        if self.query_values_count == 0 {
            self.out.write_str(self.opening).unwrap();
        } else {
            self.out.write_str(",").unwrap();
        }

        f(self.out);
        self.query_values_count += 1;
    }

    fn maybe_terminate_query(&mut self) {
        if self.query_values_count > SQL_INSERT_VALUES_SIZE {
            self.terminate_query();
        }
    }

    fn terminate_query(&mut self) {
        self.query_values_count = 0;
        self.out.write_str(self.on_conflict).unwrap();
        self.out.write_str(";").unwrap();
    }
}

impl<'a> Drop for MultiValueSqlFormatter<'a> {
    fn drop(&mut self) {
        if self.query_values_count > 0 {
            self.terminate_query();
        }
    }
}

struct OutputFormatter<'a> {
    output: MultiValueSqlFormatter<'a>,
    network: bitcoin::Network,
}

impl<'a> OutputFormatter<'a> {
    fn new(output_s: &'a mut String, mode: Mode, network: bitcoin::Network) -> Self {
        Self {
            output: MultiValueSqlFormatter::new_on_conflict_do_nothing_auto(
                output_s,
                "INSERT INTO output(tx_hash_id, tx_idx, value, address)VALUES",
                mode,
            ),
            network,
        }
    }

    fn fmt(&mut self, tx_id: &Sha256dHash, output: &bitcoin::TxOut, vout: u32) {
        let network = self.network;
        self.output.fmt_with(|s| {
            s.write_str("('\\x").unwrap();
            write_hash_id_hex(s, tx_id).unwrap();
            s.write_fmt(format_args!(
                "'::bytea,{},{},{})",
                vout,
                output.value,
                crate::util::bitcoin::address_from_script(&output.script_pubkey, network)
                    .map(|a| format!("'{}'", a))
                    .unwrap_or_else(|| "NULL".into())
            ))
            .unwrap();
        });
    }
}

struct InputFormatter<'a> {
    input: MultiValueSqlFormatter<'a>,
}

impl<'a> InputFormatter<'a> {
    fn new(input_s: &'a mut String, mode: Mode) -> Self {
        Self {
            input: MultiValueSqlFormatter::new_on_conflict_do_nothing_auto(
                input_s,
                "INSERT INTO input(output_tx_hash_id,output_tx_idx,tx_hash_id,has_witness)VALUES",
                mode,
            ),
        }
    }

    fn fmt(&mut self, tx_id: &Sha256dHash, input: &bitcoin::TxIn) {
        self.input.fmt_with(move |s| {
            s.write_str("('\\x").unwrap();
            write_hash_id_hex(s, &input.previous_output.txid.as_hash()).unwrap();
            s.write_fmt(format_args!("'::bytea,{},'\\x", input.previous_output.vout))
                .unwrap();
            write_hash_id_hex(s, &tx_id).unwrap();
            s.write_fmt(format_args!("'::bytea,{})", !input.witness.is_empty()))
                .unwrap();
        });
    }
}

struct BlockTxFormatter<'a> {
    block_tx: MultiValueSqlFormatter<'a>,
}

impl<'a> BlockTxFormatter<'a> {
    fn new(block_tx_s: &'a mut String, mode: Mode) -> Self {
        Self {
            block_tx: MultiValueSqlFormatter::new_on_conflict_do_nothing_auto(
                block_tx_s,
                "INSERT INTO block_tx(block_hash_id, tx_hash_id)VALUES",
                mode,
            ),
        }
    }

    fn fmt(&mut self, block: &BlockData, tx_id: &Sha256dHash) {
        self.block_tx.fmt_with(move |s| {
            s.write_str("('\\x").unwrap();
            write_hash_id_hex(s, &block.id.as_hash()).unwrap();
            s.write_str("'::bytea,'\\x").unwrap();
            write_hash_id_hex(s, &tx_id).unwrap();
            s.write_str("'::bytea)").unwrap();
        });
    }
}

struct TxFormatter<'a> {
    tx: MultiValueSqlFormatter<'a>,

    output_fmt: OutputFormatter<'a>,
    input_fmt: InputFormatter<'a>,

    inputs_utxo_map: UtxoDetailsMap,

    from_mempool: bool,
}

impl<'a> TxFormatter<'a> {
    fn new_for_in_block(
        tx_s: &'a mut String,
        output_s: &'a mut String,
        input_s: &'a mut String,
        mode: Mode,
        network: bitcoin::Network,
        inputs_utxo_map: UtxoDetailsMap,
    ) -> Self {
        Self {
            tx: if mode.is_bulk() {
                MultiValueSqlFormatter::new_no_conflict_check(
                    tx_s,
                    "INSERT INTO tx (hash_id, hash_rest, weight, fee, locktime, coinbase, current_height) VALUES",
                )
            } else {
                MultiValueSqlFormatter::new_tx_on_conflict_update_current_height(
                    tx_s,
                    "INSERT INTO tx (hash_id, hash_rest, weight, fee, locktime, coinbase, current_height) VALUES",
                )
            },
            output_fmt: OutputFormatter::new(output_s, mode, network),
            input_fmt: InputFormatter::new(input_s, mode),
            inputs_utxo_map,
            from_mempool: false,
        }
    }

    fn new_for_in_mempool(
        tx_s: &'a mut String,
        output_s: &'a mut String,
        input_s: &'a mut String,
        network: bitcoin::Network,
        inputs_utxo_map: UtxoDetailsMap,
    ) -> Self {
        // We can only do mempool insert in the normal mode, because otherwise bulk
        // inserts would cause conflicts, and in bulk mode we don't want indices to
        // be able to prevent them.
        let mode = Mode::Normal;
        Self {
            tx: MultiValueSqlFormatter::new_on_conflict_do_nothing(
                tx_s,
                "INSERT INTO tx (hash_id, hash_rest, weight, fee, locktime, coinbase, current_height, mempool_ts) VALUES",
            ),
            output_fmt: OutputFormatter::new(output_s, mode, network),
            input_fmt: InputFormatter::new(input_s, mode),
            inputs_utxo_map,
            from_mempool: true,
        }
    }

    fn fmt_one(
        &mut self,
        block_height: Option<BlockHeight>,
        tx: &bitcoin::Transaction,
        tx_id: &Sha256dHash,
        fee: u64,
    ) {
        let from_mempool = self.from_mempool;
        self.tx.fmt_with(|s| {
            s.write_str("('\\x").unwrap();
            write_hash_id_hex(s, &tx_id).unwrap();

            s.write_str("'::bytea,'\\x").unwrap();
            write_hash_rest_hex(s, &tx_id).unwrap();
            let weight = tx.weight();

            s.write_fmt(format_args!(
                "'::bytea,{},{},{},{},{}",
                weight,
                fee,
                tx.lock_time,
                tx.is_coin_base(),
                block_height
                    .map(|h| h.to_string())
                    .unwrap_or_else(|| "NULL".into()),
            ))
            .unwrap();
            if from_mempool {
                s.write_str(",timezone('utc', now())").unwrap();
            }
            s.write_str(")").unwrap();
        });
    }

    fn fmt(
        &mut self,
        block_height: Option<BlockHeight>,
        tx: &bitcoin::Transaction,
        tx_id: &TxHash,
    ) {
        let is_coinbase = tx.is_coin_base();

        let fee = if tx.is_coin_base() {
            0
        } else {
            let input_value_sum = tx.input.iter().fold(0, |acc, input| {
                let p = HashIdOutPoint {
                    tx_hash_id: hash_to_hash_id(&input.previous_output.txid.as_hash()),
                    vout: input.previous_output.vout,
                };
                acc + self.inputs_utxo_map[&p].value
            });
            let output_value_sum = tx.output.iter().fold(0, |acc, output| acc + output.value);
            assert!(output_value_sum <= input_value_sum);
            input_value_sum - output_value_sum
        };

        self.fmt_one(block_height, tx, &tx_id, fee);

        for (idx, output) in tx.output.iter().enumerate() {
            self.output_fmt.fmt(&tx_id, output, idx as u32);
        }

        if !is_coinbase {
            for input in &tx.input {
                self.input_fmt.fmt(&tx_id, input);
            }
        }
    }
}

struct BlockFormatter<'a> {
    event: MultiValueSqlFormatter<'a>,
    block: MultiValueSqlFormatter<'a>,

    tx_fmt: TxFormatter<'a>,
    block_tx_fmt: BlockTxFormatter<'a>,
    tx_ids: TxIdMap,
}

impl<'a> BlockFormatter<'a> {
    fn new(
        event_s: &'a mut String,
        block_s: &'a mut String,
        block_tx_s: &'a mut String,
        tx_s: &'a mut String,
        output_s: &'a mut String,
        input_s: &'a mut String,
        mode: Mode,
        network: bitcoin::Network,
        inputs_utxo_map: UtxoDetailsMap,
        tx_ids: TxIdMap,
    ) -> Self {
        BlockFormatter {
            event: MultiValueSqlFormatter::new_on_conflict_do_nothing_auto(
                event_s,
                "INSERT INTO event (block_hash_id) VALUES",
                mode
            ),
            block: MultiValueSqlFormatter::new_on_conflict_do_nothing_auto(
                block_s,
                "INSERT INTO block (hash_id, hash_rest, prev_hash_id, merkle_root, height, time) VALUES",
                mode
            ),
            tx_fmt: TxFormatter::new_for_in_block(
                tx_s,
                output_s,
                input_s,
                mode,
                network,
                inputs_utxo_map,
            ),
            block_tx_fmt: BlockTxFormatter::new(
                block_tx_s,
                mode
            ),
            tx_ids,
        }
    }

    fn fmt_one(&mut self, block: &BlockData) {
        self.event.fmt_with(|s| {
            s.write_str("('\\x").unwrap();
            write_hash_id_hex(s, &block.id.as_hash()).unwrap();
            s.write_str("'::bytea)").unwrap();
        });

        self.block.fmt_with(|s| {
            s.write_str("('\\x").unwrap();
            write_hash_id_hex(s, &block.id.as_hash()).unwrap();

            s.write_str("'::bytea,'\\x").unwrap();
            write_hash_rest_hex(s, &block.id.as_hash()).unwrap();

            s.write_str("'::bytea,'\\x").unwrap();
            write_hash_id_hex(s, &block.data.header.prev_blockhash.as_hash()).unwrap();

            s.write_str("'::bytea,'\\x").unwrap();
            write_hash_hex(s, &block.data.header.merkle_root.as_hash()).unwrap();

            s.write_fmt(format_args!(
                "'::bytea,{},{})",
                block.height, block.data.header.time
            ))
            .unwrap();
        });
    }

    fn fmt(&mut self, block: &BlockData) {
        self.fmt_one(block);

        for (tx_i, tx) in block.data.txdata.iter().enumerate() {
            let tx_id = &self.tx_ids[&(block.height, tx_i)];
            self.tx_fmt.fmt(Some(block.height), tx, &tx_id.as_hash());
            self.block_tx_fmt.fmt(block, &tx_id.as_hash());
        }
    }
}

fn fmt_fetch_outputs_sql<'a>(outputs: impl Iterator<Item = &'a HashIdOutPoint>) -> Vec<String> {
    outputs
        .chunks(SQL_INSERT_VALUES_SIZE)
        .into_iter()
        .map(|chunk| {
            let mut q: String = r#"
        SELECT tx_hash_id, tx_idx, value
        FROM output
        WHERE (tx_hash_id, tx_idx) IN ( VALUES "#
                .into();

            for (i, output) in chunk.enumerate() {
                if i > 0 {
                    q.push_str(",")
                }
                q.push_str("('\\x");
                write_hex(&mut q, &output.tx_hash_id).unwrap();
                q.push_str("'::bytea");
                q.push_str(",");
                q.write_fmt(format_args!("{})", output.vout)).unwrap();
            }
            q.write_str(");").expect("Write to string can't fail");
            q
        })
        .collect()
}

fn fetch_outputs<'a>(
    conn: &mut impl pg::GenericClient,
    outputs: impl Iterator<Item = &'a HashIdOutPoint>,
) -> Result<UtxoDetailsMap> {
    let mut out = HashMap::new();
    for q in fmt_fetch_outputs_sql(outputs) {
        let mut it = conn.query_raw::<_, _, &[&str]>(q.as_str(), &[])?;
        while let Some(row) = it.next()? {
            out.insert(
                HashIdOutPoint {
                    tx_hash_id: row.get::<_, Vec<u8>>(0),
                    vout: row.get::<_, i32>(1) as u32,
                },
                UtxoSetEntry {
                    value: row.get::<_, i64>(2) as u64,
                },
            );
        }
    }
    Ok(out)
}

#[derive(Copy, Clone, PartialEq, Eq)]
struct UtxoSetEntry {
    value: u64,
}

/// `OutPoint` but with tx_hash trimmed to be just `HashId`
#[derive(Debug, Hash, PartialOrd, Ord, PartialEq, Eq)]
struct HashIdOutPoint {
    tx_hash_id: Vec<u8>,
    vout: u32,
}

impl fmt::Display for HashIdOutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // TODO: no alloc
        f.write_str(&self.tx_hash_id.encode_hex::<String>())?;
        write!(f, "...:{}", self.vout)
    }
}

impl HashIdOutPoint {
    fn from_tx_hash_and_idx(tx_hash: &Sha256dHash, idx: u32) -> Self {
        Self {
            tx_hash_id: hash_to_hash_id(&tx_hash),
            vout: idx,
        }
    }
}

impl From<bitcoin::OutPoint> for HashIdOutPoint {
    fn from(p: bitcoin::OutPoint) -> Self {
        Self {
            tx_hash_id: hash_to_hash_id(&p.txid.as_hash()),
            vout: p.vout,
        }
    }
}

type UtxoDetailsMap = HashMap<HashIdOutPoint, UtxoSetEntry>;

/// Cache of utxo set
#[derive(Default)]
struct UtxoSetCache {
    entries: UtxoDetailsMap,
}

impl UtxoSetCache {
    fn insert(&mut self, point: HashIdOutPoint, value: u64) {
        self.entries.insert(point, UtxoSetEntry { value });
    }

    /// Process utxos from new blocks
    ///
    /// Add all new outputs, remove all used inputs, fetch all missing
    /// utxos from the db.
    ///
    /// Returns map of details of all spent outputs (for fee calculation).
    fn process_blocks(
        &mut self,
        conn: &mut impl pg::GenericClient,
        blocks: &[crate::BlockData],
        tx_ids: &TxIdMap,
    ) -> Result<UtxoDetailsMap> {
        let (mut inputs_utxo_map, missing) = trace_time(
            || {
                self.insert_new_utxos_from_blocks(blocks, tx_ids);

                Ok(self.consume_spent_utxos_from_blocks(blocks))
            },
            |duration, _| debug!("Modified utxo_cache in {}ms", duration.as_millis()),
        )?;

        let fetched_missing = self.fetch_missing_utxos(conn, &missing)?;

        for (k, v) in fetched_missing.into_iter() {
            inputs_utxo_map.insert(k, v);
        }

        Ok(inputs_utxo_map)
    }

    fn insert_new_utxos_from_blocks(&mut self, blocks: &[crate::BlockData], tx_ids: &TxIdMap) {
        for block in blocks {
            for (tx_i, tx) in block.data.txdata.iter().enumerate() {
                for (idx, output) in tx.output.iter().enumerate() {
                    let txid = &tx_ids[&(block.height, tx_i)];
                    self.insert(
                        HashIdOutPoint::from_tx_hash_and_idx(&txid.as_hash(), idx as u32),
                        output.value,
                    );
                }
            }
        }
    }

    fn consume_spent_utxos_from_blocks(
        &mut self,
        blocks: &[crate::BlockData],
    ) -> (UtxoDetailsMap, Vec<HashIdOutPoint>) {
        self.consume_spent_utxos(
            blocks
                .iter()
                .flat_map(|block| &block.data.txdata)
                .filter(|tx| !tx.is_coin_base())
                .flat_map(|tx| &tx.input)
                .map(|input| input.previous_output),
        )
    }
    /// Consume `outputs`
    ///
    /// Returns:
    /// * Mappings for Outputs that were found
    /// * Vector of outputs that were missing from the set
    fn consume_spent_utxos(
        &mut self,
        outputs: impl Iterator<Item = bitcoin::OutPoint>,
    ) -> (UtxoDetailsMap, Vec<HashIdOutPoint>) {
        let mut found = HashMap::default();
        let mut missing = vec![];

        for output in outputs {
            let output = output.into();
            match self.entries.remove(&output) {
                Some(details) => {
                    found.insert(output, details);
                }
                None => missing.push(output),
            }
        }

        (found, missing)
    }

    fn fetch_missing_utxos(
        &self,
        conn: &mut impl pg::GenericClient,
        missing: &[HashIdOutPoint],
    ) -> Result<UtxoDetailsMap> {
        if missing.is_empty() {
            return Ok(UtxoDetailsMap::new());
        }

        let missing_len = missing.len();
        let mut out = HashMap::default();
        debug!("Fetching {} missing outputs", missing_len);

        trace_time(
            || {
                out = fetch_outputs(conn, missing.iter())?;
                Ok(())
            },
            |duration, _| {
                debug!(
                    "Fetched {} missing outputs in {}ms",
                    missing_len,
                    duration.as_millis()
                )
            },
        )?;
        assert_eq!(missing_len, out.len());

        Ok(out)
    }
}

/// Convenient (arguably) function for reporting times of operations
fn trace_time<T>(
    body: impl FnOnce() -> Result<T>,
    result: impl FnOnce(std::time::Duration, &T),
) -> Result<T> {
    let start = Instant::now();

    let res = body()?;
    result(Instant::now().duration_since(start), &res);

    Ok(res)
}

fn commit_atomic_bulk_insert_sql(
    mut transaction: pg::Transaction,
    name: &str,
    len: usize,
    batch_id: u64,
    queries: impl Iterator<Item = String>,
) -> Result<()> {
    let start = Instant::now();
    for (i, s) in queries.enumerate() {
        trace_time(
            || {
                match transaction.batch_execute(&s) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        // Include a small snippet of the SQL for easier diagnostics
                        let snippet: String = s.chars().take(256).collect();
                        if let Some(dbe) = e.as_db_error() {
                            error!(
                                "Postgres error on batch {} query {}: {} (code: {:?}, detail: {:?}, hint: {:?}); sql(first 256): {}",
                                batch_id,
                                i,
                                dbe.message(),
                                dbe.code(),
                                dbe.detail(),
                                dbe.hint(),
                                snippet
                            );
                        } else {
                            error!(
                                "Postgres error on batch {} query {}: {}; sql(first 256): {}",
                                batch_id, i, e, snippet
                            );
                        }
                        Err(e.into())
                    }
                }
            },
            |duration, _| {
                debug!(
                    "Executed query {} of batch {} in {}ms",
                    i,
                    batch_id,
                    duration.as_millis()
                );
            },
        )?;
    }
    transaction.commit()?;
    trace!(
        "Inserted {} {} from batch {} in {}ms",
        len,
        name,
        batch_id,
        Instant::now().duration_since(start).as_millis()
    );
    Ok(())
}

type BlocksInFlight = HashSet<BlockHash>;

/// Asynchronous block data insertion worker
///
/// Reponsible for actually inserting data into the db.
struct AsyncBlockInsertWorker {
    tx: Option<crossbeam_channel::Sender<(u64, Vec<crate::BlockData>)>>,
    utxo_fetching_thread: Option<std::thread::JoinHandle<Result<()>>>,
    query_fmt_thread: Option<std::thread::JoinHandle<Result<()>>>,
    writer_thread: Option<std::thread::JoinHandle<Result<()>>>,
}

// TODO: fail the whole Pipeline somehow
fn fn_log_err<F>(name: &'static str, mut f: F) -> impl FnMut() -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    move || {
        let res = f();
        if let Err(ref e) = res {
            error!(
                "{} finished with an error: {}",
                name,
                e.display_causes_and_backtrace()
            );
        }

        res
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
enum Mode {
    FreshBulk,
    Bulk,
    Normal,
}

impl Mode {
    fn is_bulk(self) -> bool {
        match self {
            Mode::FreshBulk => true,
            Mode::Bulk => true,
            Mode::Normal => false,
        }
    }

    fn to_sql_query_str(self) -> &'static str {
        match self {
            Mode::FreshBulk => concat!(
                include_str!("pg/mode_fresh.sql"),
                include_str!("pg/init.sql")
            ),
            Mode::Bulk => include_str!("pg/mode_bulk.sql"),
            Mode::Normal => include_str!("pg/mode_normal.sql"),
        }
    }

    fn to_entering_str(self) -> &'static str {
        match self {
            Mode::FreshBulk => "fresh mode: no indices",
            Mode::Bulk => "fresh mode: minimum indices",
            Mode::Normal => "normal mode: all indices",
        }
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Mode::FreshBulk => "fresh-bulk",
            Mode::Bulk => "bulk",
            Mode::Normal => "normal",
        })
    }
}

/// Map block height and position in a block to `BlockHash`
///
/// Mainly used so that we don't have to recalculate txids many times
/// (it's quite expensive).
type TxIdMap = HashMap<(BlockHeight, usize), Txid>;

fn tx_id_map_from_blocks(
    blocks: &[crate::BlockData],
    network: bitcoin::Network,
) -> Result<TxIdMap> {
    trace_time(
        || {
            Ok(blocks
                .par_iter()
                .flat_map(move |block| {
                    block
                        .data
                        .txdata
                        .par_iter()
                        .enumerate()
                        .map(move |(tx_i, tx)| {
                            (
                                block.height,
                                tx_i,
                                calculate_tx_id_with_workarounds(block, tx, network),
                            )
                        })
                })
                .map(|(h, tx_i, txid)| ((h, tx_i), txid))
                .collect())
        },
        |duration, tx_ids: &TxIdMap| {
            debug!(
                "Calculated txids of {} txs in {}ms",
                tx_ids.len(),
                duration.as_millis()
            )
        },
    )
}

fn fmt_insert_blockdata_sql(
    blocks: &[crate::BlockData],
    inputs_utxo_map: UtxoDetailsMap,
    tx_ids: TxIdMap,
    mode: Mode,
    network: bitcoin::Network,
) -> Result<Vec<String>> {
    let mut event_q = String::new();
    let mut block_q = String::new();
    let mut block_tx_q = String::new();
    let mut tx_q = String::new();
    let mut output_q = String::new();
    let mut input_q = String::new();

    let mut formatter = BlockFormatter::new(
        &mut event_q,
        &mut block_q,
        &mut block_tx_q,
        &mut tx_q,
        &mut output_q,
        &mut input_q,
        mode,
        network,
        inputs_utxo_map,
        tx_ids,
    );

    trace_time(
        || {
            for block in blocks {
                formatter.fmt(block);
            }
            drop(formatter);
            Ok(())
        },
        |duration, _| debug!("Formatted queries in {}ms", duration.as_millis()),
    )?;

    // Build output_meta batched insert (append-only, idempotent)
    let mut output_meta_q = String::new();
    let mut output_meta_fmt = MultiValueSqlFormatter::new_on_conflict_do_nothing(
        &mut output_meta_q,
        "INSERT INTO output_meta(block_hash_id, tx_hash_id, tx_idx, spk_type, witness_version, witness_program_len, is_taproot, taproot_xonly_pubkey, op_return_payload) VALUES",
    );

    for block in blocks {
        for tx in block.data.txdata.iter() {
            let tx_id = calculate_tx_id_with_workarounds(block, tx, network);
            for (vout, txout) in tx.output.iter().enumerate() {
                // Script classification based on address::Payload (struct variant for WitnessProgram)
                let (spk_type, wver_opt, wprog_len_opt, is_taproot_opt, xonly_opt) = {
                    use bitcoin::util::address::{Payload, WitnessVersion};
                    match Payload::from_script(&txout.script_pubkey) {
                        Some(Payload::PubkeyHash(_)) => ("p2pkh", None, None, None, None),
                        Some(Payload::ScriptHash(_)) => ("p2sh", None, None, None, None),
                        Some(Payload::WitnessProgram { version, program }) => {
                            let ver_num: i16 = match version {
                                WitnessVersion::V0 => 0,
                                WitnessVersion::V1 => 1,
                                _ => 255,
                            };
                            let prog_len: i16 = program.len() as i16;
                            if ver_num == 1 && program.len() == 32 {
                                (
                                    "p2tr",
                                    Some(ver_num),
                                    Some(prog_len),
                                    Some(true),
                                    Some(program.to_vec()),
                                )
                            } else if ver_num == 0 && program.len() == 20 {
                                ("p2wpkh", Some(ver_num), Some(prog_len), None, None)
                            } else if ver_num == 0 && program.len() == 32 {
                                ("p2wsh", Some(ver_num), Some(prog_len), None, None)
                            } else {
                                ("witness", Some(ver_num), Some(prog_len), None, None)
                            }
                        }
                        None => ("nonstandard", None, None, None, None),
                    }
                };

                output_meta_fmt.fmt_with(|s| {
                    // block_hash_id
                    s.write_str("('\\x").unwrap();
                    write_hash_id_hex(s, &block.id.as_hash()).unwrap();
                    // tx_hash_id
                    s.write_str("'::bytea,'\\x").unwrap();
                    write_hash_id_hex(s, &tx_id.as_hash()).unwrap();
                    // tx_idx
                    s.write_fmt(format_args!("'::bytea,{}", vout)).unwrap();
                    // spk_type
                    s.write_fmt(format_args!(",'{}'", spk_type)).unwrap();
                    // witness_version
                    if let Some(v) = wver_opt {
                        s.write_fmt(format_args!(",{}", v)).unwrap();
                    } else {
                        s.write_str(",NULL").unwrap();
                    }
                    // witness_program_len
                    if let Some(l) = wprog_len_opt {
                        s.write_fmt(format_args!(",{}", l)).unwrap();
                    } else {
                        s.write_str(",NULL").unwrap();
                    }
                    // is_taproot
                    if let Some(true) = is_taproot_opt {
                        s.write_str(",true").unwrap();
                    } else {
                        s.write_str(",NULL").unwrap();
                    }
                    // taproot_xonly_pubkey
                    if let Some(prog) = xonly_opt {
                        s.write_str(",'\\x").unwrap();
                        write_hex(s, &prog).unwrap();
                        s.write_str("'::bytea").unwrap();
                    } else {
                        s.write_str(",NULL").unwrap();
                    }
                    // op_return_payload (extract for OP_RETURN if present)
                    {
                        use bitcoin::blockdata::opcodes::all::OP_RETURN;
                        let spk = &txout.script_pubkey;
                        let spk_bytes = spk.as_bytes();
                        if !spk_bytes.is_empty() && spk_bytes[0] == OP_RETURN.into_u8() {
                            // Naive payload extraction: bytes after OP_RETURN and push opcode(s)
                            // Try to skip a single-byte push opcode if present, otherwise store the raw tail
                            let mut payload_start = 1usize;
                            if spk_bytes.len() > 1 {
                                let push = spk_bytes[1] as usize;
                                // minimal support for small immediate push (<=75 bytes)
                                if push <= 75 && spk_bytes.len() >= 2 + push {
                                    payload_start = 2;
                                }
                            }
                            let payload = &spk_bytes[payload_start..];
                            s.write_str(",'\\x").unwrap();
                            write_hex(s, payload).unwrap();
                            s.write_str("'::bytea)").unwrap();
                        } else {
                            s.write_str(",NULL)").unwrap();
                        }
                    }
                });
            }
        }
    }
    drop(output_meta_fmt);

    // Insert revealed scripts first (append-only)
    let mut script_q = String::new();
    let mut script_fmt = MultiValueSqlFormatter::new_on_conflict_do_nothing(
        &mut script_q,
        "INSERT INTO script(id, script_hex, size, summary) VALUES",
    );

    // Then input_reveals, referencing scripts where applicable (append-only)
    let mut input_reveals_q = String::new();
    let mut input_reveals_fmt = MultiValueSqlFormatter::new_on_conflict_do_nothing(
        &mut input_reveals_q,
        "INSERT INTO input_reveals(block_hash_id, tx_hash_id, input_idx, output_tx_hash_id, output_tx_idx, redeem_script_id, witness_script_id, taproot_leaf_script_id, taproot_control_block, annex_present, sighash_flags) VALUES",
    );

    for block in blocks {
        for tx in block.data.txdata.iter() {
            let tx_id = calculate_tx_id_with_workarounds(block, tx, network);
            if tx.is_coin_base() {
                // Skip coinbase: previous_output is invalid (vout can be 0xffffffff)
                continue;
            }
            for (iidx, input) in tx.input.iter().enumerate() {
                // Extract witness/leaf/control for segwit/taproot
                let mut script_bytes_opt: Option<Vec<u8>> = None;
                let mut taproot_control_opt: Option<Vec<u8>> = None;
                let mut annex_present_opt: Option<bool> = None;
                let mut sighash_flags_opt: Option<i32> = None;
                if !input.witness.is_empty() {
                    let w: Vec<&[u8]> = input.witness.iter().collect();
                    let wlen = w.len();
                    // Annex is present if the first stack item starts with 0x50 (per BIP-342)
                    if let Some(first) = w.get(0) {
                        if !first.is_empty() && first[0] == 0x50 {
                            annex_present_opt = Some(true);
                        }
                    }
                    // Try to derive sighash flags from any DER-encoded signature in the witness
                    for elm in &w {
                        if let Some(v) = parse_der_sighash(elm) {
                            sighash_flags_opt = Some(v);
                            break;
                        }
                    }
                    if wlen >= 2 {
                        // Heuristic: last is control block (taproot script path), second last is leaf script
                        let leaf_script = &w[wlen - 2];
                        let control_block = &w[wlen - 1];
                        if !leaf_script.is_empty() {
                            script_bytes_opt = Some(leaf_script.to_vec());
                        }
                        if !control_block.is_empty() {
                            taproot_control_opt = Some(control_block.to_vec());
                        }
                    } else if let Some(last) = w.last() {
                        if !last.is_empty() {
                            // Single-item witness: likely a WPKH witness; no script to record here
                            script_bytes_opt = None;
                        }
                    }
                }

                // Extract potential P2SH redeemScript from scriptSig: take the last push bytes if any
                let mut redeem_script_bytes_opt: Option<Vec<u8>> = None;
                for instr in input.script_sig.instructions() {
                    if let Ok(bitcoin::blockdata::script::Instruction::PushBytes(b)) = instr {
                        // If this push is a DER-encoded signature with trailing sighash, record it
                        if sighash_flags_opt.is_none() {
                            if let Some(v) = parse_der_sighash(b) {
                                sighash_flags_opt = Some(v);
                            }
                        }
                        redeem_script_bytes_opt = Some(b.to_vec());
                    }
                }
                let mut redeem_script_hash_bytes: Option<Vec<u8>> = None;
                if let Some(ref rs_bytes) = redeem_script_bytes_opt {
                    let h = bitcoin::hashes::sha256::Hash::hash(&rs_bytes[..]);
                    let inner = h.into_inner();
                    redeem_script_hash_bytes = Some(inner.to_vec());
                    script_fmt.fmt_with(|s| {
                        s.write_str("('\\x").unwrap();
                        s.write_str(&hex::encode(&inner[..])).unwrap();
                        s.write_str("'::bytea,'").unwrap();
                        s.write_str(&hex::encode(&rs_bytes[..])).unwrap();
                        s.write_str("',").unwrap();
                        s.write_fmt(format_args!("{}", rs_bytes.len())).unwrap();
                        s.write_str(",NULL)").unwrap();
                    });
                }

                let mut script_hash_bytes: Option<Vec<u8>> = None;
                if let Some(ref script_bytes) = script_bytes_opt {
                    let h = bitcoin::hashes::sha256::Hash::hash(&script_bytes);
                    let inner = h.into_inner();
                    script_hash_bytes = Some(inner.to_vec());
                    script_fmt.fmt_with(|s| {
                        s.write_str("('\\x").unwrap();
                        s.write_str(&hex::encode(&inner[..])).unwrap();
                        s.write_str("'::bytea,'").unwrap();
                        s.write_str(&hex::encode(&script_bytes[..])).unwrap();
                        s.write_str("',").unwrap();
                        s.write_fmt(format_args!("{}", script_bytes.len())).unwrap();
                        s.write_str(",NULL)").unwrap();
                    });
                }

                // Skip if vout doesn't fit into INT column (e.g., coinbase 0xffffffff)
                if input.previous_output.vout > i32::MAX as u32 {
                    continue;
                }
                input_reveals_fmt.fmt_with(|s| {
                    // block_hash_id
                    s.write_str("('\\x").unwrap();
                    write_hash_id_hex(s, &block.id.as_hash()).unwrap();
                    // tx_hash_id
                    s.write_str("'::bytea,'\\x").unwrap();
                    write_hash_id_hex(s, &tx_id.as_hash()).unwrap();
                    // input_idx
                    s.write_fmt(format_args!("'::bytea,{}", iidx)).unwrap();
                    // output_tx_hash_id
                    s.write_str(",'\\x").unwrap();
                    write_hash_id_hex(s, &input.previous_output.txid.as_hash()).unwrap();
                    // output_tx_idx
                    s.write_fmt(format_args!("'::bytea,{}", input.previous_output.vout))
                        .unwrap();
                    // redeem_script_id
                    if let Some(ref hbytes) = redeem_script_hash_bytes {
                        s.write_str(",'\\x").unwrap();
                        s.write_str(&hex::encode(&hbytes[..])).unwrap();
                        s.write_str("'::bytea").unwrap();
                    } else {
                        s.write_str(",NULL").unwrap();
                    }
                    // witness_script_id
                    if let Some(ref hbytes) = script_hash_bytes {
                        s.write_str(",'\\x").unwrap();
                        s.write_str(&hex::encode(&hbytes[..])).unwrap();
                        s.write_str("'::bytea").unwrap();
                    } else {
                        s.write_str(",NULL").unwrap();
                    }
                    // taproot_leaf_script_id
                    s.write_str(",NULL").unwrap();
                    // taproot_control_block
                    if let Some(ref ctrl) = taproot_control_opt {
                        s.write_str(",'\\x").unwrap();
                        write_hex(s, &ctrl[..]).unwrap();
                        s.write_str("'::bytea").unwrap();
                    } else {
                        s.write_str(",NULL").unwrap();
                    }
                    // annex_present
                    if let Some(true) = annex_present_opt {
                        s.write_str(",true").unwrap();
                    } else {
                        s.write_str(",NULL").unwrap();
                    }
                    // sighash_flags
                    if let Some(v) = sighash_flags_opt {
                        s.write_fmt(format_args!(",{})", v)).unwrap();
                    } else {
                        s.write_str(",NULL)").unwrap();
                    }
                });
            }
        }
    }
    drop(script_fmt);
    drop(input_reveals_fmt);

    Ok(vec![
        event_q,
        block_q,
        block_tx_q,
        tx_q,
        output_q,
        input_q,
        script_q,
        input_reveals_q,
        output_meta_q,
    ])
}
impl AsyncBlockInsertWorker {
    fn new(
        url: String,
        in_flight: Arc<Mutex<BlocksInFlight>>,
        mode: Mode,
        network: bitcoin::Network,
    ) -> Self {
        // We use only rendezvous (0-size) channels, to allow passing
        // work and parallelism, but without doing any buffering of
        // work in the channels. Buffered work does not
        // improve performance, and more things in flight means
        // incrased memory usage.
        let (utxo_fetching_tx, utxo_fetching_rx) =
            crossbeam_channel::bounded::<(u64, Vec<crate::BlockData>)>(0);
        let (query_fmt_tx, query_fmt_rx) =
            crossbeam_channel::bounded::<(u64, Vec<crate::BlockData>, UtxoDetailsMap, TxIdMap)>(0);
        let (writer_tx, writer_rx) = crossbeam_channel::bounded::<(
            u64,
            Vec<String>,
            HashSet<BlockHash>,
            BlockHeight,
            usize,
        )>(0);

        let utxo_fetching_thread = std::thread::spawn({
            let url = url.clone();
            let mut conn = establish_connection(&url);
            fn_log_err("pg_utxo_fetching", move || {
                let mut utxo_set_cache = UtxoSetCache::default();

                while let Ok((batch_id, blocks)) = utxo_fetching_rx.recv() {
                    let tx_ids: TxIdMap = tx_id_map_from_blocks(&blocks, network)?;

                    let inputs_utxo_map =
                        utxo_set_cache.process_blocks(&mut conn, &blocks, &tx_ids)?;

                    if let Err(e) = query_fmt_tx.send((batch_id, blocks, inputs_utxo_map, tx_ids)) {
                        error!("pg_utxo_fetching: downstream channel closed: {}", e);
                        break;
                    }
                }
                Ok(())
            })
        });

        let query_fmt_thread = std::thread::spawn({
            fn_log_err("pg_query_fmt", move || {
                while let Ok((batch_id, blocks, inputs_utxo_map, tx_ids)) = query_fmt_rx.recv() {
                    let insert_queries =
                        fmt_insert_blockdata_sql(&blocks, inputs_utxo_map, tx_ids, mode, network)?;

                    let tx_len = blocks.iter().map(|b| b.data.txdata.len()).sum();

                    let max_block_height = blocks
                        .iter()
                        .rev()
                        .next()
                        .expect("at least one block")
                        .height;

                    let block_ids = blocks.into_iter().map(|block| block.id).collect();

                    if let Err(e) = writer_tx.send((
                        batch_id,
                        insert_queries,
                        block_ids,
                        max_block_height,
                        tx_len,
                    )) {
                        error!("pg_query_fmt: downstream channel closed: {}", e);
                        break;
                    }
                }
                Ok(())
            })
        });

        let writer_thread = std::thread::spawn({
            let url = url.clone();
            let mut conn = establish_connection(&url);
            fn_log_err("pg_writer", move || {
                let mut prev_time = std::time::Instant::now();
                while let Ok((batch_id, queries, block_ids, max_block_height, tx_len)) =
                    writer_rx.recv()
                {
                    let transaction = conn.transaction()?;
                    commit_atomic_bulk_insert_sql(
                        transaction,
                        "all block data",
                        block_ids.len(),
                        batch_id,
                        queries.into_iter(),
                    )?;

                    let current_time = std::time::Instant::now();
                    let duration = current_time.duration_since(prev_time);
                    prev_time = current_time;

                    info!(
                        "Block {}H fully indexed and commited; {}block/s; {}tx/s",
                        max_block_height,
                        (block_ids.len() as u64 * 1000)
                            / (duration.as_secs() as u64 * 1000
                                + u64::from(duration.subsec_millis())),
                        (tx_len as u64 * 1000)
                            / (duration.as_secs() as u64 * 1000
                                + u64::from(duration.subsec_millis())),
                    );

                    let mut any_missing = false;
                    let mut lock = in_flight.lock().unwrap();
                    for hash in &block_ids {
                        let missing = !lock.remove(hash);
                        any_missing = any_missing || missing;
                    }
                    drop(lock);
                    assert!(!any_missing);
                }

                Ok(())
            })
        });

        AsyncBlockInsertWorker {
            tx: Some(utxo_fetching_tx),
            utxo_fetching_thread: Some(utxo_fetching_thread),
            query_fmt_thread: Some(query_fmt_thread),
            writer_thread: Some(writer_thread),
        }
    }
}

impl Drop for AsyncBlockInsertWorker {
    fn drop(&mut self) {
        // Close channel to signal shutdown
        drop(self.tx.take());

        // Attempt to join threads gracefully; log errors, don't panic
        let handles = [
            self.utxo_fetching_thread.take(),
            self.query_fmt_thread.take(),
            self.writer_thread.take(),
        ];

        for handle_opt in handles {
            if let Some(handle) = handle_opt {
                match handle.join() {
                    Ok(res) => {
                        if let Err(e) = res {
                            error!(
                                "Worker thread finished with error during shutdown: {}",
                                e.display_causes_and_backtrace()
                            );
                        }
                    }
                    Err(_) => {
                        error!("Worker thread panicked during shutdown");
                    }
                }
            }
        }
    }
}

pub struct IndexerStore {
    url: String,
    connection: pg::Client,
    pipeline: Option<AsyncBlockInsertWorker>,
    batch: Vec<crate::BlockData>,
    batch_txs_total: u64,
    batch_id: u64,
    bulk_flush_txs_threshold: u64,
    bulk_flush_blocks_threshold: usize,
    mode: Mode,
    network: bitcoin::Network,
    node_chain_head_height: BlockHeight,

    // blocks that were sent to workers, but
    // were not yet written
    in_flight: Arc<Mutex<BlocksInFlight>>,

    // block count of the currently longest chain
    chain_block_count: BlockHeight,
    // to guarantee that the db never contains an inconsistent state
    // during the reorg, all reorg blocks are being gathered here
    // until they overtake the current `chain_block_count`
    pending_reorg: BTreeMap<BlockHeight, BlockData>,
}

impl Drop for IndexerStore {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

impl IndexerStore {
    pub fn new(
        url: String,
        node_chain_head_height: BlockHeight,
        network: bitcoin::Network,
    ) -> Result<Self> {
        let mut connection = establish_connection(&url);
        Self::init(&mut connection)?;
        let mode = Self::read_indexer_state(&mut connection)?;
        let chain_block_count = Self::read_db_chain_block_count(&mut connection)?;
        let chain_current_block_count = Self::read_db_chain_current_block_count(&mut connection)?;
        if chain_current_block_count > 0 {
            if let Some(db_head_hash) =
                Self::read_db_block_hash_by_height(&mut connection, chain_current_block_count - 1)?
            {
                info!(
                    "DB head at {}H: {} (chain_block_count={}, current_block_count={}, mode={})",
                    chain_current_block_count - 1,
                    db_head_hash,
                    chain_block_count,
                    chain_current_block_count,
                    mode
                );
            } else {
                info!(
                    "DB head unknown at {}H (chain_block_count={}, current_block_count={}, mode={})",
                    chain_current_block_count - 1,
                    chain_block_count,
                    chain_current_block_count,
                    mode
                );
            }
        } else {
            info!(
                "DB empty (chain_block_count={}, current_block_count={}, mode={})",
                chain_block_count, chain_current_block_count, mode
            );
        }

        assert_eq!(
            chain_block_count, chain_current_block_count,
            "db is supposed to preserve reorg atomicity"
        );
        // Configurable bulk flush thresholds
        let bulk_flush_txs_threshold = std::env::var("INDEXER_BULK_FLUSH_TXS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(100_000);
        let bulk_flush_blocks_threshold = std::env::var("INDEXER_BULK_FLUSH_BLOCKS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1000);
        let mut s = IndexerStore {
            url,
            connection,
            pipeline: None,
            batch: vec![],
            batch_txs_total: 0,
            batch_id: 0,
            bulk_flush_txs_threshold,
            bulk_flush_blocks_threshold,
            mode,
            network,
            node_chain_head_height,
            pending_reorg: BTreeMap::default(),
            in_flight: Arc::new(Mutex::new(BlocksInFlight::new())),
            chain_block_count,
        };
        if s.mode == Mode::FreshBulk {
            if std::env::var("INDEXER_SELF_TEST").ok().as_deref() == Some("1") {
                s.self_test()?;
            } else {
                trace!("Skipping self-test (set INDEXER_SELF_TEST=1 to enable)");
            }
        }
        s.set_schema_to_mode(s.mode)?;
        s.start_workers();
        Ok(s)
    }

    fn read_db_block_extinct_by_hash_id_trans(
        conn: &mut postgres::Transaction,
        hash_id: &[u8],
    ) -> Result<Option<bool>> {
        Ok(conn
            .query("SELECT extinct FROM block WHERE hash_id = $1", &[&hash_id])?
            .iter()
            .next()
            .map(|row| row.get::<_, bool>(0)))
    }

    fn read_db_chain_current_block_count(conn: &mut pg::Client) -> Result<BlockHeight> {
        Ok(query_one_value_opt::<BlockHeightSigned>(
            conn,
            "SELECT max(height) FROM block WHERE extinct = FALSE",
            &[],
        )?
        .map(|i| i as BlockHeight + 1)
        .unwrap_or(0))
    }

    fn read_db_chain_block_count(conn: &mut pg::Client) -> Result<BlockHeight> {
        Ok(
            query_one_value_opt::<BlockHeightSigned>(conn, "SELECT max(height) FROM block", &[])?
                .map(|i| i as u32 + 1)
                .unwrap_or(0),
        )
    }

    fn read_db_block_hash_by_height(
        conn: &mut pg::Client,
        height: BlockHeight,
    ) -> Result<Option<BlockHash>> {
        Ok(query_two_values::<Vec<u8>, Vec<u8>>(
            conn,
            "SELECT hash_id, hash_rest FROM block WHERE height = $1 AND extinct = false",
            &[&(height as BlockHeightSigned)],
        )?
        .map(hash_id_and_rest_to_hash))
    }

    fn read_db_block_hash_by_height_trans(
        conn: &mut postgres::Transaction,
        height: BlockHeight,
    ) -> Result<Option<BlockHash>> {
        Ok(query_two_values_trans::<Vec<u8>, Vec<u8>>(
            conn,
            "SELECT hash_id, hash_rest FROM block WHERE height = $1 AND extinct = false",
            &[&(height as BlockHeightSigned)],
        )?
        .map(hash_id_and_rest_to_hash))
    }

    fn read_indexer_state(conn: &mut pg::Client) -> Result<Mode> {
        trace!("Reading indexer state from the db");
        let state = conn.query("SELECT bulk_mode FROM indexer_state", &[])?;
        if let Some(state) = state.iter().next() {
            let is_bulk_mode = state.get(0);
            let mode = if is_bulk_mode {
                let count = conn
                    .query("SELECT COUNT(*) FROM block", &[])?
                    .into_iter()
                    .next()
                    .expect("A row from the db")
                    .get::<_, i64>(0);
                if count == 0 {
                    trace!("Indexer in fresh state");
                    Mode::FreshBulk
                } else {
                    trace!("Indexer in bulk state");
                    Mode::Bulk
                }
            } else {
                trace!("Indexer in normal state");
                Mode::Normal
            };

            Ok(mode)
        } else {
            conn.execute(
                "INSERT INTO indexer_state (bulk_mode) VALUES ($1)",
                &[&true],
            )?;
            trace!("Indexer in fresh state (on first run).");
            Ok(Mode::FreshBulk)
        }
    }

    fn batch_execute_with_log(conn: &mut pg::Client, sql: &str, context: &str) -> Result<()> {
        match conn.batch_execute(sql) {
            Ok(()) => Ok(()),
            Err(e) => {
                let snippet: String = sql.chars().take(256).collect();
                if let Some(dbe) = e.as_db_error() {
                    error!(
                        "Postgres {} error: {} (code: {:?}, detail: {:?}, hint: {:?}); sql(first 256): {}",
                        context,
                        dbe.message(),
                        dbe.code(),
                        dbe.detail(),
                        dbe.hint(),
                        snippet
                    );
                } else {
                    error!(
                        "Postgres {} error: {}; sql(first 256): {}",
                        context, e, snippet
                    );
                }
                Err(e.into())
            }
        }
    }

    fn execute_with_log(
        conn: &mut pg::Client,
        sql: &str,
        params: &[&(dyn pg::ToSql + Sync)],
        context: &str,
    ) -> Result<u64> {
        match conn.execute(sql, params) {
            Ok(n) => Ok(n),
            Err(e) => {
                if let Some(dbe) = e.as_db_error() {
                    error!(
                        "Postgres {} error: {} (code: {:?}, detail: {:?}, hint: {:?}); sql: {}",
                        context,
                        dbe.message(),
                        dbe.code(),
                        dbe.detail(),
                        dbe.hint(),
                        sql
                    );
                } else {
                    error!("Postgres {} error: {}; sql: {}", context, e, sql);
                }
                Err(e.into())
            }
        }
    }

    fn init(conn: &mut pg::Client) -> Result<()> {
        info!("Creating initial db schema");
        Self::batch_execute_with_log(conn, include_str!("pg/init.sql"), "init")?;
        Ok(())
    }

    fn stop_workers(&mut self) {
        debug!("Stopping DB pipeline workers");
        // Best-effort flush any pending batch before stopping the pipeline
        if !self.batch.is_empty() {
            if let Err(e) = self.flush_batch() {
                error!("Failed to flush final batch before stopping workers: {}", e);
            }
        }
        self.pipeline.take();
        debug!("Stopped DB pipeline workers");
        assert!(self.in_flight.lock().unwrap().is_empty());
    }

    fn are_workers_stopped(&self) -> bool {
        self.pipeline.is_none()
    }

    fn start_workers(&mut self) {
        debug!("Starting DB pipeline workers");
        self.pipeline = Some(AsyncBlockInsertWorker::new(
            self.url.clone(),
            self.in_flight.clone(),
            self.mode,
            self.network,
        ))
    }

    fn flush_workers(&mut self) -> Result<()> {
        if !self.are_workers_stopped() {
            self.flush_batch()?;
            if !self.in_flight.lock().unwrap().is_empty() {
                self.flush_workers_unconditionally();
            }
        }

        Ok(())
    }

    fn flush_workers_unconditionally(&mut self) {
        self.stop_workers();
        self.start_workers();
    }

    // Flush all batch of work to the workers
    fn flush_batch(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }
        trace!(
            "Flushing batch {}, with {} txes",
            self.batch_id,
            self.batch_txs_total
        );
        let batch = std::mem::replace(&mut self.batch, vec![]);

        let mut in_flight = self.in_flight.lock().expect("locking works");
        for block in &batch {
            in_flight.insert(block.id);
        }
        drop(in_flight);

        if let Some(pipeline) = self.pipeline.as_ref() {
            if let Some(tx) = pipeline.tx.as_ref() {
                if let Err(e) = tx.send((self.batch_id, batch)) {
                    error!("Failed to queue batch {} to pipeline: {}", self.batch_id, e);
                    bail!(
                        "pipeline channel closed while sending batch {}",
                        self.batch_id
                    );
                }
            } else {
                error!(
                    "Pipeline sender missing when flushing batch {}",
                    self.batch_id
                );
                bail!("pipeline sender missing");
            }
        } else {
            error!("Pipeline not running when flushing batch {}", self.batch_id);
            bail!("pipeline not running");
        }
        trace!("Batch flushed");
        self.batch_txs_total = 0;
        self.batch_id += 1;
        Ok(())
    }

    pub fn wipe(url: &str) -> Result<()> {
        info!("Wiping db schema");
        let mut connection = establish_connection(&url);
        connection.batch_execute(include_str!("pg/wipe.sql"))?;
        Ok(())
    }

    fn set_mode(&mut self, mode: Mode) -> Result<()> {
        if self.mode == mode {
            return Ok(());
        }

        self.set_mode_uncodintionally(mode)?;
        Ok(())
    }

    fn set_schema_to_mode(&mut self, mode: Mode) -> Result<()> {
        info!("Adjusting schema to mode: {}", mode);
        Self::batch_execute_with_log(
            &mut self.connection,
            mode.to_sql_query_str(),
            "set_schema_to_mode",
        )?;
        Ok(())
    }

    fn set_mode_uncodintionally(&mut self, mode: Mode) -> Result<()> {
        self.mode = mode;

        info!("Entering {}", mode.to_entering_str());
        self.flush_workers()?;

        self.set_schema_to_mode(mode)?;
        // commit to the new mode in the db last
        Self::execute_with_log(
            &mut self.connection,
            "UPDATE indexer_state SET bulk_mode = $1",
            &[&(mode.is_bulk())],
            "set_mode_uncodintionally:update_indexer_state",
        )?;
        Ok(())
    }

    /// Switch between all modes to double-check all queries
    fn self_test(&mut self) -> Result<()> {
        assert_eq!(self.mode, Mode::FreshBulk);

        self.set_mode_uncodintionally(Mode::FreshBulk)?;
        self.set_mode_uncodintionally(Mode::Bulk)?;
        self.set_mode_uncodintionally(Mode::Normal)?;
        self.set_mode_uncodintionally(Mode::Bulk)?;
        self.set_mode_uncodintionally(Mode::FreshBulk)?;
        Ok(())
    }

    fn is_in_reorg(&self) -> bool {
        !self.pending_reorg.is_empty()
    }

    fn insert_when_at_tip(&mut self, block: crate::BlockData) -> Result<()> {
        debug_assert!(!self.is_in_reorg());
        debug_assert!(!self.are_workers_stopped());
        debug_assert!(self.pending_reorg.is_empty());

        trace!(
            "Inserting at tip block {}H {} when chain_block_count = {}",
            block.height,
            block.id,
            self.chain_block_count
        );

        // if we extend, we can't make holes
        assert!(block.height <= self.chain_block_count);

        // we're not extending ... reorg start or something we already have
        if block.height != self.chain_block_count {
            // flush any pending batch to keep state consistent before checking db
            self.flush_batch()?;

            // fetch current db hash at this height without stopping workers yet
            let db_hash = Self::read_db_block_hash_by_height(&mut self.connection, block.height)?
                .expect("Block at this height should already by indexed");

            if db_hash == block.id {
                // already included; avoid stop/start thrash
                trace!("Already included block {}H {}", block.height, block.id);
                return Ok(());
            }

            // reorg: now stop workers because schema/table state will change
            self.stop_workers();

            info!(
                "Node block != db block at {}H; {} != {} - reorg",
                block.height, block.id, db_hash
            );

            assert!(self.batch.is_empty());
            self.pending_reorg.insert(block.height, block);
            assert!(self.is_in_reorg());

            // Note: we keep workers stopped; they will be restarted
            // when we're done with the reorg
            return Ok(());
        }

        self.batch_txs_total += block.data.txdata.len() as u64;
        let height = block.height;
        self.batch.push(block);
        self.chain_block_count += 1;

        if self.mode.is_bulk() {
            if self.batch_txs_total >= self.bulk_flush_txs_threshold
                || self.batch.len() >= self.bulk_flush_blocks_threshold
            {
                self.flush_batch()?;
            }
        } else {
            self.flush_batch()?;
        }

        if self.node_chain_head_height == height {
            self.set_mode(Mode::Normal)?;
        }

        Ok(())
    }

    fn insert_when_in_reorg(&mut self, block: crate::BlockData) -> Result<()> {
        debug_assert!(self.is_in_reorg());
        debug_assert!(self.are_workers_stopped());
        debug_assert!(!self.pending_reorg.is_empty());

        trace!(
            "Inserting in reorg block {}H {} when chain_block_count = {}",
            block.height,
            block.id,
            self.chain_block_count
        );

        // if we extend, we can't make holes
        assert!(block.height <= self.chain_block_count);

        let _ = self.pending_reorg.split_off(&block.height);

        trace!("Reorg block {}H {}", block.height, block.id);
        let height = block.height;
        self.pending_reorg.insert(height, block);

        if height == self.chain_block_count {
            trace!("Flushing reorg at {}H", height);
            self.finish_reorg()?;
        }

        Ok(())
    }

    fn finish_reorg(&mut self) -> Result<()> {
        debug_assert!(self.is_in_reorg());
        debug_assert!(self.are_workers_stopped());
        debug_assert!(!self.pending_reorg.is_empty());

        let mut transaction = self.connection.transaction()?;

        let mut first_different_height = None;
        for (height, block) in self.pending_reorg.iter() {
            if let Some(existing_hash) =
                Self::read_db_block_hash_by_height_trans(&mut transaction, *height)?
            {
                if existing_hash != block.id {
                    first_different_height = Some(block.height);
                    break;
                }
            }
        }

        let first_different_height = first_different_height.unwrap_or(self.chain_block_count);

        debug!("Reorg begining at {}H", first_different_height);

        transaction.execute(
            "INSERT INTO event (block_hash_id, revert) SELECT hash_id, true FROM block WHERE height >= $1 AND NOT extinct ORDER BY height DESC;",
            &[&(first_different_height as BlockHeightSigned)],
        )?;
        transaction.execute(
            "UPDATE block SET extinct = true WHERE height >= $1;",
            &[&(first_different_height as BlockHeightSigned)],
        )?;

        self.pending_reorg = self.pending_reorg.split_off(&first_different_height);

        let mut prev_height: Option<BlockHeight> = None;
        for (height, block) in
            std::mem::replace(&mut self.pending_reorg, BTreeMap::new()).into_iter()
        {
            if let Some(prev_height) = prev_height {
                assert_eq!(prev_height + 1, height);
            }
            prev_height = Some(block.height);

            let block_hash_id = hash_to_hash_id(&block.id.as_hash());

            match Self::read_db_block_extinct_by_hash_id_trans(&mut transaction, &block_hash_id)? {
                Some(false) => panic!(
                    "Why is block id={} not extinct?",
                    hex::encode(block_hash_id)
                ),
                Some(true) => {
                    trace!(
                        "Existing reorg block: reviving {}H {}",
                        block.height,
                        block.id
                    );
                    transaction.execute(
                        "UPDATE block SET extinct = false WHERE hash_id = $1;",
                        &[&(block_hash_id)],
                    )?;
                    transaction.execute(
                        "UPDATE tx SET current_height = NULL WHERE current_height = $1;",
                        &[&(block.height as BlockHeightSigned)],
                    )?;
                    transaction.execute(
                        "INSERT INTO event (block_hash_id) VALUES ($1);",
                        &[&block_hash_id],
                    )?;
                }
                None => {
                    trace!("Unindexed reorg block {}H {}", block.height, block.id);
                    self.batch_txs_total += block.data.txdata.len() as u64;
                    self.batch.push(block);
                }
            }
        }
        // only the last block is actually increasing the block count
        self.chain_block_count += 1;

        assert!(!self.batch.is_empty());

        let blocks = std::mem::replace(&mut self.batch, vec![]);

        let mut utxo_set_cache = UtxoSetCache::default();
        let tx_ids: TxIdMap = tx_id_map_from_blocks(&blocks, self.network)?;
        let inputs_utxo_map = utxo_set_cache.process_blocks(&mut transaction, &blocks, &tx_ids)?;

        let block_count = blocks.iter().count();
        let insert_queries =
            fmt_insert_blockdata_sql(&blocks, inputs_utxo_map, tx_ids, self.mode, self.network)?;

        commit_atomic_bulk_insert_sql(
            transaction,
            "all block data",
            block_count,
            0,
            insert_queries.into_iter(),
        )?;

        self.start_workers();

        Ok(())
    }
}

/*
fn query_one_value<T>(
    conn: &Connection,
    q: &str,
    params: &[&dyn postgres::types::ToSql],
) -> Result<Option<T>>
where
    T: postgres::types::FromSql,
{
    Ok(conn
        .query(q, params)?
        .iter()
        .next()
        .map(|row| row.get::<_, T>(0)))
}
*/

fn query_two_values<T1, T2>(
    conn: &mut pg::Client,
    q: &str,
    params: &[&(dyn pg::ToSql + Sync)],
) -> Result<Option<(T1, T2)>>
where
    T1: for<'a> postgres::types::FromSql<'a>,
    T2: for<'b> postgres::types::FromSql<'b>,
{
    Ok(conn
        .query_opt(q, params)?
        .map(|row| (row.get::<_, T1>(0), row.get::<_, T2>(1))))
}
fn query_one_value_opt<T>(
    conn: &mut pg::Client,
    q: &str,
    params: &[&(dyn pg::ToSql + Sync)],
) -> Result<Option<T>>
where
    T: for<'a> postgres::types::FromSql<'a>,
{
    Ok(conn
        .query(q, params)?
        .iter()
        .next()
        .and_then(|row| row.get::<_, Option<T>>(0)))
}

/*
fn query_one_value_trans<T>(
    conn: &postgres::transaction::Transaction,
    q: &str,
    params: &[&dyn postgres::types::ToSql],
) -> Result<Option<T>>
where
    T: postgres::types::FromSql,
{
    Ok(conn
        .query(q, params)?
        .iter()
        .next()
        .map(|row| row.get::<_, T>(0)))
}
*/

fn query_two_values_trans<T1, T2>(
    conn: &mut postgres::Transaction,
    q: &str,
    params: &[&(dyn pg::ToSql + Sync)],
) -> Result<Option<(T1, T2)>>
where
    T1: for<'a> postgres::types::FromSql<'a>,
    T2: for<'b> postgres::types::FromSql<'b>,
{
    Ok(conn
        .query(q, params)?
        .iter()
        .next()
        .map(|row| (row.get::<_, T1>(0), row.get::<_, T2>(1))))
}

impl super::IndexerStore for IndexerStore {
    fn get_head_height(&mut self) -> Result<Option<BlockHeight>> {
        Ok(if self.chain_block_count == 0 {
            None
        } else {
            Some(self.chain_block_count - 1)
        })
    }

    fn get_hash_by_height(&mut self, height: BlockHeight) -> Result<Option<BlockHash>> {
        trace!("PG: get_hash_by_height {}H", height);

        if self.chain_block_count <= height {
            return Ok(None);
        }

        if let Some(block) = self.pending_reorg.get(&height) {
            return Ok(Some(block.id));
        }

        // Only flush workers if there is pending work to avoid startup thrash
        if !self.batch.is_empty() || !self.in_flight.lock().unwrap().is_empty() {
            self.flush_workers()?;
        }

        {
            let res = Self::read_db_block_hash_by_height(&mut self.connection, height)?;
            if let Some(ref h) = res {
                info!("Resume probe: DB hash at {}H is {}", height, h);
            } else {
                info!("Resume probe: no DB hash at {}H", height);
            }
            Ok(res)
        }
    }

    fn insert(&mut self, block: crate::BlockData) -> Result<()> {
        if self.is_in_reorg() {
            self.insert_when_in_reorg(block)?;
        } else {
            self.insert_when_at_tip(block)?;
        }

        Ok(())
    }
}

impl crate::event_source::EventSource for postgres::Client {
    type Cursor = i64;
    type Id = BlockHash;
    type Data = bool;

    fn next(
        &mut self,
        cursor: Option<Self::Cursor>,
        limit: u64,
    ) -> Result<(Vec<WithHeightAndId<Self::Id, Self::Data>>, Self::Cursor)> {
        let cursor = cursor.unwrap_or(-1);
        let rows = self.query(
            "SELECT id, hash_id, hash_rest, height, revert FROM event JOIN block ON event.block_hash_id = block.hash_id WHERE event.id > $1 ORDER BY id ASC LIMIT $2;",
            &[&cursor, &(limit as i64)],
        )?;

        let mut res = vec![];
        let mut last = cursor;

        for row in &rows {
            let id: i64 = row.get(0);
            let hash_id: Vec<u8> = row.get(1);
            let hash_rest: Vec<u8> = row.get(2);
            let hash = hash_id_and_rest_to_hash((hash_id, hash_rest));
            let height: BlockHeightSigned = row.get(3);
            let revert: bool = row.get(4);

            res.push(WithHeightAndId {
                id: hash,
                height: height as BlockHeight,
                data: revert,
            });

            last = id;
        }

        Ok((res, last))
    }
}

pub struct MempoolStore {
    #[allow(unused)]
    connection: pg::Client,
    network: bitcoin::Network,
}

impl MempoolStore {
    pub fn new(url: String, network: bitcoin::Network) -> Result<Self> {
        let mut connection = establish_connection(&url);
        IndexerStore::init(&mut connection)?;

        let mode = IndexerStore::read_indexer_state(&mut connection)?;

        if mode.is_bulk() {
            bail!("Indexer still in bulk mode. Finish initial indexing, or force the mode change");
        }

        Ok(Self {
            connection,
            network,
        })
    }

    fn insert_tx_data(
        &mut self,
        tx_id: &Txid,
        tx: &bitcoin::Transaction,
        utxo_map: UtxoDetailsMap,
    ) -> Result<()> {
        let mut tx_q = String::new();
        let mut output_q = String::new();
        let mut input_q = String::new();

        let mut formatter = TxFormatter::new_for_in_mempool(
            &mut tx_q,
            &mut output_q,
            &mut input_q,
            self.network,
            utxo_map,
        );

        formatter.fmt(None, tx, &tx_id.as_hash());

        drop(formatter);

        self.connection.batch_execute(&tx_q)?;
        self.connection.batch_execute(&output_q)?;
        self.connection.batch_execute(&input_q)?;

        Ok(())
    }
}

impl super::MempoolStore for MempoolStore {
    fn insert_iter<'a>(
        &mut self,
        txs: impl Iterator<Item = &'a WithTxId<Option<bitcoin::Transaction>>>,
    ) -> Result<()> {
        // maybe one day we can optimize, right now just loop
        for tx in txs {
            self.insert(tx)?;
        }
        Ok(())
    }

    fn insert(&mut self, tx: &WithTxId<Option<bitcoin::Transaction>>) -> Result<()> {
        let tx_id = tx.id;

        if let Some(ref tx) = tx.data {
            let hash_id_out_points: Vec<_> = tx
                .input
                .clone()
                .into_iter()
                .map(|i| HashIdOutPoint::from(i.previous_output))
                .collect();

            if let Ok(utxo_map) = fetch_outputs(&mut self.connection, hash_id_out_points.iter()) {
                if utxo_map.len() != tx.input.len() {
                    bail!("Couldn't find all inputs for tx {}", tx_id);
                }
                self.insert_tx_data(&Txid::from(tx_id), tx, utxo_map)?;
            }
        }

        Ok(())
    }
}
