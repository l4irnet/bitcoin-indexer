use std::error::Error;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::Duration;

use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use clap::Parser;
use regex::Regex;
use scraper::Html;
use serde::Serialize;
use std::str::FromStr;

/// Probe a set of runes from ordinals.com and construct a JSONL corpus
/// mapping rune webpage metadata to on-chain runestones (OP_RETURN with OP_13),
/// including the raw payload, concatenated pushes, and decoded base-128 varints.
///
/// Usage examples:
///   runes_spec_probe --rpc-url http://127.0.0.1:8332 --rpc-user user --rpc-pass pass --runes YAROSLAV,ORDI
///   runes_spec_probe --rpc-url http://127.0.0.1:8332 --rpc-cookie-file ~/.bitcoin/.cookie --runes-file runes.txt
#[derive(Parser, Debug)]
#[command(name = "runes_spec_probe")]
#[command(author, version, about)]
struct Opts {
    /// Bitcoin Core RPC URL (eg: http://127.0.0.1:8332)
    #[arg(long, env = "NODE_RPC_URL")]
    rpc_url: String,

    /// Bitcoin Core RPC username (if not using cookie)
    #[arg(long, env = "NODE_RPC_USER")]
    rpc_user: Option<String>,

    /// Bitcoin Core RPC password (if not using cookie)
    #[arg(long, env = "NODE_RPC_PASS")]
    rpc_pass: Option<String>,

    /// Bitcoin Core cookie file path (alternative to user/pass)
    #[arg(long)]
    rpc_cookie_file: Option<PathBuf>,

    /// Comma-separated list of rune names to probe (e.g., YAROSLAV,ORDI)
    #[arg(long)]
    runes: Option<String>,

    /// Path to a file containing rune names (one per line)
    #[arg(long)]
    runes_file: Option<PathBuf>,

    /// Comma-separated list of txids to probe
    #[arg(long)]
    txids: Option<String>,

    /// Path to a file containing txids (one per line)
    #[arg(long)]
    txids_file: Option<PathBuf>,

    /// Output JSONL file path
    #[arg(long, default_value = "runes_corpus.jsonl")]
    out: PathBuf,

    /// Request timeout in seconds for HTTP fetches
    #[arg(long, default_value_t = 15)]
    http_timeout_secs: u64,
}

#[derive(Serialize, Debug)]
struct RuneCorpusRecord {
    // From web
    name: String,
    page_url: String,
    id_block: Option<u64>,
    id_tx_index: Option<usize>,
    divisibility: Option<u32>,
    symbol: Option<String>,
    premine_raw: Option<String>,
    terms_raw: Option<String>,

    // On-chain linkage
    block_hash: Option<String>,
    txid: Option<String>,
    block_time: Option<u32>,

    // Runestone content
    runestone_found: bool,
    op_return_spk_hex: Option<String>,
    runestone_payload_hex: Option<String>,
    pushes_concat_hex: Option<String>,
    varints: Vec<String>, // stringified u128

    // Errors / diagnostics
    error: Option<String>,
}

fn build_rpc_client(opts: &Opts) -> Result<RpcClient, Box<dyn Error>> {
    let auth = if let Some(cookie) = &opts.rpc_cookie_file {
        Auth::CookieFile(cookie.clone())
    } else {
        let user = opts
            .rpc_user
            .as_ref()
            .ok_or("rpc_user is required if rpc_cookie_file is not provided")?;
        let pass = opts
            .rpc_pass
            .as_ref()
            .ok_or("rpc_pass is required if rpc_cookie_file is not provided")?;
        Auth::UserPass(user.clone(), pass.clone())
    };
    let client = RpcClient::new(&opts.rpc_url, auth)?;
    Ok(client)
}

fn build_http_client(timeout_secs: u64) -> Result<reqwest::blocking::Client, Box<dyn Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .user_agent("runes-spec-probe/0.1 (+https://ordinals.com)")
        .build()?;
    Ok(client)
}

fn parse_runes_list_from_args(opts: &Opts) -> Result<Vec<String>, Box<dyn Error>> {
    let mut v = Vec::new();
    if let Some(s) = &opts.runes {
        for name in s.split(',') {
            let trimmed = name.trim().to_string();
            if !trimmed.is_empty() {
                v.push(trimmed);
            }
        }
    }
    if let Some(p) = &opts.runes_file {
        let txt = std::fs::read_to_string(p)?;
        for line in txt.lines() {
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                v.push(trimmed);
            }
        }
    }
    // Allow empty rune list; proceed if only --txids/--txids-file provided.
    // Dedup preserving order
    let mut seen = std::collections::HashSet::new();
    v.retain(|n| seen.insert(n.clone()));
    Ok(v)
}

fn parse_txids_from_args(opts: &Opts) -> Result<Vec<String>, Box<dyn Error>> {
    let mut v = Vec::new();
    if let Some(s) = &opts.txids {
        for t in s.split(',') {
            let trimmed = t.trim().to_string();
            if !trimmed.is_empty() {
                v.push(trimmed);
            }
        }
    }
    if let Some(p) = &opts.txids_file {
        let txt = std::fs::read_to_string(p)?;
        for line in txt.lines() {
            let trimmed = line.trim().to_string();
            if !trimmed.is_empty() {
                v.push(trimmed);
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    v.retain(|h| seen.insert(h.clone()));
    Ok(v)
}

fn html_text(doc: &Html) -> String {
    // Gather all text nodes to a single string for regex searching
    doc.root_element()
        .text()
        .map(|t| t.trim())
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

fn parse_rune_page(
    name: &str,
    html: &str,
) -> (
    Option<u64>,
    Option<usize>,
    Option<u32>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    let doc = Html::parse_document(html);
    let text = html_text(&doc);

    // ID: "BLOCK:TX" (e.g., 840000:1234)
    let re_id = Regex::new(r"(\d{5,}):(\d{1,6})").unwrap();
    let (mut id_block, mut id_tx_index) = (None, None);
    if let Some(cap) = re_id.captures(&text) {
        if let (Some(b), Some(t)) = (cap.get(1), cap.get(2)) {
            id_block = b.as_str().parse::<u64>().ok();
            id_tx_index = t.as_str().parse::<usize>().ok();
        }
    }

    // Divisibility: "Divisibility: N"
    let re_div = Regex::new(r"(?i)Divisibility\s*:\s*(\d{1,3})").unwrap();
    let mut divisibility = None;
    if let Some(cap) = re_div.captures(&text) {
        if let Some(d) = cap.get(1) {
            divisibility = d.as_str().parse::<u32>().ok();
        }
    }

    // Symbol: "Symbol: X" (may be any single codepoint; capture next non-space token)
    let re_sym = Regex::new(r"(?i)Symbol\s*:\s*([^\s]+)").unwrap();
    let mut symbol = None;
    if let Some(cap) = re_sym.captures(&text) {
        if let Some(s) = cap.get(1) {
            symbol = Some(s.as_str().to_string());
        }
    }

    // Premine: free-form; try to capture substring after "Premine:"
    // We'll extract up to the next label-like token or sentence boundary.
    let re_pre = Regex::new(r"(?i)Premine\s*:\s*([^•\|]+?)(?:\s{2,}|$)").unwrap();
    let mut premine_raw = None;
    if let Some(cap) = re_pre.captures(&text) {
        if let Some(s) = cap.get(1) {
            premine_raw = Some(s.as_str().trim().to_string());
        }
    }

    // Terms: free-form after "Terms:" string
    let re_terms = Regex::new(r"(?i)Terms\s*:\s*([^•\|]+?)(?:\s{2,}|$)").unwrap();
    let mut terms_raw = None;
    if let Some(cap) = re_terms.captures(&text) {
        if let Some(s) = cap.get(1) {
            terms_raw = Some(s.as_str().trim().to_string());
        }
    }

    // Some pages might label differently; be generous:
    if id_block.is_none() || id_tx_index.is_none() {
        // Another attempt: look for "ID " prefix explicitly
        let re2 = Regex::new(r"(?i)ID\s*[:\-]?\s*(\d{5,}):(\d{1,6})").unwrap();
        if let Some(cap) = re2.captures(&text) {
            if let (Some(b), Some(t)) = (cap.get(1), cap.get(2)) {
                id_block = b.as_str().parse::<u64>().ok();
                id_tx_index = t.as_str().parse::<usize>().ok();
            }
        }
    }

    // If the symbol is not present, but &bull; or bullets used, skip; it's optional.

    // Debug hint (suppressed in normal operation)
    // eprintln!("Parsed {} => id={:?}:{:?} div={:?} sym={:?} premine={:?} terms={:?}", name, id_block, id_tx_index, divisibility, symbol, premine_raw, terms_raw);

    (
        id_block,
        id_tx_index,
        divisibility,
        symbol,
        premine_raw,
        terms_raw,
    )
}

fn runestone_concat_pushes(payload: &[u8]) -> Option<Vec<u8>> {
    // payload is assumed to start with OP_PUSHNUM_13 (0x8d)
    if payload.is_empty() || payload[0] != bitcoin::opcodes::all::OP_PUSHNUM_13.to_u8() {
        return None;
    }
    let mut i = 1usize;
    let mut out = Vec::new();
    while i < payload.len() {
        let op = payload[i];
        i += 1;
        let len = if op <= 75 {
            op as usize
        } else if op == bitcoin::opcodes::all::OP_PUSHDATA1.to_u8() {
            if i + 1 > payload.len() {
                return None;
            }
            let l = payload[i] as usize;
            i += 1;
            l
        } else if op == bitcoin::opcodes::all::OP_PUSHDATA2.to_u8() {
            if i + 2 > payload.len() {
                return None;
            }
            let l = (payload[i] as usize) | ((payload[i + 1] as usize) << 8);
            i += 2;
            l
        } else {
            // Unknown opcode; bail
            return None;
        };
        if i + len > payload.len() {
            return None;
        }
        out.extend_from_slice(&payload[i..i + len]);
        i += len;
    }
    Some(out)
}

fn decode_varints128(mut data: &[u8]) -> Vec<u128> {
    let mut out = Vec::new();
    while !data.is_empty() {
        let mut val: u128 = 0;
        let mut shift: u32 = 0;
        let mut consumed = 0usize;
        for (idx, b) in data.iter().enumerate() {
            let low = (b & 0x7F) as u128;
            val |= low << shift;
            consumed = idx + 1;
            if (b & 0x80) == 0 {
                break;
            }
            shift += 7;
            if shift >= 128 {
                // overflow or malformed
                consumed = idx + 1;
                break;
            }
        }
        if consumed == 0 {
            break;
        }
        out.push(val);
        data = &data[consumed..];
    }
    out
}

fn hex<T: AsRef<[u8]>>(v: T) -> String {
    hex::encode(v.as_ref())
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts = Opts::parse();
    let rpc = build_rpc_client(&opts)?;
    let http = build_http_client(opts.http_timeout_secs)?;

    let runes = parse_runes_list_from_args(&opts)?;
    let out_file = File::create(&opts.out)?;
    let mut out = BufWriter::new(out_file);

    for name in runes {
        let page_url = format!("https://ordinals.com/rune/{}", name);
        let mut rec = RuneCorpusRecord {
            name: name.clone(),
            page_url: page_url.clone(),
            id_block: None,
            id_tx_index: None,
            divisibility: None,
            symbol: None,
            premine_raw: None,
            terms_raw: None,
            block_hash: None,
            txid: None,
            block_time: None,
            runestone_found: false,
            op_return_spk_hex: None,
            runestone_payload_hex: None,
            pushes_concat_hex: None,
            varints: Vec::new(),
            error: None,
        };

        // Fetch rune page
        let page_resp = http.get(&page_url).send();
        let page_html = match page_resp.and_then(|r| r.error_for_status()) {
            Ok(resp) => resp.text().unwrap_or_default(),
            Err(e) => {
                rec.error = Some(format!("fetch_page_error: {}", e));
                serde_json::to_writer(&mut out, &rec)?;
                out.write_all(b"\n")?;
                continue;
            }
        };

        let (id_block, id_tx_index, divisibility, symbol, premine_raw, terms_raw) =
            parse_rune_page(&name, &page_html);
        rec.id_block = id_block;
        rec.id_tx_index = id_tx_index;
        rec.divisibility = divisibility;
        rec.symbol = symbol;
        rec.premine_raw = premine_raw;
        rec.terms_raw = terms_raw;

        // Resolve block and tx
        if let (Some(h), Some(tx_i)) = (rec.id_block, rec.id_tx_index) {
            // RPC: get block hash and block (verbosity=2 akin via typed API)
            match rpc.get_block_hash(h as u64) {
                Ok(bhash) => {
                    rec.block_hash = Some(bhash.to_string());
                    match rpc.get_block(&bhash) {
                        Ok(block) => {
                            rec.block_time = Some(block.header.time);
                            if (tx_i as usize) < block.txdata.len() {
                                let tx = &block.txdata[tx_i];
                                rec.txid = Some(tx.txid().to_string());
                                // Find OP_RETURN/OP_13 runestone output
                                let mut found = false;
                                for outp in &tx.output {
                                    let b = outp.script_pubkey.as_bytes();
                                    if b.is_empty() {
                                        continue;
                                    }
                                    if b[0] != bitcoin::opcodes::all::OP_RETURN.to_u8() {
                                        continue;
                                    }
                                    // Minimal tail: OP_RETURN (0x6a), then expect OP_13 (0x8d) or some push first
                                    // The spec says "OP_RETURN, followed by OP_13, followed by pushes".
                                    // We check b[1] == OP_PUSHNUM_13
                                    if b.len() >= 2
                                        && b[1] == bitcoin::opcodes::all::OP_PUSHNUM_13.to_u8()
                                    {
                                        rec.runestone_found = true;
                                        rec.op_return_spk_hex = Some(hex(b));
                                        let payload = &b[1..]; // include OP_13 in payload
                                        rec.runestone_payload_hex = Some(hex(payload));
                                        if let Some(concat) = runestone_concat_pushes(payload) {
                                            rec.pushes_concat_hex = Some(hex(&concat));
                                            let ints = decode_varints128(&concat);
                                            rec.varints =
                                                ints.iter().map(|v| v.to_string()).collect();
                                        }
                                        found = true;
                                        break;
                                    }
                                }
                                if !found {
                                    // No runestone found in OP_RETURNs
                                    rec.runestone_found = false;
                                }
                            } else {
                                rec.error = Some(format!(
                                    "tx_index_out_of_bounds: tx_i={} len={}",
                                    tx_i,
                                    block.txdata.len()
                                ));
                            }
                        }
                        Err(e) => {
                            rec.error = Some(format!("get_block_error: {}", e));
                        }
                    }
                }
                Err(e) => {
                    rec.error = Some(format!("get_block_hash_error: {}", e));
                }
            }
        } else {
            rec.error = Some("missing_id_block_or_tx_index_from_page".to_string());
        }

        serde_json::to_writer(&mut out, &rec)?;
        out.write_all(b"\n")?;
        out.flush()?;
    }

    // Also probe arbitrary txids if provided
    let txids = parse_txids_from_args(&opts)?;
    for txid_hex in txids {
        let mut rec = RuneCorpusRecord {
            name: String::new(),
            page_url: String::new(),
            id_block: None,
            id_tx_index: None,
            divisibility: None,
            symbol: None,
            premine_raw: None,
            terms_raw: None,
            block_hash: None,
            txid: Some(txid_hex.clone()),
            block_time: None,
            runestone_found: false,
            op_return_spk_hex: None,
            runestone_payload_hex: None,
            pushes_concat_hex: None,
            varints: Vec::new(),
            error: None,
        };

        let txid_parsed = match bitcoin::Txid::from_str(&txid_hex) {
            Ok(t) => t,
            Err(e) => {
                rec.error = Some(format!("invalid_txid: {}", e));
                serde_json::to_writer(&mut out, &rec)?;
                out.write_all(b"\n")?;
                continue;
            }
        };

        // Get tx info to fetch block hash and block time when possible (requires txindex)
        match rpc.get_raw_transaction_info(&txid_parsed, None) {
            Ok(info) => {
                rec.block_hash = info.blockhash.map(|h| h.to_string());
                rec.block_time = info.blocktime.map(|t| t as u32);
            }
            Err(e) => {
                rec.error = Some(format!("get_raw_transaction_info_error: {}", e));
            }
        }

        // Fetch raw tx for OP_RETURN parsing
        match rpc.get_raw_transaction(&txid_parsed, None) {
            Ok(tx) => {
                let mut found = false;
                for outp in &tx.output {
                    let b = outp.script_pubkey.as_bytes();
                    if b.is_empty() {
                        continue;
                    }
                    if b[0] != bitcoin::opcodes::all::OP_RETURN.to_u8() {
                        continue;
                    }
                    if b.len() >= 2 && b[1] == bitcoin::opcodes::all::OP_PUSHNUM_13.to_u8() {
                        rec.runestone_found = true;
                        rec.op_return_spk_hex = Some(hex(b));
                        let payload = &b[1..]; // include OP_13 in payload we store
                        rec.runestone_payload_hex = Some(hex(payload));
                        if let Some(concat) = runestone_concat_pushes(payload) {
                            rec.pushes_concat_hex = Some(hex(&concat));
                            let ints = decode_varints128(&concat);
                            rec.varints = ints.iter().map(|v| v.to_string()).collect();
                        }
                        found = true;
                        break;
                    }
                }
                if !found {
                    rec.runestone_found = false;
                }
            }
            Err(e) => {
                rec.error = Some(format!("get_raw_transaction_error: {}", e));
            }
        }

        serde_json::to_writer(&mut out, &rec)?;
        out.write_all(b"\n")?;
        out.flush()?;
    }

    Ok(())
}

