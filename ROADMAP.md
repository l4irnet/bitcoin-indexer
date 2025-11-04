# Roadmap: Upgrade `bitcoin` crate and extend script indexing

Status summary (Nov 2025)
- Stage 1 — bitcoincore-rpc 0.19.x: DONE
- Stage 2 — bitcoin 0.32.x (compat mode): IN PROGRESS (next)
- Stage 3 — Script parsing utilities: PARTIAL (finish after Stage 2)
- Stage 4 — Schema scaffolding (append-only): DONE
- Stage 5 — Output classification write path: DONE
- Stage 6 — Script registry population: DONE
- Stage 7 — Witness/redeem/taproot extraction (incl. annex, control block, sighash flags): DONE
- Stage 8 — Taproot key/script-spend + schnorr details: PARTIAL (add explicit flags/fields)
- Stage 9 — Opcode/policy analytics (script_features population): PENDING
- Stage 10 — Views/indices (normal mode): DONE
- Stage 11 — Backfill tool: PENDING
- Stage 12 — Cleanup/hardening: IN PROGRESS (better logging, robust shutdown, configurable flush)

Immediate next steps (Stage 2: bitcoin 0.32.x upgrade)
- Build and compile
  - Update Cargo dependency to bitcoin = "0.32.x"
  - Adapt APIs:
    - Transaction: use compute_txid(); is_coinbase() (new spelling)
    - Script types: switch to bitcoin::Script and bitcoin::ScriptBuf
    - Address: Address::from_script(script, network) and addr.payload()
    - Hash types: use associated Hash types from bitcoin_hashes (no as_hash/as_inner/into_inner)
    - Amount/value: ensure correct integer types; avoid adding Amount to integers; convert explicitly
    - Script parsing: iterate via script.instructions(); PushBytes in bitcoin::script::Instruction
- Re-test and fix classification/extraction
  - Output classification via Address::from_script; record witness version/program length; P2TR x-only program
  - OP_RETURN parsing via script opcodes (keep heuristic lightweight)
  - input_reveals: redeemScript (P2SH), witness/taproot leaf, control block, annex detection
  - Sighash flags: keep robust DER+flag parser
- Migration hygiene
  - Keep all new writes append-only with ON CONFLICT DO NOTHING
  - Maintain current bulk/normal mode behavior (no new FKs in bulk)
  - Verify resume after crash (INDEXER_REWIND configurable)
- Validation
  - Run end-to-end indexing over a small range; sanity-check views and counts
  - Diff baseline vs new DB using the compare script/query approach

Follow-ups after Stage 2
- Stage 3: finalize script parsing helpers (typed, unit-tested) on 0.32.x
- Stage 8: add explicit fields for taproot key-vs-script spend in input_reveals (e.g., is_taproot_key_spend)
- Stage 9: populate script_features (has_cltv, has_csv, multisig m/n, optional miniscript string)
- Stage 11: add a resumable backfill CLI to populate output_meta/input_reveals/script_features for historical ranges

Operational toggles (current)
- INDEXER_REWIND: blocks to rewind on resume (default 100; set 0 for exact resume)
- INDEXER_BULK_FLUSH_TXS: tx threshold per DB flush in bulk mode (default 100000)
- INDEXER_BULK_FLUSH_BLOCKS: block threshold per DB flush in bulk mode (default 100)
- PGSSL* envs for mTLS: PGSSLROOTCERT, PGSSLCERT, PGSSLKEY
- (Optional) INDEXER_SELF_TEST=1 to run mode flip self-test (disabled by default)

Notes on safety/performance
- All new tables (script, output_meta, input_reveals, script_features) are append-only; normal mode adds FKs/indices; bulk mode avoids them
- Inserts to new tables always use ON CONFLICT DO NOTHING to remain idempotent
- Coinbase inputs are skipped for input_reveals; vout overflow is guarded
- Writer pipeline is robust to channel/worker failures; errors are logged with SQLSTATE/code/detail; exponential PG connect backoff reduces startup storms


This document outlines a staged, incremental plan to:
1) Upgrade the `bitcoin` crate from v0.28 to v0.32.x, and
2) Expand our indexing capabilities (script classification, witness/redeem/taproot details, and opcode/policy features),

while ensuring the codebase builds cleanly and runs at each stage. Each stage is designed to be an atomic, reviewable PR.

---

## Guiding principles

- Always keep the tree buildable and runnable after every PR.
- Prefer new append-only tables and derived views. Avoid adding mutable columns or updating existing rows; do not compromise reorg atomicity.
- DB migrations must be:
  - Idempotent (`IF NOT EXISTS` / `IF EXISTS`)
  - Forward-only (no destructive drops in the middle of the sequence)
  - Safe under current “bulk” and “normal” schema modes
- Preserve indexer semantics (atomic reorg handling, append-only event stream).
- Gate new indexing behind feature toggles until stable (e.g., `INDEX_SCRIPTS=1` or compile-time features) if helpful.
- Include benchmarks or sanity metrics where practical.

---

## Stage 0 — Preparation and guardrails

Goal:
- Ensure we can toggle new code paths off/on without affecting the existing pipeline.

Actions:
- Add a minimal feature flag or environment toggle scaffolding for future stages (e.g., `INDEX_SCRIPTS`, `INDEX_TAPROOT`, `INDEX_WITNESS_DETAILS`).
- Document how to enable new features in the README and `.env.example`.

Build and runtime criteria:
- No functional changes yet; main paths are unaffected.

---

## Stage 1 — Upgrade `bitcoincore-rpc` to v0.19.x and adapt types

Goal:
- Align RPC client with modern Core (v29.x) response shapes.

Actions:
- Upgrade `bitcoincore-rpc` to `0.19.x`.
- Where necessary, bridge between `bitcoincore-rpc::bitcoin` types and local `bitcoin` crate types (string/hex conversions where unavoidable).
- Handle `Network::Testnet4` and other new variants with a sensible mapping.

Build and runtime criteria:
- Build clean.
- Full sync and resumption from interrupt works.
- No schema changes.

Rollback plan:
- Revert to previous rpc version if regressions appear.

---

## Stage 2 — Upgrade `bitcoin` crate to v0.32.x (compat mode)

Goal:
- Upgrade dependency while minimizing code churn.

Actions:
- Bump `bitcoin = "0.32.x"`.
- Address API changes:
  - `Script`/`ScriptBuf` adjustments
  - Instruction iterators (`instructions()` / `Instructions`)
  - Any moved/renamed types
- Keep behavior equivalent; do not add new indexing yet.

Build and runtime criteria:
- Build clean.
- Existing indexing unaffected (same data written).

Risk/risk mitigation:
- If large refactors are needed, break into small PRs touching isolated areas (e.g., script parsing helpers, tx handling).

---

## Stage 3 — Introduce script parsing utilities (no DB writes yet)

Goal:
- Centralize and standardize script parsing using `bitcoin` 0.32’s (de)serialization and instruction iteration.

Actions:
- Add a small module providing:
  - Output script classification: P2PK, P2PKH, P2SH, P2WPKH, P2WSH, P2TR, bare multisig, OP_RETURN, nonstandard.
  - Helpers to extract:
    - Witness program version/length
    - Taproot x-only pubkey (from scriptPubKey)
    - OP_RETURN payload
- Unit tests covering main script families.

Build and runtime criteria:
- Build clean.
- No DB changes; new code unused or behind a flag.

---

## Stage 4 — Schema scaffolding for extended indexing (additive)

Goal:
- Add schema to support new data without impacting current ingestion.

Proposed schema additions (append-only, reorg-safe via joins on non-extinct blocks):
- New `script` table (deduplicated scripts, append-only):
  - `id BYTEA PRIMARY KEY` (hash of script body; e.g., sha256 or hash of raw script bytes)
  - `script_hex TEXT NOT NULL`
  - `size INT NOT NULL`
  - Optional: `summary TEXT NULL` (future; e.g., Miniscript or derived template signature)
- New `output_meta` table (append-only; one row per output per originating block):
  - `block_hash_id BYTEA NOT NULL`
  - `tx_hash_id BYTEA NOT NULL`
  - `tx_idx INT NOT NULL`
  - `spk_type TEXT NOT NULL`
  - `witness_version SMALLINT NULL`
  - `witness_program_len SMALLINT NULL`
  - `is_taproot BOOLEAN NULL`
  - `taproot_xonly_pubkey BYTEA NULL`
  - `op_return_payload BYTEA NULL`
  - PRIMARY KEY (`block_hash_id`, `tx_hash_id`, `tx_idx`)
- New `input_reveals` table (append-only; details revealed at spend time):
  - `block_hash_id BYTEA NOT NULL`
  - `tx_hash_id BYTEA NOT NULL`
  - `input_idx INT NOT NULL`
  - `redeem_script_id BYTEA NULL`
  - `witness_script_id BYTEA NULL`
  - `taproot_leaf_script_id BYTEA NULL`
  - `taproot_control_block BYTEA NULL`
  - `annex_present BOOLEAN NULL`
  - `sighash_flags INT NULL`
  - PRIMARY KEY (`block_hash_id`, `tx_hash_id`, `input_idx`)
- Supporting indices (e.g., by `spk_type`, `taproot_xonly_pubkey`) should be created in “normal” mode only to keep bulk mode fast.

Actions:
- Add idempotent DDL in `src/db/pg/*.sql`. Ensure compatibility with both bulk and normal modes.
- No data population yet.

Build and runtime criteria:
- Build clean.
- DB migrations apply without touching existing flows.

---

## Stage 5 — Output classification write path (outputs only)

Goal:
- Populate output-level classification during indexing in a safe, incremental way.

Actions:
- Behind a feature flag, insert one row per output into the append-only `output_meta` table:
  - Populate `spk_type`, `witness_version`, `witness_program_len`, `is_taproot`, `taproot_xonly_pubkey`, `op_return_payload` (if applicable).
  - Use a batched INSERT with `ON CONFLICT DO NOTHING` on (`block_hash_id`, `tx_hash_id`, `tx_idx`) for idempotence and reorg safety.
- Ensure multi-row inserts still batch efficiently (separate batched statement).
- Add lightweight counters/logging to verify coverage.

Build and runtime criteria:
- Build clean.
- When flag enabled, new fields are populated; otherwise no change.
- No performance regression beyond acceptable range.

Rollback:
- Disable the flag to revert behavior.

---

## Stage 6 — Deduplicated script registry population (revealed scripts)

Goal:
- Capture scripts revealed at spend time (redeem/witness/taproot leaf scripts).

Actions:
- When a spend reveals a script:
  - Compute `id` (hash) of the revealed script.
  - Insert into `script` table (`INSERT ... ON CONFLICT DO NOTHING`).
  - Insert a row into `input_reveals` keyed by (`block_hash_id`, `tx_hash_id`, `input_idx`) referencing the revealed `script.id` where applicable.
- Do not mutate existing `input` rows; use joins through `input_reveals` (and `block.extinct = false`) for reorg-safe queries.

Build and runtime criteria:
- Build clean.
- Normal reorg semantics preserved (all under transactional inserts).
- No unique constraint contention; use `ON CONFLICT DO NOTHING`.

---

## Stage 7 — Witness and redeem script extraction (spend path)

Goal:
- Decode scriptSig and witness stacks; persist revealed scripts and relevant flags.

Actions:
- For P2SH: extract redeemScript from scriptSig; insert into `script` (dedup) and reference via `input_reveals.redeem_script_id`.
- For P2WSH: extract witnessScript; insert into `script` and reference via `input_reveals.witness_script_id`.
- For Taproot script-path:
  - Extract leaf script and control block; insert leaf into `script` and reference via `input_reveals.taproot_leaf_script_id`; store `taproot_control_block` raw bytes in `input_reveals`.
  - Detect `annex_present` and record it in `input_reveals`.
- Save revealed scripts into `script` registry, using `ON CONFLICT DO NOTHING`.

Build and runtime criteria:
- Build clean.
- Feature-flagged; can be toggled off.
- Add unit tests for representative spend paths.

---

## Stage 8 — Taproot key/script spend classification and schnorr details

Goal:
- Distinguish Taproot key spending vs script-path spending; capture schnorr-related metadata.

Actions:
- For P2TR inputs, detect key-spend vs script-path.
- Optionally store:
  - Count of signatures (schnorr sigs) observed
  - Sighash flags (if present in stack)
- Ensure stored fields are optional and additive.

Build and runtime criteria:
- Build clean.
- No impact when disabled.

---

## Stage 9 — Opcode-/policy-level analytics (optional)

Goal:
- Persist parsed instruction summaries to enable rich queries.

Actions:
- Introduce an optional `script_features` append-only table keyed by `script.id` for instruction summaries and normalized templates (raw JSON or compact form).
- For spend-revealed scripts, parse opcodes (CLTV/CSV, CHECKMULTISIG/M, etc.) and store:
  - `has_cltv`, `has_csv`, `multisig_m`, `multisig_n`, etc. in `script_features`.
- Consider using the `miniscript` crate (future work) to produce a safe policy descriptor; store as text when feature-enabled.

Build and runtime criteria:
- Build clean.
- Behind a feature flag due to potential performance overhead.

---

## Stage 10 — Views and indices for analytics

Goal:
- Make exploration easy via stable views and selective indices.

Actions:
- Create views for:
  - “tx with decoded script details”
  - “taproot spends” and “taproot outputs”
  - “multisig spends”, “timelocked outputs”
  - “op_return payloads”
- Add selective indices (e.g., `spk_type`, `is_taproot`, `script_hash`) in normal mode to support common queries.

Build and runtime criteria:
- Build clean.
- Views/indices created idempotently.

---

## Stage 11 — Backfill strategy (optional)

Goal:
- Fill new columns for already-indexed data.

Actions:
- Introduce a backfill task that:
  - Scans outputs/inputs in batches.
  - Populates classification columns and script registry.
  - Is resumable and can be throttled.
- Keep backfill behind a separate CLI flag to avoid accidental heavy workloads.

Build and runtime criteria:
- Build clean.
- Backfill tested on a subset before full run.

---

## Stage 12 — Cleanup and hardening

Goal:
- Stabilize, remove temporary toggles where appropriate, and document.

Actions:
- Promote certain features to always-on if performance and correctness are confirmed.
- Add integration tests covering:
  - Legacy, segwit, taproot outputs/spends
  - Reorg scenario involving script-path spends
- Update README and `.env.example` with new features and guidance.

Build and runtime criteria:
- Build clean.
- Documented end state.

---

## Acceptance criteria and metrics

- Builds cleanly at each stage on supported toolchains.
- Indexer remains interrupt-resilient and reorg-atomic.
- Bulk mode performance within acceptable deltas (measure end-to-end indexing rate).
- New indexing fields populated correctly in sample validation queries.
- Toggleable features default to off until confidence is high.

---

## PR sequencing (suggested)

1. Stage 0 — Prep: flags/toggles scaffolding
2. Stage 1 — `bitcoincore-rpc` bump + type bridges
3. Stage 2 — `bitcoin` bump + API adjustments
4. Stage 3 — Script parsing utilities + tests
5. Stage 4 — Schema scaffolding (DDL only)
6. Stage 5 — Output classification write path (flagged)
7. Stage 6 — Script registry ingestion (flagged)
8. Stage 7 — Redeem/witness/taproot spend extraction (flagged)
9. Stage 8 — Taproot key/script spend + schnorr details (flagged)
10. Stage 9 — Opcode/policy analytics (flagged)
11. Stage 10 — Views/indices (normal mode only)
12. Stage 11 — Backfill task (optional)
13. Stage 12 — Cleanup/hardening + docs

Each PR: keep diffs focused, add tests where feasible, include brief performance notes if relevant.

---

## Notes

- Be mindful of how additions interact with “bulk” vs “normal” modes. Avoid building heavy indices in bulk mode; prefer normal mode for analytical indices.
- Prefer new append-only tables over modifying existing tables; avoid introducing new mutable columns.
- For large backfills, consider maintenance windows and PG resource tuning.

End of roadmap.