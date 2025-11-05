-- fresh/base schema: a schema we populate an empty db with

-- **Important**:
-- * all columns sorted by size to minimize padding (https://stackoverflow.com/questions/2966524/calculating-and-saving-space-in-postgresql/7431468#7431468)
-- signgle record table to keep persistent indexer state

-- indexer_state
CREATE TABLE IF NOT EXISTS indexer_state (
  bulk_mode BOOLEAN NOT NULL
);

-- events: append only
-- you can follow them one by one,
-- to follow blockchain state
-- canceling protocol is used
-- https://github.com/dpc/rust-bitcoin-indexer/wiki/How-to-interact-with-a-blockchain#canceling-protocol
CREATE TABLE IF NOT EXISTS event (
  indexed_ts TIMESTAMP NOT NULL DEFAULT (timezone('utc', now())),
  id BIGSERIAL NOT NULL UNIQUE PRIMARY KEY,
  revert BOOLEAN NOT NULL DEFAULT FALSE,
  block_hash_id BYTEA NOT NULL
);
CREATE INDEX IF NOT EXISTS event_indexed_ts ON event USING brin (indexed_ts);
CREATE INDEX IF NOT EXISTS event_block_hash_id ON event (block_hash_id);

-- blocks: insert only
CREATE TABLE IF NOT EXISTS block (
  time BIGINT NOT NULL, -- time from the block itself
  height INT NOT NULL,
  extinct BOOLEAN NOT NULL DEFAULT FALSE, -- this is the only mutable column in this table
  hash_id BYTEA NOT NULL UNIQUE PRIMARY KEY, -- the hash is split in two to save when referencing in other columns
  hash_rest BYTEA NOT NULL,
  prev_hash_id BYTEA NOT NULL,
  merkle_root BYTEA NOT NULL
);

-- We always want these two, as a lot of logic is based
-- on `block` table, and it's the smallest table overall,
-- so it doesn't matter that much (perforamnce wise)
CREATE INDEX IF NOT EXISTS block_height ON block USING brin (height);
-- would be nice if this was `USING brin`, but it can't do `UNIQUE` :/
CREATE UNIQUE INDEX  IF NOT EXISTS block_height_for_not_extinct ON block (height) WHERE extinct = false;
CREATE INDEX IF NOT EXISTS block_extinct ON block (extinct) WHERE extinct = true;


-- block -> tx: insert only
-- mapping between blocks and txes they include
CREATE TABLE IF NOT EXISTS block_tx (
  block_hash_id BYTEA NOT NULL,
  tx_hash_id BYTEA NOT NULL
);

-- txs: insert only
CREATE TABLE IF NOT EXISTS tx (
  mempool_ts TIMESTAMP DEFAULT NULL, -- NULL if it was indexed from an indexed block
  fee BIGINT NOT NULL,
  locktime BIGINT NOT NULL,
  current_height INT, -- Warning: mutable! But useful enough to keep it: especialy useful for mempool queries
  weight INT NOT NULL,
  coinbase BOOLEAN NOT NULL,
  hash_id BYTEA NOT NULL,
  hash_rest BYTEA NOT NULL
);

-- outputs: insert only
CREATE TABLE IF NOT EXISTS output (
  value BIGINT NOT NULL,
  tx_idx INT NOT NULL,
  tx_hash_id BYTEA NOT NULL,
  address TEXT
);

-- input: insert only
CREATE TABLE IF NOT EXISTS input (
  output_tx_idx INT NOT NULL,
  has_witness BOOLEAN NOT NULL,
  output_tx_hash_id BYTEA NOT NULL, -- output id this tx input spends
  tx_hash_id BYTEA NOT NULL -- tx id this input is from
);

-- script: deduplicated revealed scripts (append-only)
CREATE TABLE IF NOT EXISTS script (
  id BYTEA NOT NULL UNIQUE PRIMARY KEY,
  script_hex TEXT NOT NULL,
  size INT NOT NULL,
  summary TEXT
);

-- output_meta: per-output classification per originating block (append-only)
CREATE TABLE IF NOT EXISTS output_meta (
  block_hash_id BYTEA NOT NULL,
  tx_hash_id BYTEA NOT NULL,
  tx_idx INT NOT NULL,
  spk_type TEXT NOT NULL,
  witness_version SMALLINT,
  witness_program_len SMALLINT,
  is_taproot BOOLEAN,
  taproot_xonly_pubkey BYTEA,
  op_return_payload BYTEA,
  PRIMARY KEY (block_hash_id, tx_hash_id, tx_idx)
);

-- input_reveals: spend-time script details (append-only)
CREATE TABLE IF NOT EXISTS input_reveals (
  block_hash_id BYTEA NOT NULL,
  tx_hash_id BYTEA NOT NULL,
  input_idx INT NOT NULL,
  output_tx_hash_id BYTEA,
  output_tx_idx INT,
  redeem_script_id BYTEA,
  witness_script_id BYTEA,
  taproot_leaf_script_id BYTEA,
  taproot_control_block BYTEA,
  annex_present BOOLEAN,
  sighash_flags INT,
  is_taproot_key_spend BOOLEAN,
  schnorr_sig_count INT,
  PRIMARY KEY (block_hash_id, tx_hash_id, input_idx)
);

-- script_features: derived opcode/policy features keyed by script (append-only)
CREATE TABLE IF NOT EXISTS script_features (
  script_id BYTEA NOT NULL UNIQUE PRIMARY KEY,
  has_cltv BOOLEAN,
  has_csv BOOLEAN,
  multisig_m SMALLINT,
  multisig_n SMALLINT,
  miniscript TEXT,
  CONSTRAINT fk_script_features_script_id FOREIGN KEY (script_id)
    REFERENCES script(id)
    ON DELETE CASCADE
    DEFERRABLE INITIALLY DEFERRED
);

-- inscriptions derived from taproot script-path reveals (append-only)
CREATE TABLE IF NOT EXISTS inscription (
  block_hash_id BYTEA NOT NULL,
  tx_hash_id BYTEA NOT NULL,
  input_idx INT NOT NULL,
  inscription_idx INT NOT NULL,
  taproot_leaf_script_id BYTEA,
  content_type TEXT,
  body_sha256 BYTEA,
  body_size INT NOT NULL,
  parser_version SMALLINT,
  PRIMARY KEY (block_hash_id, tx_hash_id, input_idx, inscription_idx)
);

-- brc-20 events derived from inscription bodies (append-only)
CREATE TABLE IF NOT EXISTS brc20_event (
  block_hash_id BYTEA NOT NULL,
  tx_hash_id BYTEA NOT NULL,
  input_idx INT NOT NULL,
  inscription_idx INT NOT NULL,
  op TEXT NOT NULL,
  tick TEXT NOT NULL,
  decimals SMALLINT,
  amount_raw TEXT,
  limit_raw TEXT,
  max_supply_raw TEXT,
  json JSONB,
  PRIMARY KEY (block_hash_id, tx_hash_id, input_idx, inscription_idx)
);

-- runes events derived from OP_RETURN payloads (append-only)
CREATE TABLE IF NOT EXISTS runes_event (
  block_hash_id BYTEA NOT NULL,
  tx_hash_id BYTEA NOT NULL,
  tx_idx INT NOT NULL,      -- OP_RETURN output index
  kind TEXT NOT NULL,       -- 'etching' | 'edict'
  seq INT NOT NULL,         -- ordinal within payload
  rune_name TEXT,
  rune_id TEXT,
  to_vout INT,
  amount_raw TEXT,
  divisibility SMALLINT,
  symbol TEXT,
  terms JSONB,
  pointer INT,
  raw BYTEA NOT NULL,
  PRIMARY KEY (block_hash_id, tx_hash_id, tx_idx, kind, seq)
);
