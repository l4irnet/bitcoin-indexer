use bitcoin_indexer::{db, node::fetcher, prelude::*, util::reversed};
use itertools::Itertools;
use std::{borrow::Borrow, env, sync::Arc};

use common_failures::prelude::*;
use log::info;

fn run() -> Result<()> {
    // logger is initialized in main(); avoid double init
    dotenv::dotenv()?;
    let db_url = env::var("DATABASE_URL")?;
    let node_url = env::var("NODE_RPC_URL")?;

    let rpc_info = bitcoin_indexer::RpcInfo::from_url(&node_url)?;
    let mut db = db::pg::establish_connection(&db_url);
    db.execute(
        "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS merkle_root BYTEA",
        &[],
    )?;
    db.execute(
        "ALTER TABLE blocks ADD COLUMN IF NOT EXISTS time BIGINT",
        &[],
    )?;

    let rpc = rpc_info.to_rpc_client()?;
    let fetcher = fetcher::Fetcher::new(Arc::new(rpc), None, None)?;

    for batch in &fetcher.chunks(1000) {
        let mut transaction = db.transaction()?;
        for (i, item) in batch.enumerate() {
            if i == 0 {
                info!("Block {}H: {}", item.height, item.id);
            }
            transaction.execute(
                "UPDATE blocks SET time = $1, merkle_root = $2 WHERE hash = $3",
                &[
                    &(i64::from(item.data.header.time)),
                    &reversed(
                        {
                            let borrow: &[u8] = item.data.header.merkle_root.borrow();
                            borrow
                        }
                        .to_vec(),
                    ),
                    &reversed(
                        {
                            let borrow: &[u8] = item.id.borrow();
                            borrow
                        }
                        .to_vec(),
                    ),
                ],
            )?;
        }
        transaction.commit()?;
    }

    db.execute("ALTER TABLE blocks ALTER COLUMN time SET NOT NULL", &[])?;
    db.execute(
        "ALTER TABLE blocks ALTER COLUMN merkle_root SET NOT NULL",
        &[],
    )?;
    Ok(())
}

fn main() {
    // Best-effort initialize logger so top-level errors are visible even if run() fails early.
    let _ = env_logger::try_init();
    if let Err(e) = run() {
        log::error!("Fatal: {}", e.display_causes_and_backtrace());
        std::process::exit(1);
    }
}
