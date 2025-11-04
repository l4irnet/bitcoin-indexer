#![allow(unused)] // need some cleanup

use bitcoin_indexer::{
    db, node::prefetcher, opts, prelude::*, types::*, util::BottleCheck, RpcInfo,
};
use bitcoincore_rpc::RpcApi;
use log::{error, info};
use std::{env, sync::Arc};

use common_failures::prelude::*;

struct Indexer {
    node_starting_chainhead_height: BlockHeight,
    rpc: Arc<bitcoincore_rpc::Client>,
    db: Box<dyn db::IndexerStore>,
    bottlecheck_db: BottleCheck,
}

impl Indexer {
    fn new(config: Config) -> Result<Self> {
        let rpc_info = bitcoin_indexer::RpcInfo::from_url(&config.node_url)?;
        let rpc = rpc_info.to_rpc_client()?;
        let rpc = Arc::new(rpc);
        let node_starting_chainhead_height = rpc.get_block_count()? as BlockHeight;
        let network = match rpc.get_blockchain_info()?.chain {
            bitcoincore_rpc::bitcoin::Network::Bitcoin => bitcoin::Network::Bitcoin,
            bitcoincore_rpc::bitcoin::Network::Testnet => bitcoin::Network::Testnet,
            bitcoincore_rpc::bitcoin::Network::Regtest => bitcoin::Network::Regtest,
            bitcoincore_rpc::bitcoin::Network::Signet => bitcoin::Network::Signet,
            bitcoincore_rpc::bitcoin::Network::Testnet4 => bitcoin::Network::Testnet,
        };
        let mut db =
            db::pg::IndexerStore::new(config.db_url, node_starting_chainhead_height, network)?;
        info!("Node chain-head at {}H", node_starting_chainhead_height);

        Ok(Self {
            rpc,
            node_starting_chainhead_height,
            db: Box::new(db),
            bottlecheck_db: BottleCheck::new("database".into()),
        })
    }

    fn process_block(&mut self, block: BlockData) -> Result<()> {
        let block_height = block.height;
        if block_height >= self.node_starting_chainhead_height || block_height % 1000 == 0 {
            info!("Block {}H: {}", block.height, block.id);
        }

        let Self {
            ref mut db,
            ref mut bottlecheck_db,
            ..
        } = self;

        bottlecheck_db.check(|| db.insert(block))?;
        Ok(())
    }

    fn run(&mut self) -> Result<()> {
        let start: Option<WithHeightAndId<BlockHash, _>> =
            if let Some(last_indexed_height) = self.db.get_head_height()? {
                info!("Last indexed block {}H", last_indexed_height);

                assert!(last_indexed_height <= self.node_starting_chainhead_height);
                let rewind: u32 = env::var("INDEXER_REWIND")
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(100);
                let start_from_block = last_indexed_height.saturating_sub(rewind); // configurable rewind
                let start_hash = self
                    .db
                    .get_hash_by_height(start_from_block)?
                    .expect("Block hash should be there");
                info!(
                    "Resuming with rewind={}, starting at {}H (hash={})",
                    rewind, start_from_block, start_hash
                );
                Some(WithHeightAndId {
                    height: start_from_block,
                    id: start_hash,
                    data: (),
                })
            } else {
                None
            };

        let prefetcher = prefetcher::Prefetcher::new(self.rpc.clone(), start)?;
        let mut bottlecheck_fetcher = BottleCheck::new("block fetcher".into());
        for item in bottlecheck_fetcher.check_iter(prefetcher) {
            self.process_block(item)?;
        }

        Ok(())
    }
}

struct Config {
    db_url: String,
    node_url: String,
}

impl Config {
    fn from_env() -> Result<Self> {
        Ok(Self {
            db_url: env::var("DATABASE_URL")?,
            node_url: env::var("NODE_RPC_URL")?,
        })
    }
}

fn run() -> Result<()> {
    dotenv::dotenv()?;

    let config = Config::from_env()?;

    let opts: opts::Opts = structopt::StructOpt::from_args();

    if opts.wipe_db {
        db::pg::IndexerStore::wipe(&env::var("DATABASE_URL")?)?;
        return Ok(());
    }

    let mut indexer = Indexer::new(config)?;
    indexer.run()?;

    Ok(())
}

fn main() {
    // Best-effort initialize logger so top-level errors are visible even if run() fails early.
    let _ = env_logger::try_init();
    if let Err(e) = run() {
        error!("Fatal: {}", e.display_causes_and_backtrace());
        std::process::exit(1);
    }
}
