use bitcoin::consensus::encode::deserialize;
use bitcoin::hashes::hex::FromHex;
use bitcoin_indexer::{
    db::{self, MempoolStore},
    prelude::*,
    types::WithId,
};
use bitcoincore_rpc::RpcApi;
use log::trace;
use std::{collections::HashSet, env};

use common_failures::quick_main;

fn run() -> Result<()> {
    env_logger::init();
    dotenv::dotenv()?;
    let db_url = env::var("DATABASE_URL")?;
    let node_url = env::var("NODE_RPC_URL")?;

    let rpc_info = bitcoin_indexer::RpcInfo::from_url(&node_url)?;

    let rpc = rpc_info.to_rpc_client()?;
    let network = match rpc.get_blockchain_info()?.chain {
        bitcoincore_rpc::bitcoin::Network::Bitcoin => bitcoin::Network::Bitcoin,
        bitcoincore_rpc::bitcoin::Network::Testnet => bitcoin::Network::Testnet,
        bitcoincore_rpc::bitcoin::Network::Regtest => bitcoin::Network::Regtest,
        bitcoincore_rpc::bitcoin::Network::Signet => bitcoin::Network::Signet,
        bitcoincore_rpc::bitcoin::Network::Testnet4 => bitcoin::Network::Testnet,
    };
    trace!("Creating mempool store");
    let mut db = db::pg::MempoolStore::new(db_url, network)?;

    let mut done: HashSet<String> = HashSet::new();

    loop {
        // TODO: FIXME: Just use LRU instead
        let mut inserted = 0;
        let mut failed = 0;

        if done.len() > 500_000 {
            done.clear();
        }
        trace!("Checking mempool");
        for tx_id_rpc in rpc.get_raw_mempool()? {
            let txid_str = tx_id_rpc.to_string();
            if done.contains(&txid_str) {
                continue;
            }

            let tx: Option<bitcoin::Transaction> =
                match rpc.get_raw_transaction_hex(&tx_id_rpc, None) {
                    Ok(hex) => {
                        match hex::decode(hex)
                            .ok()
                            .and_then(|bytes| deserialize::<bitcoin::Transaction>(&bytes).ok())
                        {
                            Some(tx) => Some(tx),
                            None => None,
                        }
                    }
                    Err(_) => None,
                };

            trace!("Inserting mempool tx {}", txid_str);

            let tx_id_local = match bitcoin_indexer::Txid::from_hex(&txid_str) {
                Ok(t) => t,
                Err(_) => {
                    failed += 1;
                    continue;
                }
            };

            match db.insert(&WithId {
                id: tx_id_local,
                data: tx,
            }) {
                Err(e) => {
                    eprintln!("{}", e);
                    failed += 1;
                }
                Ok(()) => {
                    done.insert(txid_str);
                    inserted += 1;
                }
            }
        }
        eprintln!("Scanned mempool; success: {}; failed: {}", inserted, failed);
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
}

quick_main!(run);
