use clap::Parser;
use structopt::StructOpt;

#[derive(Debug, StructOpt, Parser, Clone)]
#[structopt(name = "indexer", about = "Bitcoin Indexer")]
#[command(name = "indexer", about = "Bitcoin Indexer")]
pub struct Opts {
    /// Path to .env file to load (overrides default .env in current directory)
    #[structopt(long = "env-file")]
    #[arg(long = "env-file", value_name = "PATH")]
    pub env_file: Option<String>,

    /// Drop schema/data using wipe.sql and exit
    #[structopt(long = "wipe-db")]
    #[arg(long = "wipe-db", alias = "wipe-whole-db")]
    pub wipe_db: bool,
}
