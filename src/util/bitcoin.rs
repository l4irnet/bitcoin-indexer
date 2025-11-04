use crate::prelude::*;

pub fn address_from_script(
    script: &bitcoin::Script,
    network: bitcoin::Network,
) -> Option<bitcoin::Address> {
    bitcoin::Address::from_script(script, network).ok()
}

pub fn network_from_str(s: &str) -> Result<bitcoin::Network> {
    Ok(match s {
        "main" | "mainnet" | "bitcoin" => bitcoin::Network::Bitcoin,
        "test" | "testnet" | "testnet4" => bitcoin::Network::Testnet,
        "signet" => bitcoin::Network::Signet,
        "regtest" => bitcoin::Network::Regtest,
        _ => bail!("Unknown bitcoin chain {}", s),
    })
}
