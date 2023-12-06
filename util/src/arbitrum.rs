//! Utils relating to Starknet interaction

use std::{fs::File, io::Read};

use eyre::{eyre, Result};

/// The deployments key in the `deployments.json` file
pub const DEPLOYMENTS_KEY: &str = "deployments";
/// The darkpool key in the `deployments.json` file
pub const DARKPOOL_KEY: &str = "darkpool";
/// The darkpool proxy contract key in the `deployments.json` file
pub const DARKPOOL_PROXY_CONTRACT_KEY: &str = "darkpool_proxy_contract";

/// Parse the address of the deployed contract from the `deployments.json` file
pub fn parse_addr_from_deployments_file(file_path: &str, contract_key: &str) -> Result<String> {
    let mut file_contents = String::new();
    File::open(file_path)?.read_to_string(&mut file_contents)?;

    let parsed_json = json::parse(&file_contents)?;
    parsed_json[DEPLOYMENTS_KEY][contract_key]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| eyre!("Could not parse darkpool address from deployments file"))
}
