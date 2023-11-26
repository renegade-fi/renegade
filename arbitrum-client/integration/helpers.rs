//! Helper functions for Arbitrum client integration tests

use eyre::{eyre, Result};
use std::{fs::File, io::Read};

use crate::constants::DEPLOYMENTS_KEY;

/// Parse a `deployments.json` file to get the address of a deployed contract
pub fn parse_addr_from_deployments_file(file_path: &str, contract_key: &str) -> Result<String> {
    let mut file_contents = String::new();
    File::open(file_path)?.read_to_string(&mut file_contents)?;

    let parsed_json = json::parse(&file_contents)?;
    parsed_json[DEPLOYMENTS_KEY][contract_key]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| eyre!("Could not parse darkpool address from deployments file"))
}
