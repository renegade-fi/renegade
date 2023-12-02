//! Utils relating to Starknet interaction

use std::{fs::File, io::Read};

use eyre::{eyre, Result};

/// The deployments key in the `deployments.json` file
pub const DEPLOYMENTS_KEY: &str = "deployments";
/// The darkpool key in the `deployments.json` file
pub const DARKPOOL_KEY: &str = "darkpool";

/// Parse a `deployments.json` file to get the address of the darkpool contract
pub fn parse_addr_from_deployments_file(file_path: String) -> Result<String> {
    let mut file_contents = String::new();
    File::open(file_path)?.read_to_string(&mut file_contents)?;

    let parsed_json = json::parse(&file_contents)?;
    parsed_json[DEPLOYMENTS_KEY][DARKPOOL_KEY]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| eyre!("Could not parse darkpool address from deployments file"))
}
