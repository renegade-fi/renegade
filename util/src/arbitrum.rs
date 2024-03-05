//! Utils relating to Starknet interaction

use std::{fs::File, io::Read};

use circuit_types::elgamal::EncryptionKey;
use constants::PROTOCOL_ENCRYPTION_KEY;
use eyre::{eyre, Result};

use crate::hex::jubjub_from_hex_string;

/// The deployments key in the `deployments.json` file
pub const DEPLOYMENTS_KEY: &str = "deployments";
/// The darkpool proxy contract key in the `deployments.json` file
pub const DARKPOOL_PROXY_CONTRACT_KEY: &str = "darkpool_proxy_contract";
/// The first dummy erc20 contract key in a `deployments.json` file
pub const DUMMY_ERC20_0_CONTRACT_KEY: &str = "DUMMY1";
/// The second dummy erc20 contract key in a `deployments.json` file
pub const DUMMY_ERC20_1_CONTRACT_KEY: &str = "DUMMY2";
/// The permit2 contract key in a `deployments.json` file
pub const PERMIT2_CONTRACT_KEY: &str = "permit2_contract";

/// Parse the address of the deployed contract from the `deployments.json` file
pub fn parse_addr_from_deployments_file(file_path: &str, contract_key: &str) -> Result<String> {
    let mut file_contents = String::new();
    File::open(file_path)?.read_to_string(&mut file_contents)?;

    let parsed_json = json::parse(&file_contents)?;
    parsed_json[DEPLOYMENTS_KEY][contract_key]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| eyre!("Could not parse {contract_key} address from deployments file"))
}

/// Get a copy of the protocol's encryption key
pub fn get_protocol_encryption_key() -> EncryptionKey {
    jubjub_from_hex_string(PROTOCOL_ENCRYPTION_KEY)
        .expect("contract encryption key is not a valid jubjub point")
}
