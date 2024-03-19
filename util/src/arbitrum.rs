//! Utils relating to Starknet interaction

use std::{fs::File, io::Read, sync::OnceLock};

use circuit_types::{elgamal::EncryptionKey, fixed_point::FixedPoint};
use eyre::{eyre, Result};

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
/// The protocol fee that the contract charges on a match
pub static PROTOCOL_FEE: OnceLock<FixedPoint> = OnceLock::new();
/// The protocol's public encryption key used for paying fees
pub static PROTOCOL_PUBKEY: OnceLock<EncryptionKey> = OnceLock::new();

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

/// Get the protocol fee from the static variable
///
/// Panics if the protocol fee has not been set
pub fn get_protocol_fee() -> FixedPoint {
    let fee = PROTOCOL_FEE.get();

    // If the mocks feature is enabled we unwrap to a default
    #[cfg(feature = "mocks")]
    {
        *fee.unwrap_or(&FixedPoint::from_f64_round_down(0.0006)) // 6 bps
    }

    #[cfg(not(feature = "mocks"))]
    {
        *fee.expect("Protocol fee not set")
    }
}

/// Get the protocol encryption key from the static variable
///
/// Panics if the protocol encryption key has not been set
pub fn get_protocol_pubkey() -> EncryptionKey {
    // If the mocks feature is enabled we unwrap to a default
    #[cfg(feature = "mocks")]
    {
        use circuit_types::elgamal::DecryptionKey;
        use rand::thread_rng;

        let mut rng = thread_rng();
        *PROTOCOL_PUBKEY.get_or_init(|| DecryptionKey::random(&mut rng).public_key())
    }

    #[cfg(not(feature = "mocks"))]
    {
        *PROTOCOL_PUBKEY.get().expect("Protocol pubkey has not been set")
    }
}
