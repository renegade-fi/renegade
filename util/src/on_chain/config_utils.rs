//! Utils relating to Starknet interaction

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    sync::{OnceLock, RwLock},
};

use circuit_types::{Address, elgamal::EncryptionKey, fixed_point::FixedPoint};
use eyre::{Result, eyre};

use crate::concurrency::RwStatic;

/// The deployments key in the `deployments.json` file
pub const DEPLOYMENTS_KEY: &str = "deployments";
/// The ERC-20s sub-key in the `deployments.json` file
#[cfg(feature = "mocks")]
pub const ERC20S_KEY: &str = "erc20s";
/// The darkpool proxy contract key in the `deployments.json` file
pub const DARKPOOL_PROXY_CONTRACT_KEY: &str = "darkpool_proxy_contract";
/// The first dummy erc20 ticker
#[cfg(feature = "mocks")]
pub const DUMMY_ERC20_0_TICKER: &str = "DUMMY1";
/// The second dummy erc20 ticker
#[cfg(feature = "mocks")]
pub const DUMMY_ERC20_1_TICKER: &str = "DUMMY2";
/// The permit2 contract key in a `deployments.json` file
#[cfg(feature = "mocks")]
pub const PERMIT2_CONTRACT_KEY: &str = "permit2_contract";
/// The protocol fee that the contract charges on a match
static PROTOCOL_FEE: RwStatic<FixedPoint> = RwStatic::new(|| RwLock::new(FixedPoint::zero()));
/// The protocol fee overrides for an external match
///
/// Maps a mint to the fee override if one exists
pub static PROTOCOL_FEE_OVERRIDES: RwStatic<HashMap<Address, FixedPoint>> =
    RwStatic::new(|| RwLock::new(HashMap::new()));
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

/// Parse the address of an ERC-20 contract from the `deployments.json` file
#[cfg(feature = "mocks")]
pub fn parse_erc20_addr_from_deployments_file(file_path: &str, ticker: &str) -> Result<String> {
    let mut file_contents = String::new();
    File::open(file_path)?.read_to_string(&mut file_contents)?;

    let parsed_json = json::parse(&file_contents)?;
    parsed_json[DEPLOYMENTS_KEY][ERC20S_KEY][ticker]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| eyre!("Could not parse {ticker} address from deployments file"))
}

/// Get the protocol fee from the static variable
///
/// Panics if the protocol fee has not been set
pub fn get_protocol_fee() -> FixedPoint {
    #[cfg(feature = "mocks")]
    {
        FixedPoint::from_f64_round_down(0.0006) // 6 bps
    }

    #[cfg(not(feature = "mocks"))]
    {
        *PROTOCOL_FEE.read().expect("fee lock poisoned")
    }
}

/// Set the protocol fee
pub fn set_protocol_fee(fee: FixedPoint) {
    *PROTOCOL_FEE.write().expect("fee lock poisoned") = fee;
}

/// Get the external match fee override for the given mint
///
/// Defaults to the protocol base fee if no override exists
pub fn get_external_match_fee(mint: &Address) -> FixedPoint {
    let fee_override =
        PROTOCOL_FEE_OVERRIDES.read().expect("fee override lock poisoned").get(mint).cloned();
    fee_override.unwrap_or(get_protocol_fee())
}

/// Set the external match fee override for the given mint
pub fn set_external_match_fee(mint: &Address, fee: FixedPoint) {
    PROTOCOL_FEE_OVERRIDES.write().expect("fee override lock poisoned").insert(mint.clone(), fee);
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
