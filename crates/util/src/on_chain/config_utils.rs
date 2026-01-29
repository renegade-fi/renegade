//! Configuration utils for contract interaction

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    sync::{OnceLock, RwLock},
};

use alloy::primitives::Address;
use circuit_types::{elgamal::EncryptionKey, fixed_point::FixedPoint};
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
/// The default protocol fee rate, used when no per-pair fee is cached
static DEFAULT_PROTOCOL_FEE: RwStatic<FixedPoint> =
    RwStatic::new(|| RwLock::new(FixedPoint::zero()));
/// Per-pair protocol fee overrides
///
/// Maps (asset0, asset1) to the protocol fee override for that pair.
/// Falls back to DEFAULT_PROTOCOL_FEE when a pair is not present.
static PROTOCOL_FEE_PAIR_OVERRIDES: RwStatic<HashMap<(Address, Address), FixedPoint>> =
    RwStatic::new(|| RwLock::new(HashMap::new()));
/// The protocol's public encryption key used for paying fees
pub static PROTOCOL_PUBKEY: OnceLock<EncryptionKey> = OnceLock::new();
/// The chain ID for the blockchain network
static CHAIN_ID: RwStatic<u64> = RwStatic::new(|| RwLock::new(0));

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

/// Get the key for a trading pair
///
/// This ensures consistent key ordering so that `(A, B)` and `(B, A)` map to
/// the same key, matching the contract's `_getPairKey` behavior.
fn get_pair_key(asset0: &Address, asset1: &Address) -> (Address, Address) {
    if asset0 < asset1 { (*asset0, *asset1) } else { (*asset1, *asset0) }
}

/// Get the default protocol fee
pub fn get_default_protocol_fee() -> FixedPoint {
    #[cfg(feature = "mocks")]
    {
        FixedPoint::from_f64_round_down(0.0006) // 6 bps
    }

    #[cfg(not(feature = "mocks"))]
    {
        *DEFAULT_PROTOCOL_FEE.read().expect("default fee lock poisoned")
    }
}

/// Set the default protocol fee
pub fn set_default_protocol_fee(fee: FixedPoint) {
    *DEFAULT_PROTOCOL_FEE.write().expect("default fee lock poisoned") = fee;
}

/// Get the protocol fee for a given asset pair
///
/// Falls back to the default protocol fee if the pair is not cached.
pub fn get_protocol_fee_for_pair(asset0: &Address, asset1: &Address) -> FixedPoint {
    #[cfg(feature = "mocks")]
    {
        let _ = (asset0, asset1);
        FixedPoint::from_f64_round_down(0.0006) // 6 bps
    }

    #[cfg(not(feature = "mocks"))]
    {
        let key = get_pair_key(asset0, asset1);
        PROTOCOL_FEE_PAIR_OVERRIDES
            .read()
            .expect("fee overrides lock poisoned")
            .get(&key)
            .cloned()
            .unwrap_or_else(get_default_protocol_fee)
    }
}

/// Set the protocol fee override for a given asset pair
pub fn set_protocol_fee_for_pair(asset0: &Address, asset1: &Address, fee: FixedPoint) {
    let key = get_pair_key(asset0, asset1);
    PROTOCOL_FEE_PAIR_OVERRIDES.write().expect("fee overrides lock poisoned").insert(key, fee);
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

/// Get the chain ID from the static variable
pub fn get_chain_id() -> u64 {
    *CHAIN_ID.read().expect("chain ID lock poisoned")
}

/// Set the chain ID
pub fn set_chain_id(chain_id: u64) {
    *CHAIN_ID.write().expect("chain ID lock poisoned") = chain_id;
}
