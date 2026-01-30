//! Helpers related to interfacing with an Arbitrum devnet node

use std::str::FromStr;

use alloy::signers::local::PrivateKeySigner;

/// The default hostport that the Nitro devnet L2 node runs on
pub const DEFAULT_DEVNET_HOSTPORT: &str = "http://localhost:8547";
/// The default private key that the Nitro devnet is seeded with
pub const DEFAULT_DEVNET_PKEY: &str =
    "0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";

/// Get a parsed `LocalWallet` from the default private key
pub fn get_devnet_key() -> PrivateKeySigner {
    PrivateKeySigner::from_str(DEFAULT_DEVNET_PKEY).unwrap()
}
