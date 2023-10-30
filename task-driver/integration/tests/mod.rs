//! Integration tests

pub mod create_new_wallet;
pub mod lookup_wallet;
pub mod settle_match;
pub mod update_wallet;

/// The deployed address of the WETH ERC20 contract
pub(crate) const WETH_ADDR: &str =
    "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
