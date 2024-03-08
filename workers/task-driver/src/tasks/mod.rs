//! Task definitions run by the driver

pub mod create_new_wallet;
pub mod lookup_wallet;
pub mod pay_offline_fee;
pub mod pay_relayer_fee;
pub mod redeem_relayer_fee;
pub mod settle_match;
pub mod settle_match_internal;
pub mod update_merkle_proof;
pub mod update_wallet;

/// The error emitted when a wallet is missing from state
pub(crate) const ERR_WALLET_MISSING: &str = "wallet not found in global state";
/// The error emitted when a balance for a given mint is missing
pub(crate) const ERR_BALANCE_MISSING: &str = "balance not found in wallet";
/// The error message emitted when a Merkle proof is not found for a wallet
pub(crate) const ERR_NO_MERKLE_PROOF: &str = "no merkle proof found for wallet";
