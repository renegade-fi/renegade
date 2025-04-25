//! Task definitions run by the driver

pub mod create_new_wallet;
pub mod lookup_wallet;
pub mod node_startup;
pub mod pay_offline_fee;
pub mod pay_relayer_fee;
pub mod redeem_fee;
pub mod refresh_wallet;
pub mod settle_malleable_external_match;
pub mod settle_match;
pub mod settle_match_external;
pub mod settle_match_internal;
pub mod update_merkle_proof;
pub mod update_wallet;

/// The error emitted when a wallet is missing from state
pub(crate) const ERR_WALLET_MISSING: &str = "wallet not found in global state";
/// The error emitted when a balance for a given mint is missing
pub(crate) const ERR_BALANCE_MISSING: &str = "balance not found in wallet";
/// The error message emitted when a Merkle proof is not found for a wallet
pub(crate) const ERR_NO_MERKLE_PROOF: &str = "no merkle proof found for wallet";
/// The error message emitted when validity proofs are not found for an order
pub(crate) const ERR_NO_VALIDITY_PROOF: &str = "no validity proofs found for order";
/// Error message emitted when awaiting a proof fails
pub(crate) const ERR_AWAITING_PROOF: &str = "error awaiting proof";
