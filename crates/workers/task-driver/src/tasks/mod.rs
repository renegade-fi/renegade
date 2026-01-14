//! Task definitions run by the driver

// pub mod create_new_wallet;
// pub mod lookup_wallet;
pub mod node_startup;
// pub mod pay_offline_fee;
// pub mod redeem_fee;
// pub mod refresh_wallet;
// pub mod settle_malleable_external_match;
// pub mod settle_match;
// pub mod settle_match_external;
// pub mod settle_match_internal;
// pub mod update_merkle_proof;
// pub mod update_wallet;
pub mod create_balance;
pub mod create_new_account;
pub mod deposit;

// ------------------
// | Error Messages |
// ------------------

/// Error message emitted when an account cannot be found
pub(crate) const ERR_ACCOUNT_NOT_FOUND: &str = "account not found";
