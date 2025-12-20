//! Settlement circuits
//!
//! Settlement circuits verify updates to intents and balances after a match is
//! settled. A match generates two `SettlementObligation`s, one for each party.
//! The obligation itself may be public or private from the perspective of the
//! verifier.
//!
//! The settlement circuits in this module represent different configurations of
//! private vs public obligations and private vs public intents and balances.

pub mod intent_and_balance_private_settlement;
pub mod intent_and_balance_public_settlement;
pub mod intent_only_public_settlement;
pub mod settlement_lib;

/// The group name for the INTENT ONLY VALIDITY <-> INTENT ONLY
/// SETTLEMENT link for both exact and bounded settlement circuits
pub const INTENT_ONLY_SETTLEMENT_LINK: &str = "intent_only_settlement";

/// The group name for the INTENT AND BALANCE VALIDITY <-> INTENT
/// AND BALANCE SETTLEMENT link for exact and bounded settlement circuits
pub const INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK: &str = "intent_and_balance_settlement_party0";
/// The group name for the INTENT AND BALANCE SETTLEMENT link for the
/// second party
pub const INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK: &str = "intent_and_balance_settlement_party1";

/// The group name for the OUTPUT BALANCE SETTLEMENT link
pub const OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK: &str = "output_balance_settlement_party0";
/// The group name for the OUTPUT BALANCE SETTLEMENT link for the second party
pub const OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK: &str = "output_balance_settlement_party1";

// ----------------------
// | Bounded Settlement |
// ----------------------

pub mod intent_and_balance_bounded_settlement;
pub mod intent_only_bounded_settlement;
