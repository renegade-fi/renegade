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

/// The group name for the INTENT ONLY (FIRST FILL) VALIDITY <-> INTENT ONLY
/// SETTLEMENT link
pub const INTENT_ONLY_PUBLIC_SETTLEMENT_LINK: &str = "intent_only_settlement";

/// The group name for the INTENT AND BALANCE (FIRST FILL) VALIDITY <-> INTENT
/// AND BALANCE SETTLEMENT link
pub const INTENT_AND_BALANCE_PUBLIC_SETTLEMENT_LINK: &str = "intent_and_balance_settlement";

/// The group name for the OUTPUT BALANCE SETTLEMENT link
pub const OUTPUT_BALANCE_SETTLEMENT_LINK: &str = "output_balance_settlement";
