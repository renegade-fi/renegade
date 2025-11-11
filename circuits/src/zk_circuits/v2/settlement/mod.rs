//! Settlement circuits
//!
//! Settlement circuits verify updates to intents and balances after a match is
//! settled. A match generates two `SettlementObligation`s, one for each party.
//! The obligation itself may be public or private from the perspective of the
//! verifier.
//!
//! The settlement circuits in this module represent different configurations of
//! private vs public obligations and private vs public intents and balances.

pub mod intent_and_balance_public_settlement;
pub mod intent_only_public_settlement;

/// The group name for the INTENT ONLY (FIRST FILL) VALIDITY <-> INTENT ONLY
/// PUBLIC SETTLEMENT link
pub const INTENT_ONLY_PUBLIC_SETTLEMENT_LINK: &str = "intent_only_public_settlement";

/// The group name for the INTENT AND BALANCE (FIRST FILL) VALIDITY <-> INTENT
/// AND BALANCE PUBLIC SETTLEMENT link
pub const INTENT_AND_BALANCE_PUBLIC_SETTLEMENT_LINK: &str = "intent_and_balance_public_settlement";
