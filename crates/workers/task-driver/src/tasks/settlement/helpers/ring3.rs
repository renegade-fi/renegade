//! Ring 3 (private settlement) helpers
//!
//! Private settlement uses the `IntentAndBalancePrivateSettlement` circuit,
//! which proves both parties' settlement in a single proof. This module
//! gathers data for both parties, generates the combined proof, and splits
//! the result into two per-party `SettlementBundle` values.
//!
//! TODO: Implement `build_private_settlement` on `SettlementProcessor`.
