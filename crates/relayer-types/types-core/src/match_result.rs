//! Defines the match result type
//!
//! A match result is a pair of settlement obligations; one for each party

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use darkpool_types::settlement_obligation::SettlementObligation;
use serde::{Deserialize, Serialize};

use crate::Token;

/// A match result is a pair of settlement obligations; one for each party
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct MatchResult {
    /// The settlement obligation for the first party
    pub party0_obligation: SettlementObligation,
    /// The settlement obligation for the second party
    pub party1_obligation: SettlementObligation,
}

impl MatchResult {
    /// Creates a new match result from two settlement obligations
    pub fn new(
        party0_obligation: SettlementObligation,
        party1_obligation: SettlementObligation,
    ) -> Self {
        Self { party0_obligation, party1_obligation }
    }

    /// Get the first party's obligation
    pub fn party0_obligation(&self) -> &SettlementObligation {
        &self.party0_obligation
    }

    /// Get the second party's obligation
    pub fn party1_obligation(&self) -> &SettlementObligation {
        &self.party1_obligation
    }

    /// Get the base token of the matched pair
    ///
    /// All pairs are USDC quoted, so this is the non-USDC token
    pub fn base_token(&self) -> Token {
        let usdc = Token::usdc();
        let addr = if self.party0_obligation.input_token == usdc.get_alloy_address() {
            self.party0_obligation.output_token
        } else {
            self.party0_obligation.input_token
        };

        Token::from_alloy_address(&addr)
    }
}
