//! Obligation bundle helpers

use renegade_solidity_abi::v2::IDarkpoolV2::ObligationBundle;
use types_core::MatchResult;

use crate::tasks::settlement::helpers::SettlementProcessor;

impl SettlementProcessor {
    /// Create an obligation bundle for a given match result
    pub fn public_obligation_bundle(&self, match_result: &MatchResult) -> ObligationBundle {
        let obligation0 = match_result.party0_obligation().clone();
        let obligation1 = match_result.party1_obligation().clone();
        ObligationBundle::new_public(obligation0.into(), obligation1.into())
    }
}
