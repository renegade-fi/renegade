//! Ring 2 settlement helpers

use darkpool_types::{
    bounded_match_result::BoundedMatchResult, settlement_obligation::SettlementObligation,
};
use renegade_solidity_abi::v2::IDarkpoolV2::SettlementBundle;
use types_account::{OrderId, order::Order};

use crate::tasks::settlement::helpers::{SettlementProcessor, error::SettlementError};

// ----------------------
// | Settlement Bundles |
// ----------------------

impl SettlementProcessor {
    /// Build a Ring 2 settlement bundle for an internal match
    pub async fn build_ring2_internal_settlement_bundle(
        &self,
        order: Order,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        todo!()
    }
}
