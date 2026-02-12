//! Helpers for building settlement bundles

use darkpool_types::{
    bounded_match_result::BoundedMatchResult, settlement_obligation::SettlementObligation,
};
use renegade_solidity_abi::v2::IDarkpoolV2::SettlementBundle;
use types_account::{OrderId, order::PrivacyRing};

use crate::tasks::settlement::helpers::{SettlementProcessor, error::SettlementError};

impl SettlementProcessor {
    /// Build a settlement bundle for an internal match
    pub async fn build_internal_settlement_bundle(
        &self,
        order_id: OrderId,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        let order = self.get_order(order_id).await?;
        match order.ring {
            PrivacyRing::Ring0 => {
                self.build_ring0_internal_settlement_bundle(order, obligation).await
            },
            PrivacyRing::Ring1 => {
                self.build_ring1_internal_settlement_bundle(order, obligation).await
            },
            _ => unimplemented!("implementing settlement bundle for ring {:?}", order.ring),
        }
    }

    /// Build a settlement bundle for an external match
    pub async fn build_external_settlement_bundle(
        &self,
        order_id: OrderId,
        obligation: SettlementObligation,
        match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        let order = self.get_order(order_id).await?;
        match order.ring {
            PrivacyRing::Ring0 => {
                self.build_ring0_external_settlement_bundle(order, obligation, match_res).await
            },
            PrivacyRing::Ring1 => {
                self.build_ring1_external_settlement_bundle(order, obligation, match_res).await
            },
            _ => unimplemented!("implementing settlement bundle for ring {:?}", order.ring),
        }
    }
}
