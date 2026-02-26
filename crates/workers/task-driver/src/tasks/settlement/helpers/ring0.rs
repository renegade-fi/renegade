//! Ring 0 settlement helpers

use darkpool_types::{
    bounded_match_result::BoundedMatchResult, settlement_obligation::SettlementObligation,
};
use renegade_solidity_abi::v2::IDarkpoolV2::{
    self, FeeRate, PublicIntentAuthBundle, SettlementBundle, SignatureWithNonce, SignedPermitSingle,
};
use types_account::{order::Order, pair::Pair};
use types_tasks::ExternalRelayerFeeRate;
use util::on_chain::get_chain_id;

use crate::tasks::settlement::helpers::{SettlementProcessor, error::SettlementError};

// ----------------------
// | Settlement Bundles |
// ----------------------

impl SettlementProcessor {
    /// Build a ring 0 settlement bundle for an internal match
    pub async fn build_ring0_internal_settlement_bundle(
        &self,
        order: Order,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        // Get signatures from the executor and user
        let pair = Pair::from_obligation(&obligation);
        let base = pair.base_token();
        let relayer_fee = self.abi_relayer_fee(&base)?;
        let executor_sig = self.build_executor_signature(obligation.clone(), &relayer_fee).await?;
        self.build_ring0_settlement_bundle_with_executor_sig(order, relayer_fee, executor_sig).await
    }

    /// Build a ring 0 settlement bundle for an external match
    pub async fn build_ring0_external_settlement_bundle(
        &self,
        order: Order,
        match_res: BoundedMatchResult,
        external_relayer_fee_rate: ExternalRelayerFeeRate,
    ) -> Result<SettlementBundle, SettlementError> {
        let relayer_fee_recipient = self.ctx.state.get_relayer_fee_addr()?;
        let relayer_fee = FeeRate {
            rate: external_relayer_fee_rate.rate().into(),
            recipient: relayer_fee_recipient,
        };

        let executor_sig =
            self.build_bounded_match_executor_signature(match_res, &relayer_fee).await?;
        self.build_ring0_settlement_bundle_with_executor_sig(order, relayer_fee, executor_sig).await
    }

    /// Build a ring 0 settlement bundle for a given order
    async fn build_ring0_settlement_bundle_with_executor_sig(
        &self,
        order: Order,
        relayer_fee: FeeRate,
        executor_sig: SignatureWithNonce,
    ) -> Result<SettlementBundle, SettlementError> {
        let (intent_permit, user_sig) = self.get_public_intent_auth(order.id).await?;
        let auth_bundle = PublicIntentAuthBundle {
            intentPermit: intent_permit,
            intentSignature: user_sig,
            executorSignature: executor_sig,
            allowancePermit: SignedPermitSingle::default(),
        };

        Ok(SettlementBundle::public_intent_settlement(auth_bundle, relayer_fee))
    }

    /// Build an executor signature for the match
    async fn build_executor_signature(
        &self,
        obligation: SettlementObligation,
        fee: &FeeRate,
    ) -> Result<SignatureWithNonce, SettlementError> {
        let contract_obligation = IDarkpoolV2::SettlementObligation::from(obligation.clone());

        let chain_id = get_chain_id();
        let signer = self.get_executor_key().await?;
        let sig = contract_obligation
            .create_executor_signature(fee, chain_id, &signer)
            .map_err(SettlementError::signing)?;

        Ok(sig)
    }

    /// Build an executor signature for a bounded match result
    async fn build_bounded_match_executor_signature(
        &self,
        match_res: BoundedMatchResult,
        fee: &FeeRate,
    ) -> Result<SignatureWithNonce, SettlementError> {
        let contract_match = IDarkpoolV2::BoundedMatchResult::from(match_res.clone());

        let chain_id = get_chain_id();
        let executor = self.get_executor_key().await?;
        let sig = contract_match
            .create_executor_signature(fee.clone(), chain_id, &executor)
            .map_err(SettlementError::signing)?;

        Ok(sig)
    }
}

// -----------------
// | State Updates |
// -----------------

impl SettlementProcessor {
    /// Update an intent after a match settlement
    pub async fn update_ring0_intent_after_match(
        &self,
        order: &mut Order,
        obligation: &SettlementObligation,
    ) -> Result<(), SettlementError> {
        order.decrement_amount_in(obligation.amount_in);
        order.metadata.mark_filled();
        Ok(())
    }
}
