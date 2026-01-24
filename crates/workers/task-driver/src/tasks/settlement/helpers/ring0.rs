//! Ring 0 settlement helpers

use darkpool_types::settlement_obligation::SettlementObligation;
use renegade_solidity_abi::v2::IDarkpoolV2::{
    self, FeeRate, PublicIntentAuthBundle, PublicIntentPermit, SettlementBundle,
    SignatureWithNonce, SignedPermitSingle,
};
use types_account::{OrderId, order_auth::OrderAuth, pair::Pair};
use util::on_chain::get_chain_id;

use crate::tasks::settlement::helpers::{SettlementProcessor, error::SettlementError};

impl SettlementProcessor {
    /// Build a ring 0 settlement bundle for a given order
    pub async fn build_ring0_settlement_bundle(
        &self,
        order_id: OrderId,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        let pair = Pair::from_obligation(&obligation);
        let base = pair.base_token();
        let relayer_fee = self.relayer_fee(base).await?;
        let order = self.get_order(order_id).await?;

        // Get signatures from the executor and user
        let executor = self.get_executor_key().await?;
        let executor_sig = self.build_executor_signature(obligation, &relayer_fee).await?;
        let user_sig = self.get_intent_signature(order_id).await?;

        // Build the intent permit
        let intent_permit = PublicIntentPermit {
            intent: order.intent().clone().into(),
            executor: executor.address(),
        };

        // Build the auth and settlement bundle
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
        let contract_obligation = IDarkpoolV2::SettlementObligation::from(obligation);

        let chain_id = get_chain_id();
        let signer = self.get_executor_key().await?;
        let sig = contract_obligation
            .create_executor_signature(fee, chain_id, &signer)
            .map_err(SettlementError::signing)?;

        Ok(sig)
    }

    /// Get the order authorization for an order ID
    async fn get_intent_signature(
        &self,
        order_id: OrderId,
    ) -> Result<SignatureWithNonce, SettlementError> {
        let auth =
            self.ctx.state.get_order_auth(&order_id).await?.ok_or_else(|| {
                SettlementError::state(format!("order auth not found: {order_id}"))
            })?;

        let sig = match auth {
            OrderAuth::PublicOrder { intent_signature } => intent_signature,
            _ => {
                return Err(SettlementError::state(format!(
                    "invalid order auth type for order {order_id}"
                )));
            },
        };
        Ok(sig)
    }
}
