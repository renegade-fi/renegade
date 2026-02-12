//! Ring 1 settlement helpers
//!
//! Ring 1 ("natively settled private intent") uses private Merklized intents
//! with public EOA balances. Settlement requires:
//! 1. A validity proof (generated at order creation, stored in state)
//! 2. A settlement proof (generated at settlement time via the proof manager)
//! 3. A proof link connecting the validity and settlement proofs

use alloy::primitives::U256;
use circuit_types::ProofLinkingHint;
use circuits_core::zk_circuits::settlement::{
    intent_only_bounded_settlement::{
        IntentOnlyBoundedSettlementStatement, IntentOnlyBoundedSettlementWitness,
    },
    intent_only_public_settlement::{
        IntentOnlyPublicSettlementStatement, IntentOnlyPublicSettlementWitness,
    },
};
use constants::MERKLE_HEIGHT;
use darkpool_types::{
    bounded_match_result::BoundedMatchResult, settlement_obligation::SettlementObligation,
};
use job_types::proof_manager::ProofJob;
use renegade_solidity_abi::v2::IDarkpoolV2::{
    PrivateIntentAuthBundle, PrivateIntentAuthBundleFirstFill, SettlementBundle, SignatureWithNonce,
};
use types_account::{order::Order, pair::Pair};
use types_proofs::{
    IntentOnlyBoundedSettlementBundle, IntentOnlyFirstFillValidityBundle,
    IntentOnlyPublicSettlementBundle, IntentOnlyValidityBundle,
};

use crate::{
    tasks::settlement::helpers::{SettlementProcessor, error::SettlementError},
    utils::enqueue_proof_job,
};

impl SettlementProcessor {
    /// Build a Ring 1 settlement bundle for an internal match
    pub async fn build_ring1_internal_settlement_bundle(
        &self,
        order: Order,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        if order.metadata.has_been_filled {
            self.build_ring1_internal_subsequent_fill(order, obligation).await
        } else {
            self.build_ring1_internal_first_fill(order, obligation).await
        }
    }

    /// Build a Ring 1 settlement bundle for an external match
    pub async fn build_ring1_external_settlement_bundle(
        &self,
        order: Order,
        obligation: SettlementObligation,
        match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        if order.metadata.has_been_filled {
            self.build_ring1_external_subsequent_fill(order, obligation, match_res).await
        } else {
            self.build_ring1_external_first_fill(order, obligation, match_res).await
        }
    }

    // --- Internal Match Helpers --- //

    /// Build a first-fill internal settlement bundle for Ring 1
    async fn build_ring1_internal_first_fill(
        &self,
        order: Order,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        let validity_bundle = self.get_first_fill_validity_bundle(order.id).await?;
        let settlement = self
            .generate_internal_settlement_proof(&order, &obligation, &validity_bundle.linking_hint)
            .await?
            .into_inner();

        let intent_sig = self.get_natively_settled_intent_auth(order.id).await?;
        let auth = build_first_fill_auth_bundle(intent_sig, &validity_bundle);

        Ok(SettlementBundle::private_intent_public_balance_first_fill(
            auth,
            settlement.statement.into(),
            settlement.proof.into(),
            settlement.link_proof.into(),
        ))
    }

    /// Build a subsequent-fill internal settlement bundle for Ring 1
    async fn build_ring1_internal_subsequent_fill(
        &self,
        order: Order,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        let validity_bundle = self.get_subsequent_fill_validity_bundle(order.id).await?;
        let settlement = self
            .generate_internal_settlement_proof(&order, &obligation, &validity_bundle.linking_hint)
            .await?
            .into_inner();

        let auth = build_subsequent_fill_auth_bundle(&validity_bundle);

        Ok(SettlementBundle::private_intent_public_balance(
            auth,
            settlement.statement.into(),
            settlement.proof.into(),
            settlement.link_proof.into(),
        ))
    }

    // --- External Match Helpers --- //

    /// Build a first-fill external settlement bundle for Ring 1
    async fn build_ring1_external_first_fill(
        &self,
        order: Order,
        obligation: SettlementObligation,
        match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        let validity_bundle = self.get_first_fill_validity_bundle(order.id).await?;
        let settlement = self
            .generate_external_settlement_proof(
                &order,
                &obligation,
                &match_res,
                &validity_bundle.linking_hint,
            )
            .await?
            .into_inner();

        // Build the bundles
        let intent_sig = self.get_natively_settled_intent_auth(order.id).await?;
        let auth = build_first_fill_auth_bundle(intent_sig, &validity_bundle);
        Ok(SettlementBundle::private_intent_public_balance_bounded_first_fill(
            auth,
            settlement.statement.into(),
            settlement.proof.into(),
            settlement.link_proof.into(),
        ))
    }

    /// Build a subsequent-fill external settlement bundle for Ring 1
    async fn build_ring1_external_subsequent_fill(
        &self,
        order: Order,
        obligation: SettlementObligation,
        match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        let validity_bundle = self.get_subsequent_fill_validity_bundle(order.id).await?;
        let settlement = self
            .generate_external_settlement_proof(
                &order,
                &obligation,
                &match_res,
                &validity_bundle.linking_hint,
            )
            .await?
            .into_inner();

        // Build the bundles
        let auth = build_subsequent_fill_auth_bundle(&validity_bundle);
        Ok(SettlementBundle::private_intent_public_balance_bounded(
            auth,
            settlement.statement.into(),
            settlement.proof.into(),
            settlement.link_proof.into(),
        ))
    }

    // --- Proof Generation --- //

    /// Generate an internal (public) settlement proof for Ring 1
    async fn generate_internal_settlement_proof(
        &self,
        order: &Order,
        obligation: &SettlementObligation,
        validity_link_hint: &ProofLinkingHint,
    ) -> Result<IntentOnlyPublicSettlementBundle, SettlementError> {
        let pair = Pair::from_obligation(obligation);
        let base = pair.base_token();
        let (relayer_fee, relayer_fee_recipient) = self.relayer_fee(&base)?;

        let witness = IntentOnlyPublicSettlementWitness { intent: order.intent.inner.clone() };
        let statement = IntentOnlyPublicSettlementStatement {
            settlement_obligation: obligation.clone(),
            relayer_fee,
            relayer_fee_recipient,
        };

        let job = ProofJob::IntentOnlyPublicSettlement {
            witness,
            statement,
            validity_link_hint: validity_link_hint.clone(),
        };

        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(SettlementError::proof_generation)?;
        let bundle: IntentOnlyPublicSettlementBundle =
            proof_recv.await.map_err(SettlementError::proof_generation)?.into();

        Ok(bundle)
    }

    /// Generate an external (bounded) settlement proof for Ring 1
    async fn generate_external_settlement_proof(
        &self,
        order: &Order,
        obligation: &SettlementObligation,
        match_res: &BoundedMatchResult,
        validity_link_hint: &ProofLinkingHint,
    ) -> Result<IntentOnlyBoundedSettlementBundle, SettlementError> {
        let pair = Pair::from_obligation(obligation);
        let base = pair.base_token();
        let (internal_relayer_fee, relayer_fee_recipient) = self.relayer_fee(&base)?;

        // External party has no relayer fee
        let external_relayer_fee = Default::default();

        let witness = IntentOnlyBoundedSettlementWitness { intent: order.intent.inner.clone() };
        let statement = IntentOnlyBoundedSettlementStatement {
            bounded_match_result: match_res.clone(),
            internal_relayer_fee,
            external_relayer_fee,
            relayer_fee_recipient,
        };

        let job = ProofJob::IntentOnlyBoundedSettlement {
            witness,
            statement,
            validity_link_hint: validity_link_hint.clone(),
        };

        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(SettlementError::proof_generation)?;
        let bundle: IntentOnlyBoundedSettlementBundle =
            proof_recv.await.map_err(SettlementError::proof_generation)?.into();

        Ok(bundle)
    }

    // --- Proof Retrieval --- //

    /// Retrieve the first-fill validity proof bundle for a given order
    async fn get_first_fill_validity_bundle(
        &self,
        order_id: types_account::OrderId,
    ) -> Result<IntentOnlyFirstFillValidityBundle, SettlementError> {
        self.ctx.state.get_intent_only_first_fill_validity_proof(order_id).await?.ok_or_else(|| {
            SettlementError::state(format!(
                "first-fill validity proof not found for order {order_id}"
            ))
        })
    }

    /// Retrieve the subsequent-fill validity proof bundle for a given order
    async fn get_subsequent_fill_validity_bundle(
        &self,
        order_id: types_account::OrderId,
    ) -> Result<IntentOnlyValidityBundle, SettlementError> {
        self.ctx.state.get_intent_only_validity_proof(order_id).await?.ok_or_else(|| {
            SettlementError::state(format!("validity proof not found for order {order_id}"))
        })
    }
}

// -----------
// | Helpers |
// -----------

/// Build a first-fill auth bundle for a private intent (Ring 1)
///
/// Includes the intent signature (signed commitment) alongside the validity
/// proof and statement.
fn build_first_fill_auth_bundle(
    intent_signature: SignatureWithNonce,
    validity_bundle: &IntentOnlyFirstFillValidityBundle,
) -> PrivateIntentAuthBundleFirstFill {
    let statement = validity_bundle.statement.clone().into();
    let proof = validity_bundle.proof.clone().into();

    PrivateIntentAuthBundleFirstFill {
        intentSignature: intent_signature,
        merkleDepth: U256::from(MERKLE_HEIGHT),
        statement,
        validityProof: proof,
    }
}

/// Build a subsequent-fill auth bundle for a private intent (Ring 1)
///
/// Uses the Merkle opening from the validity proof instead of a signature.
fn build_subsequent_fill_auth_bundle(
    validity_bundle: &IntentOnlyValidityBundle,
) -> PrivateIntentAuthBundle {
    let statement = validity_bundle.statement.clone().into();
    let proof = validity_bundle.proof.clone().into();

    PrivateIntentAuthBundle {
        merkleDepth: U256::from(MERKLE_HEIGHT),
        statement,
        validityProof: proof,
    }
}
