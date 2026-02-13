//! Ring 2 settlement helpers

use alloy::primitives::U256;
use circuits_core::zk_circuits::settlement::intent_and_balance_public_settlement::{
    IntentAndBalancePublicSettlementStatement, IntentAndBalancePublicSettlementWitness,
};
use constants::{MERKLE_HEIGHT, Scalar};
use darkpool_types::{
    balance::{DarkpoolBalance, PostMatchBalanceShare},
    bounded_match_result::BoundedMatchResult,
    intent::Intent,
    settlement_obligation::SettlementObligation,
};
use job_types::proof_manager::ProofJob;
use renegade_solidity_abi::v2::IDarkpoolV2::{
    RenegadeSettledIntentAuthBundle, RenegadeSettledIntentAuthBundleFirstFill, SettlementBundle,
};
use types_account::{OrderId, order::Order, pair::Pair};
use types_core::AccountId;
use types_proofs::{
    IntentAndBalanceFirstFillValidityBundle, IntentAndBalancePublicSettlementBundle,
    IntentAndBalanceValidityBundle, SizedIntentAndBalanceFirstFillValidityWitness,
    SizedIntentAndBalanceValidityWitness,
};

use crate::{
    tasks::settlement::helpers::{SettlementProcessor, error::SettlementError},
    utils::enqueue_proof_job,
};
use circuit_types::ProofLinkingHint;

// ----------------------
// | Settlement Bundles |
// ----------------------

impl SettlementProcessor {
    // --- Internal Match Helpers --- //

    /// Build a Ring 2 settlement bundle for an external match
    pub async fn build_ring2_external_settlement_bundle(
        &self,
        order: Order,
        obligation: SettlementObligation,
        match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        if order.metadata.has_been_filled {
            self.build_ring2_external_subsequent_fill(order, obligation, match_res).await
        } else {
            self.build_ring2_external_first_fill(order, obligation, match_res).await
        }
    }

    /// Build a Ring 2 settlement bundle for an internal match
    pub async fn build_ring2_internal_settlement_bundle(
        &self,
        order: Order,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        let account_id = self.get_account_id_for_order(order.id).await?;
        if order.metadata.has_been_filled {
            self.build_ring2_internal_subsequent_fill(account_id, order, obligation).await
        } else {
            self.build_ring2_internal_first_fill(account_id, order, obligation).await
        }
    }

    /// Build a first-fill internal settlement bundle for Ring 2
    async fn build_ring2_internal_first_fill(
        &self,
        account_id: AccountId,
        order: Order,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        let (validity_bundle, validity_witness) =
            self.get_ring2_first_fill_validity_bundle(order.id).await?;
        let output_bundle = self.get_output_balance_bundle(account_id, &order).await?;

        let settlement_data = self
            .prove_intent_and_balance_public_settlement(
                validity_witness.intent.clone(),
                validity_witness.balance.clone(),
                output_bundle.balance(),
                validity_witness.new_amount_public_share,
                validity_witness.post_match_balance_shares.clone(),
                output_bundle.post_match_balance_shares(),
                obligation.clone(),
                validity_bundle.linking_hint.clone(),
                output_bundle.linking_hint(),
            )
            .await?
            .into_inner();

        // Build the auth bundle for the first fill
        let auth = RenegadeSettledIntentAuthBundleFirstFill {
            merkleDepth: U256::from(MERKLE_HEIGHT),
            statement: validity_bundle.statement.clone().into(),
            validityProof: validity_bundle.proof.clone().into(),
        };

        // Build a settlement bundle
        let link_proof = settlement_data.output_balance_link_proof.clone();
        let output_bundle = output_bundle.build_abi_bundle(link_proof);

        let bundle = SettlementBundle::renegade_settled_private_intent_first_fill(
            auth,
            output_bundle,
            settlement_data.statement.clone().into(),
            settlement_data.proof.clone().into(),
            settlement_data.validity_link_proof.clone().into(),
        );
        Ok(bundle)
    }

    /// Build a subsequent-fill internal settlement bundle for Ring 2
    async fn build_ring2_internal_subsequent_fill(
        &self,
        account_id: AccountId,
        order: Order,
        obligation: SettlementObligation,
    ) -> Result<SettlementBundle, SettlementError> {
        let (validity_bundle, validity_witness) =
            self.get_ring2_subsequent_fill_validity_bundle(order.id).await?;
        let output_bundle = self.get_output_balance_bundle(account_id, &order).await?;

        let settlement_data = self
            .prove_intent_and_balance_public_settlement(
                validity_witness.intent.clone(),
                validity_witness.balance.clone(),
                output_bundle.balance(),
                validity_witness.new_amount_public_share,
                validity_witness.post_match_balance_shares.clone(),
                output_bundle.post_match_balance_shares(),
                obligation.clone(),
                validity_bundle.linking_hint.clone(),
                output_bundle.linking_hint(),
            )
            .await?
            .into_inner();

        // Build the auth bundle for the subsequent fill (no signature)
        let auth = RenegadeSettledIntentAuthBundle {
            merkleDepth: U256::from(MERKLE_HEIGHT),
            statement: validity_bundle.statement.clone().into(),
            validityProof: validity_bundle.proof.clone().into(),
        };

        // Build a settlement bundle
        let link_proof = settlement_data.output_balance_link_proof.clone();
        let output_bundle = output_bundle.build_abi_bundle(link_proof);

        let bundle = SettlementBundle::renegade_settled_private_intent(
            auth,
            output_bundle,
            settlement_data.statement.clone().into(),
            settlement_data.proof.clone().into(),
            settlement_data.validity_link_proof.clone().into(),
        );
        Ok(bundle)
    }

    // --- External Match Helpers --- //

    /// Build a first-fill external settlement bundle for Ring 2
    async fn build_ring2_external_first_fill(
        &self,
        _order: Order,
        _obligation: SettlementObligation,
        _match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        todo!()
    }

    /// Build a subsequent-fill external settlement bundle for Ring 2
    async fn build_ring2_external_subsequent_fill(
        &self,
        _order: Order,
        _obligation: SettlementObligation,
        _match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        todo!()
    }

    // --- Prover Helpers --- //

    /// Generate a proof of `INTENT AND BALANCE PUBLIC SETTLEMENT`
    #[allow(clippy::too_many_arguments)]
    async fn prove_intent_and_balance_public_settlement(
        &self,
        intent: Intent,
        in_balance: DarkpoolBalance,
        out_balance: DarkpoolBalance,
        amount_share: Scalar,
        in_balance_share: PostMatchBalanceShare,
        out_balance_share: PostMatchBalanceShare,
        obligation: SettlementObligation,
        validity_link_hint: ProofLinkingHint,
        output_balance_link_hint: ProofLinkingHint,
    ) -> Result<IntentAndBalancePublicSettlementBundle, SettlementError> {
        // The public shares on the input values are pre-update
        // The public fill circuit does not update the public shares directly, so no
        // updates need to be made in constructing the witness & statement
        let witness = IntentAndBalancePublicSettlementWitness {
            intent,
            in_balance: in_balance.clone(),
            out_balance: out_balance.clone(),
            pre_settlement_amount_public_share: amount_share,
            pre_settlement_in_balance_shares: in_balance_share.clone(),
            pre_settlement_out_balance_shares: out_balance_share.clone(),
        };

        let pair = Pair::from_obligation(&obligation);
        let fee_rates = self.fee_rates(&pair)?;
        let statement = IntentAndBalancePublicSettlementStatement {
            settlement_obligation: obligation.clone(),
            amount_public_share: amount_share,
            in_balance_public_shares: in_balance_share,
            out_balance_public_shares: out_balance_share,
            fee_rates,
            relayer_fee_recipient: out_balance.relayer_fee_recipient,
        };

        // Generate the proof
        let job = ProofJob::IntentAndBalancePublicSettlement {
            witness,
            statement,
            validity_link_hint: validity_link_hint.clone(),
            output_balance_link_hint: output_balance_link_hint.clone(),
        };

        // Wait for a response
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(SettlementError::proof_generation)?;
        let bundle: IntentAndBalancePublicSettlementBundle =
            proof_recv.await.map_err(SettlementError::proof_generation)?.into();

        Ok(bundle)
    }

    // --- Proof Retrieval --- //

    /// Get the first fill validity proof bundle for a Ring 2 order
    async fn get_ring2_first_fill_validity_bundle(
        &self,
        order_id: OrderId,
    ) -> Result<
        (IntentAndBalanceFirstFillValidityBundle, SizedIntentAndBalanceFirstFillValidityWitness),
        SettlementError,
    > {
        self.ctx
            .state
            .get_intent_and_balance_first_fill_validity_proof_and_witness(order_id)
            .await?
            .ok_or_else(|| {
                SettlementError::state(format!(
                    "first fill validity proof not found for order {order_id}"
                ))
            })
    }

    /// Get the subsequent-fill validity proof bundle for a Ring 2 order
    async fn get_ring2_subsequent_fill_validity_bundle(
        &self,
        order_id: OrderId,
    ) -> Result<
        (IntentAndBalanceValidityBundle, SizedIntentAndBalanceValidityWitness),
        SettlementError,
    > {
        self.ctx
            .state
            .get_intent_and_balance_validity_proof_and_witness(order_id)
            .await?
            .ok_or_else(|| {
                SettlementError::state(format!(
                    "subsequent fill validity proof not found for order {order_id}"
                ))
            })
    }
}
