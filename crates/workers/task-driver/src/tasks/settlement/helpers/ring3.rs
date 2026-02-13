//! Ring 3 (private fill) helpers
//!
//! Note that the methods in this module are not strictly for ring 3 orders, but
//! more generally are for private fills. A ring 2 order can be privately
//! filled, for example, if it crosses with another ring 2/3 order. The specific
//! criteria for a private fill is that both orders must be in ring {2, 3}.
//!
//! Private fill uses the `IntentAndBalancePrivateSettlement` circuit,
//! which proves both parties' settlement in a single proof. This module
//! gathers data for both parties, generates the combined proof, and splits
//! the result into two per-party `SettlementBundle` values.

use circuits_core::zk_circuits::settlement::intent_and_balance_private_settlement::{
    IntentAndBalancePrivateSettlementStatement, IntentAndBalancePrivateSettlementWitness,
};
use constants::Scalar;
use darkpool_types::{
    balance::PostMatchBalanceShare, fee::FeeRates, settlement_obligation::SettlementObligation,
};
use job_types::proof_manager::ProofJob;
use renegade_solidity_abi::v2::IDarkpoolV2::{ObligationBundle, SettlementBundle};
use types_account::OrderId;
use types_account::pair::Pair;
use types_proofs::IntentAndBalancePrivateSettlementBundle;

use crate::tasks::settlement::helpers::{
    SettlementProcessor, error::SettlementError, output_balance::OutputBalanceBundle,
    private_fill_validity_bundle::PrivateFillValidityBundle,
};
use crate::utils::enqueue_proof_job;

impl SettlementProcessor {
    /// Build calldata bundles for a private fill
    pub async fn build_private_fill_calldata_bundle(
        &self,
        order_id0: OrderId,
        order_id1: OrderId,
        obligation0: SettlementObligation,
        obligation1: SettlementObligation,
    ) -> Result<(SettlementBundle, SettlementBundle, ObligationBundle), SettlementError> {
        let account_id0 = self.get_account_id_for_order(order_id0).await?;
        let account_id1 = self.get_account_id_for_order(order_id1).await?;
        let order0 = self.get_order(order_id0).await?;
        let order1 = self.get_order(order_id1).await?;

        // Fetch validity bundles for both parties
        let validity_bundle0 = self.get_private_fill_validity_bundle(&order0).await?;
        let validity_bundle1 = self.get_private_fill_validity_bundle(&order1).await?;
        let output_bundle0 = self.get_output_balance_bundle(account_id0, &order0).await?;
        let output_bundle1 = self.get_output_balance_bundle(account_id1, &order1).await?;

        // Generate a settlement proof for the obligations
        let settlement_data = self
            .prove_intent_and_balance_private_settlement(
                obligation0,
                obligation1,
                &validity_bundle0,
                &validity_bundle1,
                &output_bundle0,
                &output_bundle1,
            )
            .await?
            .into_inner();

        // Build an obligation bundle that contains the settlement linking the parties
        let obligation_bundle = ObligationBundle::new_private(
            settlement_data.statement.clone().into(),
            settlement_data.proof.clone().into(),
        );

        let output_bundle0 =
            output_bundle0.build_abi_bundle(settlement_data.output_balance_link_proof_0.clone());
        let output_bundle1 =
            output_bundle1.build_abi_bundle(settlement_data.output_balance_link_proof_1.clone());

        let settlement_bundle0 = validity_bundle0
            .build_settlement_bundle(output_bundle0, settlement_data.validity_link_proof_0.clone());
        let settlement_bundle1 = validity_bundle1
            .build_settlement_bundle(output_bundle1, settlement_data.validity_link_proof_1.clone());

        Ok((settlement_bundle0, settlement_bundle1, obligation_bundle))
    }

    // --- Prover Helpers --- //

    /// Generate a proof of `INTENT AND BALANCE PRIVATE SETTLEMENT`
    #[allow(clippy::too_many_arguments)]
    async fn prove_intent_and_balance_private_settlement(
        &self,
        obligation0: SettlementObligation,
        obligation1: SettlementObligation,
        validity_bundle0: &PrivateFillValidityBundle,
        validity_bundle1: &PrivateFillValidityBundle,
        output_bundle0: &OutputBalanceBundle,
        output_bundle1: &OutputBalanceBundle,
    ) -> Result<IntentAndBalancePrivateSettlementBundle, SettlementError> {
        let pair0 = Pair::from_obligation(&obligation0);
        let pair1 = Pair::from_obligation(&obligation1);
        let fee_rates0 = self.fee_rates(&pair0)?;
        let fee_rates1 = self.fee_rates(&pair1)?;
        let protocol_fee = fee_rates0.protocol_fee_rate;

        let output_balance0 = output_bundle0.balance();
        let output_balance1 = output_bundle1.balance();
        let pre_settlement_out_balance_shares0 = output_bundle0.post_match_balance_shares();
        let pre_settlement_out_balance_shares1 = output_bundle1.post_match_balance_shares();
        let witness = IntentAndBalancePrivateSettlementWitness {
            settlement_obligation0: obligation0,
            intent0: validity_bundle0.intent(),
            pre_settlement_amount_public_share0: validity_bundle0.new_amount_public_share(),
            input_balance0: validity_bundle0.balance(),
            pre_settlement_in_balance_shares0: validity_bundle0.post_match_balance_shares(),
            output_balance0,
            pre_settlement_out_balance_shares0,
            settlement_obligation1: obligation1,
            intent1: validity_bundle1.intent(),
            pre_settlement_amount_public_share1: validity_bundle1.new_amount_public_share(),
            input_balance1: validity_bundle1.balance(),
            pre_settlement_in_balance_shares1: validity_bundle1.post_match_balance_shares(),
            output_balance1,
            pre_settlement_out_balance_shares1,
        };

        // Make updates to the public shares for intents and balances of each party
        // Party 0
        let (
            new_amount_public_share0,
            new_in_balance_public_shares0,
            new_out_balance_public_shares0,
        ) = Self::apply_obligation_to_shares(
            witness.pre_settlement_amount_public_share0,
            &witness.pre_settlement_in_balance_shares0,
            &witness.pre_settlement_out_balance_shares0,
            &witness.settlement_obligation0,
            &fee_rates0,
        );

        // Party 1
        let (
            new_amount_public_share1,
            new_in_balance_public_shares1,
            new_out_balance_public_shares1,
        ) = Self::apply_obligation_to_shares(
            witness.pre_settlement_amount_public_share1,
            &witness.pre_settlement_in_balance_shares1,
            &witness.pre_settlement_out_balance_shares1,
            &witness.settlement_obligation1,
            &fee_rates1,
        );

        // Create the statement
        let statement = IntentAndBalancePrivateSettlementStatement {
            new_amount_public_share0,
            new_in_balance_public_shares0,
            new_out_balance_public_shares0,
            new_amount_public_share1,
            new_in_balance_public_shares1,
            new_out_balance_public_shares1,
            relayer_fee0: fee_rates0.relayer_fee_rate,
            relayer_fee1: fee_rates1.relayer_fee_rate,
            protocol_fee,
        };

        // Generate the proof
        let job = ProofJob::IntentAndBalancePrivateSettlement {
            witness,
            statement,
            validity_link_hint_0: validity_bundle0.linking_hint(),
            validity_link_hint_1: validity_bundle1.linking_hint(),
            output_balance_link_hint_0: output_bundle0.linking_hint(),
            output_balance_link_hint_1: output_bundle1.linking_hint(),
        };

        // Wait for a response
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(SettlementError::proof_generation)?;
        let bundle: IntentAndBalancePrivateSettlementBundle =
            proof_recv.await.map_err(SettlementError::proof_generation)?.into();

        Ok(bundle)
    }

    /// Apply an obligation to one party's pre-settlement public shares.
    fn apply_obligation_to_shares(
        pre_settlement_amount_public_share: Scalar,
        pre_settlement_in_balance_shares: &PostMatchBalanceShare,
        pre_settlement_out_balance_shares: &PostMatchBalanceShare,
        obligation: &SettlementObligation,
        fee_rates: &FeeRates,
    ) -> (Scalar, PostMatchBalanceShare, PostMatchBalanceShare) {
        let new_amount_public_share =
            pre_settlement_amount_public_share - Scalar::from(obligation.amount_in);

        let mut new_in_balance_public_shares = (*pre_settlement_in_balance_shares).clone();
        new_in_balance_public_shares.amount -= Scalar::from(obligation.amount_in);

        let fee_take = fee_rates.compute_fee_take(obligation.amount_out);
        let net_receive = obligation.amount_out - fee_take.total();
        let mut new_out_balance_public_shares = (*pre_settlement_out_balance_shares).clone();
        new_out_balance_public_shares.amount += Scalar::from(net_receive);
        new_out_balance_public_shares.relayer_fee_balance += Scalar::from(fee_take.relayer_fee);
        new_out_balance_public_shares.protocol_fee_balance += Scalar::from(fee_take.protocol_fee);

        (new_amount_public_share, new_in_balance_public_shares, new_out_balance_public_shares)
    }
}
