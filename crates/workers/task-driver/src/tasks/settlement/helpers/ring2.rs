//! Ring 2 settlement helpers

use alloy::{primitives::U256, rpc::types::TransactionReceipt};
use circuits_core::zk_circuits::settlement::{
    intent_and_balance_bounded_settlement::{
        IntentAndBalanceBoundedSettlementStatement, IntentAndBalanceBoundedSettlementWitness,
    },
    intent_and_balance_public_settlement::{
        IntentAndBalancePublicSettlementStatement, IntentAndBalancePublicSettlementWitness,
    },
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
use types_account::balance::{Balance, BalanceLocation};
use types_account::{OrderId, order::Order, pair::Pair};
use types_core::AccountId;
use types_proofs::{
    IntentAndBalanceBoundedSettlementBundle, IntentAndBalanceFirstFillValidityBundle,
    IntentAndBalancePublicSettlementBundle, IntentAndBalanceValidityBundle,
    SizedIntentAndBalanceFirstFillValidityWitness, SizedIntentAndBalanceValidityWitness,
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
            self.get_private_first_fill_validity_bundle(order.id).await?;
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
            self.get_private_subsequent_fill_validity_bundle(order.id).await?;
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
        order: Order,
        obligation: SettlementObligation,
        match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        let account_id = self.get_account_id_for_order(order.id).await?;
        let (validity_bundle, validity_witness) =
            self.get_private_first_fill_validity_bundle(order.id).await?;
        let output_bundle = self.get_output_balance_bundle(account_id, &order).await?;

        let settlement_data = self
            .prove_intent_and_balance_bounded_settlement(
                validity_witness.intent.clone(),
                validity_witness.balance.clone(),
                output_bundle.balance(),
                validity_witness.new_amount_public_share,
                validity_witness.post_match_balance_shares.clone(),
                output_bundle.post_match_balance_shares(),
                obligation.clone(),
                match_res,
                validity_bundle.linking_hint.clone(),
                output_bundle.linking_hint(),
            )
            .await?
            .into_inner();

        let auth = RenegadeSettledIntentAuthBundleFirstFill {
            merkleDepth: U256::from(MERKLE_HEIGHT),
            statement: validity_bundle.statement.clone().into(),
            validityProof: validity_bundle.proof.clone().into(),
        };

        let link_proof = settlement_data.output_balance_link_proof.clone();
        let output_bundle = output_bundle.build_abi_bundle(link_proof);

        Ok(SettlementBundle::renegade_settled_private_intent_bounded_first_fill(
            auth,
            output_bundle,
            settlement_data.statement.into(),
            settlement_data.proof.into(),
            settlement_data.validity_link_proof.into(),
        ))
    }

    /// Build a subsequent-fill external settlement bundle for Ring 2
    async fn build_ring2_external_subsequent_fill(
        &self,
        order: Order,
        obligation: SettlementObligation,
        match_res: BoundedMatchResult,
    ) -> Result<SettlementBundle, SettlementError> {
        let account_id = self.get_account_id_for_order(order.id).await?;
        let (validity_bundle, validity_witness) =
            self.get_private_subsequent_fill_validity_bundle(order.id).await?;
        let output_bundle = self.get_output_balance_bundle(account_id, &order).await?;

        let settlement_data = self
            .prove_intent_and_balance_bounded_settlement(
                validity_witness.intent.clone(),
                validity_witness.balance.clone(),
                output_bundle.balance(),
                validity_witness.new_amount_public_share,
                validity_witness.post_match_balance_shares.clone(),
                output_bundle.post_match_balance_shares(),
                obligation.clone(),
                match_res,
                validity_bundle.linking_hint.clone(),
                output_bundle.linking_hint(),
            )
            .await?
            .into_inner();

        let auth = RenegadeSettledIntentAuthBundle {
            merkleDepth: U256::from(MERKLE_HEIGHT),
            statement: validity_bundle.statement.clone().into(),
            validityProof: validity_bundle.proof.clone().into(),
        };

        let link_proof = settlement_data.output_balance_link_proof.clone();
        let output_bundle = output_bundle.build_abi_bundle(link_proof);

        Ok(SettlementBundle::renegade_settled_private_intent_bounded(
            auth,
            output_bundle,
            settlement_data.statement.into(),
            settlement_data.proof.into(),
            settlement_data.validity_link_proof.into(),
        ))
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

    /// Generate a proof of `INTENT AND BALANCE BOUNDED SETTLEMENT`
    #[allow(clippy::too_many_arguments)]
    async fn prove_intent_and_balance_bounded_settlement(
        &self,
        intent: Intent,
        in_balance: DarkpoolBalance,
        out_balance: DarkpoolBalance,
        amount_share: Scalar,
        in_balance_share: PostMatchBalanceShare,
        out_balance_share: PostMatchBalanceShare,
        obligation: SettlementObligation,
        match_res: BoundedMatchResult,
        validity_link_hint: ProofLinkingHint,
        output_balance_link_hint: ProofLinkingHint,
    ) -> Result<IntentAndBalanceBoundedSettlementBundle, SettlementError> {
        // The public shares on the input values are pre-update
        // The bounded fill circuit does not update the public shares directly, so no
        // updates need to be made in constructing the witness & statement
        let witness = IntentAndBalanceBoundedSettlementWitness {
            intent,
            in_balance: in_balance.clone(),
            out_balance: out_balance.clone(),
            pre_settlement_amount_public_share: amount_share,
            pre_settlement_in_balance_shares: in_balance_share.clone(),
            pre_settlement_out_balance_shares: out_balance_share.clone(),
        };

        let pair = Pair::from_obligation(&obligation);
        let (internal_relayer_fee, relayer_fee_recipient) = self.relayer_fee(&pair.base_token())?;
        let statement = IntentAndBalanceBoundedSettlementStatement {
            bounded_match_result: match_res,
            amount_public_share: amount_share,
            in_balance_public_shares: in_balance_share,
            out_balance_public_shares: out_balance_share,
            internal_relayer_fee,
            external_relayer_fee: Default::default(),
            relayer_fee_recipient,
        };

        let job = ProofJob::IntentAndBalanceBoundedSettlement {
            witness,
            statement,
            validity_link_hint: validity_link_hint.clone(),
            output_balance_link_hint: output_balance_link_hint.clone(),
        };

        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(SettlementError::proof_generation)?;
        let bundle: IntentAndBalanceBoundedSettlementBundle =
            proof_recv.await.map_err(SettlementError::proof_generation)?.into();

        Ok(bundle)
    }

    // --- Proof Retrieval --- //

    /// Get the first fill validity proof bundle for a Ring 2 order
    pub(crate) async fn get_private_first_fill_validity_bundle(
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
    pub(crate) async fn get_private_subsequent_fill_validity_bundle(
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

// -----------------
// | State Updates |
// -----------------

impl SettlementProcessor {
    /// Update an intent after a Ring 2 match settlement
    ///
    /// The intent update mirrors Ring 1: re-encrypt the `amount_in` share on
    /// subsequent fills, decrement the remaining amount, and advance the
    /// recovery stream so the stored order matches the post-settlement
    /// Merkle leaf.
    pub async fn update_ring2_intent_after_match(
        &self,
        order: &mut Order,
        obligation: &SettlementObligation,
    ) -> Result<(), SettlementError> {
        // Re-encrypt only for subsequent fills; first fill uses initial shares
        if order.metadata.has_been_filled {
            order.intent.reencrypt_amount_in();
        }

        // Decrement amount in then advance the recovery stream
        order.decrement_amount_in(obligation.amount_in);
        order.intent.advance_recovery_stream();
        order.metadata.mark_filled();
        Ok(())
    }

    /// Build the post-settlement input balance for a Ring 2 order
    ///
    /// Re-encrypts the post-match shares (the validity proof always
    /// re-encrypts before the settlement circuit runs), applies the
    /// settlement obligation to decrement the input amount, and advances the
    /// recovery stream.
    pub async fn build_updated_input_balance(
        &self,
        account_id: AccountId,
        obligation: &SettlementObligation,
    ) -> Result<Balance, SettlementError> {
        let mut balance =
            self.get_balance(account_id, obligation.input_token, BalanceLocation::Darkpool).await?;

        // Re-encrypt the post-match shares to match the validity proof state
        balance.state_wrapper.reencrypt_post_match_share();

        // Subtract the obligation amount from both inner value and public share
        balance.state_wrapper.apply_obligation_in_balance(obligation);

        // Advance the recovery stream for the next validity proof cycle
        balance.state_wrapper.advance_recovery_stream();

        Ok(balance)
    }

    /// Build the post-settlement output balance for a Ring 2 order
    ///
    /// Handles both newly created output balances and existing ones:
    /// - **Existing**: fetched from state, post-match shares re-encrypted
    /// - **New**: fetched from the `NEW OUTPUT BALANCE VALIDITY` witness
    ///
    /// In both cases the settlement obligation is applied (receive amount
    /// net of fees credited, fees accrued) and the recovery stream is
    /// advanced.
    pub async fn build_updated_output_balance(
        &self,
        account_id: AccountId,
        order: &Order,
        obligation: &SettlementObligation,
        apply_fees: bool,
    ) -> Result<Balance, SettlementError> {
        let output_mint = order.intent.inner.out_token;
        let has_balance = self.ctx.state.has_darkpool_balance(&account_id, &output_mint).await?;
        let mut balance = if has_balance {
            self.build_existing_output_balance(account_id, output_mint).await?
        } else {
            self.build_new_output_balance(account_id, output_mint).await?
        };

        // Compute fees and apply only the net receive amount to the output
        // balance. For this settlement path, fee transfers are handled as
        // external transfers by the contract and are not accrued on-balance.
        let pair = Pair::from_obligation(obligation);
        let fee_rates = self.fee_rates(&pair)?;
        let fee_take = fee_rates.compute_fee_take(obligation.amount_out);

        if apply_fees {
            balance.state_wrapper.apply_obligation_out_balance(obligation, &fee_take);
        } else {
            balance.state_wrapper.apply_obligation_out_balance_no_fees(obligation, &fee_take);
        }

        // Advance the recovery stream for the next validity proof cycle
        balance.state_wrapper.advance_recovery_stream();

        Ok(balance)
    }

    /// Build the updated state for an existing output balance
    ///
    /// Re-encrypts the post-match shares to match the validity proof
    /// re-encryption that preceded the settlement circuit.
    ///
    /// This re-encryption is only necessary for existing output balances. New
    /// output balances sign their initial shares and don't need to be
    /// re-encrypted.
    async fn build_existing_output_balance(
        &self,
        account_id: AccountId,
        mint: alloy::primitives::Address,
    ) -> Result<Balance, SettlementError> {
        let mut balance = self.get_balance(account_id, mint, BalanceLocation::Darkpool).await?;

        // Re-encrypt post-match shares to match the validity proof state
        balance.state_wrapper.reencrypt_post_match_share();
        Ok(balance)
    }

    /// Build the updated state for a newly created output balance
    ///
    /// Fetches the initial balance from the stored `NEW OUTPUT BALANCE
    /// VALIDITY` proof witness. No re-encryption is needed because the
    /// shares are fresh from creation.
    async fn build_new_output_balance(
        &self,
        account_id: AccountId,
        mint: alloy::primitives::Address,
    ) -> Result<Balance, SettlementError> {
        let (_, witness) = self
            .ctx
            .state
            .get_new_output_balance_validity_proof_and_witness(account_id, mint)
            .await?
            .ok_or_else(|| {
                SettlementError::state(format!(
                    "new output balance validity proof not found for account {account_id} \
                     and mint {mint}"
                ))
            })?;

        Ok(Balance::new_darkpool(witness.new_balance))
    }

    /// Extract and store Merkle authentication paths for both the input and
    /// output balances of a Ring 2 order from a settlement transaction
    /// receipt
    ///
    /// Computes the post-settlement balance commitments and looks them up in
    /// the receipt's `MerkleInsertion` events.
    pub async fn update_ring2_balance_merkle_proofs_after_match(
        &self,
        account_id: AccountId,
        updated_input_balance: &Balance,
        updated_output_balance: &Balance,
        receipt: &TransactionReceipt,
    ) -> Result<(), SettlementError> {
        let in_fut = self.store_balance_merkle_proof(account_id, updated_input_balance, receipt);
        let out_fut = self.store_balance_merkle_proof(account_id, updated_output_balance, receipt);

        tokio::try_join!(in_fut, out_fut)?;
        Ok(())
    }

    /// Compute a balance's commitment, find the corresponding Merkle path
    /// in the receipt, and persist it in state
    async fn store_balance_merkle_proof(
        &self,
        account_id: AccountId,
        balance: &Balance,
        receipt: &TransactionReceipt,
    ) -> Result<(), SettlementError> {
        let commitment = balance.state_wrapper.compute_commitment();
        let mint = balance.mint();

        let merkle_proof = self
            .ctx
            .darkpool_client
            .find_merkle_authentication_path_with_tx(commitment, receipt)
            .map_err(SettlementError::darkpool)?;

        let waiter =
            self.ctx.state.add_balance_merkle_proof(account_id, mint, merkle_proof).await?;
        waiter.await.map_err(SettlementError::from)?;

        Ok(())
    }
}
