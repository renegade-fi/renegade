//! Interface methods for validity proof bundles and witnesses.

use alloy_primitives::Address;
use tracing::instrument;
use types_account::OrderId;
use types_core::AccountId;
use types_proofs::{
    IntentAndBalanceFirstFillValidityBundle, IntentAndBalanceValidityBundle,
    IntentOnlyFirstFillValidityBundle, IntentOnlyFirstFillValidityWitness,
    IntentOnlyValidityBundle, NewOutputBalanceValidityBundle, OutputBalanceValidityBundle,
    SizedIntentAndBalanceFirstFillValidityWitness, SizedIntentAndBalanceValidityWitness,
    SizedIntentOnlyValidityWitness, SizedNewOutputBalanceValidityWitness,
    SizedOutputBalanceValidityWitness, ValidityProofBundle, ValidityProofLocator,
};

use crate::{error::StateError, notifications::ProposalWaiter, state_transition::StateTransition};

use super::StateInner;

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Check whether an output balance validity proof exists for the given
    /// account and mint
    pub async fn has_output_balance_validity_proof(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<bool, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Balance { account_id, mint };
            let exists = tx.has_output_balance_validity_proof(&locator)?;
            Ok(exists)
        })
        .await
    }

    /// Get the intent-only validity proof for a given order (subsequent fill)
    pub async fn get_intent_only_validity_proof(
        &self,
        order_id: OrderId,
    ) -> Result<Option<IntentOnlyValidityBundle>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let bundle = tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator)?;
            Ok(bundle)
        })
        .await
    }

    /// Get the intent-only first-fill validity proof for a given order
    pub async fn get_intent_only_first_fill_validity_proof(
        &self,
        order_id: OrderId,
    ) -> Result<Option<IntentOnlyFirstFillValidityBundle>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let bundle = tx.get_validity_proof::<IntentOnlyFirstFillValidityBundle>(&locator)?;
            Ok(bundle)
        })
        .await
    }

    /// Get the intent-and-balance validity proof for a given order (subsequent
    /// fill)
    pub async fn get_intent_and_balance_validity_proof(
        &self,
        order_id: OrderId,
    ) -> Result<Option<IntentAndBalanceValidityBundle>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let bundle = tx.get_validity_proof::<IntentAndBalanceValidityBundle>(&locator)?;
            Ok(bundle)
        })
        .await
    }

    /// Get the intent-and-balance first-fill validity proof for a given order
    pub async fn get_intent_and_balance_first_fill_validity_proof(
        &self,
        order_id: OrderId,
    ) -> Result<Option<IntentAndBalanceFirstFillValidityBundle>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let bundle =
                tx.get_validity_proof::<IntentAndBalanceFirstFillValidityBundle>(&locator)?;
            Ok(bundle)
        })
        .await
    }

    /// Get the new-output-balance validity proof for an account and mint
    pub async fn get_new_output_balance_validity_proof(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<Option<NewOutputBalanceValidityBundle>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Balance { account_id, mint };
            let bundle = tx.get_validity_proof::<NewOutputBalanceValidityBundle>(&locator)?;
            Ok(bundle)
        })
        .await
    }

    /// Get the output-balance validity proof for an account and mint
    pub async fn get_output_balance_validity_proof(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<Option<OutputBalanceValidityBundle>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Balance { account_id, mint };
            let bundle = tx.get_validity_proof::<OutputBalanceValidityBundle>(&locator)?;
            Ok(bundle)
        })
        .await
    }

    // ----------------------------
    // | Proof + Witness Combined |
    // ----------------------------

    /// Get the intent-only validity proof and witness for a given order
    /// (subsequent fill)
    pub async fn get_intent_only_validity_proof_and_witness(
        &self,
        order_id: OrderId,
    ) -> Result<Option<(IntentOnlyValidityBundle, SizedIntentOnlyValidityWitness)>, StateError>
    {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let bundle = tx.get_validity_proof::<IntentOnlyValidityBundle>(&locator)?;
            let witness = tx.get_validity_witness::<SizedIntentOnlyValidityWitness>(&locator)?;
            Ok(bundle.zip(witness))
        })
        .await
    }

    /// Get the intent-only first-fill validity proof and witness for a given
    /// order
    pub async fn get_intent_only_first_fill_validity_proof_and_witness(
        &self,
        order_id: OrderId,
    ) -> Result<
        Option<(IntentOnlyFirstFillValidityBundle, IntentOnlyFirstFillValidityWitness)>,
        StateError,
    > {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let bundle = tx.get_validity_proof::<IntentOnlyFirstFillValidityBundle>(&locator)?;
            let witness =
                tx.get_validity_witness::<IntentOnlyFirstFillValidityWitness>(&locator)?;
            Ok(bundle.zip(witness))
        })
        .await
    }

    /// Get the intent-and-balance validity proof and witness for a given order
    /// (subsequent fill)
    pub async fn get_intent_and_balance_validity_proof_and_witness(
        &self,
        order_id: OrderId,
    ) -> Result<
        Option<(IntentAndBalanceValidityBundle, SizedIntentAndBalanceValidityWitness)>,
        StateError,
    > {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let bundle = tx.get_validity_proof::<IntentAndBalanceValidityBundle>(&locator)?;
            let witness =
                tx.get_validity_witness::<SizedIntentAndBalanceValidityWitness>(&locator)?;
            Ok(bundle.zip(witness))
        })
        .await
    }

    /// Get the intent-and-balance first-fill validity proof and witness for a
    /// given order
    pub async fn get_intent_and_balance_first_fill_validity_proof_and_witness(
        &self,
        order_id: OrderId,
    ) -> Result<
        Option<(
            IntentAndBalanceFirstFillValidityBundle,
            SizedIntentAndBalanceFirstFillValidityWitness,
        )>,
        StateError,
    > {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let bundle =
                tx.get_validity_proof::<IntentAndBalanceFirstFillValidityBundle>(&locator)?;
            let witness =
                tx.get_validity_witness::<SizedIntentAndBalanceFirstFillValidityWitness>(&locator)?;
            Ok(bundle.zip(witness))
        })
        .await
    }

    /// Get the new-output-balance validity proof and witness for an account
    /// and mint
    pub async fn get_new_output_balance_validity_proof_and_witness(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<
        Option<(NewOutputBalanceValidityBundle, SizedNewOutputBalanceValidityWitness)>,
        StateError,
    > {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Balance { account_id, mint };
            let bundle = tx.get_validity_proof::<NewOutputBalanceValidityBundle>(&locator)?;
            let witness =
                tx.get_validity_witness::<SizedNewOutputBalanceValidityWitness>(&locator)?;
            Ok(bundle.zip(witness))
        })
        .await
    }

    /// Get the output-balance validity proof and witness for an account and
    /// mint
    pub async fn get_output_balance_validity_proof_and_witness(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<Option<(OutputBalanceValidityBundle, SizedOutputBalanceValidityWitness)>, StateError>
    {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Balance { account_id, mint };
            let bundle = tx.get_validity_proof::<OutputBalanceValidityBundle>(&locator)?;
            let witness = tx.get_validity_witness::<SizedOutputBalanceValidityWitness>(&locator)?;
            Ok(bundle.zip(witness))
        })
        .await
    }

    // -------------------
    // | Witness Getters |
    // -------------------

    /// Get the intent-only validity witness for a given order (subsequent fill)
    pub async fn get_intent_only_validity_witness(
        &self,
        order_id: OrderId,
    ) -> Result<Option<SizedIntentOnlyValidityWitness>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let witness = tx.get_validity_witness::<SizedIntentOnlyValidityWitness>(&locator)?;
            Ok(witness)
        })
        .await
    }

    /// Get the intent-only first-fill validity witness for a given order
    pub async fn get_intent_only_first_fill_validity_witness(
        &self,
        order_id: OrderId,
    ) -> Result<Option<IntentOnlyFirstFillValidityWitness>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let witness =
                tx.get_validity_witness::<IntentOnlyFirstFillValidityWitness>(&locator)?;
            Ok(witness)
        })
        .await
    }

    /// Get the intent-and-balance validity witness for a given order
    /// (subsequent fill)
    pub async fn get_intent_and_balance_validity_witness(
        &self,
        order_id: OrderId,
    ) -> Result<Option<SizedIntentAndBalanceValidityWitness>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let witness =
                tx.get_validity_witness::<SizedIntentAndBalanceValidityWitness>(&locator)?;
            Ok(witness)
        })
        .await
    }

    /// Get the intent-and-balance first-fill validity witness for a given order
    pub async fn get_intent_and_balance_first_fill_validity_witness(
        &self,
        order_id: OrderId,
    ) -> Result<Option<SizedIntentAndBalanceFirstFillValidityWitness>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Intent { order_id };
            let witness =
                tx.get_validity_witness::<SizedIntentAndBalanceFirstFillValidityWitness>(&locator)?;
            Ok(witness)
        })
        .await
    }

    /// Get the new-output-balance validity witness for an account and mint
    pub async fn get_new_output_balance_validity_witness(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<Option<SizedNewOutputBalanceValidityWitness>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Balance { account_id, mint };
            let witness =
                tx.get_validity_witness::<SizedNewOutputBalanceValidityWitness>(&locator)?;
            Ok(witness)
        })
        .await
    }

    /// Get the output-balance validity witness for an account and mint
    pub async fn get_output_balance_validity_witness(
        &self,
        account_id: AccountId,
        mint: Address,
    ) -> Result<Option<SizedOutputBalanceValidityWitness>, StateError> {
        self.with_read_tx(move |tx| {
            let locator = ValidityProofLocator::Balance { account_id, mint };
            let witness = tx.get_validity_witness::<SizedOutputBalanceValidityWitness>(&locator)?;
            Ok(witness)
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Propose adding a validity proof for an intent, keyed by order id
    #[instrument(name = "add_intent_validity_proof", skip_all, err, fields(%order_id))]
    pub async fn add_intent_validity_proof(
        &self,
        order_id: OrderId,
        bundle: ValidityProofBundle,
    ) -> Result<ProposalWaiter, StateError> {
        let locator = ValidityProofLocator::Intent { order_id };
        self.send_proposal(StateTransition::AddValidityProof { locator, bundle }).await
    }

    /// Propose adding a validity proof for a balance, keyed by account id and
    /// mint
    #[instrument(name = "add_balance_validity_proof", skip_all, err, fields(%account_id, ?mint))]
    pub async fn add_balance_validity_proof(
        &self,
        account_id: AccountId,
        mint: Address,
        bundle: ValidityProofBundle,
    ) -> Result<ProposalWaiter, StateError> {
        let locator = ValidityProofLocator::Balance { account_id, mint };
        self.send_proposal(StateTransition::AddValidityProof { locator, bundle }).await
    }
}
