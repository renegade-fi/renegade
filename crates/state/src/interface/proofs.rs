//! Interface methods for validity proof bundles.

use alloy_primitives::Address;
use tracing::instrument;
use types_account::OrderId;
use types_core::AccountId;
use types_proofs::{ValidityProofBundle, ValidityProofLocator};

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
