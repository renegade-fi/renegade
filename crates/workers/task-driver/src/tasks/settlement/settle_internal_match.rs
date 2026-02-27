//! Defines a task to settle an internal match

use std::fmt::{Display, Formatter, Result as FmtResult};

use alloy::rpc::types::TransactionReceipt;
use ark_mpc::{PARTY0, PARTY1, network::PartyId};
use async_trait::async_trait;
use darkpool_client::errors::DarkpoolClientError;
use darkpool_types::settlement_obligation::SettlementObligation;
use renegade_metrics::record_match_volume;
use serde::Serialize;
use state::error::StateError;
use tracing::instrument;
use types_account::OrderId;
use types_account::balance::Balance;
use types_account::order::{Order, PrivacyRing};
use types_core::MatchResult;
use types_core::{AccountId, TimestampedPriceFp};
use types_tasks::SettleInternalMatchTaskDescriptor;

use crate::hooks::RunMatchingEngineHook;
use crate::tasks::settlement::helpers::error::SettlementError;
use crate::tasks::settlement::helpers::{SettlementProcessor, branch_party};
use crate::tasks::validity_proofs::error::ValidityProofsError;
use crate::tasks::validity_proofs::intent_and_balance::update_intent_and_balance_validity_proof;
use crate::tasks::validity_proofs::intent_only::update_intent_only_validity_proof;
use crate::tasks::validity_proofs::output_balance::update_output_balance_validity_proof;
use crate::{
    hooks::{RefreshAccountHook, TaskHook},
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

/// The task name for the settle internal match task
const SETTLE_INTERNAL_MATCH_TASK_NAME: &str = "settle-internal-match";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettleInternalMatchTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is submitting the transaction
    SubmittingTx,
    /// The task is updating the account state for the parties involved in the
    /// match
    UpdatingState,
    /// The task is regenerating validity proofs for private (Ring 1+) orders
    UpdatingValidityProofs,
    /// The task is completed
    Completed,
}

impl TaskState for SettleInternalMatchTaskState {
    fn commit_point() -> Self {
        SettleInternalMatchTaskState::SubmittingTx
    }

    fn completed(&self) -> bool {
        matches!(self, SettleInternalMatchTaskState::Completed)
    }
}

impl Display for SettleInternalMatchTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            SettleInternalMatchTaskState::Pending => write!(f, "Pending"),
            SettleInternalMatchTaskState::SubmittingTx => write!(f, "SubmittingTx"),
            SettleInternalMatchTaskState::UpdatingState => write!(f, "UpdatingState"),
            SettleInternalMatchTaskState::UpdatingValidityProofs => {
                write!(f, "UpdatingValidityProofs")
            },
            SettleInternalMatchTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<SettleInternalMatchTaskState> for TaskStateWrapper {
    fn from(state: SettleInternalMatchTaskState) -> Self {
        TaskStateWrapper::SettleInternalMatch(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the settle internal match task
#[derive(Clone, Debug, thiserror::Error)]
pub enum SettleInternalMatchTaskError {
    /// A darkpool client error
    #[error("darkpool client error: {0}")]
    Darkpool(String),
    /// A settlement error
    #[error("settlement error: {0}")]
    Settlement(String),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
    /// A validity proof generation error
    #[error("validity proof error: {0}")]
    ValidityProofs(String),
}

impl TaskError for SettleInternalMatchTaskError {
    fn retryable(&self) -> bool {
        matches!(self, SettleInternalMatchTaskError::State(_))
    }
}

impl From<SettlementError> for SettleInternalMatchTaskError {
    fn from(e: SettlementError) -> Self {
        SettleInternalMatchTaskError::Settlement(e.to_string())
    }
}

impl From<StateError> for SettleInternalMatchTaskError {
    fn from(e: StateError) -> Self {
        SettleInternalMatchTaskError::State(e.to_string())
    }
}

impl From<DarkpoolClientError> for SettleInternalMatchTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        SettleInternalMatchTaskError::Darkpool(e.to_string())
    }
}

impl From<ValidityProofsError> for SettleInternalMatchTaskError {
    fn from(e: ValidityProofsError) -> Self {
        SettleInternalMatchTaskError::ValidityProofs(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, SettleInternalMatchTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to settle an internal match
#[derive(Clone)]
pub struct SettleInternalMatchTask {
    /// The account ID for the initiating order
    pub account_id: AccountId,
    /// The account ID for the counterparty order
    pub other_account_id: AccountId,
    /// The ID of the initiating order
    pub order_id: OrderId,
    /// The ID of the counterparty order
    pub other_order_id: OrderId,
    /// The price at which the match was executed
    pub execution_price: TimestampedPriceFp,
    /// The match result
    pub match_result: MatchResult,
    /// The initiating order after settlement-derived intent updates
    pub updated_order0: Option<Order>,
    /// The counterparty order after settlement-derived intent updates
    pub updated_order1: Option<Order>,
    /// The updated input balance for party 0 (Ring 2+ only)
    pub updated_input_balance0: Option<Balance>,
    /// The updated input balance for party 1 (Ring 2+ only)
    pub updated_input_balance1: Option<Balance>,
    /// The updated output balance for party 0 (Ring 2+ only)
    pub updated_output_balance0: Option<Balance>,
    /// The updated output balance for party 1 (Ring 2+ only)
    pub updated_output_balance1: Option<Balance>,
    /// The state of the task's execution
    pub task_state: SettleInternalMatchTaskState,
    /// The settlement processor
    pub processor: SettlementProcessor,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for SettleInternalMatchTask {
    type State = SettleInternalMatchTaskState;
    type Error = SettleInternalMatchTaskError;
    type Descriptor = SettleInternalMatchTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        let processor = SettlementProcessor::new(ctx.clone());
        Ok(Self {
            account_id: descriptor.account_id,
            other_account_id: descriptor.other_account_id,
            order_id: descriptor.order_id,
            other_order_id: descriptor.other_order_id,
            execution_price: descriptor.execution_price,
            match_result: descriptor.match_result,
            updated_order0: None,
            updated_order1: None,
            updated_input_balance0: None,
            updated_input_balance1: None,
            updated_output_balance0: None,
            updated_output_balance1: None,
            task_state: SettleInternalMatchTaskState::Pending,
            processor,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            SettleInternalMatchTaskState::Pending => {
                self.task_state = SettleInternalMatchTaskState::SubmittingTx;
            },
            SettleInternalMatchTaskState::SubmittingTx => {
                self.submit_tx().await?;
                self.task_state = SettleInternalMatchTaskState::UpdatingState;
            },
            SettleInternalMatchTaskState::UpdatingState => {
                self.update_state().await?;
                self.task_state = SettleInternalMatchTaskState::UpdatingValidityProofs;
            },
            SettleInternalMatchTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                record_match_volume(
                    &self.match_result,
                    false, // is_external_match
                    &[self.account_id, self.other_account_id],
                );
                self.task_state = SettleInternalMatchTaskState::Completed;
            },
            SettleInternalMatchTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        SETTLE_INTERNAL_MATCH_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    // Re-run the matching engine on both orders for recursive fills
    fn success_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        // Create a hook for each order/account pair
        let engine_run1 = RunMatchingEngineHook::new(self.account_id, vec![self.order_id]);
        let engine_run2 =
            RunMatchingEngineHook::new(self.other_account_id, vec![self.other_order_id]);
        vec![Box::new(engine_run1), Box::new(engine_run2)]
    }

    // Refresh both accounts after a failure
    fn failure_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let refresh = RefreshAccountHook::new(vec![self.account_id, self.other_account_id]);
        vec![Box::new(refresh)]
    }
}

impl Descriptor for SettleInternalMatchTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl SettleInternalMatchTask {
    /// Submit the settlement transaction and extract Merkle proofs
    ///
    /// After the transaction lands, Merkle proofs are extracted from the
    /// receipt for any Ring 1+ orders so subsequent validity proofs can
    /// reference the new Merkle leaf.
    async fn submit_tx(&mut self) -> Result<()> {
        let obligation_bundle = self.processor.public_obligation_bundle(&self.match_result);
        let obligation0 = self.get_obligation(PARTY0)?.clone();
        let obligation1 = self.get_obligation(PARTY1)?.clone();
        let settlement_bundle0 = self
            .processor
            .build_internal_settlement_bundle(self.order_id, obligation0.clone())
            .await?;
        let settlement_bundle1 = self
            .processor
            .build_internal_settlement_bundle(self.other_order_id, obligation1.clone())
            .await?;

        // Submit the transaction
        let receipt = self
            .ctx
            .darkpool_client
            .settle_match(obligation_bundle, settlement_bundle0, settlement_bundle1)
            .await?;

        // Get an updated version of the orders and store them for later steps
        let order0 = self.processor.build_updated_intent(self.order_id, &obligation0).await?;
        let order1 = self.processor.build_updated_intent(self.other_order_id, &obligation1).await?;
        self.updated_order0 = Some(order0);
        self.updated_order1 = Some(order1);

        // For Ring 2 parties, build updated input and output balances
        self.build_updated_balances_for_party(PARTY0, &obligation0).await?;
        self.build_updated_balances_for_party(PARTY1, &obligation1).await?;

        // Extract and store Merkle proofs for Ring 1+ orders
        self.update_merkle_proofs(&receipt).await?;
        Ok(())
    }

    /// Extract and store Merkle proofs for both parties from the settlement
    /// receipt
    async fn update_merkle_proofs(
        &self,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Result<()> {
        let party0_fut = self.update_merkle_proof_for_party(PARTY0, receipt);
        let party1_fut = self.update_merkle_proof_for_party(PARTY1, receipt);
        tokio::try_join!(party0_fut, party1_fut)?;
        Ok(())
    }

    /// Extract and store the Merkle proof for a single party's order and,
    /// for Ring 2 parties, both input and output balance Merkle proofs
    async fn update_merkle_proof_for_party(
        &self,
        party_id: PartyId,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Result<()> {
        let order =
            branch_party!(party_id, &self.updated_order0, &self.updated_order1).as_ref().unwrap();
        self.processor.update_intent_merkle_proof_after_match(order, receipt).await?;

        // For Ring 2 parties, extract and store balance Merkle proofs
        if order.ring != PrivacyRing::Ring2 {
            return Ok(());
        }

        self.update_ring2_balance_merkle_proofs_after_match(party_id, receipt).await?;
        Ok(())
    }

    /// Update balance Merkle proofs for a ring 2 party
    async fn update_ring2_balance_merkle_proofs_after_match(
        &self,
        party_id: PartyId,
        receipt: &TransactionReceipt,
    ) -> Result<()> {
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let input_balance =
            branch_party!(party_id, &self.updated_input_balance0, &self.updated_input_balance1)
                .as_ref()
                .unwrap();
        let output_balance =
            branch_party!(party_id, &self.updated_output_balance0, &self.updated_output_balance1)
                .as_ref()
                .unwrap();

        self.processor
            .update_ring2_balance_merkle_proofs_after_match(
                account_id,
                input_balance,
                output_balance,
                receipt,
            )
            .await?;

        Ok(())
    }

    /// Update the account state for the parties involved in the match
    ///
    /// This involves decreasing the amount remaining on the matched orders and
    /// the input balances. For Ring 1+ orders the intent shares and streams
    /// are also advanced to match the post-settlement Merkle leaf.
    ///
    /// For Ring 2 orders the pre-computed darkpool input and output balances
    /// are written to state. For Ring 0/1 orders only the EOA input balance
    /// amount is decremented.
    async fn update_state(&self) -> Result<()> {
        let party0_fut = self.update_state_for_party(PARTY0);
        let party1_fut = self.update_state_for_party(PARTY1);
        tokio::try_join!(party0_fut, party1_fut)?;
        Ok(())
    }

    /// Update the state for a given party
    async fn update_state_for_party(&self, party_id: PartyId) -> Result<()> {
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let obligation = self.get_obligation(party_id)?;
        let order =
            branch_party!(party_id, &self.updated_order0, &self.updated_order1).clone().unwrap();

        // Update the balances for the party
        let updated_balances = self.get_updated_balances(party_id);
        self.processor
            .update_balances_after_match(account_id, &order, obligation, updated_balances)
            .await?;

        // Update the order after settlement
        self.processor.update_order_after_match(order).await?;
        Ok(())
    }

    /// Regenerate validity proofs for Ring 1+ orders after settlement
    ///
    /// The stored order already has the correct re-encrypted shares and
    /// advanced stream states (from `update_order_after_match`), so the
    /// validity proof generator can read the order directly from state.
    async fn update_validity_proofs(&self) -> Result<()> {
        let party0_fut = self.update_validity_proofs_for_party(PARTY0);
        let party1_fut = self.update_validity_proofs_for_party(PARTY1);
        tokio::try_join!(party0_fut, party1_fut)?;
        Ok(())
    }

    /// Regenerate the validity proof for a single party's order if it is a
    /// private (Ring 1+) order
    ///
    /// Ring 1 orders use `INTENT ONLY VALIDITY`. Ring 2 orders use both
    /// `INTENT AND BALANCE VALIDITY` and `OUTPUT BALANCE VALIDITY`.
    async fn update_validity_proofs_for_party(&self, party_id: PartyId) -> Result<()> {
        let order_id = branch_party!(party_id, self.order_id, self.other_order_id);
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let order = self.processor.get_order(order_id).await?;

        match order.ring {
            PrivacyRing::Ring0 => Ok(()),
            PrivacyRing::Ring1 => {
                update_intent_only_validity_proof(order_id, &self.ctx).await?;
                Ok(())
            },
            PrivacyRing::Ring2 => self.update_ring2_validity_proofs(account_id, order_id).await,
            _ => unimplemented!("validity proof update for ring {:?}", order.ring),
        }
    }

    /// Regenerate both the intent-and-balance and output-balance validity
    /// proofs for a Ring 2 order after settlement
    async fn update_ring2_validity_proofs(
        &self,
        account_id: AccountId,
        order_id: OrderId,
    ) -> Result<()> {
        let (intent_sig, out_balance_sig) =
            self.processor.get_renegade_settled_auth(order_id).await?;

        update_intent_and_balance_validity_proof(account_id, order_id, intent_sig, &self.ctx)
            .await?;

        update_output_balance_validity_proof(
            account_id,
            order_id,
            out_balance_sig,
            false, // force
            &self.ctx,
        )
        .await?;

        Ok(())
    }
}

// -----------
// | Helpers |
// -----------

impl SettleInternalMatchTask {
    /// Get the pre-computed updated balances for a party, if any
    ///
    /// Returns `Some((input, output))` for Ring 2 parties whose balances
    /// were pre-computed, or `None` for Ring 0/1 parties.
    fn get_updated_balances(&self, party_id: PartyId) -> Option<(Balance, Balance)> {
        let input =
            branch_party!(party_id, &self.updated_input_balance0, &self.updated_input_balance1)
                .clone();
        let output =
            branch_party!(party_id, &self.updated_output_balance0, &self.updated_output_balance1)
                .clone();
        input.zip(output)
    }

    /// Get the obligation for a given party
    fn get_obligation(&self, party_id: PartyId) -> Result<&SettlementObligation> {
        let obligation = branch_party!(
            party_id,
            &self.match_result.party0_obligation,
            &self.match_result.party1_obligation
        );
        Ok(obligation)
    }

    /// Build updated input and output balances for a Ring 2 party
    ///
    /// For Ring 0/1 parties this is a no-op since their balances are
    /// EOA-based and only require a simple amount decrement.
    async fn build_updated_balances_for_party(
        &mut self,
        party_id: PartyId,
        obligation: &SettlementObligation,
    ) -> Result<()> {
        let order =
            branch_party!(party_id, &self.updated_order0, &self.updated_order1).as_ref().unwrap();
        if order.ring != PrivacyRing::Ring2 {
            return Ok(());
        }

        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let input_balance =
            self.processor.build_updated_input_balance(account_id, obligation).await?;

        // Build an updated output balance
        // We don't apply fees here as the settlement was public, and fees are
        // transferred externally by the contract to their recipients.
        let output_balance = self
            .processor
            .build_updated_output_balance(
                account_id, order, obligation, false, // apply_fees
            )
            .await?;

        // Store the updated balances for later steps
        match party_id {
            PARTY0 => {
                self.updated_input_balance0 = Some(input_balance);
                self.updated_output_balance0 = Some(output_balance);
            },
            PARTY1 => {
                self.updated_input_balance1 = Some(input_balance);
                self.updated_output_balance1 = Some(output_balance);
            },
            _ => unreachable!("invalid party ID: {party_id}"),
        }

        Ok(())
    }
}
