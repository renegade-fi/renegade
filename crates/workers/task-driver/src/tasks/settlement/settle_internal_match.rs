//! Defines a task to settle an internal match

use std::fmt::{Display, Formatter, Result as FmtResult};

use ark_mpc::{PARTY0, PARTY1, network::PartyId};
use async_trait::async_trait;
use darkpool_client::errors::DarkpoolClientError;
use darkpool_types::settlement_obligation::SettlementObligation;
use serde::Serialize;
use state::error::StateError;
use tracing::{info, instrument};
use types_account::OrderId;
use types_core::MatchResult;
use types_core::{AccountId, TimestampedPriceFp};
use types_tasks::SettleInternalMatchTaskDescriptor;

use crate::hooks::RunMatchingEngineHook;
use crate::tasks::settlement::helpers::error::SettlementError;
use crate::tasks::settlement::helpers::{SettlementProcessor, branch_party};
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
    /// A signing error
    #[error("signing error: {0}")]
    Signing(String),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
    /// A miscellaneous error
    #[error("error: {0}")]
    Misc(String),
}

impl SettleInternalMatchTaskError {
    /// Create a signing error
    #[allow(clippy::needless_pass_by_value)]
    pub fn signing<T: ToString>(e: T) -> Self {
        Self::Signing(e.to_string())
    }

    /// Create a state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(e: T) -> Self {
        Self::State(e.to_string())
    }

    /// Create a miscellaneous error
    #[allow(clippy::needless_pass_by_value)]
    pub fn misc<T: ToString>(e: T) -> Self {
        Self::Misc(e.to_string())
    }

    /// Create an order not found error
    pub fn order_not_found(order_id: OrderId) -> Self {
        Self::State(format!("Order not found: {order_id}"))
    }

    /// Create an order auth not found error
    pub fn order_auth_not_found(order_id: OrderId) -> Self {
        Self::State(format!("Order auth not found: {order_id}"))
    }
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
    /// Submit the transaction to the contract
    async fn submit_tx(&self) -> Result<()> {
        let obligation_bundle = self.processor.public_obligation_bundle(&self.match_result);
        let obligation0 = self.get_obligation(PARTY0)?.clone();
        let obligation1 = self.get_obligation(PARTY1)?.clone();
        let settlement_bundle0 = self
            .processor
            .build_ring0_internal_settlement_bundle(self.order_id, obligation0)
            .await?;
        let settlement_bundle1 = self
            .processor
            .build_ring0_internal_settlement_bundle(self.other_order_id, obligation1)
            .await?;

        // Submit the transaction
        let tx = self
            .ctx
            .darkpool_client
            .settle_match(obligation_bundle, settlement_bundle0, settlement_bundle1)
            .await?;

        info!("Settled match with tx hash: {}", tx.transaction_hash);
        Ok(())
    }

    /// Update the account state for the parties involved in the match
    ///
    /// This involves decreasing the amount remaining on the matched orders and
    /// the input balances.
    ///
    /// The output balances are not updated except by the chain events listener
    /// as we only update balances for amounts approved to the darkpool for
    /// matching.
    async fn update_state(&self) -> Result<()> {
        self.update_state_for_party(PARTY0).await?;
        self.update_state_for_party(PARTY1).await?;
        Ok(())
    }

    /// Update the state for a given party
    async fn update_state_for_party(&self, party_id: PartyId) -> Result<()> {
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let order_id = branch_party!(party_id, self.order_id, self.other_order_id);
        let obligation = self.get_obligation(party_id)?;

        self.processor.update_input_balance(account_id, obligation.input_token, obligation).await?;
        self.processor.update_order_amount_in(order_id, obligation).await?;
        Ok(())
    }
}

// -----------
// | Helpers |
// -----------

impl SettleInternalMatchTask {
    /// Get the obligation for a given party
    fn get_obligation(&self, party_id: PartyId) -> Result<&SettlementObligation> {
        let obligation = branch_party!(
            party_id,
            &self.match_result.party0_obligation,
            &self.match_result.party1_obligation
        );
        Ok(obligation)
    }
}
