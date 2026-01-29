//! Defines a task to settle an external match
//!
//! An external match settles a match between an internal party (with state
//! in the darkpool) and an external party (with no state in the darkpool).

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use circuit_types::Amount;
use darkpool_client::errors::DarkpoolClientError;
use darkpool_types::bounded_match_result::BoundedMatchResult;
use renegade_solidity_abi::v2::IDarkpoolV2::SettlementBundle;
use serde::Serialize;
use state::error::StateError;
use system_bus::SystemBusMessage;
use tracing::{info, instrument};
use types_account::OrderId;
use types_core::AccountId;
use types_tasks::SettleExternalMatchTaskDescriptor;

use crate::{
    task_state::TaskStateWrapper,
    tasks::settlement::helpers::{SettlementProcessor, error::SettlementError},
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

/// The task name for the settle external match task
const SETTLE_EXTERNAL_MATCH_TASK_NAME: &str = "settle-external-match";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettleExternalMatchTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is generating calldata for the match settlement
    GeneratingCalldata,
    /// The task is responding to the client with the calldata
    ForwardingBoundedMatch,
    /// The task is completed
    Completed,
}

impl TaskState for SettleExternalMatchTaskState {
    fn commit_point() -> Self {
        SettleExternalMatchTaskState::ForwardingBoundedMatch
    }

    fn completed(&self) -> bool {
        matches!(self, SettleExternalMatchTaskState::Completed)
    }
}

impl Display for SettleExternalMatchTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            SettleExternalMatchTaskState::Pending => write!(f, "Pending"),
            SettleExternalMatchTaskState::GeneratingCalldata => write!(f, "Generating Calldata"),
            SettleExternalMatchTaskState::ForwardingBoundedMatch => {
                write!(f, "Forwarding Bounded Match")
            },
            SettleExternalMatchTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<SettleExternalMatchTaskState> for TaskStateWrapper {
    fn from(state: SettleExternalMatchTaskState) -> Self {
        TaskStateWrapper::SettleExternalMatch(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the settle external match task
#[derive(Clone, Debug, thiserror::Error)]
pub enum SettleExternalMatchTaskError {
    /// A darkpool client error
    #[error("darkpool client error: {0}")]
    Darkpool(String),
    /// A settlement error
    #[error("settlement error: {0}")]
    Settlement(String),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
    /// A miscellaneous error
    #[error("error: {0}")]
    Misc(String),
}

impl SettleExternalMatchTaskError {
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
}

impl TaskError for SettleExternalMatchTaskError {
    fn retryable(&self) -> bool {
        matches!(self, SettleExternalMatchTaskError::State(_))
    }
}

impl From<SettlementError> for SettleExternalMatchTaskError {
    fn from(e: SettlementError) -> Self {
        SettleExternalMatchTaskError::Settlement(e.to_string())
    }
}

impl From<StateError> for SettleExternalMatchTaskError {
    fn from(e: StateError) -> Self {
        SettleExternalMatchTaskError::State(e.to_string())
    }
}

impl From<DarkpoolClientError> for SettleExternalMatchTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        SettleExternalMatchTaskError::Darkpool(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, SettleExternalMatchTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to settle an external match
#[derive(Clone)]
pub struct SettleExternalMatchTask {
    /// The account ID for the internal order
    pub account_id: AccountId,
    /// The ID of the internal order
    pub order_id: OrderId,
    /// The requested input amount for the internal party
    pub amount_in: Amount,
    /// The bounded match result
    pub match_result: BoundedMatchResult,
    /// The system bus topic on which to send the response
    pub response_topic: String,
    /// The number of blocks the match remains valid from the current block
    pub validity_window_blocks: u64,
    /// The internal party's settlement bundle
    pub settlement_bundle: Option<SettlementBundle>,
    /// The state of the task's execution
    pub task_state: SettleExternalMatchTaskState,
    /// The settlement processor
    pub processor: SettlementProcessor,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for SettleExternalMatchTask {
    type State = SettleExternalMatchTaskState;
    type Error = SettleExternalMatchTaskError;
    type Descriptor = SettleExternalMatchTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        let processor = SettlementProcessor::new(ctx.clone());
        Ok(Self {
            account_id: descriptor.account_id,
            order_id: descriptor.order_id,
            amount_in: descriptor.amount_in,
            match_result: descriptor.match_result,
            response_topic: descriptor.response_topic,
            validity_window_blocks: descriptor.validity_window_blocks,
            settlement_bundle: None,
            task_state: SettleExternalMatchTaskState::Pending,
            processor,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            SettleExternalMatchTaskState::Pending => {
                self.task_state = SettleExternalMatchTaskState::GeneratingCalldata;
            },
            SettleExternalMatchTaskState::GeneratingCalldata => {
                self.generate_calldata().await?;
                self.task_state = SettleExternalMatchTaskState::ForwardingBoundedMatch;
            },
            SettleExternalMatchTaskState::ForwardingBoundedMatch => {
                self.forward_bounded_match().await?;
                self.task_state = SettleExternalMatchTaskState::Completed;
            },
            SettleExternalMatchTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        SETTLE_EXTERNAL_MATCH_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    /// External matches bypass the task queue to prevent raft contention
    fn bypass_task_queue(&self) -> bool {
        true
    }
}

impl Descriptor for SettleExternalMatchTaskDescriptor {
    fn bypass_task_queue(&self) -> bool {
        true
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl SettleExternalMatchTask {
    /// Generate calldata for the match settlement
    async fn generate_calldata(&mut self) -> Result<()> {
        info!("generating calldata for match settlement...");

        // Set a block deadline for the match result
        // This must be done before generating calldata as the executor must sign the
        // finalized bounded match result.
        let current_block = self.ctx.darkpool_client.block_number().await?;
        self.match_result.block_deadline = current_block + self.validity_window_blocks;

        // Generate the settlement bundle
        let obligation = self.match_result.to_internal_obligation(self.amount_in);
        let settlement_bundle = self
            .processor
            .build_ring0_external_settlement_bundle(
                self.order_id,
                obligation,
                self.match_result.clone(),
            )
            .await?;
        self.settlement_bundle = Some(settlement_bundle);

        Ok(())
    }

    /// Forward the bounded match to the client
    async fn forward_bounded_match(&self) -> Result<()> {
        info!("forwarding bounded match to client...");
        let settlement_bundle = self.settlement_bundle.clone().unwrap();
        let message = SystemBusMessage::ExternalOrderBundle {
            match_result: self.match_result.clone(),
            settlement_bundle,
        };

        self.ctx.bus.publish(self.response_topic.clone(), message);
        Ok(())
    }
}
