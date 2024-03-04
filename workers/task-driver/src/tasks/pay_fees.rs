//! The `PayFees` task is responsible for settling the fees due for a given
//! wallet

// TODO: Remove this lint allowance
#![allow(unused)]

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use common::types::{tasks::PayFeesTaskDescriptor, wallet::WalletIdentifier};
use job_types::proof_manager::ProofManagerQueue;
use num_bigint::BigUint;
use serde::Serialize;
use state::{error::StateError, State};
use tracing::instrument;

use crate::{
    driver::StateWrapper,
    traits::{Task, TaskContext, TaskError, TaskState},
};

/// The name of the task
const TASK_NAME: &str = "pay-fees";

// --------------
// | Task State |
// --------------

/// Defines the state of the fee payment task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum PayFeesTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is proving relayer fee payment for the ith balance
    ProvingRelayerPayment,
    /// The task is submitting a fee payment transaction for the ith balance
    SubmittingPayment,
    /// The task is proving protocol fee payment for the ith balance
    ProvingProtocolPayment,
    /// The task is submitting a fee payment transaction for the ith balance
    SubmittingProtocolPayment,
    /// The task is updating the validity proofs for the wallet
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl TaskState for PayFeesTaskState {
    fn commit_point() -> Self {
        PayFeesTaskState::ProvingRelayerPayment
    }

    fn completed(&self) -> bool {
        matches!(self, PayFeesTaskState::Completed)
    }
}

impl Display for PayFeesTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl From<PayFeesTaskState> for StateWrapper {
    fn from(value: PayFeesTaskState) -> Self {
        StateWrapper::PayFees(value)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the pay fees task
#[derive(Clone, Debug)]
pub enum PayFeesTaskError {
    /// An error interacting with Arbitrum
    Arbitrum(String),
    /// An error interacting with the state
    State(String),
}

impl TaskError for PayFeesTaskError {
    fn retryable(&self) -> bool {
        match self {
            PayFeesTaskError::Arbitrum(_) | PayFeesTaskError::State(_) => true,
        }
    }
}

impl Display for PayFeesTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for PayFeesTaskError {}

impl From<StateError> for PayFeesTaskError {
    fn from(error: StateError) -> Self {
        PayFeesTaskError::State(error.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the pay fees task flow
pub struct PayFeesTask {
    /// The wallet to pay fees for
    pub wallet_id: WalletIdentifier,
    /// The balance to pay fees for
    pub mint: BigUint,
    /// The arbitrum client used for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A hand to the global state
    pub state: State,
    /// The work queue for the proof manager
    pub proof_queue: ProofManagerQueue,
    /// The current state of the task
    pub task_state: PayFeesTaskState,
}

#[async_trait]
impl Task for PayFeesTask {
    type State = PayFeesTaskState;
    type Error = PayFeesTaskError;
    type Descriptor = PayFeesTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        Ok(Self {
            wallet_id: descriptor.wallet_id,
            mint: descriptor.balance_mint,
            arbitrum_client: ctx.arbitrum_client,
            state: ctx.state,
            proof_queue: ctx.proof_queue,
            task_state: PayFeesTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        todo!()
    }

    fn completed(&self) -> bool {
        self.task_state.completed()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn name(&self) -> String {
        TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl PayFeesTask {
    /// Generate a proof of `VALID RELAYER FEE SETTLEMENT` for the given balance
    async fn generate_relayer_proof(&mut self) -> Result<(), PayFeesTaskError> {
        todo!()
    }

    /// Submit the `settle_relayer_fee` transaction for the balance
    async fn submit_relayer_payment(&mut self) -> Result<(), PayFeesTaskError> {
        todo!()
    }

    /// Generate a proof of `VALID PROTOCOL FEE SETTLEMENT` for the given
    /// balance
    async fn generate_protocol_proof(&mut self) -> Result<(), PayFeesTaskError> {
        todo!()
    }

    /// Submit the `settle_protocol_fee` transaction for the balance
    async fn submit_protocol_payment(&mut self) -> Result<(), PayFeesTaskError> {
        todo!()
    }

    /// Update the validity proofs for the wallet after fee payment
    async fn update_validity_proofs(&mut self) -> Result<(), PayFeesTaskError> {
        todo!()
    }
}
