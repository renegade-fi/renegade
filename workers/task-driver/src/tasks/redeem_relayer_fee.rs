//! Redeems a fee into the relayer wallet

use std::{error::Error, fmt::Display};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::note::Note;
use common::types::{proof_bundles::FeeRedemptionBundle, tasks::RedeemRelayerFeeTaskDescriptor};
use job_types::{network_manager::NetworkManagerQueue, proof_manager::ProofManagerQueue};
use serde::Serialize;
use state::{error::StateError, State};
use tracing::instrument;

use crate::{
    driver::StateWrapper,
    traits::{Task, TaskContext, TaskError, TaskState},
};

/// The name of the task
const TASK_NAME: &str = "redeem-relayer-fee";

// --------------
// | Task State |
// --------------

/// Defines the state of the redeem relayer fee task
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Serialize)]
pub enum RedeemRelayerFeeTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the Merkle opening for the note
    FindingNoteOpening,
    /// The task is proving note redemption
    ProvingRedemption,
    /// The task is submitting a note redemption transaction
    SubmittingRedemption,
    /// The task is finding the relayer wallet's opening
    FindingWalletOpening,
    /// The task has finished
    Completed,
}

impl TaskState for RedeemRelayerFeeTaskState {
    fn commit_point() -> Self {
        RedeemRelayerFeeTaskState::SubmittingRedemption
    }

    fn completed(&self) -> bool {
        matches!(self, RedeemRelayerFeeTaskState::Completed)
    }
}

impl Display for RedeemRelayerFeeTaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<RedeemRelayerFeeTaskState> for StateWrapper {
    fn from(value: RedeemRelayerFeeTaskState) -> Self {
        StateWrapper::RedeemRelayerFee(value)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the redeem relayer fee task
#[derive(Clone, Debug)]
pub enum RedeemRelayerFeeError {
    /// An error interacting with Arbitrum
    Arbitrum(String),
    /// An error generating a proof for fee payment
    ProofGeneration(String),
    /// An error interacting with the state
    State(String),
    /// An error updating validity proofs after the fees are settled
    UpdateValidityProofs(String),
}

impl TaskError for RedeemRelayerFeeError {
    fn retryable(&self) -> bool {
        match self {
            RedeemRelayerFeeError::Arbitrum(_)
            | RedeemRelayerFeeError::ProofGeneration(_)
            | RedeemRelayerFeeError::State(_)
            | RedeemRelayerFeeError::UpdateValidityProofs(_) => true,
        }
    }
}

impl Display for RedeemRelayerFeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for RedeemRelayerFeeError {}

impl From<StateError> for RedeemRelayerFeeError {
    fn from(err: StateError) -> Self {
        RedeemRelayerFeeError::State(err.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the redeem relayer fee task
pub struct RedeemRelayerFeeTask {
    /// The note to redeem
    pub note: Note,
    /// The proof of `VALID FEE REDEMPTION` used to pay the fee
    pub proof: Option<FeeRedemptionBundle>,
    /// The arbitrum client used for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A handle on the global state
    pub state: State,
    /// The work queue for the proof manager
    pub proof_queue: ProofManagerQueue,
    /// A sender to the network manager's queue
    pub network_sender: NetworkManagerQueue,
    /// The current state of the task
    pub task_state: RedeemRelayerFeeTaskState,
}

#[async_trait]
impl Task for RedeemRelayerFeeTask {
    type State = RedeemRelayerFeeTaskState;
    type Error = RedeemRelayerFeeError;
    type Descriptor = RedeemRelayerFeeTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        Ok(Self {
            note: descriptor.note,
            proof: None,
            arbitrum_client: ctx.arbitrum_client,
            state: ctx.state,
            proof_queue: ctx.proof_queue,
            network_sender: ctx.network_queue,
            task_state: RedeemRelayerFeeTaskState::Pending,
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
