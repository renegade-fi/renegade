//! Redeem a note into a wallet

use std::{
    error::Error,
    fmt::{self, Display},
};

use arbitrum_client::{client::ArbitrumClient, errors::ArbitrumClientError};
use async_trait::async_trait;
use circuit_types::elgamal::DecryptionKey;
use common::types::{tasks::RedeemNoteTaskDescriptor, wallet::WalletIdentifier};
use job_types::{network_manager::NetworkManagerQueue, proof_manager::ProofManagerQueue};
use serde::Serialize;
use state::{error::StateError, State};
use tracing::instrument;

use crate::{
    driver::StateWrapper,
    traits::{Task, TaskContext, TaskError, TaskState},
};

/// The name of the task
const REDEEM_NOTE_TASK_NAME: &str = "redeem-note";

// --------------
// | Task State |
// --------------

/// Defines the state of the redeem note task
#[derive(Copy, Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RedeemNoteTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the note on-chain
    FindingNote,
    /// The task is proving redemption
    ProvingRedemption,
    /// The task is submitting the redemption transaction
    SubmittingRedemption,
    /// The task is finding the wallet in contract storage
    FindingWallet,
    /// The task is creating validity proofs for the orders in the wallet
    CreatingValidityProofs,
    /// The task is completed
    Completed,
}

impl TaskState for RedeemNoteTaskState {
    fn commit_point() -> Self {
        RedeemNoteTaskState::SubmittingRedemption
    }

    fn completed(&self) -> bool {
        matches!(self, RedeemNoteTaskState::Completed)
    }
}

impl Display for RedeemNoteTaskState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RedeemNoteTaskState::Pending => write!(f, "Pending"),
            RedeemNoteTaskState::FindingNote => write!(f, "Finding Note"),
            RedeemNoteTaskState::ProvingRedemption => write!(f, "Proving Redemption"),
            RedeemNoteTaskState::SubmittingRedemption => write!(f, "Submitting Redemption"),
            RedeemNoteTaskState::FindingWallet => write!(f, "Finding Wallet"),
            RedeemNoteTaskState::CreatingValidityProofs => write!(f, "Creating Validity Proofs"),
            RedeemNoteTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<RedeemNoteTaskState> for StateWrapper {
    fn from(state: RedeemNoteTaskState) -> Self {
        StateWrapper::RedeemNote(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the redeem note task
#[derive(Clone, Debug, Serialize)]
pub enum RedeemNoteTaskError {
    /// An error occurred while finding the note on-chain
    Arbitrum(String),
    /// An error interacting with relayer state
    State(String),
}

impl TaskError for RedeemNoteTaskError {
    fn retryable(&self) -> bool {
        match self {
            RedeemNoteTaskError::Arbitrum(_) => true,
            RedeemNoteTaskError::State(_) => true,
        }
    }
}

impl Display for RedeemNoteTaskError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl Error for RedeemNoteTaskError {}

impl From<StateError> for RedeemNoteTaskError {
    fn from(error: StateError) -> Self {
        RedeemNoteTaskError::Arbitrum(error.to_string())
    }
}

impl From<ArbitrumClientError> for RedeemNoteTaskError {
    fn from(error: ArbitrumClientError) -> Self {
        RedeemNoteTaskError::Arbitrum(error.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to redeem a note into a wallet
pub struct RedeemNoteTask {
    /// The id of the wallet to redeem the note into
    pub wallet_id: WalletIdentifier,
    /// The tx hash of the note to redeem
    pub tx_hash: String,
    /// The decryption key to decrypt the note
    pub decryption_key: DecryptionKey,
    /// An arbitrum client for the task to submit transactions
    pub arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// A copy of the relayer-global state
    pub state: State,
    /// The work queue to add proof management jobs to
    pub proof_queue: ProofManagerQueue,
    /// The state of the task's execution
    pub task_state: RedeemNoteTaskState,
}

#[async_trait]
impl Task for RedeemNoteTask {
    type Error = RedeemNoteTaskError;
    type State = RedeemNoteTaskState;
    type Descriptor = RedeemNoteTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        Ok(Self {
            wallet_id: descriptor.wallet_id,
            tx_hash: descriptor.tx_hash,
            decryption_key: descriptor.decryption_key,
            arbitrum_client: ctx.arbitrum_client,
            network_sender: ctx.network_queue,
            state: ctx.state,
            proof_queue: ctx.proof_queue,
            task_state: RedeemNoteTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on task state
        match self.task_state {
            RedeemNoteTaskState::Pending => {
                self.task_state = RedeemNoteTaskState::FindingNote;
            },
            RedeemNoteTaskState::FindingNote => {
                self.find_note().await?;
                self.task_state = RedeemNoteTaskState::ProvingRedemption;
            },
            RedeemNoteTaskState::ProvingRedemption => {
                self.prove_redemption().await?;
                self.task_state = RedeemNoteTaskState::SubmittingRedemption;
            },
            RedeemNoteTaskState::SubmittingRedemption => {
                self.submit_redemption().await?;
                self.task_state = RedeemNoteTaskState::Completed;
            },
            RedeemNoteTaskState::FindingWallet => {
                self.find_wallet().await?;
                self.task_state = RedeemNoteTaskState::CreatingValidityProofs;
            },
            RedeemNoteTaskState::CreatingValidityProofs => {
                self.create_validity_proofs().await?;
                self.task_state = RedeemNoteTaskState::Completed;
            },
            RedeemNoteTaskState::Completed => {
                unreachable!("step called on task in Completed state");
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        REDEEM_NOTE_TASK_NAME.to_string()
    }

    fn state(&self) -> Self::State {
        self.task_state
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl RedeemNoteTask {
    /// Find the note in contract state and decrypt it
    async fn find_note(&mut self) -> Result<(), RedeemNoteTaskError> {
        todo!()
    }

    /// Prove the redemption of the note
    async fn prove_redemption(&mut self) -> Result<(), RedeemNoteTaskError> {
        todo!()
    }

    /// Submit the redemption transaction
    async fn submit_redemption(&mut self) -> Result<(), RedeemNoteTaskError> {
        todo!()
    }

    /// Find the wallet in contract storage
    async fn find_wallet(&mut self) -> Result<(), RedeemNoteTaskError> {
        todo!()
    }

    /// Create validity proofs for the orders in the wallet
    async fn create_validity_proofs(&mut self) -> Result<(), RedeemNoteTaskError> {
        todo!()
    }
}
