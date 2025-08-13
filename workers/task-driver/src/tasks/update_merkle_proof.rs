//! The `update_merkle_proof` task updates the Merkle opening for a wallet to
//! the most recent known root

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    sync::atomic::Ordering,
};

use async_trait::async_trait;
use common::types::{tasks::UpdateMerkleProofTaskDescriptor, wallet::Wallet};
use darkpool_client::{DarkpoolClient, errors::DarkpoolClientError};
use job_types::{network_manager::NetworkManagerQueue, proof_manager::ProofManagerQueue};
use serde::Serialize;
use state::{State, error::StateError};
use tracing::instrument;

use crate::{
    task_state::StateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
    utils::validity_proofs::update_wallet_validity_proofs,
};

/// The human-readable name of the the task
const UPDATE_MERKLE_PROOF_TASK_NAME: &str = "update-merkle-proof";

// --------------
// | Task State |
// --------------

/// Defines the state of the deposit balance task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UpdateMerkleProofTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding a new Merkle opening for the wallet
    FindingOpening,
    /// The task is updating the validity proofs for all orders in the
    /// wallet
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl TaskState for UpdateMerkleProofTaskState {
    fn commit_point() -> Self {
        Self::UpdatingValidityProofs
    }

    fn completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl Display for UpdateMerkleProofTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::FindingOpening => write!(f, "Finding Opening"),
            Self::UpdatingValidityProofs => write!(f, "Updating Validity Proofs"),
            Self::Completed => write!(f, "Completed"),
        }
    }
}

impl Serialize for UpdateMerkleProofTaskState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl From<UpdateMerkleProofTaskState> for StateWrapper {
    fn from(state: UpdateMerkleProofTaskState) -> Self {
        StateWrapper::UpdateMerkleProof(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the update merkle proof task
#[derive(Clone, Debug)]
pub enum UpdateMerkleProofTaskError {
    /// An error interacting with the darkpool client
    Darkpool(String),
    /// An error interacting with global state
    State(String),
    /// An error while updating validity proofs for a wallet
    UpdatingValidityProofs(String),
    /// Wallet is already locked, cannot update
    WalletLocked,
}

impl TaskError for UpdateMerkleProofTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            UpdateMerkleProofTaskError::Darkpool(_)
                | UpdateMerkleProofTaskError::State(_)
                | UpdateMerkleProofTaskError::UpdatingValidityProofs(_)
        )
    }
}

impl Display for UpdateMerkleProofTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}
impl Error for UpdateMerkleProofTaskError {}

impl From<StateError> for UpdateMerkleProofTaskError {
    fn from(value: StateError) -> Self {
        UpdateMerkleProofTaskError::State(value.to_string())
    }
}

impl From<DarkpoolClientError> for UpdateMerkleProofTaskError {
    fn from(value: DarkpoolClientError) -> Self {
        UpdateMerkleProofTaskError::Darkpool(value.to_string())
    }
}

impl Descriptor for UpdateMerkleProofTaskDescriptor {}

// -------------------
// | Task Definition |
// -------------------

/// Defines the long running flow for updating the Merkle opening for a wallet
pub struct UpdateMerkleProofTask {
    /// The wallet to update
    pub wallet: Wallet,
    /// The darkpool client to use for submitting transactions
    pub darkpool_client: DarkpoolClient,
    /// A copy of the relayer-global state
    pub global_state: State,
    /// The work queue to add proof management jobs to
    pub proof_queue: ProofManagerQueue,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// The state of the task
    pub task_state: UpdateMerkleProofTaskState,
}

#[async_trait]
impl Task for UpdateMerkleProofTask {
    type Error = UpdateMerkleProofTaskError;
    type State = UpdateMerkleProofTaskState;
    type Descriptor = UpdateMerkleProofTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        Ok(Self {
            wallet: descriptor.wallet,
            darkpool_client: ctx.darkpool_client,
            global_state: ctx.state,
            proof_queue: ctx.proof_queue,
            network_sender: ctx.network_queue,
            task_state: UpdateMerkleProofTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.state() {
            UpdateMerkleProofTaskState::Pending => {
                self.task_state = UpdateMerkleProofTaskState::FindingOpening
            },
            UpdateMerkleProofTaskState::FindingOpening => {
                self.find_opening().await?;
                self.task_state = UpdateMerkleProofTaskState::UpdatingValidityProofs
            },
            UpdateMerkleProofTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = UpdateMerkleProofTaskState::Completed
            },
            UpdateMerkleProofTaskState::Completed => {
                panic!("step() called in state Completed")
            },
        }

        Ok(())
    }

    fn completed(&self) -> bool {
        matches!(self.state(), Self::State::Completed)
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn name(&self) -> String {
        UPDATE_MERKLE_PROOF_TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl UpdateMerkleProofTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Find the opening of the wallet to the newest known Merkle root
    pub async fn find_opening(&mut self) -> Result<(), UpdateMerkleProofTaskError> {
        let wallet_commitment = self.wallet.get_wallet_share_commitment();
        let new_opening =
            self.darkpool_client.find_merkle_authentication_path(wallet_commitment).await?;
        self.wallet.merkle_proof = Some(new_opening);
        self.wallet.merkle_staleness.store(0, Ordering::Relaxed);

        // Update the global state
        let waiter = self.global_state.update_wallet(self.wallet.clone()).await?;
        waiter.await?;
        Ok(())
    }

    /// Update the validity proofs for all orders in the wallet
    pub async fn update_validity_proofs(&self) -> Result<(), UpdateMerkleProofTaskError> {
        update_wallet_validity_proofs(
            &self.wallet,
            self.proof_queue.clone(),
            self.global_state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(|e| UpdateMerkleProofTaskError::UpdatingValidityProofs(e.to_string()))
    }
}
