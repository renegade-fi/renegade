//! The `update_merkle_proof` task updates the Merkle opening for a wallet to
//! the most recent known root

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
    sync::atomic::Ordering,
};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use common::types::wallet::Wallet;
use crossbeam::channel::Sender as CrossbeamSender;
use gossip_api::gossip::GossipOutbound;
use job_types::proof_manager::ProofManagerJob;
use serde::Serialize;
use statev2::{error::StateError, State};
use tokio::sync::mpsc::UnboundedSender as TokioSender;

use crate::{
    driver::{StateWrapper, Task},
    helpers::update_wallet_validity_proofs,
};

/// The human-readable name of the the task
const UPDATE_MERKLE_PROOF_TASK_NAME: &str = "update-merkle-proof";

// -------------------
// | Task Definition |
// -------------------

/// Defines the long running flow for updating the Merkle opening for a wallet
pub struct UpdateMerkleProofTask {
    /// The wallet to update
    pub wallet: Wallet,
    /// The arbitrum client to use for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A copy of the relayer-global state
    pub global_state: State,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// A sender to the network manager's work queue
    pub network_sender: TokioSender<GossipOutbound>,
    /// The state of the task
    pub task_state: UpdateMerkleProofTaskState,
}

/// The error type for the update merkle proof task
#[derive(Clone, Debug)]
pub enum UpdateMerkleProofTaskError {
    /// An error occurred interacting with Arbitrum
    Arbitrum(String),
    /// An error interacting with global state
    State(String),
    /// An error while updating validity proofs for a wallet
    UpdatingValidityProofs(String),
    /// Wallet is already locked, cannot update
    WalletLocked,
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

/// Defines the state of the deposit balance task
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
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

impl Display for UpdateMerkleProofTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::FindingOpening => write!(f, "FindingOpening"),
            Self::UpdatingValidityProofs => write!(f, "UpdatingValidityProofs"),
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

#[async_trait]
impl Task for UpdateMerkleProofTask {
    type Error = UpdateMerkleProofTaskError;
    type State = UpdateMerkleProofTaskState;

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

    // Unlock the update lock if the task fails
    async fn cleanup(&mut self) -> Result<(), UpdateMerkleProofTaskError> {
        self.wallet.unlock_wallet();
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
    /// Constructor
    pub async fn new(
        wallet: Wallet,
        arbitrum_client: ArbitrumClient,
        global_state: State,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
        network_sender: TokioSender<GossipOutbound>,
    ) -> Result<Self, UpdateMerkleProofTaskError> {
        if !wallet.try_lock_wallet() {
            return Err(UpdateMerkleProofTaskError::WalletLocked);
        }

        Ok(Self {
            wallet,
            arbitrum_client,
            global_state,
            proof_manager_work_queue,
            network_sender,
            task_state: UpdateMerkleProofTaskState::Pending,
        })
    }

    // --------------
    // | Task Steps |
    // --------------

    /// Find the opening of the wallet to the newest known Merkle root
    pub async fn find_opening(&mut self) -> Result<(), UpdateMerkleProofTaskError> {
        let wallet_commitment = self.wallet.get_wallet_share_commitment();
        let new_opening = self
            .arbitrum_client
            .find_merkle_authentication_path(wallet_commitment)
            .await
            .map_err(|err| UpdateMerkleProofTaskError::Arbitrum(err.to_string()))?;
        self.wallet.merkle_proof = Some(new_opening);
        self.wallet.merkle_staleness.store(0, Ordering::Relaxed);

        // Update the global state
        self.global_state.update_wallet(self.wallet.clone())?.await?;
        Ok(())
    }

    /// Update the validity proofs for all orders in the wallet
    pub async fn update_validity_proofs(&self) -> Result<(), UpdateMerkleProofTaskError> {
        update_wallet_validity_proofs(
            &self.wallet,
            self.proof_manager_work_queue.clone(),
            self.global_state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(|e| UpdateMerkleProofTaskError::UpdatingValidityProofs(e.to_string()))
    }
}
