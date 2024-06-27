//! Refresh a wallet from on-chain state

use std::{
    error::Error,
    fmt::{self, Display},
};

use arbitrum_client::{client::ArbitrumClient, errors::ArbitrumClientError};
use async_trait::async_trait;
use circuit_types::SizedWalletShare;
use common::types::{
    tasks::RefreshWalletTaskDescriptor,
    wallet::{Wallet, WalletIdentifier},
};
use constants::Scalar;
use job_types::{network_manager::NetworkManagerQueue, proof_manager::ProofManagerQueue};
use serde::Serialize;
use state::{error::StateError, State};
use tracing::instrument;

use crate::{
    driver::StateWrapper,
    traits::{Task, TaskContext, TaskError, TaskState},
    utils::{
        find_wallet::{find_latest_wallet_tx, gen_private_shares},
        validity_proofs::{find_merkle_path, update_wallet_validity_proofs},
    },
};

/// The task name
const REFRESH_WALLET_TASK_NAME: &str = "refresh-wallet";

/// Error emitted when the wallet is not found in contract storage
const ERR_WALLET_NOT_FOUND: &str = "wallet not found";

// --------------
// | Task State |
// --------------

/// Defines the state of the refresh wallet task
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum RefreshWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the wallet in contract storage
    FindingWallet,
    /// The task is creating validity proofs for the orders in the wallet
    CreatingValidityProofs,
    /// The task is completed
    Completed,
}

impl TaskState for RefreshWalletTaskState {
    fn commit_point() -> Self {
        RefreshWalletTaskState::CreatingValidityProofs
    }

    fn completed(&self) -> bool {
        matches!(self, RefreshWalletTaskState::Completed)
    }
}

impl Display for RefreshWalletTaskState {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RefreshWalletTaskState::Pending => write!(f, "Pending"),
            RefreshWalletTaskState::FindingWallet => write!(f, "Finding Wallet"),
            RefreshWalletTaskState::CreatingValidityProofs => write!(f, "Creating Validity Proofs"),
            RefreshWalletTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<RefreshWalletTaskState> for StateWrapper {
    fn from(state: RefreshWalletTaskState) -> Self {
        StateWrapper::RefreshWallet(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the wallet refresh task
#[derive(Clone, Debug)]
pub enum RefreshWalletTaskError {
    /// Wallet was not found in contract storage
    NotFound(String),
    /// Error generating a proof of `VALID COMMITMENTS`
    ProofGeneration(String),
    /// Error interacting with the arbitrum client
    Arbitrum(String),
    /// Error interacting with state
    State(String),
}

impl TaskError for RefreshWalletTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            RefreshWalletTaskError::Arbitrum(_)
                | RefreshWalletTaskError::ProofGeneration(_)
                | RefreshWalletTaskError::State(_)
        )
    }
}

impl Display for RefreshWalletTaskError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for RefreshWalletTaskError {}

impl From<StateError> for RefreshWalletTaskError {
    fn from(e: StateError) -> Self {
        RefreshWalletTaskError::State(e.to_string())
    }
}

impl From<ArbitrumClientError> for RefreshWalletTaskError {
    fn from(e: ArbitrumClientError) -> Self {
        RefreshWalletTaskError::Arbitrum(e.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to refresh a wallet from on-chain state
pub struct RefreshWalletTask {
    /// The ID to provision for the wallet
    pub wallet_id: WalletIdentifier,
    /// An arbitrum client for the task to submit transactions
    pub arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// A copy of the relayer-global state
    pub state: State,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: ProofManagerQueue,
    /// The state of the task's execution
    pub task_state: RefreshWalletTaskState,
}

#[async_trait]
impl Task for RefreshWalletTask {
    type State = RefreshWalletTaskState;
    type Error = RefreshWalletTaskError;
    type Descriptor = RefreshWalletTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        Ok(Self {
            wallet_id: descriptor.wallet_id,
            arbitrum_client: ctx.arbitrum_client,
            network_sender: ctx.network_queue,
            state: ctx.state,
            proof_manager_work_queue: ctx.proof_queue,
            task_state: RefreshWalletTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on task state
        match self.task_state {
            RefreshWalletTaskState::Pending => {
                self.task_state = RefreshWalletTaskState::FindingWallet
            },

            RefreshWalletTaskState::FindingWallet => {
                self.find_wallet().await?;
                self.task_state = RefreshWalletTaskState::CreatingValidityProofs;
            },

            RefreshWalletTaskState::CreatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = RefreshWalletTaskState::Completed;
            },

            RefreshWalletTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        REFRESH_WALLET_TASK_NAME.to_string()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl RefreshWalletTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Find the wallet in contract storage
    async fn find_wallet(&mut self) -> Result<(), RefreshWalletTaskError> {
        let curr_wallet = self.get_wallet().await?;
        let (public_share, private_share) = self.find_wallet_shares(&curr_wallet).await?;
        let mut wallet = Wallet::new_from_shares(
            self.wallet_id,
            curr_wallet.key_chain,
            public_share,
            private_share,
        );

        // Update the merkle proof for the wallet, then write to state
        let merkle_proof = find_merkle_path(&wallet, &self.arbitrum_client).await?;
        wallet.merkle_proof = Some(merkle_proof);

        let waiter = self.state.update_wallet(wallet.clone()).await?;
        waiter.await?;
        Ok(())
    }

    /// Update validity proofs for the wallet
    async fn update_validity_proofs(&mut self) -> Result<(), RefreshWalletTaskError> {
        let wallet = self.get_wallet().await?;
        update_wallet_validity_proofs(
            &wallet,
            self.proof_manager_work_queue.clone(),
            self.state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(RefreshWalletTaskError::ProofGeneration)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the wallet from the state
    async fn get_wallet(&self) -> Result<Wallet, RefreshWalletTaskError> {
        self.state
            .get_wallet(&self.wallet_id)
            .await?
            .ok_or_else(|| RefreshWalletTaskError::NotFound(ERR_WALLET_NOT_FOUND.to_string()))
    }

    /// Find the latest wallet shares from on-chain
    ///
    /// Returns the public shares and private shares in order
    async fn find_wallet_shares(
        &self,
        wallet: &Wallet,
    ) -> Result<(SizedWalletShare, SizedWalletShare), RefreshWalletTaskError> {
        let (public_blinder, private_share) = self.get_latest_shares(wallet).await?;

        // Fetch public shares from on-chain
        let blinded_public_shares =
            self.arbitrum_client.fetch_public_shares_for_blinder(public_blinder).await?;
        Ok((blinded_public_shares, private_share))
    }

    /// Get the latest known shares on-chain
    ///
    /// Returns the public blinder share and the private shares
    async fn get_latest_shares(
        &self,
        wallet: &Wallet,
    ) -> Result<(Scalar, SizedWalletShare), RefreshWalletTaskError> {
        // If the locally stored version of the wallet has not been nullified on-chain,
        // it is the latest
        let nullifier = wallet.get_wallet_nullifier();
        if !self.arbitrum_client.check_nullifier_used(nullifier).await? {
            let public_blinder = wallet.blinded_public_shares.blinder;
            return Ok((public_blinder, wallet.private_shares.clone()));
        }

        // Otherwise lookup the wallet
        let blinder_seed = wallet.private_blinder_share();
        let (idx, blinder, private_blinder_share) =
            find_latest_wallet_tx(blinder_seed, &self.arbitrum_client)
                .await
                .map_err(|e| RefreshWalletTaskError::NotFound(e.to_string()))?;

        // Construct private shares from the blinder index
        let share_seed = wallet.get_last_private_share();
        let private_shares = gen_private_shares(idx, share_seed, private_blinder_share);

        let public_blinder = blinder - private_blinder_share;
        Ok((public_blinder, private_shares))
    }
}
