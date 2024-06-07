//! Defines a task that looks up a wallet in contract storage by its
//! public view key identifier, then begins managing the wallet

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::SizedWalletShare;
use common::types::{
    tasks::LookupWalletTaskDescriptor,
    wallet::{KeyChain, Wallet, WalletIdentifier},
};
use constants::Scalar;
use job_types::{network_manager::NetworkManagerQueue, proof_manager::ProofManagerQueue};
use serde::Serialize;
use state::{error::StateError, State};
use tracing::instrument;

use crate::{
    driver::StateWrapper,
    helpers::{find_latest_wallet_tx, gen_private_shares},
    traits::{Task, TaskContext, TaskError, TaskState},
};

use crate::helpers::{find_merkle_path, update_wallet_validity_proofs};

/// The task name for the lookup wallet task
const LOOKUP_WALLET_TASK_NAME: &str = "lookup-wallet";

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum LookupWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the wallet in contract storage
    FindingWallet,
    /// The task is creating validity proofs for the orders in the wallet
    CreatingValidityProofs,
    /// The task is completed
    Completed,
}

impl TaskState for LookupWalletTaskState {
    fn commit_point() -> Self {
        LookupWalletTaskState::CreatingValidityProofs
    }

    fn completed(&self) -> bool {
        matches!(self, LookupWalletTaskState::Completed)
    }
}

impl Display for LookupWalletTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            LookupWalletTaskState::Pending => write!(f, "Pending"),
            LookupWalletTaskState::FindingWallet => write!(f, "Finding Wallet"),
            LookupWalletTaskState::CreatingValidityProofs => write!(f, "Creating Validity Proofs"),
            LookupWalletTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<LookupWalletTaskState> for StateWrapper {
    fn from(state: LookupWalletTaskState) -> Self {
        StateWrapper::LookupWallet(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the wallet lookup task
#[derive(Clone, Debug)]
pub enum LookupWalletTaskError {
    /// Wallet was not found in contract storage
    NotFound(String),
    /// Error generating a proof of `VALID COMMITMENTS`
    ProofGeneration(String),
    /// Error interacting with the arbitrum client
    Arbitrum(String),
    /// Error interacting with global state
    State(String),
}

impl TaskError for LookupWalletTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            LookupWalletTaskError::Arbitrum(_)
                | LookupWalletTaskError::ProofGeneration(_)
                | LookupWalletTaskError::State(_)
        )
    }
}

impl Display for LookupWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for LookupWalletTaskError {}

impl From<StateError> for LookupWalletTaskError {
    fn from(e: StateError) -> Self {
        LookupWalletTaskError::State(e.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to lookup a wallet in contract storage
pub struct LookupWalletTask {
    /// The ID to provision for the wallet
    pub wallet_id: WalletIdentifier,
    /// The CSPRNG seed for the blinder stream
    pub blinder_seed: Scalar,
    /// The CSPRNG seed for the secret share stream
    pub secret_share_seed: Scalar,
    /// The keychain to manage the wallet with
    pub key_chain: KeyChain,
    /// The wallet recovered from contract state
    pub wallet: Option<Wallet>,
    /// An arbitrum client for the task to submit transactions
    pub arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// A copy of the relayer-global state
    pub global_state: State,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: ProofManagerQueue,
    /// The state of the task's execution
    pub task_state: LookupWalletTaskState,
}

#[async_trait]
impl Task for LookupWalletTask {
    type State = LookupWalletTaskState;
    type Error = LookupWalletTaskError;
    type Descriptor = LookupWalletTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        Ok(Self {
            wallet_id: descriptor.wallet_id,
            blinder_seed: descriptor.blinder_seed,
            secret_share_seed: descriptor.secret_share_seed,
            key_chain: descriptor.key_chain,
            arbitrum_client: ctx.arbitrum_client,
            network_sender: ctx.network_queue,
            global_state: ctx.state,
            proof_manager_work_queue: ctx.proof_queue,
            wallet: None,
            task_state: LookupWalletTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on task state
        match self.task_state {
            LookupWalletTaskState::Pending => {
                self.task_state = LookupWalletTaskState::FindingWallet
            },

            LookupWalletTaskState::FindingWallet => {
                self.find_wallet().await?;
                self.task_state = LookupWalletTaskState::CreatingValidityProofs;
            },

            LookupWalletTaskState::CreatingValidityProofs => {
                self.create_validity_proofs().await?;
                self.task_state = LookupWalletTaskState::Completed;
            },

            LookupWalletTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        LOOKUP_WALLET_TASK_NAME.to_string()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl LookupWalletTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Find the wallet in the contract storage and create an opening for the
    /// wallet
    async fn find_wallet(&mut self) -> Result<(), LookupWalletTaskError> {
        // Lookup the public and private shares from contract calldata
        // then recover the wallet
        let (blinded_public_shares, private_shares) = self.find_wallet_shares().await?;
        let mut wallet = Wallet::new_from_shares(
            self.wallet_id,
            self.key_chain.clone(),
            blinded_public_shares,
            private_shares,
        );

        // Find the authentication path for the wallet
        let authentication_path = find_merkle_path(&wallet, &self.arbitrum_client)
            .await
            .map_err(|e| LookupWalletTaskError::Arbitrum(e.to_string()))?;
        wallet.merkle_proof = Some(authentication_path);

        let waiter = self.global_state.update_wallet(wallet.clone()).await?;
        waiter.await?;
        self.wallet = Some(wallet);

        Ok(())
    }

    /// Prove `VALID REBLIND` for the recovered wallet, and `VALID COMMITMENTS`
    /// for each order within the wallet
    async fn create_validity_proofs(&self) -> Result<(), LookupWalletTaskError> {
        let wallet = self
            .wallet
            .clone()
            .expect("wallet should be present when CreateValidityProofs state is reached");

        update_wallet_validity_proofs(
            &wallet,
            self.proof_manager_work_queue.clone(),
            self.global_state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(LookupWalletTaskError::ProofGeneration)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Find the public and private shares of the wallet seeded by the given
    /// value
    ///
    /// Unblinds the public shares before returning them
    async fn find_wallet_shares(
        &self,
    ) -> Result<(SizedWalletShare, SizedWalletShare), LookupWalletTaskError> {
        // Find the latest index of the wallet in its share stream
        let (blinder_index, curr_blinder, curr_blinder_private_share) =
            find_latest_wallet_tx(self.blinder_seed, &self.arbitrum_client)
                .await
                .map_err(|e| LookupWalletTaskError::NotFound(e.to_string()))?;

        // Fetch the secret shares from the tx
        let blinder_public_share = curr_blinder - curr_blinder_private_share;
        let blinded_public_shares = self
            .arbitrum_client
            .fetch_public_shares_for_blinder(blinder_public_share)
            .await
            .map_err(|e| LookupWalletTaskError::Arbitrum(e.to_string()))?;

        // Sample the private shares for the wallet
        let private_shares =
            gen_private_shares(blinder_index, self.secret_share_seed, curr_blinder_private_share);

        Ok((blinded_public_shares, private_shares))
    }
}
