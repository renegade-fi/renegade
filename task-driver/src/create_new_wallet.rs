//! A task defining the flow to create a new wallet, at a high level the steps
//! are:
//!     1. Index the wallet locally
//!     2. Prove `VALID WALLET CREATE` for the wallet
//!     3. Submit this on-chain and await transaction success
//!     4. Pull the Merkle authentication path of the newly created wallet from
//!        on-chain state

use core::panic;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::{
    native_helpers::{compute_wallet_private_share_commitment, wallet_from_blinded_shares},
    SizedWallet,
};
use circuits::zk_circuits::valid_wallet_create::{
    SizedValidWalletCreateStatement, SizedValidWalletCreateWitness, ValidWalletCreateStatement,
    ValidWalletCreateWitness,
};
use common::types::{proof_bundles::ValidWalletCreateBundle, wallet::Wallet};
use job_types::proof_manager::{ProofJob, ProofManagerQueue};
use serde::{Deserialize, Serialize};
use state::error::StateError;
use state::State;

use crate::driver::StateWrapper;
use crate::helpers::enqueue_proof_job;
use crate::traits::{Task, TaskContext, TaskError, TaskState};

use super::helpers::find_merkle_path;

/// Error occurs when a wallet is submitted with secret shares that do not
/// combine to recover the wallet
const ERR_INVALID_SHARING: &str = "invalid secret shares for wallet";
/// The task name to display when logging
const NEW_WALLET_TASK_NAME: &str = "create-new-wallet";

// --------------
// | Task State |
// --------------

/// Defines the state of the long-running wallet create flow
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NewWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is awaiting a proof of `VALID WALLET CREATE`
    Proving,
    /// The task is submitting the transaction to the contract and
    /// awaiting finality
    SubmittingTx,
    /// The task is searching for the Merkle authentication proof for the
    /// new wallet on-chain
    FindingMerkleOpening,
    /// Task completed
    Completed,
}

impl TaskState for NewWalletTaskState {
    fn commit_point() -> Self {
        NewWalletTaskState::SubmittingTx
    }

    fn completed(&self) -> bool {
        matches!(self, NewWalletTaskState::Completed)
    }
}

/// Display implementation that ignores structure fields
impl Display for NewWalletTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            NewWalletTaskState::SubmittingTx { .. } => {
                write!(f, "SubmittingTx")
            },
            _ => write!(f, "{self:?}"),
        }
    }
}

/// Serialize implementation that uses the display implementation above
impl Serialize for NewWalletTaskState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl From<NewWalletTaskState> for StateWrapper {
    fn from(state: NewWalletTaskState) -> Self {
        StateWrapper::NewWallet(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the task
#[derive(Clone, Debug)]
pub enum NewWalletTaskError {
    /// A wallet was submitted with an invalid secret shares
    InvalidShares(String),
    /// Error generating a proof of `VALID WALLET CREATE`
    ProofGeneration(String),
    /// Error interacting with the Arbitrum client
    Arbitrum(String),
    /// Error sending a message to another worker
    SendMessage(String),
    /// Error setting up the task
    Setup(String),
    /// Error interacting with global state
    State(String),
}

impl TaskError for NewWalletTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            NewWalletTaskError::Arbitrum(_)
                | NewWalletTaskError::ProofGeneration(_)
                | NewWalletTaskError::State(_)
        )
    }
}

impl Display for NewWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}
impl Error for NewWalletTaskError {}

impl From<StateError> for NewWalletTaskError {
    fn from(e: StateError) -> Self {
        NewWalletTaskError::State(e.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// The task descriptor containing only the parameterization of the task
#[derive(Debug, Serialize, Deserialize)]
pub struct NewWalletTaskDescriptor {
    /// The wallet to create
    pub wallet: Wallet,
}

/// The task itself, containing the state, context, descriptor, etc
pub struct NewWalletTask {
    /// The wallet to create
    pub wallet: Wallet,
    /// The proof of `VALID WALLET CREATE` for the wallet, generated in the
    /// first step
    pub proof_bundle: Option<ValidWalletCreateBundle>,
    /// An arbitrum client for the task to submit transactions
    pub arbitrum_client: ArbitrumClient,
    /// A copy of the relayer-global state
    pub global_state: State,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: ProofManagerQueue,
    /// The state of the task's execution
    pub task_state: NewWalletTaskState,
}

// -----------------------
// | Task Implementation |
// -----------------------

#[async_trait]
impl Task for NewWalletTask {
    type Error = NewWalletTaskError;
    type State = NewWalletTaskState;
    type Descriptor = NewWalletTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        // Safety: verify that the wallet's shares recover the wallet correctly
        let wallet = &descriptor.wallet;
        let circuit_wallet: SizedWallet = wallet.clone().into();
        let recovered_wallet =
            wallet_from_blinded_shares(&wallet.private_shares, &wallet.blinded_public_shares);

        if circuit_wallet != recovered_wallet {
            return Err(NewWalletTaskError::InvalidShares(ERR_INVALID_SHARING.to_string()));
        }

        Ok(Self {
            wallet: descriptor.wallet,
            proof_bundle: None, // Initialize as None since it's not part of the descriptor
            arbitrum_client: ctx.arbitrum_client,
            global_state: ctx.state,
            proof_manager_work_queue: ctx.proof_queue,
            task_state: NewWalletTaskState::Pending, // Initialize to the initial state
        })
    }

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current state of the task
        match self.state() {
            NewWalletTaskState::Pending => {
                self.task_state = NewWalletTaskState::Proving;
            },
            NewWalletTaskState::Proving => {
                // Begin proof and attach the proof to the state afterwards
                self.generate_proof().await?;
                self.task_state = NewWalletTaskState::SubmittingTx;
            },
            NewWalletTaskState::SubmittingTx { .. } => {
                // Submit the wallet on-chain
                self.submit_wallet_tx().await?;
                self.task_state = NewWalletTaskState::FindingMerkleOpening;
            },
            NewWalletTaskState::FindingMerkleOpening => {
                // Find the authentication path via contract events, and index this
                // in the global state
                self.find_merkle_path().await?;
                self.task_state = NewWalletTaskState::Completed;
            },
            NewWalletTaskState::Completed => {
                panic!("step() called in completed state")
            },
        }

        Ok(())
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn name(&self) -> String {
        NEW_WALLET_TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl NewWalletTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Generate a proof of `VALID WALLET CREATE` for the new wallet
    async fn generate_proof(&mut self) -> Result<(), NewWalletTaskError> {
        // Construct the witness and statement for the proof
        let (witness, statement) = self.get_witness_statement();

        // Enqueue a job with the proof manager to prove `VALID NEW WALLET`
        let job = ProofJob::ValidWalletCreate { statement, witness };
        let proof_recv = enqueue_proof_job(job, &self.proof_manager_work_queue)
            .map_err(NewWalletTaskError::SendMessage)?;

        // Await the proof
        let bundle =
            proof_recv.await.map_err(|e| NewWalletTaskError::ProofGeneration(e.to_string()))?;
        self.proof_bundle = Some(bundle.proof.into());
        Ok(())
    }

    /// Submit the newly created wallet on-chain with proof of validity
    async fn submit_wallet_tx(&mut self) -> Result<(), NewWalletTaskError> {
        let proof = self.proof_bundle.clone().unwrap();
        self.arbitrum_client
            .new_wallet(&proof)
            .await
            .map_err(|err| NewWalletTaskError::Arbitrum(err.to_string()))
    }

    /// A helper to find the new Merkle authentication path in the contract
    /// state and update the global state with the new wallet's
    /// authentication path
    async fn find_merkle_path(&self) -> Result<(), NewWalletTaskError> {
        // Find the authentication path of the wallet's private shares
        let wallet_auth_path = find_merkle_path(&self.wallet, &self.arbitrum_client)
            .await
            .map_err(|err| NewWalletTaskError::Arbitrum(err.to_string()))?;

        // Index the wallet in the global state
        let mut wallet = self.wallet.clone();
        wallet.merkle_proof = Some(wallet_auth_path);
        Ok(self.global_state.new_wallet(wallet)?.await?)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Create a witness and statement for `VALID WALLET CREATE`
    fn get_witness_statement(
        &self,
    ) -> (SizedValidWalletCreateWitness, SizedValidWalletCreateStatement) {
        let private_shares_commitment =
            compute_wallet_private_share_commitment(&self.wallet.private_shares);

        (
            ValidWalletCreateWitness { private_wallet_share: self.wallet.private_shares.clone() },
            ValidWalletCreateStatement {
                private_shares_commitment,
                public_wallet_shares: self.wallet.blinded_public_shares.clone(),
            },
        )
    }
}
