//! A take to create a new wallet
//!
//! At a high level the steps are:
//!     1. Index the wallet locally
//!     2. Prove `VALID WALLET CREATE` for the wallet
//!     3. Submit this on-chain and await transaction success
//!     4. Pull the Merkle authentication path of the newly created wallet from
//!        on-chain state

use core::panic;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

use alloy::rpc::types::TransactionReceipt;
use async_trait::async_trait;
use circuit_types::native_helpers::compute_wallet_share_commitment;
use circuits::zk_circuits::valid_wallet_create::{
    SizedValidWalletCreateStatement, SizedValidWalletCreateWitness, ValidWalletCreateStatement,
    ValidWalletCreateWitness,
};
use common::types::tasks::NewWalletTaskDescriptor;
use common::types::{proof_bundles::ValidWalletCreateBundle, wallet::Wallet};
use constants::Scalar;
use darkpool_client::errors::DarkpoolClientError;
use job_types::event_manager::{RelayerEventType, WalletCreationEvent, try_send_event};
use job_types::proof_manager::ProofJob;
use renegade_metrics::labels::NUM_NEW_WALLETS_METRIC;
use serde::Serialize;
use state::error::StateError;
use tracing::instrument;
use util::err_str;

use crate::task_state::StateWrapper;
use crate::traits::{Descriptor, Task, TaskContext, TaskError, TaskState};
use crate::utils::enqueue_proof_job;
use crate::utils::merkle_path::find_merkle_path_with_tx;

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
            NewWalletTaskState::Pending => write!(f, "Pending"),
            NewWalletTaskState::Proving => write!(f, "Proving"),
            NewWalletTaskState::SubmittingTx => write!(f, "Submitting Tx"),
            NewWalletTaskState::FindingMerkleOpening => write!(f, "Finding Opening"),
            NewWalletTaskState::Completed => write!(f, "Completed"),
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
    /// Error interacting with the darkpool client
    Darkpool(String),
    /// Error sending a message to another worker
    SendMessage(String),
    /// Error setting up the task
    Setup(String),
    /// Error interacting with global state
    State(String),
}

impl From<DarkpoolClientError> for NewWalletTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        NewWalletTaskError::Darkpool(e.to_string())
    }
}

impl TaskError for NewWalletTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            NewWalletTaskError::Darkpool(_)
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

/// The task itself, containing the state, context, descriptor, etc
pub struct NewWalletTask {
    /// The wallet to create
    pub wallet: Wallet,
    /// The blinder seed to use for the new wallet
    pub blinder_seed: Scalar,
    /// The proof of `VALID WALLET CREATE` for the wallet, generated in the
    /// first step
    pub proof_bundle: Option<ValidWalletCreateBundle>,
    /// The transaction receipt of the wallet creation
    pub tx: Option<TransactionReceipt>,
    /// The state of the task's execution
    pub task_state: NewWalletTaskState,
    /// The context of the task
    pub ctx: TaskContext,
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
        Ok(Self {
            wallet: descriptor.wallet,
            blinder_seed: descriptor.blinder_seed,
            proof_bundle: None, // Initialize as None since it's not part of the descriptor
            tx: None,
            task_state: NewWalletTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.state(), wallet_id = %self.wallet.wallet_id))]
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
            NewWalletTaskState::SubmittingTx => {
                // Submit the wallet on-chain
                self.submit_wallet_tx().await?;
                self.task_state = NewWalletTaskState::FindingMerkleOpening;
            },
            NewWalletTaskState::FindingMerkleOpening => {
                // Find the authentication path via contract events, and index this
                // in the global state
                self.find_merkle_path().await?;
                self.emit_event()?;
                metrics::counter!(NUM_NEW_WALLETS_METRIC).increment(1);

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

impl Descriptor for NewWalletTaskDescriptor {}

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
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(NewWalletTaskError::SendMessage)?;

        // Await the proof
        let bundle =
            proof_recv.await.map_err(|e| NewWalletTaskError::ProofGeneration(e.to_string()))?;
        self.proof_bundle = Some(bundle.into());
        Ok(())
    }

    /// Submit the newly created wallet on-chain with proof of validity
    async fn submit_wallet_tx(&mut self) -> Result<(), NewWalletTaskError> {
        let proof = self.proof_bundle.clone().unwrap();
        let tx = self.ctx.darkpool_client.new_wallet(&proof).await?;
        self.tx = Some(tx);
        Ok(())
    }

    /// A helper to find the new Merkle authentication path in the contract
    /// state and update the global state with the new wallet's
    /// authentication path
    async fn find_merkle_path(&self) -> Result<(), NewWalletTaskError> {
        // Find the authentication path of the wallet's private shares
        let tx = self.tx.as_ref().unwrap();
        let wallet_auth_path = find_merkle_path_with_tx(&self.wallet, tx, &self.ctx)?;

        // Index the wallet in the global state
        let mut wallet = self.wallet.clone();
        wallet.merkle_proof = Some(wallet_auth_path);
        let waiter = self.ctx.state.new_wallet(wallet).await?;
        waiter.await?;
        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Create a witness and statement for `VALID WALLET CREATE`
    fn get_witness_statement(
        &self,
    ) -> (SizedValidWalletCreateWitness, SizedValidWalletCreateStatement) {
        let public_shares = &self.wallet.blinded_public_shares;
        let private_shares = &self.wallet.private_shares;
        let wallet_share_commitment =
            compute_wallet_share_commitment(public_shares, private_shares);

        (
            ValidWalletCreateWitness {
                private_wallet_share: self.wallet.private_shares.clone(),
                blinder_seed: self.blinder_seed,
            },
            ValidWalletCreateStatement {
                wallet_share_commitment,
                public_wallet_shares: self.wallet.blinded_public_shares.clone(),
            },
        )
    }

    /// Emit a wallet creation event to the event manager
    fn emit_event(&self) -> Result<(), NewWalletTaskError> {
        let event = RelayerEventType::WalletCreation(WalletCreationEvent::new(
            self.wallet.wallet_id,
            self.wallet.key_chain.symmetric_key().to_base64_string(),
        ));

        try_send_event(event, &self.ctx.event_queue)
            .map_err(err_str!(NewWalletTaskError::SendMessage))
    }
}
