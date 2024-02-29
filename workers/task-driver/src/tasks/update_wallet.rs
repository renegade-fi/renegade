//! Defines a task for submitting `update_wallet` transactions, transitioning
//! the state of an existing darkpool wallet
//!
//! This involves proving `VALID WALLET UPDATE`, submitting on-chain, and
//! re-indexing state

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::{
    native_helpers::wallet_from_blinded_shares, transfers::ExternalTransfer, SizedWallet,
};
use circuits::zk_circuits::valid_wallet_update::{
    SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
};
use common::types::transfer_auth::ExternalTransferWithAuth;
use common::types::{proof_bundles::ValidWalletUpdateBundle, wallet::Wallet};
use common::types::{tasks::UpdateWalletTaskDescriptor, transfer_auth::TransferAuth};
use job_types::network_manager::NetworkManagerQueue;
use job_types::proof_manager::{ProofJob, ProofManagerQueue};
use serde::Serialize;
use state::error::StateError;
use state::State;
use tracing::instrument;

use crate::driver::StateWrapper;
use crate::helpers::{enqueue_proof_job, find_merkle_path};
use crate::traits::{Task, TaskContext, TaskError, TaskState};

use crate::helpers::update_wallet_validity_proofs;

/// The human-readable name of the the task
const UPDATE_WALLET_TASK_NAME: &str = "update-wallet";
/// The given wallet shares do not recover the new wallet
const ERR_INVALID_BLINDING: &str = "invalid blinding for new wallet";
/// The wallet does not have a known Merkle proof attached
const ERR_NO_MERKLE_PROOF: &str = "merkle proof for wallet not found";

// --------------
// | Task State |
// --------------

/// Defines the state of the deposit update wallet task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[allow(clippy::large_enum_variant)]
pub enum UpdateWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is awaiting a proof of `VALID WALLET UPDATE` from
    /// the proof management worker
    Proving,
    /// The task is submitting the transaction to the contract and awaiting
    /// transaction finality
    SubmittingTx,
    /// The task is finding a new Merkle opening for the wallet
    FindingOpening,
    /// The task is updating the validity proofs for all orders in the
    /// now nullified wallet
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl TaskState for UpdateWalletTaskState {
    fn commit_point() -> Self {
        Self::SubmittingTx
    }

    fn completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl Display for UpdateWalletTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::SubmittingTx { .. } => write!(f, "SubmittingTx"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl Serialize for UpdateWalletTaskState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl From<UpdateWalletTaskState> for StateWrapper {
    fn from(state: UpdateWalletTaskState) -> Self {
        StateWrapper::UpdateWallet(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the update wallet task
#[derive(Clone, Debug)]
pub enum UpdateWalletTaskError {
    /// A wallet was submitted with an invalid secret shares
    InvalidShares(String),
    /// Error generating a proof of `VALID WALLET UPDATE`
    ProofGeneration(String),
    /// An error occurred interacting with Arbitrum
    Arbitrum(String),
    /// A state element was not found that is necessary for task execution
    Missing(String),
    /// An error interacting with the relayer state
    State(String),
    /// An error while updating validity proofs for a wallet
    UpdatingValidityProofs(String),
    /// Wallet is already locked, cannot update
    WalletLocked,
}

impl TaskError for UpdateWalletTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            UpdateWalletTaskError::ProofGeneration(_)
                | UpdateWalletTaskError::Arbitrum(_)
                | UpdateWalletTaskError::State(_)
                | UpdateWalletTaskError::UpdatingValidityProofs(_)
        )
    }
}

impl Display for UpdateWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for UpdateWalletTaskError {}

impl From<StateError> for UpdateWalletTaskError {
    fn from(e: StateError) -> Self {
        UpdateWalletTaskError::State(e.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the long running flow for updating a wallet
pub struct UpdateWalletTask {
    /// The timestamp at which the task was initiated, used to timestamp orders
    pub timestamp_received: u64,
    /// The external transfer & auth data, if one exists
    pub external_transfer_with_auth: Option<ExternalTransferWithAuth>,
    /// The old wallet before update
    pub old_wallet: Wallet,
    /// The new wallet after update
    pub new_wallet: Wallet,
    /// A signature of the `VALID WALLET UPDATE` statement by the wallet's root
    /// key, the contract uses this to authorize the update
    pub wallet_update_signature: Vec<u8>,
    /// A proof of `VALID WALLET UPDATE` created in the first step
    pub proof_bundle: Option<ValidWalletUpdateBundle>,
    /// The arbitrum client to use for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// A copy of the relayer-global state
    pub global_state: State,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: ProofManagerQueue,
    /// The state of the task
    pub task_state: UpdateWalletTaskState,
}

#[async_trait]
impl Task for UpdateWalletTask {
    type Error = UpdateWalletTaskError;
    type State = UpdateWalletTaskState;
    type Descriptor = UpdateWalletTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        // Safety check, the new wallet's secret shares must recover the new wallet
        Self::check_wallet_shares(&descriptor.new_wallet)?;

        Ok(Self {
            timestamp_received: descriptor.timestamp_received,
            external_transfer_with_auth: descriptor.external_transfer_with_auth,
            old_wallet: descriptor.old_wallet,
            new_wallet: descriptor.new_wallet,
            wallet_update_signature: descriptor.wallet_update_signature,
            proof_bundle: None,
            arbitrum_client: ctx.arbitrum_client,
            network_sender: ctx.network_queue,
            global_state: ctx.state,
            proof_manager_work_queue: ctx.proof_queue,
            task_state: UpdateWalletTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.state() {
            UpdateWalletTaskState::Pending => {
                self.task_state = UpdateWalletTaskState::Proving;
            },
            UpdateWalletTaskState::Proving => {
                // Begin the proof of `VALID WALLET UPDATE`
                self.generate_proof().await?;
                self.task_state = UpdateWalletTaskState::SubmittingTx;
            },
            UpdateWalletTaskState::SubmittingTx { .. } => {
                // Submit the proof and transaction info to the contract and await
                // transaction finality
                self.submit_tx().await?;
                self.task_state = UpdateWalletTaskState::FindingOpening;
            },
            UpdateWalletTaskState::FindingOpening => {
                // Find a new Merkle opening for the wallet
                self.find_opening().await?;
                self.task_state = UpdateWalletTaskState::UpdatingValidityProofs;
            },
            UpdateWalletTaskState::UpdatingValidityProofs => {
                // Update validity proofs for now-nullified orders
                self.update_validity_proofs().await?;
                self.task_state = UpdateWalletTaskState::Completed;
            },
            UpdateWalletTaskState::Completed => {
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
        UPDATE_WALLET_TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl UpdateWalletTask {
    // --------------
    // | Task Steps |
    // --------------

    /// Generate a proof of `VALID WALLET UPDATE` for the wallet
    async fn generate_proof(&mut self) -> Result<(), UpdateWalletTaskError> {
        let (witness, statement) = self.get_witness_statement()?;

        // Dispatch a job to the proof manager, and await the job's result
        let job = ProofJob::ValidWalletUpdate { witness, statement };
        let proof_recv = enqueue_proof_job(job, &self.proof_manager_work_queue)
            .map_err(UpdateWalletTaskError::ProofGeneration)?;

        // Await the proof
        let bundle =
            proof_recv.await.map_err(|e| UpdateWalletTaskError::ProofGeneration(e.to_string()))?;

        self.proof_bundle = Some(bundle.proof.into());
        Ok(())
    }

    /// Submit the `update_wallet` transaction to the contract and await
    /// finality
    async fn submit_tx(&mut self) -> Result<(), UpdateWalletTaskError> {
        let proof = self.proof_bundle.clone().unwrap();
        let transfer_auth =
            self.external_transfer_with_auth.as_ref().map(|t| t.transfer_auth.clone());
        self.arbitrum_client
            .update_wallet(&proof, self.wallet_update_signature.clone(), transfer_auth)
            .await
            .map_err(|e| e.to_string())
            .map_err(UpdateWalletTaskError::Arbitrum)
    }

    /// Find the wallet opening for the new wallet and re-index the wallet in
    /// the global state
    async fn find_opening(&mut self) -> Result<(), UpdateWalletTaskError> {
        // Attach the opening to the new wallet, and index the wallet in the global
        // state
        let merkle_opening = find_merkle_path(&self.new_wallet, &self.arbitrum_client)
            .await
            .map_err(|e| UpdateWalletTaskError::Arbitrum(e.to_string()))?;
        self.new_wallet.merkle_proof = Some(merkle_opening);

        // After the state is finalized on-chain, re-index the wallet in the global
        // state
        self.global_state.update_wallet(self.new_wallet.clone())?.await?;
        Ok(())
    }

    /// After a wallet update has been submitted on-chain, re-prove `VALID
    /// REBLIND` for the wallet and `VALID COMMITMENTS` for all orders in
    /// the wallet
    async fn update_validity_proofs(&self) -> Result<(), UpdateWalletTaskError> {
        update_wallet_validity_proofs(
            &self.new_wallet,
            self.proof_manager_work_queue.clone(),
            self.global_state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(UpdateWalletTaskError::UpdatingValidityProofs)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Check the construction of a wallet's shares, i.e. that the shares match
    /// the wallet as a whole
    fn check_wallet_shares(new_wallet: &Wallet) -> Result<(), UpdateWalletTaskError> {
        let new_circuit_wallet: SizedWallet = new_wallet.clone().into();
        let recovered_wallet = wallet_from_blinded_shares(
            &new_wallet.private_shares,
            &new_wallet.blinded_public_shares,
        );

        if recovered_wallet != new_circuit_wallet {
            return Err(UpdateWalletTaskError::InvalidShares(ERR_INVALID_BLINDING.to_string()));
        }

        Ok(())
    }

    /// Construct a witness and statement for `VALID WALLET UPDATE`
    fn get_witness_statement(
        &self,
    ) -> Result<
        (SizedValidWalletUpdateWitness, SizedValidWalletUpdateStatement),
        UpdateWalletTaskError,
    > {
        // Get the Merkle opening previously stored to the wallet
        let merkle_opening = self
            .old_wallet
            .merkle_proof
            .clone()
            .ok_or_else(|| UpdateWalletTaskError::Missing(ERR_NO_MERKLE_PROOF.to_string()))?;
        let merkle_root = merkle_opening.compute_root();

        // Build the witness and statement
        let old_wallet = &self.old_wallet;
        let new_wallet = &self.new_wallet;
        let new_private_share_commitment = self.new_wallet.get_private_share_commitment();

        let statement = SizedValidWalletUpdateStatement {
            old_shares_nullifier: old_wallet.get_wallet_nullifier(),
            new_private_shares_commitment: new_private_share_commitment,
            new_public_shares: new_wallet.blinded_public_shares.clone(),
            merkle_root,
            external_transfer: self.external_transfer.clone().unwrap_or_default(),
            old_pk_root: old_wallet.key_chain.public_keys.pk_root.clone(),
            timestamp: self.timestamp_received,
        };

        let witness = SizedValidWalletUpdateWitness {
            old_wallet_private_shares: old_wallet.private_shares.clone(),
            old_wallet_public_shares: old_wallet.blinded_public_shares.clone(),
            old_shares_opening: merkle_opening.into(),
            new_wallet_private_shares: new_wallet.private_shares.clone(),
        };

        Ok((witness, statement))
    }
}
