//! Defines a task for submitting `update_wallet` transactions, transitioning
//! the state of an existing darkpool wallet
//!
//! This involves proving `VALID WALLET UPDATE`, submitting on-chain, and
//! re-indexing state

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

use alloy::rpc::types::TransactionReceipt;
use async_trait::async_trait;
use common::types::tasks::WalletUpdateType;
use common::types::{
    proof_bundles::ValidWalletUpdateBundle, tasks::UpdateWalletTaskDescriptor,
    transfer_auth::ExternalTransferWithAuth, wallet::Wallet,
};
use darkpool_client::errors::DarkpoolClientError;
use job_types::event_manager::RelayerEventType;
use job_types::proof_manager::ProofJob;
use renegade_metrics::helpers::maybe_record_transfer_metrics;
use serde::Serialize;
use state::error::StateError;
use tracing::{info, instrument};

use crate::task_state::StateWrapper;
use crate::traits::{Descriptor, Task, TaskContext, TaskError, TaskState};
use crate::utils::{
    enqueue_proof_job, merkle_path::find_merkle_path_with_tx,
    validity_proofs::update_wallet_validity_proofs,
};

/// The human-readable name of the the task
const UPDATE_WALLET_TASK_NAME: &str = "update-wallet";
/// The wallet no longer exists in global state
const ERR_WALLET_MISSING: &str = "wallet not found in global state";
/// The new wallet does not correspond to a valid reblinding of the old wallet
const ERR_INVALID_REBLIND: &str = "new wallet is not a valid reblind of old wallet";

// --------------
// | Task State |
// --------------

/// Defines the state of the deposit update wallet task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    /// The task state in which we update the wallet in the global state for
    /// updates that don't require an on-chain update
    UpdatingConsensusState,
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
            Self::Pending => write!(f, "Pending"),
            Self::Proving => write!(f, "Proving"),
            Self::SubmittingTx => write!(f, "Submitting Tx"),
            Self::FindingOpening => write!(f, "Finding Opening"),
            Self::UpdatingValidityProofs => write!(f, "Updating Validity Proofs"),
            Self::UpdatingConsensusState => write!(f, "Updating Consensus State"),
            Self::Completed => write!(f, "Completed"),
        }
    }
}

impl FromStr for UpdateWalletTaskState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Pending" => Ok(Self::Pending),
            "Proving" => Ok(Self::Proving),
            "Submitting Tx" => Ok(Self::SubmittingTx),
            "Finding Opening" => Ok(Self::FindingOpening),
            "Updating Validity Proofs" => Ok(Self::UpdatingValidityProofs),
            "Updating Consensus State" => Ok(Self::UpdatingConsensusState),
            "Completed" => Ok(Self::Completed),
            _ => Err(format!("invalid {UPDATE_WALLET_TASK_NAME} task state: {s}")),
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

impl Descriptor for UpdateWalletTaskDescriptor {}

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
    /// An error interacting with the darkpool client
    Darkpool(String),
    /// A state element was not found that is necessary for task execution
    Missing(String),
    /// An error interacting with the relayer state
    State(String),
    /// An error while updating validity proofs for a wallet
    UpdatingValidityProofs(String),
    /// An error occurred sending an event to the event manager
    SendEvent(String),
}

impl TaskError for UpdateWalletTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            UpdateWalletTaskError::ProofGeneration(_)
                | UpdateWalletTaskError::Darkpool(_)
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

impl From<DarkpoolClientError> for UpdateWalletTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        UpdateWalletTaskError::Darkpool(e.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the long running flow for updating a wallet
pub struct UpdateWalletTask {
    /// The type of wallet update being executed
    pub update_type: WalletUpdateType,
    /// The external transfer & auth data, if one exists
    pub transfer: Option<ExternalTransferWithAuth>,
    /// The old wallet before update
    pub old_wallet: Wallet,
    /// The new wallet after update
    pub new_wallet: Wallet,
    /// A signature of the `VALID WALLET UPDATE` statement by the wallet's root
    /// key, the contract uses this to authorize the update
    pub wallet_update_signature: Vec<u8>,
    /// A proof of `VALID WALLET UPDATE` created in the first step
    pub proof_bundle: Option<ValidWalletUpdateBundle>,
    /// The transaction receipt of the wallet update transaction
    pub tx: Option<TransactionReceipt>,
    /// The state of the task
    pub task_state: UpdateWalletTaskState,
    /// The pending event to emit after the task is complete.
    /// We construct this event before emitting it, as we may need to
    /// access state that is deleted by the end of the task to do so
    /// (e.g., in the case of an order cancellation).
    pub completion_event: Option<RelayerEventType>,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for UpdateWalletTask {
    type Error = UpdateWalletTaskError;
    type State = UpdateWalletTaskState;
    type Descriptor = UpdateWalletTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        // Pull in the most recent version of the `old_wallet`
        let old_wallet = ctx
            .state
            .get_wallet(&descriptor.wallet_id)
            .await?
            .ok_or_else(|| UpdateWalletTaskError::Missing(ERR_WALLET_MISSING.to_string()))?;

        // Check that the new wallet is properly reblinded from the old wallet.
        // We do this here, as opposed to in the creation of the task descriptor, to
        // ensure we are checking a reblind progression from the most recent
        // wallet state. This is important, as an improperly-reblinded wallet
        // can be successfully committed onchain, but future wallet lookup tasks
        // will not return the most recent wallet state.
        if !Self::check_reblind_progression(&old_wallet, &descriptor.new_wallet) {
            return Err(UpdateWalletTaskError::InvalidShares(ERR_INVALID_REBLIND.to_string()));
        }

        let mut task = Self {
            update_type: descriptor.description,
            transfer: descriptor.transfer,
            old_wallet,
            new_wallet: descriptor.new_wallet,
            wallet_update_signature: descriptor.wallet_update_signature,
            proof_bundle: None,
            tx: None,
            task_state: UpdateWalletTaskState::Pending,
            completion_event: None,
            ctx,
        };

        // Prepare the completion event
        task.prepare_completion_event().await?;

        Ok(task)
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(
        task = self.name(),
        state = %self.state(),
        old_wallet_id = %self.old_wallet.wallet_id,
        new_wallet_id = %self.new_wallet.wallet_id,
    ))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.state() {
            UpdateWalletTaskState::Pending => {
                // Skip proving and tx submission if the update doesn't require
                // an on-chain update
                if self.requires_onchain_update() {
                    self.task_state = UpdateWalletTaskState::Proving;
                } else {
                    self.task_state = UpdateWalletTaskState::UpdatingConsensusState;
                }
            },
            UpdateWalletTaskState::Proving => {
                // Begin the proof of `VALID WALLET UPDATE`
                self.generate_proof().await?;
                self.task_state = UpdateWalletTaskState::SubmittingTx;
            },
            UpdateWalletTaskState::SubmittingTx => {
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
                self.emit_event()?;
                maybe_record_transfer_metrics(&self.transfer);

                self.task_state = UpdateWalletTaskState::Completed;
            },
            UpdateWalletTaskState::UpdatingConsensusState => {
                // Update the wallet in the global state
                self.update_consensus_state().await?;
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
        let (witness, statement) = self.build_task_witness_statement()?;

        // Dispatch a job to the proof manager, and await the job's result
        let job = ProofJob::ValidWalletUpdate { witness, statement };
        let proof_recv =
            enqueue_proof_job(job, &self.ctx).map_err(UpdateWalletTaskError::ProofGeneration)?;

        // Await the proof
        let bundle =
            proof_recv.await.map_err(|e| UpdateWalletTaskError::ProofGeneration(e.to_string()))?;

        self.proof_bundle = Some(bundle.into());
        Ok(())
    }

    /// Submit the `update_wallet` transaction to the contract and await
    /// finality
    async fn submit_tx(&mut self) -> Result<(), UpdateWalletTaskError> {
        let proof = self.proof_bundle.clone().unwrap();
        let transfer_auth = self.transfer.as_ref().map(|t| t.transfer_auth.clone());
        let sig = self.wallet_update_signature.clone();
        let tx = self.ctx.darkpool_client.update_wallet(&proof, sig, transfer_auth).await?;
        self.tx = Some(tx);

        Ok(())
    }

    /// Find the wallet opening for the new wallet and re-index the wallet in
    /// the global state
    async fn find_opening(&mut self) -> Result<(), UpdateWalletTaskError> {
        // Attach the opening to the new wallet, and index the wallet in the global
        // state
        let tx = self.tx.as_ref().unwrap();
        let merkle_opening = find_merkle_path_with_tx(&self.new_wallet, tx, &self.ctx)?;
        self.new_wallet.merkle_proof = Some(merkle_opening);

        // After the state is finalized on-chain, re-index the wallet in the global
        // state
        let waiter = self.ctx.state.update_wallet(self.new_wallet.clone()).await?;
        waiter.await?;

        // If we're placing a new order into a matching pool, assign it as
        // appropriate. We assume that the matching pool exists.
        if let WalletUpdateType::PlaceOrder {
            id,
            matching_pool: Some(ref matching_pool_name),
            ..
        } = self.update_type
        {
            self.ctx.state.assign_order_to_matching_pool(id, matching_pool_name.clone()).await?;
        }

        Ok(())
    }

    /// After a wallet update has been submitted on-chain, re-prove `VALID
    /// REBLIND` for the wallet and `VALID COMMITMENTS` for all orders in
    /// the wallet
    async fn update_validity_proofs(&self) -> Result<(), UpdateWalletTaskError> {
        // Spawn the validity proofs update
        let new_wallet = self.new_wallet.clone();
        let ctx = self.ctx.clone();
        let validity_jh = tokio::spawn(async move {
            update_wallet_validity_proofs(&new_wallet, &ctx)
                .await
                .map_err(UpdateWalletTaskError::UpdatingValidityProofs)
        });

        // Precompute a cancellation proof for an order if necessary
        let cancellation_proof = self.precompute_cancellation_proof().await?;
        if let Some(proof) = cancellation_proof {
            self.store_cancellation_proof(&proof).await?;
        }

        validity_jh
            .await
            .map_err(|e| UpdateWalletTaskError::UpdatingValidityProofs(e.to_string()))? // Join error
            .map_err(|e| UpdateWalletTaskError::UpdatingValidityProofs(e.to_string())) // Validity proof error
    }

    /// Update the wallet directly in the global state
    async fn update_consensus_state(&self) -> Result<(), UpdateWalletTaskError> {
        info!("Wallet update does not require on-chain update, updating consensus state directly");
        // No reblind occurs here, so force the new wallet to have the same secret
        // shares as the old one
        let mut new_wallet = self.new_wallet.clone();
        new_wallet.private_shares = self.old_wallet.private_shares.clone();
        new_wallet.blinded_public_shares = self.old_wallet.blinded_public_shares.clone();
        new_wallet.blinder = self.old_wallet.blinder;
        new_wallet.merkle_proof = self.old_wallet.merkle_proof.clone();

        let waiter = self.ctx.state.update_wallet(new_wallet).await?;
        waiter.await?;
        Ok(())
    }
}
