//! Defines a task for submitting `update_wallet` transactions, transitioning
//! the state of an existing darkpool wallet
//!
//! This involves proving `VALID WALLET UPDATE`, submitting on-chain, and
//! re-indexing state

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

use alloy::rpc::types::TransactionReceipt;
use async_trait::async_trait;
use circuit_types::{transfers::ExternalTransferDirection, SizedWallet as CircuitWallet};
use circuits::zk_circuits::valid_wallet_update::{
    SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
};
use common::types::tasks::WalletUpdateType;
use common::types::wallet::{Order, OrderIdentifier};
use common::types::MatchingPoolName;
use common::types::{
    proof_bundles::ValidWalletUpdateBundle, tasks::UpdateWalletTaskDescriptor,
    transfer_auth::ExternalTransferWithAuth, wallet::Wallet,
};
use darkpool_client::errors::DarkpoolClientError;
use darkpool_client::DarkpoolClient;
use itertools::Itertools;
use job_types::event_manager::{
    try_send_event, EventManagerQueue, ExternalTransferEvent, OrderCancellationEvent,
    OrderPlacementEvent, OrderUpdateEvent, RelayerEventType,
};
use job_types::network_manager::NetworkManagerQueue;
use job_types::proof_manager::{ProofJob, ProofManagerQueue};
use renegade_metrics::helpers::maybe_record_transfer_metrics;
use serde::Serialize;
use state::error::StateError;
use state::storage::tx::matching_pools::GLOBAL_MATCHING_POOL;
use state::State;
use tracing::{info, instrument};
use util::err_str;

use crate::task_state::StateWrapper;
use crate::traits::{Task, TaskContext, TaskError, TaskState};
use crate::utils::validity_proofs::{
    enqueue_proof_job, find_merkle_path_with_tx, update_wallet_validity_proofs,
};

/// The human-readable name of the the task
const UPDATE_WALLET_TASK_NAME: &str = "update-wallet";
/// The wallet no longer exists in global state
const ERR_WALLET_MISSING: &str = "wallet not found in global state";
/// The wallet does not have a known Merkle proof attached
const ERR_NO_MERKLE_PROOF: &str = "merkle proof for wallet not found";
/// The new wallet does not correspond to a valid reblinding of the old wallet
const ERR_INVALID_REBLIND: &str = "new wallet is not a valid reblind of old wallet";
/// A deposit or withdrawal wallet update type is missing an external transfer
const ERR_MISSING_TRANSFER: &str = "missing external transfer";
/// A cancelled order cannot be found in an order cancellation wallet update
/// type
const ERR_MISSING_CANCELLED_ORDER: &str = "missing cancelled order";
/// An order metadata is missing from the global state
const ERR_MISSING_ORDER_METADATA: &str = "missing order metadata";

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
    /// The darkpool client to use for submitting transactions
    pub darkpool_client: DarkpoolClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// A copy of the relayer-global state
    pub state: State,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: ProofManagerQueue,
    /// The state of the task
    pub task_state: UpdateWalletTaskState,
    /// The event manager queue
    pub event_queue: EventManagerQueue,
    /// The pending event to emit after the task is complete.
    /// We construct this event before emitting it, as we may need to
    /// access state that is deleted by the end of the task to do so
    /// (e.g., in the case of an order cancellation).
    pub completion_event: Option<RelayerEventType>,
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
            darkpool_client: ctx.darkpool_client,
            network_sender: ctx.network_queue,
            state: ctx.state,
            proof_manager_work_queue: ctx.proof_queue,
            task_state: UpdateWalletTaskState::Pending,
            event_queue: ctx.event_queue,
            completion_event: None,
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
        let transfer_auth = self.transfer.as_ref().map(|t| t.transfer_auth.clone());
        let sig = self.wallet_update_signature.clone();
        let tx = self.darkpool_client.update_wallet(&proof, sig, transfer_auth).await?;
        self.tx = Some(tx);

        Ok(())
    }

    /// Find the wallet opening for the new wallet and re-index the wallet in
    /// the global state
    async fn find_opening(&mut self) -> Result<(), UpdateWalletTaskError> {
        // Attach the opening to the new wallet, and index the wallet in the global
        // state
        let tx = self.tx.as_ref().unwrap();
        let merkle_opening = find_merkle_path_with_tx(&self.new_wallet, &self.darkpool_client, tx)?;
        self.new_wallet.merkle_proof = Some(merkle_opening);

        // After the state is finalized on-chain, re-index the wallet in the global
        // state
        let waiter = self.state.update_wallet(self.new_wallet.clone()).await?;
        waiter.await?;

        // If we're placing a new order into a matching pool, assign it as
        // appropriate. We assume that the matching pool exists.
        if let WalletUpdateType::PlaceOrder {
            id,
            matching_pool: Some(ref matching_pool_name),
            ..
        } = self.update_type
        {
            self.state.assign_order_to_matching_pool(id, matching_pool_name.clone()).await?;
        }

        Ok(())
    }

    /// After a wallet update has been submitted on-chain, re-prove `VALID
    /// REBLIND` for the wallet and `VALID COMMITMENTS` for all orders in
    /// the wallet
    async fn update_validity_proofs(&self) -> Result<(), UpdateWalletTaskError> {
        update_wallet_validity_proofs(
            &self.new_wallet,
            self.proof_manager_work_queue.clone(),
            self.state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(UpdateWalletTaskError::UpdatingValidityProofs)
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

        let waiter = self.state.update_wallet(new_wallet).await?;
        waiter.await?;
        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Whether the wallet update requires an on-chain update
    ///
    /// Some wallet updates do not modify the on-chain state, e.g. marking an
    /// order as externally matchable. In these cases, we can skip the on-chain
    /// interaction and just update the local copy of the wallet
    ///
    /// Concretely, if an update doesn't change the circuit representation of
    /// the wallet, we can skip the on-chain update
    ///
    /// TODO: In the future we'll want to allow reblind-only updates, for which
    /// we can force an on-chain update
    pub(crate) fn requires_onchain_update(&self) -> bool {
        let old_circuit_wallet: CircuitWallet = self.old_wallet.clone().into();
        let mut new_circuit_wallet: CircuitWallet = self.new_wallet.clone().into();

        // The wallet blinders are allowed to be different, all other fields must
        // match exactly to skip the on-chain update
        new_circuit_wallet.blinder = self.old_wallet.blinder;
        new_circuit_wallet != old_circuit_wallet
    }

    /// Check that the wallet's blinder and private shares are the result of
    /// applying a reblind to the old wallet
    pub fn check_reblind_progression(old_wallet: &Wallet, new_wallet: &Wallet) -> bool {
        let mut old_wallet_clone = old_wallet.clone();
        old_wallet_clone.reblind_wallet();
        let expected_private_shares = old_wallet_clone.private_shares;
        let expected_blinder = old_wallet_clone.blinder;

        new_wallet.private_shares == expected_private_shares
            && new_wallet.blinder == expected_blinder
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
        let new_wallet_commitment = self.new_wallet.get_wallet_share_commitment();

        let transfer_index = self.get_transfer_idx()?;
        let transfer = self.transfer.clone().map(|t| t.external_transfer).unwrap_or_default();
        let statement = SizedValidWalletUpdateStatement {
            old_shares_nullifier: old_wallet.get_wallet_nullifier(),
            new_wallet_commitment,
            new_public_shares: new_wallet.blinded_public_shares.clone(),
            merkle_root,
            external_transfer: transfer,
            old_pk_root: old_wallet.key_chain.public_keys.pk_root.clone(),
        };

        let witness = SizedValidWalletUpdateWitness {
            old_wallet_private_shares: old_wallet.private_shares.clone(),
            old_wallet_public_shares: old_wallet.blinded_public_shares.clone(),
            old_shares_opening: merkle_opening.into(),
            new_wallet_private_shares: new_wallet.private_shares.clone(),
            transfer_index,
        };

        Ok((witness, statement))
    }

    /// Get the index that the transfer is applied to
    fn get_transfer_idx(&self) -> Result<usize, UpdateWalletTaskError> {
        if let Some(transfer) = self.transfer.as_ref().map(|t| &t.external_transfer) {
            let mint = &transfer.mint;
            match transfer.direction {
                ExternalTransferDirection::Deposit => self.new_wallet.get_balance_index(mint),
                ExternalTransferDirection::Withdrawal => self.old_wallet.get_balance_index(mint),
            }
            .ok_or(UpdateWalletTaskError::Missing(format!("transfer mint {mint:#x} not found")))
        } else {
            Ok(0)
        }
    }

    /// Emit the completion event to the event manager
    fn emit_event(&mut self) -> Result<(), UpdateWalletTaskError> {
        try_send_event(self.completion_event.take().unwrap(), &self.event_queue)
            .map_err(err_str!(UpdateWalletTaskError::SendEvent))
    }

    /// Construct the event to emit after the task is complete & record
    /// it in the task
    async fn prepare_completion_event(&mut self) -> Result<(), UpdateWalletTaskError> {
        let event = match &self.update_type {
            WalletUpdateType::Deposit { .. } | WalletUpdateType::Withdraw { .. } => {
                self.construct_external_transfer_event()?
            },
            WalletUpdateType::PlaceOrder { order, id, matching_pool } => {
                self.construct_order_placement_or_update_event(id, order, matching_pool)
            },
            WalletUpdateType::CancelOrder { order } => {
                self.construct_order_cancellation_event(order).await?
            },
        };

        self.completion_event = Some(event);
        Ok(())
    }

    /// Construct an external transfer event
    fn construct_external_transfer_event(&self) -> Result<RelayerEventType, UpdateWalletTaskError> {
        let wallet_id = self.new_wallet.wallet_id;
        let transfer = self
            .transfer
            .clone()
            .map(|t| t.external_transfer)
            .ok_or(UpdateWalletTaskError::Missing(ERR_MISSING_TRANSFER.to_string()))?;

        Ok(RelayerEventType::ExternalTransfer(ExternalTransferEvent::new(wallet_id, transfer)))
    }

    /// Construct either an order placement or an order update event,
    /// depending on whether the order already exists in the new wallet
    fn construct_order_placement_or_update_event(
        &self,
        order_id: &OrderIdentifier,
        order: &Order,
        matching_pool: &Option<MatchingPoolName>,
    ) -> RelayerEventType {
        let wallet_id = self.new_wallet.wallet_id;
        let order_id = *order_id;
        let order = order.clone();
        let matching_pool = matching_pool.clone().unwrap_or(GLOBAL_MATCHING_POOL.to_string());

        if self.old_wallet.contains_order(&order_id) {
            RelayerEventType::OrderUpdate(OrderUpdateEvent::new(
                wallet_id,
                order_id,
                order,
                matching_pool,
            ))
        } else {
            RelayerEventType::OrderPlacement(OrderPlacementEvent::new(
                wallet_id,
                order_id,
                order,
                matching_pool,
            ))
        }
    }

    /// Construct an order cancellation event
    async fn construct_order_cancellation_event(
        &self,
        order: &Order,
    ) -> Result<RelayerEventType, UpdateWalletTaskError> {
        let wallet_id = self.new_wallet.wallet_id;
        let order = order.clone();

        // Find the ID of the cancelled order
        let mut new_order_ids = self.new_wallet.get_nonzero_orders().into_keys();
        let order_id = self
            .old_wallet
            .get_nonzero_orders()
            .into_keys()
            .find(|id| !new_order_ids.contains(id))
            .ok_or(UpdateWalletTaskError::Missing(ERR_MISSING_CANCELLED_ORDER.to_string()))?;

        let amount_remaining = order.amount;

        let amount_filled = self
            .state
            .get_order_metadata(&order_id)
            .await?
            .ok_or(UpdateWalletTaskError::Missing(ERR_MISSING_ORDER_METADATA.to_string()))?
            .total_filled();

        Ok(RelayerEventType::OrderCancellation(OrderCancellationEvent::new(
            wallet_id,
            order_id,
            order,
            amount_remaining,
            amount_filled,
        )))
    }
}
