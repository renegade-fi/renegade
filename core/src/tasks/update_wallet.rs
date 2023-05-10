//! Defines a task for submitting `update_wallet` transactions, transitioning the state of
//! an existing darkpool wallet
//!
//! This involves proving `VALID WALLET UPDATE`, submitting on-chain, and re-indexing state

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use circuits::{native_helpers::wallet_from_blinded_shares, types::transfers::ExternalTransfer};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::starknet_felt_to_biguint;
use serde::Serialize;
use starknet::core::types::TransactionStatus;
use tokio::sync::{mpsc::UnboundedSender as TokioSender, oneshot};
use tracing::log;

use crate::{
    gossip_api::gossip::GossipOutbound,
    proof_generation::{
        jobs::{ProofJob, ProofManagerJob, ValidWalletUpdateBundle},
        SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
    },
    starknet_client::client::StarknetClient,
    state::{wallet::Wallet, NetworkOrder, RelayerState},
    tasks::helpers::get_current_timestamp,
    SizedWallet,
};

use super::{
    driver::{StateWrapper, Task},
    helpers::update_wallet_validity_proofs,
};

/// The human-readable name of the the task
const UPDATE_WALLET_TASK_NAME: &str = "update-wallet";
/// The given wallet shares do not recover the new wallet
const ERR_INVALID_BLINDING: &str = "invalid blinding for new wallet";
/// The wallet does not have a known Merkle proof attached
const ERR_NO_MERKLE_PROOF: &str = "merkle proof for wallet not found";
/// A transaction submitted to the contract failed to execute
const ERR_TRANSACTION_FAILED: &str = "transaction failed";

// -------------------
// | Task Definition |
// -------------------

/// Defines the long running flow for adding a balance to a wallet
pub struct UpdateWalletTask {
    /// The external transfer, if one exists
    pub external_transfer: Option<ExternalTransfer>,
    /// The old wallet before update
    pub old_wallet: Wallet,
    /// The new wallet after update
    pub new_wallet: Wallet,
    /// The starknet client to use for submitting transactions
    pub starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    pub network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task
    pub task_state: UpdateWalletTaskState,
}

/// The error type for the deposit balance task
#[derive(Clone, Debug)]
pub enum UpdateWalletTaskError {
    /// An invalid blinding of the new wallet was submitted
    InvalidBlinding(String),
    /// Error generating a proof of `VALID WALLET UPDATE`
    ProofGeneration(String),
    /// An error occurred interacting with Starknet
    StarknetClient(String),
    /// A state element was not found that is necessary for task execution
    StateMissing(String),
    /// An error while updating validity proofs for a wallet
    UpdatingValidityProofs(String),
}

impl Display for UpdateWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

/// Defines the state of the deposit balance task
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum UpdateWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is awaiting a proof of `VALID WALLET UPDATE` from
    /// the proof management worker
    Proving,
    /// The task is submitting the transaction to the contract and awaiting
    /// transaction finality
    SubmittingTx {
        /// The proof of VALID WALLET UPDATE created in the previous step
        proof_bundle: ValidWalletUpdateBundle,
    },
    /// The task is updating the validity proofs for all orders in the
    /// now nullified wallet
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
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

#[async_trait]
impl Task for UpdateWalletTask {
    type Error = UpdateWalletTaskError;
    type State = UpdateWalletTaskState;

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.state() {
            UpdateWalletTaskState::Pending => {
                self.task_state = UpdateWalletTaskState::Proving;
            }
            UpdateWalletTaskState::Proving => {
                // Begin the proof of `VALID WALLET UPDATE`
                let proof_bundle = self.generate_proof().await?;
                self.task_state = UpdateWalletTaskState::SubmittingTx { proof_bundle };
            }
            UpdateWalletTaskState::SubmittingTx { .. } => {
                // Submit the proof and transaction info to the contract and await
                // transaction finality
                self.submit_tx().await?;
                self.task_state = UpdateWalletTaskState::UpdatingValidityProofs;
            }
            UpdateWalletTaskState::UpdatingValidityProofs => {
                // Update validity proofs for now-nullified orders
                self.update_validity_proofs().await?;
                self.task_state = UpdateWalletTaskState::Completed;
            }
            UpdateWalletTaskState::Completed => {
                panic!("step() called in state Completed")
            }
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
    /// Constructor
    ///
    /// Assumes that the state updates to the wallet have been applied in
    /// the caller
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        external_transfer: Option<ExternalTransfer>,
        old_wallet: Wallet,
        new_wallet: Wallet,
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Result<Self, UpdateWalletTaskError> {
        // Safety check, the new wallet's secret shares must recover the new wallet
        let new_circuit_wallet: SizedWallet = new_wallet.clone().into();
        let recovered_wallet = wallet_from_blinded_shares(
            new_wallet.private_shares.clone(),
            new_wallet.public_shares.clone(),
        );

        if recovered_wallet != new_circuit_wallet {
            return Err(UpdateWalletTaskError::InvalidBlinding(
                ERR_INVALID_BLINDING.to_string(),
            ));
        }

        Ok(Self {
            external_transfer,
            old_wallet,
            new_wallet,
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_state: UpdateWalletTaskState::Pending,
        })
    }

    /// Generate a proof of `VALID WALLET UPDATE` for the wallet with added balance
    async fn generate_proof(&self) -> Result<ValidWalletUpdateBundle, UpdateWalletTaskError> {
        let timestamp = get_current_timestamp();
        let merkle_opening =
            self.old_wallet.merkle_proof.clone().ok_or_else(|| {
                UpdateWalletTaskError::StateMissing(ERR_NO_MERKLE_PROOF.to_string())
            })?;
        let merkle_root = merkle_opening.public_share_path.compute_root();

        // Build a witness and statement
        let private_share_nullifier = self.old_wallet.get_private_share_nullifier();
        let public_share_nullifier = self.old_wallet.get_public_share_nullifier();
        let new_private_share_commitment = self.new_wallet.get_private_share_commitment();

        let statement = SizedValidWalletUpdateStatement {
            old_private_shares_nullifier: private_share_nullifier,
            old_public_shares_nullifier: public_share_nullifier,
            new_private_shares_commitment: new_private_share_commitment,
            new_public_shares: self.new_wallet.public_shares.clone(),
            merkle_root,
            external_transfer: self.external_transfer.clone().unwrap_or_default(),
            old_pk_root: self.old_wallet.key_chain.public_keys.pk_root.clone(),
            timestamp,
        };

        let witness = SizedValidWalletUpdateWitness {
            old_wallet_private_shares: self.old_wallet.private_shares.clone(),
            old_wallet_public_shares: self.old_wallet.public_shares.clone(),
            private_shares_opening: merkle_opening.private_share_path.into(),
            public_shares_opening: merkle_opening.public_share_path.into(),
            new_wallet_private_shares: self.new_wallet.private_shares.clone(),
        };

        // Dispatch a job to the proof manager, and await the job's result
        let (proof_sender, proof_receiver) = oneshot::channel();
        self.proof_manager_work_queue
            .send(ProofManagerJob {
                response_channel: proof_sender,
                type_: ProofJob::ValidWalletUpdate { witness, statement },
            })
            .map_err(|err| UpdateWalletTaskError::ProofGeneration(err.to_string()))?;

        proof_receiver
            .await
            .map(|bundle| bundle.into())
            .map_err(|err| UpdateWalletTaskError::ProofGeneration(err.to_string()))
    }

    /// Submit the `update_wallet` transaction to the contract and await finality
    async fn submit_tx(&mut self) -> Result<(), UpdateWalletTaskError> {
        let proof = if let UpdateWalletTaskState::SubmittingTx { proof_bundle } = self.state() {
            proof_bundle
        } else {
            unreachable!("submit_tx may only be called from a SubmittingTx task state")
        };

        // Submit on-chain
        let tx_hash = self
            .starknet_client
            .update_wallet(
                self.new_wallet.get_private_share_commitment(),
                self.old_wallet.get_private_share_nullifier(),
                self.old_wallet.get_public_share_nullifier(),
                self.external_transfer
                    .clone()
                    .map(|transfer| transfer.into()),
                self.new_wallet.public_shares.clone(),
                proof,
            )
            .await
            .map_err(|err| UpdateWalletTaskError::StarknetClient(err.to_string()))?;
        log::info!("tx hash: 0x{:x}", starknet_felt_to_biguint(&tx_hash));

        // Await transaction completion
        let tx_info = self
            .starknet_client
            .poll_transaction_completed(tx_hash)
            .await
            .map_err(|err| UpdateWalletTaskError::StarknetClient(err.to_string()))?;

        if let TransactionStatus::Rejected = tx_info.status {
            return Err(UpdateWalletTaskError::StarknetClient(
                ERR_TRANSACTION_FAILED.to_string(),
            ));
        }

        // After the state is finalized on-chain, add new orders to the book and
        // re-index the wallet in the global state
        self.add_new_orders_to_book().await;
        self.global_state
            .update_wallet(self.new_wallet.clone())
            .await;
        Ok(())
    }

    /// Add new orders to the network order book
    async fn add_new_orders_to_book(&self) {
        let local_cluster_id = self.global_state.local_cluster_id.clone();
        let wallet_public_share_nullifier = self.new_wallet.get_public_share_nullifier();

        for order_id in self.new_wallet.orders.keys() {
            if !self
                .global_state
                .read_order_book()
                .await
                .contains_order(order_id)
            {
                self.global_state
                    .add_order(NetworkOrder::new(
                        *order_id,
                        wallet_public_share_nullifier,
                        local_cluster_id.clone(),
                        true, /* local */
                    ))
                    .await
            }
        }
    }

    /// After a wallet update has been submitted on-chain, find its authentication
    /// path, and re-prove `VALID REBLIND` for the wallet and `VALID COMMITMENTS`
    /// for all orders in the wallet
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
}
