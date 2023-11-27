//! Defines a task for submitting `update_wallet` transactions, transitioning
//! the state of an existing darkpool wallet
//!
//! This involves proving `VALID WALLET UPDATE`, submitting on-chain, and
//! re-indexing state

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use circuit_types::{
    native_helpers::wallet_from_blinded_shares, transfers::ExternalTransfer, SizedWallet,
};
use circuits::zk_circuits::valid_wallet_update::{
    SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
};
use common::types::{proof_bundles::ValidWalletUpdateBundle, wallet::Wallet};
use crossbeam::channel::Sender as CrossbeamSender;
use gossip_api::gossip::GossipOutbound;
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use renegade_crypto::fields::starknet_felt_to_biguint;
use serde::Serialize;
use starknet_client::client::StarknetClient;
use state::RelayerState;
use tokio::sync::{mpsc::UnboundedSender as TokioSender, oneshot};
use tracing::log;

use crate::helpers::find_merkle_path;

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

// -------------------
// | Task Definition |
// -------------------

/// Defines the long running flow for adding a balance to a wallet
pub struct UpdateWalletTask {
    /// The timestamp at which the task was initiated, used to timestamp orders
    pub timestamp_received: u64,
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
    /// A wallet was submitted with an invalid secret shares
    InvalidShares(String),
    /// Error generating a proof of `VALID WALLET UPDATE`
    ProofGeneration(String),
    /// An error occurred interacting with Starknet
    StarknetClient(String),
    /// A state element was not found that is necessary for task execution
    StateMissing(String),
    /// An error while updating validity proofs for a wallet
    UpdatingValidityProofs(String),
    /// Wallet is already locked, cannot update
    WalletLocked,
}

impl Display for UpdateWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for UpdateWalletTaskError {}

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
    /// The task is finding a new Merkle opening for the wallet
    FindingOpening,
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
            },
            UpdateWalletTaskState::Proving => {
                // Begin the proof of `VALID WALLET UPDATE`
                let proof_bundle = self.generate_proof().await?;
                self.task_state = UpdateWalletTaskState::SubmittingTx { proof_bundle };
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

    // Unlock the update lock if the task fails
    async fn cleanup(&mut self) -> Result<(), UpdateWalletTaskError> {
        self.old_wallet.unlock_wallet();
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
        timestamp_received: u64,
        external_transfer: Option<ExternalTransfer>,
        old_wallet: Wallet,
        new_wallet: Wallet,
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Result<Self, UpdateWalletTaskError> {
        if !old_wallet.try_lock_wallet() {
            return Err(UpdateWalletTaskError::WalletLocked);
        }

        // Safety check, the new wallet's secret shares must recover the new wallet
        let new_circuit_wallet: SizedWallet = new_wallet.clone().into();
        let recovered_wallet = wallet_from_blinded_shares(
            new_wallet.private_shares.clone(),
            new_wallet.blinded_public_shares.clone(),
        );

        if recovered_wallet != new_circuit_wallet {
            return Err(UpdateWalletTaskError::InvalidShares(ERR_INVALID_BLINDING.to_string()));
        }

        Ok(Self {
            timestamp_received,
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

    /// Generate a proof of `VALID WALLET UPDATE` for the wallet with added
    /// balance
    async fn generate_proof(&self) -> Result<ValidWalletUpdateBundle, UpdateWalletTaskError> {
        let merkle_opening =
            self.old_wallet.merkle_proof.clone().ok_or_else(|| {
                UpdateWalletTaskError::StateMissing(ERR_NO_MERKLE_PROOF.to_string())
            })?;
        let merkle_root = merkle_opening.compute_root();

        // Build a witness and statement
        let new_private_share_commitment = self.new_wallet.get_private_share_commitment();

        let statement = SizedValidWalletUpdateStatement {
            old_shares_nullifier: self.old_wallet.get_wallet_nullifier(),
            new_private_shares_commitment: new_private_share_commitment,
            new_public_shares: self.new_wallet.blinded_public_shares.clone(),
            merkle_root,
            external_transfer: self.external_transfer.clone().unwrap_or_default(),
            old_pk_root: self.old_wallet.key_chain.public_keys.pk_root.clone(),
            timestamp: self.timestamp_received,
        };

        let witness = SizedValidWalletUpdateWitness {
            old_wallet_private_shares: self.old_wallet.private_shares.clone(),
            old_wallet_public_shares: self.old_wallet.blinded_public_shares.clone(),
            old_shares_opening: merkle_opening.into(),
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

    /// Submit the `update_wallet` transaction to the contract and await
    /// finality
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
                self.old_wallet.get_wallet_nullifier(),
                self.external_transfer.clone().map(|transfer| transfer.into()),
                self.new_wallet.blinded_public_shares.clone(),
                proof,
            )
            .await
            .map_err(|err| UpdateWalletTaskError::StarknetClient(err.to_string()))?;

        log::info!("tx hash: 0x{:x}", starknet_felt_to_biguint(&tx_hash));
        let status = self
            .starknet_client
            .poll_transaction_completed(tx_hash)
            .await
            .map_err(|err| UpdateWalletTaskError::StarknetClient(err.to_string()))?;

        status.into_result().map_err(|err| UpdateWalletTaskError::StarknetClient(err.to_string()))
    }

    /// Find the wallet opening for the new wallet and re-index the wallet in
    /// the global state
    async fn find_opening(&mut self) -> Result<(), UpdateWalletTaskError> {
        // Attach the opening to the new wallet, and index the wallet in the global
        // state
        let merkle_opening = find_merkle_path(&self.new_wallet, &self.starknet_client)
            .await
            .map_err(|err| UpdateWalletTaskError::StarknetClient(err.to_string()))?;
        self.new_wallet.merkle_proof = Some(merkle_opening);

        // After the state is finalized on-chain, re-index the wallet in the global
        // state
        self.global_state.update_wallet(self.new_wallet.clone()).await;

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
}
