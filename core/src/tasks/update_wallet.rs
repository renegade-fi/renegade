//! Defines a task for submitting `update_wallet` transactions, transitioning the state of
//! an existing darkpool wallet
//!
//! This involves proving `VALID WALLET UPDATE`, submitting on-chain, and re-indexing state

use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result as FmtResult},
};

use async_trait::async_trait;
use circuits::{
    native_helpers::compute_poseidon_hash,
    types::{
        keychain::SecretIdentificationKey,
        order::Order as CircuitOrder,
        transfers::{ExternalTransfer, InternalTransfer},
    },
    zk_circuits::{
        valid_commitments::ValidCommitmentsStatement,
        valid_wallet_update::ValidWalletUpdateStatement,
    },
    zk_gadgets::merkle::MerkleOpening,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::starknet_felt_to_biguint;
use curve25519_dalek::scalar::Scalar;
use serde::Serialize;
use starknet::core::types::TransactionStatus;
use tokio::sync::{mpsc::UnboundedSender as TokioSender, oneshot};
use tracing::log;

use crate::{
    gossip_api::{
        gossip::{GossipOutbound, PubsubMessage},
        orderbook_management::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
    },
    price_reporter::exchanges::get_current_time,
    proof_generation::jobs::{
        ProofJob, ProofManagerJob, ValidCommitmentsBundle, ValidWalletUpdateBundle,
    },
    starknet_client::client::StarknetClient,
    state::{wallet::Wallet, NetworkOrder, NetworkOrderState, OrderIdentifier, RelayerState},
    tasks::{encrypt_internal_transfer, encrypt_wallet},
    types::{SizedValidCommitmentsWitness, SizedValidWalletUpdateWitness},
    SizedWallet,
};

use super::{
    driver::{StateWrapper, Task},
    RANDOMNESS_INCREMENT,
};

/// The human-readable name of the the task
const UPDATE_WALLET_TASK_NAME: &str = "update-wallet";
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
    /// The internal transfer, if one exists
    pub internal_transfer: Option<InternalTransfer>,
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
    /// Error generating a proof of `VALID WALLET UPDATE`
    ProofGeneration(String),
    /// An error enqueuing a message for another worker
    SendMessage(String),
    /// An error occurred interacting with Starknet
    StarknetClient(String),
    /// A state element was not found that is necessary for task execution
    StateMissing(String),
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
        /// The proof of `VALID WALLET UPDATE` submitted to the contract
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
                let proof = self.generate_proof().await?;
                self.task_state = UpdateWalletTaskState::SubmittingTx {
                    proof_bundle: proof,
                };
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
        internal_transfer: Option<InternalTransfer>,
        old_wallet: Wallet,
        mut new_wallet: Wallet,
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        // Increment the randomness
        new_wallet.randomness = &old_wallet.randomness + RANDOMNESS_INCREMENT;
        Self {
            external_transfer,
            internal_transfer,
            old_wallet,
            new_wallet,
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_state: UpdateWalletTaskState::Pending,
        }
    }

    /// Generate a proof of `VALID WALLET UPDATE` for the wallet with added balance
    async fn generate_proof(&self) -> Result<ValidWalletUpdateBundle, UpdateWalletTaskError> {
        let timestamp: Scalar = get_current_time().into();
        let merkle_opening =
            self.old_wallet.merkle_proof.clone().ok_or_else(|| {
                UpdateWalletTaskError::StateMissing(ERR_NO_MERKLE_PROOF.to_string())
            })?;

        // Build the statement
        let statement = ValidWalletUpdateStatement {
            timestamp,
            pk_root: self.old_wallet.key_chain.public_keys.pk_root.clone(),
            new_wallet_commitment: self.new_wallet.get_commitment(),
            match_nullifier: self.old_wallet.get_match_nullifier(),
            spend_nullifier: self.old_wallet.get_spend_nullifier(),
            merkle_root: merkle_opening.compute_root(),
            external_transfer: self.external_transfer.clone().unwrap_or_default(),
        };

        // Construct the witness
        let old_circuit_wallet: SizedWallet = self.old_wallet.clone().into();
        let new_circuit_wallet: SizedWallet = self.new_wallet.clone().into();
        let witness = SizedValidWalletUpdateWitness {
            wallet1: old_circuit_wallet,
            wallet2: new_circuit_wallet,
            wallet1_opening: merkle_opening.into(),
            internal_transfer: InternalTransfer::default(),
        };

        // Send a job to the proof manager and await completion
        let (response_sender, response_receiver) = oneshot::channel();
        self.proof_manager_work_queue
            .send(ProofManagerJob {
                type_: ProofJob::ValidWalletUpdate { witness, statement },
                response_channel: response_sender,
            })
            .map_err(|err| UpdateWalletTaskError::SendMessage(err.to_string()))?;

        response_receiver
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

        // Encrypt the new wallet and internal transfer under the public view key
        // TODO: This will eventually come directly from the user as they sign the encryption
        let encrypted_internal_transfer = self
            .internal_transfer
            .clone()
            .map(|transfer| encrypt_internal_transfer(&transfer));
        let encrypted_wallet = encrypt_wallet(
            self.new_wallet.clone().into(),
            self.old_wallet.key_chain.public_keys.pk_view,
        );

        // Submit on-chain
        let tx_hash = self
            .starknet_client
            .update_wallet(
                self.new_wallet.key_chain.public_keys.pk_view,
                self.new_wallet.get_commitment(),
                self.old_wallet.get_match_nullifier(),
                self.old_wallet.get_spend_nullifier(),
                self.external_transfer
                    .clone()
                    .map(|transfer| transfer.into()),
                encrypted_internal_transfer,
                encrypted_wallet,
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

        // Update the wallet in the global state
        self.global_state
            .update_wallet(self.new_wallet.clone())
            .await;

        Ok(())
    }

    /// After a wallet update has been submitted on-chain, find its authentication
    /// path, and re-prove `VALID COMMITMENTS` for all orders in the wallet
    async fn update_validity_proofs(&self) -> Result<(), UpdateWalletTaskError> {
        // Find the new wallet in the Merkle state
        let authentication_path = self
            .starknet_client
            .find_merkle_authentication_path(self.new_wallet.get_commitment())
            .await
            .map_err(|err| UpdateWalletTaskError::StarknetClient(err.to_string()))?;
        let new_root = authentication_path.compute_root();

        // A wallet that is compatible with circuit types
        let circuit_wallet: SizedWallet = self.new_wallet.clone().into();
        let randomness_hash = compute_poseidon_hash(&[circuit_wallet.randomness]);
        let wallet_opening: MerkleOpening = authentication_path.into();

        // The statement in `VALID COMMITMENTS` is only parameterized by wallet-specific variables;
        // so we construct it once and use it for all order commitment proofs
        let new_statement = ValidCommitmentsStatement {
            nullifier: self.new_wallet.get_match_nullifier(),
            merkle_root: new_root,
            pk_settle: self.new_wallet.key_chain.public_keys.pk_settle,
        };

        // Request that the proof manager prove `VALID COMMITMENTS` for each order
        let mut proof_response_channels = HashMap::new();
        for (order_id, order) in self.new_wallet.orders.clone().into_iter() {
            // Skip default orders
            if order.is_default() {
                continue;
            }

            // Build a witness for this order's validity proof
            let witness = if let Some(witness) = self
                .get_witness_for_order(
                    order,
                    circuit_wallet.clone(),
                    wallet_opening.clone(),
                    randomness_hash,
                    self.new_wallet.key_chain.secret_keys.sk_match,
                )
                .await
            {
                witness
            } else {
                log::error!("could not find witness for order {order_id}, skipping...");
                continue;
            };

            // Send a job to the proof manager to prove `VALID COMMITMENTS` for this wallet
            let (response_sender, response_receiver) = oneshot::channel();
            self.proof_manager_work_queue
                .send(ProofManagerJob {
                    type_: ProofJob::ValidCommitments {
                        witness: witness.clone(),
                        statement: new_statement,
                    },
                    response_channel: response_sender,
                })
                .map_err(|err| UpdateWalletTaskError::SendMessage(err.to_string()))?;

            proof_response_channels.insert(order_id, (response_receiver, witness));
        }

        // Await proofs for all orders
        for (order_id, (proof_channel, witness)) in proof_response_channels.into_iter() {
            let proof = proof_channel
                .await
                .map_err(|err| UpdateWalletTaskError::ProofGeneration(err.to_string()))?;
            log::info!("got proof for order {order_id}");

            // Update the global state of the order
            self.update_order_state(order_id, proof.into(), witness)
                .await?;
        }

        Ok(())
    }

    /// Generate a `VALID COMMITMENTS` witness for the given order
    ///
    /// This will use the old witness -- modifying it appropriately -- if one exists,
    /// otherwise, it will create a brand new witness
    #[allow(clippy::too_many_arguments)]
    async fn get_witness_for_order(
        &self,
        order: CircuitOrder,
        wallet: SizedWallet,
        wallet_opening: MerkleOpening,
        randomness_hash: Scalar,
        sk_match: SecretIdentificationKey,
    ) -> Option<SizedValidCommitmentsWitness> {
        // Always recreate the witness anew, even if a witness previously existed
        // The balances used in a witness may have changes so it is easier to just
        // recreate the witness
        let (balance, fee, fee_balance) = self.new_wallet.get_balance_and_fee_for_order(&order)?;
        Some(SizedValidCommitmentsWitness {
            wallet,
            order: order.into(),
            balance: balance.into(),
            fee: fee.into(),
            fee_balance: fee_balance.into(),
            wallet_opening,
            randomness_hash: randomness_hash.into(),
            sk_match,
        })
    }

    /// Update the order in the state
    async fn update_order_state(
        &self,
        order_id: OrderIdentifier,
        proof: ValidCommitmentsBundle,
        witness: SizedValidCommitmentsWitness,
    ) -> Result<(), UpdateWalletTaskError> {
        // If the order does not currently exist in the book, add it
        if !self
            .global_state
            .read_order_book()
            .await
            .contains_order(&order_id)
        {
            self.global_state
                .add_order(NetworkOrder {
                    id: order_id,
                    match_nullifier: self.new_wallet.get_match_nullifier(),
                    local: true,
                    cluster: self.global_state.local_cluster_id.clone(),
                    state: NetworkOrderState::Verified,
                    valid_commit_proof: Some(proof.clone()),
                    valid_commit_witness: Some(witness),
                })
                .await;
        } else {
            // Otherwise, update the existing proof
            self.global_state
                .add_order_validity_proof(&order_id, proof.clone())
                .await;
            self.global_state
                .read_order_book()
                .await
                .attach_validity_proof_witness(&order_id, witness)
                .await;
        }

        // Broadcast the new order's validity proof to the network
        let cluster = self.global_state.local_cluster_id.clone();
        let message = OrderBookManagementMessage::OrderProofUpdated {
            order_id,
            cluster,
            proof,
        };

        self.network_sender
            .send(GossipOutbound::Pubsub {
                topic: ORDER_BOOK_TOPIC.to_string(),
                message: PubsubMessage::OrderBookManagement(message),
            })
            .map_err(|err| UpdateWalletTaskError::SendMessage(err.to_string()))
    }
}
