//! Handles the flow of adding a new order to a wallet

use std::{
    collections::HashMap,
    fmt::{Display, Formatter, Result as FmtResult},
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use circuits::{
    native_helpers::compute_poseidon_hash, types::order::Order as CircuitOrder,
    zk_circuits::valid_wallet_update::ValidWalletUpdateStatement,
    zk_gadgets::merkle::MerkleOpening,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::{scalar_to_biguint, starknet_felt_to_biguint};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use serde::Serialize;
use starknet::core::types::TransactionStatus;
use tokio::sync::oneshot;
use tracing::log;

use crate::{
    external_api::types::Order,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidWalletUpdateBundle},
    starknet_client::client::StarknetClient,
    state::{
        wallet::{Wallet, WalletIdentifier},
        RelayerState,
    },
    types::SizedValidWalletUpdateWitness,
    SizedWallet,
};

use super::{
    driver::{StateWrapper, Task},
    encrypt_wallet,
};

/// The wallet does not have a merkle proof attached to it
const ERR_NO_MERKLE_PROOF: &str = "wallet merkle proof not attached";
/// A transaction to the contract was rejected
const ERR_TRANSACTION_FAILED: &str = "transaction rejected";
/// The wallet to create the order within was not found
const ERR_WALLET_NOT_FOUND: &str = "wallet not found in state";
/// The order creation task name
const NEW_ORDER_TASK_NAME: &str = "create-new-order";
/// The amount to increment the randomness each time a wallet is nullified
const RANDOMNESS_INCREMENT: u8 = 2;

/// Helper function to get the current UNIX epoch time in milliseconds
pub fn get_current_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
}

/// The task definition for the long-run async flow of creating
/// a new order within a wallet
pub struct NewOrderTask {
    /// The wallet before the update
    old_wallet: Wallet,
    /// The wallet after update
    new_wallet: Wallet,
    /// A starknet client for the task to submit transactions
    starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// The work queue for the proof manager
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task execution
    task_state: NewOrderTaskState,
}

/// The error type for the task
#[derive(Clone, Debug)]
pub enum NewOrderTaskError {
    /// A piece of state necessary for task execution is missing
    MissingState(String),
    /// Error generating a proof of `VALID WALLET UPDATE`
    ProofGeneration(String),
    /// An error occurred sending a message to another local worker
    SendMessage(String),
    /// An error interacting with Starknet
    StarknetClient(String),
}

impl Display for NewOrderTaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the state of the order create flow
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum NewOrderTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is awaiting a proof of `VALID WALLET UPDATE`
    Proving,
    /// The task is submitting the proof and transaction info to
    /// the contract and awaiting transaction finality
    SubmittingTx {
        /// The proof of `VALID WALLET UPDATE` from the proving step
        proof_bundle: ValidWalletUpdateBundle,
    },
    /// The task is updating the validity proofs for all orders in the
    /// now nullified wallet
    UpdatingValidityProofs,
    /// The task has finished executing
    Completed,
}

impl Display for NewOrderTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            NewOrderTaskState::SubmittingTx { .. } => write!(f, "SubmittingTx"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl Serialize for NewOrderTaskState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl From<NewOrderTaskState> for StateWrapper {
    fn from(state: NewOrderTaskState) -> Self {
        StateWrapper::NewOrder(state)
    }
}

#[async_trait]
impl Task for NewOrderTask {
    type Error = NewOrderTaskError;
    type State = NewOrderTaskState;

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.state() {
            NewOrderTaskState::Pending => {
                self.task_state = NewOrderTaskState::Proving;
            }
            NewOrderTaskState::Proving => {
                // Begin the proof of `VALID WALLET UPDATE`
                let proof = self.generate_proof().await?;
                self.task_state = NewOrderTaskState::SubmittingTx {
                    proof_bundle: proof,
                };
            }
            NewOrderTaskState::SubmittingTx { .. } => {
                // Submit the proof and transaction info to the contract and await
                // transaction finality
                self.submit_tx().await?;
                self.task_state = NewOrderTaskState::UpdatingValidityProofs;
            }
            NewOrderTaskState::UpdatingValidityProofs => {
                // Update validity proofs for now-nullified orders
                self.update_validity_proofs().await?;
                self.task_state = NewOrderTaskState::Completed;
            }
            NewOrderTaskState::Completed => {
                panic!("step() called in state Completed")
            }
        }

        Ok(())
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn completed(&self) -> bool {
        matches!(self.state(), NewOrderTaskState::Completed)
    }

    fn name(&self) -> String {
        NEW_ORDER_TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl NewOrderTask {
    /// Constructor
    pub async fn new(
        wallet_id: WalletIdentifier,
        order: Order,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Result<Self, NewOrderTaskError> {
        // Cast explicitly to an order type that is indexed in the state
        let order_id = order.id;
        let order: CircuitOrder = order.into();

        // Get a copy of the old wallet and update it with the new order
        let old_wallet = global_state
            .read_wallet_index()
            .await
            .get_wallet(&wallet_id)
            .await
            .ok_or_else(|| NewOrderTaskError::MissingState(ERR_WALLET_NOT_FOUND.to_string()))?;

        let mut new_wallet = old_wallet.clone();
        new_wallet.orders.insert(order_id, order.clone());
        new_wallet.randomness += RANDOMNESS_INCREMENT;

        Ok(Self {
            old_wallet,
            new_wallet,
            starknet_client,
            global_state,
            proof_manager_work_queue,
            task_state: NewOrderTaskState::Pending,
        })
    }

    /// Prove `VALID WALLET UPDATE` on the new wallet transition
    async fn generate_proof(&self) -> Result<ValidWalletUpdateBundle, NewOrderTaskError> {
        // Prove `VALID WALLET UPDATE`
        let timestamp: Scalar = get_current_time().into();
        let merkle_opening = self
            .old_wallet
            .merkle_proof
            .clone()
            .ok_or_else(|| NewOrderTaskError::MissingState(ERR_NO_MERKLE_PROOF.to_string()))?;

        // Build the statement
        let statement = ValidWalletUpdateStatement {
            timestamp,
            pk_root: self.old_wallet.public_keys.pk_root,
            new_wallet_commitment: self.new_wallet.get_commitment(),
            wallet_match_nullifier: self.old_wallet.get_match_nullifier(),
            wallet_spend_nullifier: self.old_wallet.get_spend_nullifier(),
            merkle_root: merkle_opening.compute_root(),
            external_transfer: (Scalar::zero(), Scalar::zero(), Scalar::zero()),
        };

        // Construct the witness
        let old_circuit_wallet: SizedWallet = self.old_wallet.clone().into();
        let new_circuit_wallet: SizedWallet = self.new_wallet.clone().into();
        let witness = SizedValidWalletUpdateWitness {
            wallet1: old_circuit_wallet,
            wallet2: new_circuit_wallet,
            wallet1_opening: merkle_opening.into(),
            internal_transfer: (Scalar::zero(), Scalar::zero()),
        };

        // Send a job to the proof manager and await completion
        let (response_sender, response_receiver) = oneshot::channel();
        self.proof_manager_work_queue
            .send(ProofManagerJob {
                type_: ProofJob::ValidWalletUpdate { witness, statement },
                response_channel: response_sender,
            })
            .map_err(|err| NewOrderTaskError::SendMessage(err.to_string()))?;

        response_receiver
            .await
            .map(|bundle| bundle.into())
            .map_err(|err| NewOrderTaskError::ProofGeneration(err.to_string()))
    }

    /// Submit the `update_wallet` transaction on-chain
    async fn submit_tx(&self) -> Result<(), NewOrderTaskError> {
        let proof = if let NewOrderTaskState::SubmittingTx { proof_bundle } = self.state() {
            proof_bundle
        } else {
            unreachable!("submit_tx may only be called from a SubmittingTx task state")
        };

        // Encrypt the new wallet under the public view key
        // TODO: This will eventually come directly from the user as they sign the encryption
        let pk_view = scalar_to_biguint(&self.new_wallet.public_keys.pk_view);
        let encrypted_wallet = encrypt_wallet(self.new_wallet.clone().into(), &pk_view);

        // Submit on-chain
        // TODO: Remove this
        let mut rng = OsRng {};
        let tx_hash = self
            .starknet_client
            .update_wallet(
                self.new_wallet.get_commitment(),
                self.old_wallet.get_match_nullifier() + Scalar::random(&mut rng),
                self.old_wallet.get_spend_nullifier() + Scalar::random(&mut rng),
                encrypted_wallet,
                proof,
            )
            .await
            .map_err(|err| NewOrderTaskError::StarknetClient(err.to_string()))?;
        log::info!("got tx hash: {}", starknet_felt_to_biguint(&tx_hash));

        // Await transaction completion
        let tx_info = self
            .starknet_client
            .poll_transaction_completed(tx_hash)
            .await
            .map_err(|err| NewOrderTaskError::StarknetClient(err.to_string()))?;

        if let TransactionStatus::Rejected = tx_info.status {
            return Err(NewOrderTaskError::StarknetClient(
                ERR_TRANSACTION_FAILED.to_string(),
            ));
        }

        Ok(())
    }

    /// After a wallet update has been submitted on-chain, find its authentication
    /// path, and re-prove `VALID COMMITMENTS` for all orders in the wallet
    async fn update_validity_proofs(&self) -> Result<(), NewOrderTaskError> {
        // Find the new wallet in the Merkle state
        let authentication_path = self
            .starknet_client
            .find_merkle_authentication_path(self.new_wallet.get_commitment())
            .await
            .map_err(|err| NewOrderTaskError::StarknetClient(err.to_string()))?;
        let new_root = authentication_path.compute_root();

        let match_nullifier = self.new_wallet.get_match_nullifier();

        // A wallet that is compatible with circuit types
        let circuit_wallet: SizedWallet = self.new_wallet.clone().into();
        let randomness_hash = compute_poseidon_hash(&[circuit_wallet.randomness]);
        let wallet_opening: MerkleOpening = authentication_path.into();

        // Request that the proof manager prove `VALID COMMITMENTS` for each order
        let mut proof_response_channels = HashMap::new();
        let locked_order_book = self.global_state.read_order_book().await;
        for order_id in self.new_wallet.orders.keys() {
            // Fetch the old witness
            let old_witness = locked_order_book.get_validity_proof_witness(order_id).await;
            if old_witness.is_none() {
                // TODO: If a witness is not present, generate one now
                continue;
            }
            let mut new_witness = old_witness.unwrap();

            // Update the witness with the new wallet information
            new_witness.wallet = circuit_wallet.clone();
            new_witness.wallet_opening = wallet_opening.clone();
            new_witness.randomness_hash = randomness_hash.into();

            // Update the statement for the new wallet
            let mut new_statement = locked_order_book
                .get_validity_proof(order_id)
                .await
                .unwrap()
                .statement;

            new_statement.nullifier = match_nullifier;
            new_statement.merkle_root = new_root;

            // Send a job to the proof manager to prove `VALID COMMITMENTS` for this wallet
            let (response_sender, response_receiver) = oneshot::channel();
            self.proof_manager_work_queue
                .send(ProofManagerJob {
                    type_: ProofJob::ValidCommitments {
                        witness: new_witness,
                        statement: new_statement,
                    },
                    response_channel: response_sender,
                })
                .map_err(|err| NewOrderTaskError::SendMessage(err.to_string()))?;

            proof_response_channels.insert(*order_id, response_receiver);
        }

        // Await proofs for all orders
        for (order_id, proof_channel) in proof_response_channels.into_iter() {
            let _proof = proof_channel
                .await
                .map_err(|err| NewOrderTaskError::ProofGeneration(err.to_string()))?;

            log::info!("received proof for order: {order_id}");
        }

        log::info!("got proofs for all orders");

        Ok(())
    }
}
