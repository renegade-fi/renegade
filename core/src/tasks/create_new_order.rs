//! Handles the flow of adding a new order to a wallet

use std::{
    collections::HashMap,
    fmt::Display,
    time::{SystemTime, UNIX_EPOCH},
};

use circuits::{
    native_helpers::compute_poseidon_hash,
    types::{
        order::Order as CircuitOrder,
        wallet::{Nullifier, WalletCommitment},
    },
    zk_circuits::valid_wallet_update::ValidWalletUpdateStatement,
    zk_gadgets::merkle::MerkleOpening,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::{
    elgamal::ElGamalCiphertext,
    fields::{scalar_to_biguint, starknet_felt_to_biguint},
};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;
use starknet::core::types::TransactionStatus;
use tokio::sync::oneshot;
use tracing::log;

use crate::{
    external_api::types::Order,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidWalletUpdateBundle},
    starknet_client::client::StarknetClient,
    state::{
        wallet::{Wallet, WalletIdentifier},
        OrderIdentifier, RelayerState,
    },
    types::SizedValidWalletUpdateWitness,
    SizedWallet,
};

use super::encrypt_wallet;

/// The wallet does not have a merkle proof attached to it
const ERR_NO_MERKLE_PROOF: &str = "wallet merkle proof not attached";
/// A transaction to the contract was rejected
const ERR_TRANSACTION_FAILED: &str = "transaction rejected";
/// The wallet to create the order within was not found
const ERR_WALLET_NOT_FOUND: &str = "wallet not found in state";
/// The amount to increment the randomness each time a wallet is nullified
const RANDOMNESS_INCREMENT: u8 = 2;

/// Helper function to get the current UNIX epoch time in milliseconds
pub fn get_current_time() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis()
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

/// The task definition for the long-run async flow of creating
/// a new order within a wallet
pub struct NewOrderTask {
    /// The ID of the wallet to create the order within
    wallet_id: WalletIdentifier,
    /// The ID of the order being added to the wallet
    order_id: OrderIdentifier,
    /// The order to add to the wallet
    order: CircuitOrder,
    /// A starknet client for the task to submit transactions
    starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    global_state: RelayerState,
    /// The work queue for the proof manager
    proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
}

impl NewOrderTask {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        order: Order,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        // Cast explicitly to an order type that is indexed in the state
        let order_id = order.id;
        let order: CircuitOrder = order.into();

        Self {
            wallet_id,
            order_id,
            order,
            starknet_client,
            global_state,
            proof_manager_work_queue,
        }
    }

    /// Run the task to completion
    pub async fn run(self) -> Result<(), NewOrderTaskError> {
        log::info!("Beginning new order task execution");

        if let Err(e) = self.run_helper().await {
            log::error!("Error creating new order in wallet: {e}")
        } else {
            log::info!("Successfully added order to wallet")
        }

        Ok(())
    }

    /// A helper function that allows the caller to log errors in a central piece
    /// of logic
    async fn run_helper(self) -> Result<(), NewOrderTaskError> {
        // Get a copy of the old wallet and update it with the new order
        let old_wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&self.wallet_id)
            .await
            .ok_or_else(|| NewOrderTaskError::MissingState(ERR_WALLET_NOT_FOUND.to_string()))?;

        let mut new_wallet = old_wallet.clone();
        new_wallet.orders.insert(self.order_id, self.order.clone());
        new_wallet.randomness += RANDOMNESS_INCREMENT;

        // Compute public statement variables sent to the contract
        let new_wallet_comm = new_wallet.get_commitment();
        let old_wallet_match_nullifier = old_wallet.get_match_nullifier();
        let old_wallet_spend_nullifier = old_wallet.get_spend_nullifier();

        // Prove `VALID WALLET UPDATE`
        let proof = self
            .prove_valid_wallet_update(old_wallet.clone(), new_wallet.clone())
            .await?;

        // Encrypt the new wallet under the public view key
        // TODO: This will eventually come directly from the user as they sign the encryption
        let pk_view = scalar_to_biguint(&new_wallet.public_keys.pk_view);
        let encrypted_wallet = encrypt_wallet(new_wallet.clone().into(), &pk_view);

        self.submit_tx(
            new_wallet_comm,
            old_wallet_match_nullifier,
            old_wallet_spend_nullifier,
            encrypted_wallet,
            proof,
        )
        .await?;

        // Re-prove validity proofs for all orders in wallet
        self.update_validity_proofs(new_wallet).await?;

        // Update state
        Ok(())
    }

    /// Prove `VALID WALLET UPDATE` on the given change between old and new wallet
    async fn prove_valid_wallet_update(
        &self,
        old_wallet: Wallet,
        new_wallet: Wallet,
    ) -> Result<ValidWalletUpdateBundle, NewOrderTaskError> {
        let timestamp: Scalar = get_current_time().into();
        let merkle_opening = old_wallet
            .merkle_proof
            .clone()
            .ok_or_else(|| NewOrderTaskError::MissingState(ERR_NO_MERKLE_PROOF.to_string()))?;

        // Build the statement
        let statement = ValidWalletUpdateStatement {
            timestamp,
            pk_root: old_wallet.public_keys.pk_root,
            new_wallet_commitment: new_wallet.get_commitment(),
            wallet_match_nullifier: old_wallet.get_match_nullifier(),
            wallet_spend_nullifier: old_wallet.get_spend_nullifier(),
            merkle_root: merkle_opening.compute_root(),
            external_transfer: (Scalar::zero(), Scalar::zero(), Scalar::zero()),
        };

        // Construct the witness
        let old_circuit_wallet: SizedWallet = old_wallet.into();
        let new_circuit_wallet: SizedWallet = new_wallet.into();
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

    /// Helper to submit a update request on-chain and await the transaction's
    /// completion
    async fn submit_tx(
        &self,
        new_wallet_comm: WalletCommitment,
        old_wallet_match_nullifier: Nullifier,
        old_wallet_spend_nullifier: Nullifier,
        wallet_ciphertext: Vec<ElGamalCiphertext>,
        proof: ValidWalletUpdateBundle,
    ) -> Result<(), NewOrderTaskError> {
        // Submit on-chain
        // TODO: Remove this
        let mut rng = OsRng {};
        let tx_hash = self
            .starknet_client
            .update_wallet(
                new_wallet_comm,
                old_wallet_match_nullifier + Scalar::random(&mut rng),
                old_wallet_spend_nullifier + Scalar::random(&mut rng),
                wallet_ciphertext,
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
    async fn update_validity_proofs(&self, new_wallet: Wallet) -> Result<(), NewOrderTaskError> {
        // Find the new wallet in the Merkle state
        let authentication_path = self
            .starknet_client
            .find_merkle_authentication_path(new_wallet.get_commitment())
            .await
            .map_err(|err| NewOrderTaskError::StarknetClient(err.to_string()))?;
        let new_root = authentication_path.compute_root();

        let match_nullifier = new_wallet.get_match_nullifier();

        // A wallet that is compatible with circuit types
        let circuit_wallet: SizedWallet = new_wallet.clone().into();
        let randomness_hash = compute_poseidon_hash(&[circuit_wallet.randomness]);
        let wallet_opening: MerkleOpening = authentication_path.into();

        // Request that the proof manager prove `VALID COMMITMENTS` for each order
        let mut proof_response_channels = HashMap::new();
        let locked_order_book = self.global_state.read_order_book().await;
        for order_id in new_wallet.orders.keys() {
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
