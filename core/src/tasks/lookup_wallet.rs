//! Defines a task that looks up a wallet in contract storage by its
//! public view key identifier, then begins managing the wallet

use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    sync::atomic::AtomicU32,
};

use async_trait::async_trait;
use circuits::{
    native_helpers::compute_poseidon_hash,
    types::{order::Order as CircuitOrder, wallet::Nullifier},
    zk_circuits::valid_commitments::ValidCommitmentsStatement,
    zk_gadgets::merkle::MerkleOpening,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::{biguint_to_scalar, scalar_to_biguint, starknet_felt_to_biguint};
use curve25519_dalek::scalar::Scalar;
use serde::Serialize;
use starknet::core::types::FieldElement as StarknetFieldElement;
use tokio::sync::oneshot;
use tracing::log;
use uuid::Uuid;

use crate::{
    external_api::types::KeyChain,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidCommitmentsBundle},
    starknet_client::client::{StarknetClient, TransactionHash},
    state::{
        wallet::{Wallet, WalletIdentifier, WalletMetadata},
        NetworkOrder, NetworkOrderState, OrderIdentifier, RelayerState,
    },
    tasks::decrypt_wallet,
    types::SizedValidCommitmentsWitness,
    SizedWallet,
};

use super::driver::{StateWrapper, Task};

/// The error thrown when the wallet cannot be found in tx history
const ERR_WALLET_NOT_FOUND: &str = "wallet not found in wallet_last_updated map";
/// The task name for the lookup wallet task
const LOOKUP_WALLET_TASK_NAME: &str = "lookup-wallet";

/// Represents a task to lookup a wallet in contract storage
pub struct LookupWalletTask {
    /// The ID to provision for the wallet
    pub wallet_id: WalletIdentifier,
    /// The keychain to manage the wallet with
    pub key_chain: KeyChain,
    /// The wallet parsed and decrypted from contract state
    pub wallet: Option<Wallet>,
    /// A starknet client for the task to submit transactions
    pub starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task's execution
    pub task_state: LookupWalletTaskState,
}

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize)]
pub enum LookupWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the wallet in contract storage
    FindingWallet,
    /// The task is creating validity proofs for the orders in the wallet
    CreatingValidityProofs,
    /// The task is completed
    Completed,
}

impl Display for LookupWalletTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl From<LookupWalletTaskState> for StateWrapper {
    fn from(state: LookupWalletTaskState) -> Self {
        StateWrapper::LookupWallet(state)
    }
}

/// The error type thrown by the wallet lookup task
#[derive(Clone, Debug)]
pub enum LookupWalletTaskError {
    /// Wallet was not found in contract storage
    NotFound(String),
    /// Error generating a proof of `VALID COMMITMENTS`
    ProofGeneration(String),
    /// Error sending a message to another worker in the local relayer
    SendMessage(String),
    /// Error interacting with the starknet client
    Starknet(String),
}

impl Display for LookupWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

#[async_trait]
impl Task for LookupWalletTask {
    type State = LookupWalletTaskState;
    type Error = LookupWalletTaskError;

    fn completed(&self) -> bool {
        matches!(self.state(), LookupWalletTaskState::Completed)
    }

    fn name(&self) -> String {
        LOOKUP_WALLET_TASK_NAME.to_string()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on task state
        match self.task_state {
            LookupWalletTaskState::Pending => {
                self.task_state = LookupWalletTaskState::FindingWallet
            }
            LookupWalletTaskState::FindingWallet => {
                self.find_wallet().await?;
                self.task_state = LookupWalletTaskState::CreatingValidityProofs;
            }
            LookupWalletTaskState::CreatingValidityProofs => {
                self.create_validity_proofs().await?;
                self.task_state = LookupWalletTaskState::Completed;
            }
            LookupWalletTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            }
        }

        Ok(())
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl LookupWalletTask {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        key_chain: KeyChain,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        Self {
            wallet_id,
            key_chain,
            wallet: None, // replaced in the first task step
            starknet_client,
            global_state,
            proof_manager_work_queue,
            task_state: LookupWalletTaskState::Pending,
        }
    }

    /// Find the wallet in the contract storage and create an opening for the wallet
    async fn find_wallet(&mut self) -> Result<(), LookupWalletTaskError> {
        // Get the transaction that last updated the given wallet
        let pk_view_scalar = biguint_to_scalar(&self.key_chain.public_keys.pk_view);
        let last_updated: TransactionHash = self
            .starknet_client
            .get_wallet_last_updated(pk_view_scalar)
            .await
            .map_err(|err| LookupWalletTaskError::Starknet(err.to_string()))?;

        if last_updated == StarknetFieldElement::ZERO {
            return Err(LookupWalletTaskError::NotFound(
                ERR_WALLET_NOT_FOUND.to_string(),
            ));
        }

        log::info!(
            "wallet last updated at: 0x{:x}",
            starknet_felt_to_biguint(&last_updated)
        );

        let ciphertext_blob = self
            .starknet_client
            .fetch_ciphertext_from_tx(last_updated)
            .await
            .map_err(|err| LookupWalletTaskError::Starknet(err.to_string()))?;

        // Decrypt the ciphertext into an encrypted wallet
        let decrypted_wallet = decrypt_wallet(
            ciphertext_blob,
            &self.key_chain.secret_keys.sk_view,
            self.key_chain.public_keys.clone().into(),
        );

        let mut wallet = Wallet {
            wallet_id: self.wallet_id,
            orders: decrypted_wallet
                .orders
                .iter()
                .cloned()
                .map(|order| (Uuid::new_v4(), order))
                .collect(),
            balances: decrypted_wallet
                .balances
                .iter()
                .cloned()
                .map(|balance| (balance.mint.clone(), balance))
                .collect(),
            fees: decrypted_wallet.fees.to_vec(),
            public_keys: decrypted_wallet.keys,
            secret_keys: self.key_chain.secret_keys.clone().into(),
            randomness: scalar_to_biguint(&decrypted_wallet.randomness),
            metadata: WalletMetadata::default(),
            merkle_proof: None, // found in next step
            proof_staleness: AtomicU32::default(),
        };

        // Find the Merkle authentication path for the wallet
        let wallet_commitment = wallet.get_commitment();
        let authentication_path = self
            .starknet_client
            .find_merkle_authentication_path(wallet_commitment)
            .await
            .map_err(|err| LookupWalletTaskError::Starknet(err.to_string()))?;
        wallet.merkle_proof = Some(authentication_path);

        // Index the wallet
        self.global_state.add_wallets(vec![wallet.clone()]).await;

        self.wallet = Some(wallet);
        Ok(())
    }

    /// Prove `VALID COMMITMENTS` for all orders in the wallet
    async fn create_validity_proofs(&self) -> Result<(), LookupWalletTaskError> {
        let wallet = self
            .wallet
            .clone()
            .expect("wallet should be present when CreateValidityProofs state is reached");

        let merkle_proof = wallet.merkle_proof.clone().unwrap();
        let merkle_root = merkle_proof.compute_root();

        // Convert state types into circuit types
        let circuit_wallet: SizedWallet = wallet.clone().into();
        let wallet_opening: MerkleOpening = merkle_proof.into();
        let randomness_hash = compute_poseidon_hash(&[circuit_wallet.randomness]);

        // The statement in `VALID COMMITMENTS` is only parameterized by wallet-specific variables;
        // so we construct it once and use it for all order commitment proofs
        let wallet_match_nullifier = wallet.get_match_nullifier();
        let statement = ValidCommitmentsStatement {
            nullifier: wallet_match_nullifier,
            merkle_root,
            pk_settle: wallet.public_keys.pk_settle,
        };

        let mut proof_response_channels = Vec::new();
        for (order_id, order) in wallet.orders.clone().into_iter() {
            // Skip default orders
            if order.is_default() {
                continue;
            }

            // Construct a witness for the order
            let witness = if let Some(witness) = self.get_witness_for_order(
                order,
                circuit_wallet.clone(),
                wallet_opening.clone(),
                randomness_hash,
                wallet.secret_keys.sk_match,
            ) {
                witness
            } else {
                log::error!("could not construct witness for order, skipping...");
                continue;
            };

            // Send a job to the proof manager to prove `VALID COMMITMENTS` for this order
            let (proof_response_sender, proof_response_receiver) = oneshot::channel();
            self.proof_manager_work_queue
                .send(ProofManagerJob {
                    type_: ProofJob::ValidCommitments {
                        statement,
                        witness: witness.clone(),
                    },
                    response_channel: proof_response_sender,
                })
                .map_err(|err| LookupWalletTaskError::SendMessage(err.to_string()))?;

            proof_response_channels.push((order_id, witness, proof_response_receiver));
        }

        // Await proofs for all orders
        for (order_id, witness, proof_channel) in proof_response_channels.into_iter() {
            let proof = proof_channel
                .await
                .map_err(|err| LookupWalletTaskError::ProofGeneration(err.to_string()))?;
            log::info!("got proof for order {order_id}");

            // Update the global state of the order
            self.update_order_state(order_id, wallet_match_nullifier, proof.into(), witness)
                .await;
        }

        // Update the wallet in the global state
        self.global_state
            .update_wallet(self.wallet.clone().unwrap())
            .await;

        Ok(())
    }

    /// Generate a `VALID COMMITMENTS` witness for the given order
    ///
    /// This will use the old witness -- modifying it appropriately -- if one exists,
    /// otherwise, it will create a brand new witness
    #[allow(clippy::too_many_arguments)]
    fn get_witness_for_order(
        &self,
        order: CircuitOrder,
        wallet: SizedWallet,
        wallet_opening: MerkleOpening,
        randomness_hash: Scalar,
        sk_match: Scalar,
    ) -> Option<SizedValidCommitmentsWitness> {
        // Otherwise, create a brand new witness
        // Select a balance and fee for the order
        let (balance, fee, fee_balance) = self
            .wallet
            .as_ref()
            .unwrap()
            .get_balance_and_fee_for_order(&order)?;

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
        match_nullifier: Nullifier,
        proof: ValidCommitmentsBundle,
        witness: SizedValidCommitmentsWitness,
    ) {
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
                    match_nullifier,
                    local: true,
                    cluster: self.global_state.local_cluster_id.clone(),
                    state: NetworkOrderState::Verified,
                    valid_commit_proof: Some(proof),
                    valid_commit_witness: Some(witness),
                })
                .await;
        } else {
            // Otherwise, update the existing proof
            self.global_state
                .add_order_validity_proof(&order_id, proof)
                .await;
            self.global_state
                .read_order_book()
                .await
                .attach_validity_proof_witness(&order_id, witness)
                .await;
        }
    }
}
