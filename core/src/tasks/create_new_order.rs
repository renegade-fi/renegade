//! Handles the flow of adding a new order to a wallet

use std::{
    fmt::Display,
    time::{SystemTime, UNIX_EPOCH},
};

use circuits::{
    types::order::Order as CircuitOrder,
    zk_circuits::valid_wallet_update::ValidWalletUpdateStatement,
};
use crossbeam::channel::Sender as CrossbeamSender;
use curve25519_dalek::scalar::Scalar;
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

/// The wallet does not have a merkle proof attached to it
const ERR_NO_MERKLE_PROOF: &str = "wallet merkle proof not attached";
/// The wallet to create the order within was not found
const ERR_WALLET_NOT_FOUND: &str = "wallet not found in state";

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

        // Prove `VALID WALLET UPDATE`
        let _proof = self
            .prove_valid_wallet_update(old_wallet, new_wallet)
            .await?;
        log::info!("generated a proof of valid wallet update!");

        // Submit on-chain

        // Re-prove validity proofs

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
}
