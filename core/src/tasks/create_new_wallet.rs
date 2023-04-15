//! A task defining the flow to create a new wallet, at a high level the steps are:
//!     1. Index the wallet locally
//!     2. Prove `VALID NEW WALLETS` for the wallet
//!     3. Submit this on-chain and await transaction success
//!     4. Pull the Merkle authentication path of the newly created wallet from on-chain state
//!     5. Prove `VALID COMMITMENTS`

use core::panic;
use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::{biguint_to_scalar, starknet_felt_to_biguint};
use serde::Serialize;
use starknet::core::types::TransactionStatus;
use tokio::sync::oneshot;
use tracing::log;

use crate::{
    external_api::types::Wallet,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidWalletCreateBundle},
    starknet_client::client::StarknetClient,
    state::{
        wallet::{Wallet as StateWallet, WalletIdentifier},
        RelayerState,
    },
    SizedWallet,
};

use super::{
    driver::{StateWrapper, Task},
    encrypt_wallet,
};

/// Error occurs when a Starknet transaction fails
const ERR_TRANSACTION_FAILED: &str = "transaction rejected";
/// The task name to display when logging
const NEW_WALLET_TASK_NAME: &str = "create-new-wallet";

/// The task struct defining the long-run async flow for creating a new wallet
pub struct NewWalletTask {
    /// The wallet to create
    pub wallet: StateWallet,
    /// A starknet client for the task to submit transactions
    pub starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task's execution
    pub task_state: NewWalletTaskState,
}

/// The error type for the task
#[derive(Clone, Debug)]
pub enum NewWalletTaskError {
    /// Error generating a proof of `VALID WALLET CREATE`
    ProofGeneration(String),
    /// Error interacting with the Starknet client
    Starknet(String),
    /// Error sending a message to another worker
    SendMessage(String),
}

impl Display for NewWalletTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the state of the long-running wallet create flow
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum NewWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is awaiting a proof of `VALID WALLET CREATE`
    Proving,
    /// The task is submitting the transaction to the contract and
    /// awaiting finality
    SubmittingTx {
        /// The proof of `VALID WALLET CREATE` from the last step
        proof_bundle: ValidWalletCreateBundle,
    },
    /// The task is searching for the Merkle authentication proof for the
    /// new wallet on-chain
    FindingMerkleOpening,
    /// Task completed
    Completed,
}

/// Display implementation that ignores structure fields
impl Display for NewWalletTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            NewWalletTaskState::SubmittingTx { .. } => {
                write!(f, "SubmittingTx")
            }
            _ => write!(f, "{self:?}"),
        }
    }
}

/// Serialize implementation that uses the display implementation above
impl Serialize for NewWalletTaskState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl From<NewWalletTaskState> for StateWrapper {
    fn from(state: NewWalletTaskState) -> Self {
        StateWrapper::NewWallet(state)
    }
}

#[async_trait]
impl Task for NewWalletTask {
    type Error = NewWalletTaskError;
    type State = NewWalletTaskState;

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current state of the task
        match self.state() {
            NewWalletTaskState::Pending => {
                self.task_state = NewWalletTaskState::Proving;
            }
            NewWalletTaskState::Proving => {
                // Begin proof and attach the proof to the state afterwards
                let proof_bundle = self.generate_proof().await?;
                self.task_state = NewWalletTaskState::SubmittingTx { proof_bundle }
            }
            NewWalletTaskState::SubmittingTx { .. } => {
                // Submit the wallet on-chain
                self.submit_wallet_tx().await?;
                self.task_state = NewWalletTaskState::FindingMerkleOpening;
            }
            NewWalletTaskState::FindingMerkleOpening => {
                // Find the authentication path via contract events, and index this
                // in the global state
                self.find_merkle_path().await?;
                self.task_state = NewWalletTaskState::Completed;
            }
            NewWalletTaskState::Completed => {
                panic!("step() called in completed state")
            }
        }

        Ok(())
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn completed(&self) -> bool {
        matches!(self.state(), NewWalletTaskState::Completed)
    }

    fn name(&self) -> String {
        NEW_WALLET_TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl NewWalletTask {
    /// Constructor
    pub fn new(
        wallet_id: WalletIdentifier,
        wallet: Wallet,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        // When we cast to a state wallet, the identifier is erased, add
        // it from the request explicitly
        let mut wallet: StateWallet = wallet.into();
        wallet.wallet_id = wallet_id;

        Self {
            wallet,
            starknet_client,
            global_state,
            proof_manager_work_queue,
            task_state: NewWalletTaskState::Pending,
        }
    }

    /// Generate a proof of `VALID NEW WALLET` for the new wallet
    async fn generate_proof(&self) -> Result<ValidWalletCreateBundle, NewWalletTaskError> {
        // Index the wallet in the global state
        self.global_state
            .add_wallets(vec![self.wallet.clone()])
            .await;

        // Enqueue a job with the proof manager to prove `VALID NEW WALLET`
        let (response_sender, response_receiver) = oneshot::channel();
        let job_req = ProofManagerJob {
            type_: ProofJob::ValidWalletCreate {
                fees: self.wallet.fees.clone(),
                keys: self.wallet.key_chain.public_keys.clone(),
                randomness: biguint_to_scalar(&self.wallet.randomness),
            },
            response_channel: response_sender,
        };
        self.proof_manager_work_queue
            .send(job_req)
            .map_err(|err| NewWalletTaskError::SendMessage(err.to_string()))?;

        let proof_bundle = response_receiver
            .await
            .map_err(|err| NewWalletTaskError::ProofGeneration(err.to_string()))?;

        Ok(proof_bundle.into())
    }

    /// Submit the newly created wallet on-chain with proof of validity
    async fn submit_wallet_tx(&self) -> Result<(), NewWalletTaskError> {
        let proof = if let NewWalletTaskState::SubmittingTx { proof_bundle } = self.state() {
            proof_bundle
        } else {
            unreachable!("can only begin submitting wallet after proof is generated")
        };

        // Compute a commitment to the wallet and submit the bundle on-chain
        let wallet_commitment = self.wallet.get_commitment();

        // Generate an encryption of the wallet under the public view key
        let circuit_wallet: SizedWallet = self.wallet.clone().into();
        let wallet_ciphertext =
            encrypt_wallet(circuit_wallet, self.wallet.key_chain.public_keys.pk_view);

        let tx_hash = self
            .starknet_client
            .new_wallet(
                self.wallet.key_chain.public_keys.pk_view,
                wallet_commitment,
                wallet_ciphertext,
                proof,
            )
            .await
            .map_err(|err| NewWalletTaskError::Starknet(err.to_string()))?;
        log::info!("tx hash: 0x{:x}", starknet_felt_to_biguint(&tx_hash));

        let res = self
            .starknet_client
            .poll_transaction_completed(tx_hash)
            .await
            .map_err(|err| NewWalletTaskError::Starknet(err.to_string()))?;

        if let TransactionStatus::Rejected = res.status {
            return Err(NewWalletTaskError::Starknet(
                ERR_TRANSACTION_FAILED.to_string(),
            ));
        }

        Ok(())
    }

    /// A helper to find the new Merkle authentication path in the contract state
    /// and update the global state with the new wallet's authentication path
    async fn find_merkle_path(&self) -> Result<(), NewWalletTaskError> {
        // Find the updated Merkle path for the wallet
        let merkle_auth_path = self
            .starknet_client
            .find_merkle_authentication_path(self.wallet.get_commitment())
            .await
            .map_err(|err| NewWalletTaskError::Starknet(err.to_string()))?;

        // Add the authentication path to the wallet in the global state
        self.global_state
            .read_wallet_index()
            .await
            .add_wallet_merkle_proof(&self.wallet.wallet_id, merkle_auth_path)
            .await;

        Ok(())
    }
}
