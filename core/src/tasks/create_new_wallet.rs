//! A task defining the flow to create a new wallet, at a high level the steps are:
//!     1. Index the wallet locally
//!     2. Prove `VALID NEW WALLETS` for the wallet
//!     3. Submit this on-chain and await transaction success
//!     4. Pull the Merkle authentication path of the newly created wallet from on-chain state
//!     5. Prove `VALID COMMITMENTS`

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use serde::{Deserialize, Serialize};
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
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum NewWalletTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is awaiting a proof of `VALID WALLET CREATE`
    Proving,
    /// The task has submitted the wallet on-chain and is awaiting
    /// transaction finality
    Submitted,
    /// The task is searching for the Merkle authentication proof for the
    /// new wallet on-chain
    FindingMerkleOpening,
    /// Task completed
    Completed,
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
        // Dispatch based on state
        match self.state() {
            NewWalletTaskState::Pending => {
                unimplemented!()
            }
            NewWalletTaskState::Proving => {
                unimplemented!()
            }
            NewWalletTaskState::Submitted => {
                unimplemented!()
            }
            NewWalletTaskState::FindingMerkleOpening => {
                unimplemented!()
            }
            NewWalletTaskState::Completed => {
                unimplemented!()
            }
        }
    }

    fn state(&self) -> Self::State {
        self.task_state
    }

    fn completed(&self) -> bool {
        matches!(self.state(), NewWalletTaskState::Completed)
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

    /// Run the task to completion, provides a wrapper of error logging
    /// around the helper defined below
    pub async fn run(self) -> Result<(), NewWalletTaskError> {
        let res = self.run_helper().await;
        if let Err(e) = res.clone() {
            log::error!("error running new wallet task: {e}");
        } else {
            log::info!("successfully created new wallet");
        }

        res
    }

    /// A helper to run the task to completion
    async fn run_helper(self) -> Result<(), NewWalletTaskError> {
        log::info!("Beginning new wallet task execution");

        // Index the wallet in the global state
        self.global_state
            .add_wallets(vec![self.wallet.clone()])
            .await;

        // Enqueue a job with the proof manager to prove `VALID NEW WALLET`
        let (response_sender, response_receiver) = oneshot::channel();
        let job_req = ProofManagerJob {
            type_: ProofJob::ValidWalletCreate {
                fees: self.wallet.fees.clone(),
                keys: self.wallet.public_keys,
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

        // Submit the wallet on-chain
        self.submit_new_wallet(proof_bundle.into())
            .await
            .map_err(|err| NewWalletTaskError::Starknet(err.to_string()))?;

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

    /// Submits a proof and wallet commitment + encryption on-chain
    ///
    /// TODO: Add wallet encryptions as well
    async fn submit_new_wallet(
        &self,
        proof: ValidWalletCreateBundle,
    ) -> Result<(), NewWalletTaskError> {
        // Compute a commitment to the wallet and submit the bundle on-chain
        let wallet_commitment = self.wallet.get_commitment();

        // Generate an encryption of the wallet under the public view key
        let circuit_wallet: SizedWallet = self.wallet.clone().into();
        let pk_view = scalar_to_biguint(&self.wallet.public_keys.pk_view);
        let wallet_ciphertext = encrypt_wallet(circuit_wallet, &pk_view);

        let tx_hash = self
            .starknet_client
            .new_wallet(wallet_commitment, wallet_ciphertext, proof)
            .await
            .map_err(|err| NewWalletTaskError::Starknet(err.to_string()))?;

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
}
