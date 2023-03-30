//! Defines a task that submits a transaction transferring an ERC20 token into
//! an existing darkpool wallet
//!
//! This involves proving `VALID WALLET UPDATE`, submitting on-chain, and re-indexing state

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use circuits::{
    types::balance::Balance, zk_circuits::valid_wallet_update::ValidWalletUpdateStatement,
};
use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::{scalar_to_biguint, starknet_felt_to_biguint};
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use rand_core::OsRng;
use serde::Serialize;
use starknet::core::types::TransactionStatus;
use tokio::sync::oneshot;
use tracing::log;

use crate::{
    price_reporter::exchanges::get_current_time,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidWalletUpdateBundle},
    starknet_client::{
        client::StarknetClient,
        types::{ExternalTransfer, ExternalTransferDirection},
    },
    state::{
        wallet::{Wallet, WalletIdentifier},
        RelayerState,
    },
    tasks::encrypt_wallet,
    types::SizedValidWalletUpdateWitness,
    SizedWallet,
};

use super::{
    driver::{StateWrapper, Task},
    RANDOMNESS_INCREMENT,
};

/// The display name of the task
const DEPOSIT_BALANCE_TASK_NAME: &str = "deposit-balance";
/// The wallet does not have a known Merkle proof attached
const ERR_NO_MERKLE_PROOF: &str = "merkle proof for wallet not found";
/// A transaction submitted to the contract failed to execute
const ERR_TRANSACTION_FAILED: &str = "transaction failed";
/// The wallet to update was not found in global state
const ERR_WALLET_NOT_FOUND: &str = "wallet not found in global state";

/// Defines the long running flow for adding a balance to a wallet
pub struct DepositBalanceTask {
    /// The ERC20 address of the token to deposit
    pub mint: BigUint,
    /// The amount of the token to deposit
    pub amount: BigUint,
    /// The address to deposit from
    pub sender_address: BigUint,
    /// The old wallet before update
    pub old_wallet: Wallet,
    /// The new wallet after update
    pub new_wallet: Wallet,
    /// The starknet client to use for submitting transactions
    pub starknet_client: StarknetClient,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task
    pub task_state: DepositBalanceTaskState,
}

/// The error type for the deposit balance task
#[derive(Clone, Debug)]
pub enum DepositBalanceTaskError {
    /// Error generating a proof of `VALID WALLET UPDATE`
    ProofGeneration(String),
    /// An error enqueuing a message for another worker
    SendMessage(String),
    /// An error occurred interacting with Starknet
    StarknetClient(String),
    /// A state element was not found that is necessary for task execution
    StateMissing(String),
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the state of the deposit balance task
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum DepositBalanceTaskState {
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

impl Display for DepositBalanceTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::SubmittingTx { .. } => write!(f, "SubmittingTx"),
            _ => write!(f, "{self:?}"),
        }
    }
}

impl Serialize for DepositBalanceTaskState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl From<DepositBalanceTaskState> for StateWrapper {
    fn from(state: DepositBalanceTaskState) -> Self {
        StateWrapper::DepositBalance(state)
    }
}

#[async_trait]
impl Task for DepositBalanceTask {
    type Error = DepositBalanceTaskError;
    type State = DepositBalanceTaskState;

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.state() {
            DepositBalanceTaskState::Pending => {
                self.task_state = DepositBalanceTaskState::Proving;
            }
            DepositBalanceTaskState::Proving => {
                // Begin the proof of `VALID WALLET UPDATE`
                let proof = self.generate_proof().await?;
                self.task_state = DepositBalanceTaskState::SubmittingTx {
                    proof_bundle: proof,
                };
            }
            DepositBalanceTaskState::SubmittingTx { .. } => {
                // Submit the proof and transaction info to the contract and await
                // transaction finality
                self.submit_tx().await?;
                self.task_state = DepositBalanceTaskState::UpdatingValidityProofs;
            }
            DepositBalanceTaskState::UpdatingValidityProofs => {
                // Update validity proofs for now-nullified orders
                self.update_validity_proofs().await?;
                self.task_state = DepositBalanceTaskState::Completed;
            }
            DepositBalanceTaskState::Completed => {
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
        DEPOSIT_BALANCE_TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl DepositBalanceTask {
    /// Constructor
    pub async fn new(
        mint: BigUint,
        amount: BigUint,
        sender_address: BigUint,
        wallet_id: &WalletIdentifier,
        starknet_client: StarknetClient,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Result<Self, DepositBalanceTaskError> {
        // Lookup the wallet in global state
        let old_wallet = global_state
            .read_wallet_index()
            .await
            .get_wallet(wallet_id)
            .await
            .ok_or_else(|| {
                DepositBalanceTaskError::StateMissing(ERR_WALLET_NOT_FOUND.to_string())
            })?;

        let mut new_wallet = old_wallet.clone();
        new_wallet
            .balances
            .entry(mint.clone())
            .or_insert(Balance {
                mint: mint.clone(),
                amount: 0u64,
            })
            .amount += amount.to_u64().unwrap();
        new_wallet.randomness += RANDOMNESS_INCREMENT;

        Ok(Self {
            mint,
            amount,
            sender_address,
            old_wallet,
            new_wallet,
            starknet_client,
            global_state,
            proof_manager_work_queue,
            task_state: DepositBalanceTaskState::Pending,
        })
    }

    /// Generate a proof of `VALID WALLET UPDATE` for the wallet with added balance
    async fn generate_proof(&self) -> Result<ValidWalletUpdateBundle, DepositBalanceTaskError> {
        let timestamp: Scalar = get_current_time().into();
        let merkle_opening = self.old_wallet.merkle_proof.clone().ok_or_else(|| {
            DepositBalanceTaskError::StateMissing(ERR_NO_MERKLE_PROOF.to_string())
        })?;

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
            .map_err(|err| DepositBalanceTaskError::SendMessage(err.to_string()))?;

        response_receiver
            .await
            .map(|bundle| bundle.into())
            .map_err(|err| DepositBalanceTaskError::ProofGeneration(err.to_string()))
    }

    /// Submit the `update_wallet` transaction to the contract and await finality
    async fn submit_tx(&self) -> Result<(), DepositBalanceTaskError> {
        let external_transfer = ExternalTransfer::new(
            self.sender_address.clone(),
            self.mint.clone(),
            self.amount.clone(),
            ExternalTransferDirection::Deposit,
        );

        let proof = if let DepositBalanceTaskState::SubmittingTx { proof_bundle } = self.state() {
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
                Some(external_transfer),
                encrypted_wallet,
                proof,
            )
            .await
            .map_err(|err| DepositBalanceTaskError::StarknetClient(err.to_string()))?;
        log::info!("got tx hash: {}", starknet_felt_to_biguint(&tx_hash));

        // Await transaction completion
        let tx_info = self
            .starknet_client
            .poll_transaction_completed(tx_hash)
            .await
            .map_err(|err| DepositBalanceTaskError::StarknetClient(err.to_string()))?;

        if let TransactionStatus::Rejected = tx_info.status {
            return Err(DepositBalanceTaskError::StarknetClient(
                ERR_TRANSACTION_FAILED.to_string(),
            ));
        }

        Ok(())
    }

    /// Update the proofs of `VALID COMMITMENTS` for each order after the wallet update is complete
    async fn update_validity_proofs(&self) -> Result<(), DepositBalanceTaskError> {
        unimplemented!("")
    }
}
