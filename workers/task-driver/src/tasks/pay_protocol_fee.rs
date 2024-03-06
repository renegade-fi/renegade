//! The `PayProtocolFee` task is responsible for settling the fees due for a
//! given wallet

use std::{
    error::Error,
    fmt::{Display, Formatter, Result as FmtResult},
};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::{native_helpers::encrypt_note, note::Note, Amount};
use circuits::zk_circuits::valid_offline_fee_settlement::{
    SizedValidOfflineFeeSettlementStatement, SizedValidOfflineFeeSettlementWitness,
};
use common::types::{
    proof_bundles::OfflineFeeSettlementBundle, tasks::PayProtocolFeeTaskDescriptor, wallet::Wallet,
};
use job_types::{
    network_manager::NetworkManagerQueue,
    proof_manager::{ProofJob, ProofManagerQueue},
};
use num_bigint::BigUint;
use serde::Serialize;
use state::{error::StateError, State};
use tracing::instrument;
use util::{arbitrum::get_protocol_encryption_key, err_str};

use crate::{
    driver::StateWrapper,
    helpers::{enqueue_proof_job, find_merkle_path, update_wallet_validity_proofs},
    traits::{Task, TaskContext, TaskError, TaskState},
};

/// The name of the task
const TASK_NAME: &str = "pay-protocol-fee";
/// The error emitted when a wallet is missing from state
const ERR_WALLET_MISSING: &str = "wallet not found in global state";
/// The error emitted when a balance for a given mint is missing
const ERR_BALANCE_MISSING: &str = "balance not found in wallet";
/// The error message emitted when a Merkle proof is not found for a wallet
const ERR_NO_MERKLE_PROOF: &str = "no merkle proof found for wallet";

// --------------
// | Task State |
// --------------

/// Defines the state of the fee payment task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum PayProtocolFeeTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is proving fee payment for the balance
    ProvingPayment,
    /// The task is submitting a fee payment transaction
    SubmittingPayment,
    /// The task is finding the new Merkle opening for the wallet
    FindingOpening,
    /// The task is updating the validity proofs for the wallet
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl TaskState for PayProtocolFeeTaskState {
    fn commit_point() -> Self {
        PayProtocolFeeTaskState::SubmittingPayment
    }

    fn completed(&self) -> bool {
        matches!(self, PayProtocolFeeTaskState::Completed)
    }
}

impl Display for PayProtocolFeeTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl From<PayProtocolFeeTaskState> for StateWrapper {
    fn from(value: PayProtocolFeeTaskState) -> Self {
        StateWrapper::PayProtocolFee(value)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the pay fees task
#[derive(Clone, Debug)]
pub enum PayProtocolFeeTaskError {
    /// An error interacting with Arbitrum
    Arbitrum(String),
    /// An error generating a proof for fee payment
    ProofGeneration(String),
    /// An error interacting with the state
    State(String),
    /// An error updating validity proofs after the fees are settled
    UpdateValidityProofs(String),
}

impl TaskError for PayProtocolFeeTaskError {
    fn retryable(&self) -> bool {
        match self {
            PayProtocolFeeTaskError::Arbitrum(_)
            | PayProtocolFeeTaskError::State(_)
            | PayProtocolFeeTaskError::ProofGeneration(_)
            | PayProtocolFeeTaskError::UpdateValidityProofs(_) => true,
        }
    }
}

impl Display for PayProtocolFeeTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for PayProtocolFeeTaskError {}

impl From<StateError> for PayProtocolFeeTaskError {
    fn from(error: StateError) -> Self {
        PayProtocolFeeTaskError::State(error.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the pay fees task flow
pub struct PayProtocolFeeTask {
    /// The balance to pay fees for
    pub mint: BigUint,
    /// The wallet that this task pays fees for
    pub old_wallet: Wallet,
    /// The new wallet after fees have been paid
    pub new_wallet: Wallet,
    /// The proof of `VALID OFFLINE FEE SETTLEMENT` used to pay the protocol fee
    pub protocol_proof: Option<OfflineFeeSettlementBundle>,
    /// The arbitrum client used for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A hand to the global state
    pub state: State,
    /// The work queue for the proof manager
    pub proof_queue: ProofManagerQueue,
    /// A sender to the network manager's queue
    pub network_sender: NetworkManagerQueue,
    /// The current state of the task
    pub task_state: PayProtocolFeeTaskState,
}

#[async_trait]
impl Task for PayProtocolFeeTask {
    type State = PayProtocolFeeTaskState;
    type Error = PayProtocolFeeTaskError;
    type Descriptor = PayProtocolFeeTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        let old_wallet = ctx
            .state
            .get_wallet(&descriptor.wallet_id)?
            .ok_or_else(|| PayProtocolFeeTaskError::State(ERR_WALLET_MISSING.to_string()))?;

        // Construct the new wallet
        let new_wallet = Self::get_new_wallet(&descriptor.balance_mint, &old_wallet)?;

        Ok(Self {
            mint: descriptor.balance_mint,
            old_wallet,
            new_wallet,
            protocol_proof: None,
            arbitrum_client: ctx.arbitrum_client,
            state: ctx.state,
            proof_queue: ctx.proof_queue,
            network_sender: ctx.network_queue,
            task_state: PayProtocolFeeTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        match self.state() {
            PayProtocolFeeTaskState::Pending => {
                self.task_state = PayProtocolFeeTaskState::ProvingPayment;
            },
            PayProtocolFeeTaskState::ProvingPayment => {
                self.generate_proof().await?;
                self.task_state = PayProtocolFeeTaskState::SubmittingPayment;
            },
            PayProtocolFeeTaskState::SubmittingPayment => {
                self.submit_payment().await?;
                self.task_state = PayProtocolFeeTaskState::FindingOpening;
            },
            PayProtocolFeeTaskState::FindingOpening => {
                self.find_merkle_opening().await?;
                self.task_state = PayProtocolFeeTaskState::UpdatingValidityProofs;
            },
            PayProtocolFeeTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = PayProtocolFeeTaskState::Completed;
            },
            PayProtocolFeeTaskState::Completed => {
                panic!("step() called in state Completed")
            },
        }

        Ok(())
    }

    fn completed(&self) -> bool {
        self.task_state.completed()
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn name(&self) -> String {
        TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl PayProtocolFeeTask {
    /// Generate a proof of `VALID PROTOCOL FEE SETTLEMENT` for the given
    /// balance
    async fn generate_proof(&mut self) -> Result<(), PayProtocolFeeTaskError> {
        let (statement, witness) = self.get_witness_statement()?;
        let job = ProofJob::ValidOfflineFeeSettlement { witness, statement };

        let proof_recv = enqueue_proof_job(job, &self.proof_queue)
            .map_err(PayProtocolFeeTaskError::ProofGeneration)?;

        // Await the proof
        let bundle =
            proof_recv.await.map_err(err_str!(PayProtocolFeeTaskError::ProofGeneration))?;
        self.protocol_proof = Some(bundle.proof.into());
        Ok(())
    }

    /// Submit the `settle_protocol_fee` transaction for the balance
    async fn submit_payment(&mut self) -> Result<(), PayProtocolFeeTaskError> {
        let proof = self.protocol_proof.clone().unwrap();
        self.arbitrum_client
            .settle_offline_fee(&proof)
            .await
            .map_err(err_str!(PayProtocolFeeTaskError::Arbitrum))
    }

    /// Find the Merkle opening for the new wallet
    async fn find_merkle_opening(&mut self) -> Result<(), PayProtocolFeeTaskError> {
        let merkle_opening = find_merkle_path(&self.new_wallet, &self.arbitrum_client)
            .await
            .map_err(err_str!(PayProtocolFeeTaskError::Arbitrum))?;
        self.new_wallet.merkle_proof = Some(merkle_opening);

        // Update the global state to include the new wallet
        self.state.update_wallet(self.new_wallet.clone())?.await?;
        Ok(())
    }

    /// Update the validity proofs for the wallet after fee payment
    async fn update_validity_proofs(&mut self) -> Result<(), PayProtocolFeeTaskError> {
        update_wallet_validity_proofs(
            &self.new_wallet,
            self.proof_queue.clone(),
            self.state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(PayProtocolFeeTaskError::UpdateValidityProofs)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Clone the old wallet and update it to reflect the fee payment
    fn get_new_wallet(
        mint: &BigUint,
        old_wallet: &Wallet,
    ) -> Result<Wallet, PayProtocolFeeTaskError> {
        let mut new_wallet = old_wallet.clone();
        let balance = new_wallet
            .get_balance_mut(mint)
            .ok_or_else(|| PayProtocolFeeTaskError::State(ERR_BALANCE_MISSING.to_string()))?;

        balance.protocol_fee_balance = Amount::from(0u8);
        new_wallet.reblind_wallet();

        Ok(new_wallet)
    }

    /// Get the witness and statement for the `VALID PROTOCOL FEE SETTLEMENT`
    fn get_witness_statement(
        &self,
    ) -> Result<
        (SizedValidOfflineFeeSettlementStatement, SizedValidOfflineFeeSettlementWitness),
        PayProtocolFeeTaskError,
    > {
        // Get the old wallet's state transition info
        let wallet = &self.old_wallet;
        let nullifier = wallet.get_wallet_nullifier();
        let opening = wallet
            .merkle_proof
            .clone()
            .ok_or_else(|| PayProtocolFeeTaskError::State(ERR_NO_MERKLE_PROOF.to_string()))?;
        let original_wallet_public_shares = wallet.blinded_public_shares.clone();
        let original_wallet_private_shares = wallet.private_shares.clone();

        // Generate a note
        let send_index = wallet.get_balance_index(&self.mint).unwrap();
        let bal = wallet.get_balance(&self.mint).unwrap();

        let protocol_key = get_protocol_encryption_key();
        let note = Note::new(self.mint.clone(), bal.protocol_fee_balance, protocol_key);
        let note_commitment = note.commitment();

        // Encrypt the note
        let (note_ciphertext, encryption_randomness) = encrypt_note(&note, &protocol_key);

        // Generate new wallet shares
        let new_wallet = &self.new_wallet;
        let updated_wallet_commitment = new_wallet.get_private_share_commitment();
        let updated_wallet_public_shares = new_wallet.blinded_public_shares.clone();
        let updated_wallet_private_shares = new_wallet.private_shares.clone();

        // Create the witness and statement
        let statement = SizedValidOfflineFeeSettlementStatement {
            merkle_root: opening.compute_root(),
            nullifier,
            updated_wallet_commitment,
            updated_wallet_public_shares,
            note_ciphertext,
            note_commitment,
            protocol_key,
            is_protocol_fee: true,
        };

        let witness = SizedValidOfflineFeeSettlementWitness {
            original_wallet_public_shares,
            original_wallet_private_shares,
            updated_wallet_private_shares,
            merkle_opening: opening.into(),
            note,
            encryption_randomness,
            send_index,
        };

        Ok((statement, witness))
    }
}
