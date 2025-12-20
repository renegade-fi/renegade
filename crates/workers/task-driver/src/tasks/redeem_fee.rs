//! Redeems a fee into the relayer wallet

use std::{error::Error, fmt::Display};

use alloy::rpc::types::TransactionReceipt;
use async_trait::async_trait;
use circuit_types::{balance::Balance, elgamal::DecryptionKey, note::Note};
use circuits::zk_circuits::valid_fee_redemption::{
    SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness,
};
use common::types::{
    merkle::MerkleAuthenticationPath, proof_bundles::FeeRedemptionBundle,
    tasks::RedeemFeeTaskDescriptor, wallet::Wallet,
};
use darkpool_client::errors::DarkpoolClientError;
use job_types::proof_manager::ProofJob;
use serde::Serialize;
use state::error::StateError;
use tracing::instrument;
use util::err_str;

use crate::{
    task_state::StateWrapper,
    tasks::ERR_NO_MERKLE_PROOF,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
    utils::{enqueue_proof_job, merkle_path::find_merkle_path_with_tx},
};

/// The name of the task
const TASK_NAME: &str = "redeem-relayer-fee";

/// The error message emitted when a wallet cannot be found
const ERR_WALLET_NOT_FOUND: &str = "wallet not found in state";

// --------------
// | Task State |
// --------------

/// Defines the state of the redeem relayer fee task
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Serialize)]
pub enum RedeemFeeTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is finding the Merkle opening for the note
    FindingNoteOpening,
    /// The task is proving note redemption
    ProvingRedemption,
    /// The task is submitting a note redemption transaction
    SubmittingRedemption,
    /// The task is finding the relayer wallet's opening
    FindingWalletOpening,
    /// The task has finished
    Completed,
}

impl TaskState for RedeemFeeTaskState {
    fn commit_point() -> Self {
        RedeemFeeTaskState::SubmittingRedemption
    }

    fn completed(&self) -> bool {
        matches!(self, RedeemFeeTaskState::Completed)
    }
}

impl Display for RedeemFeeTaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RedeemFeeTaskState::Pending => write!(f, "Pending"),
            RedeemFeeTaskState::FindingNoteOpening => write!(f, "Finding Note Opening"),
            RedeemFeeTaskState::ProvingRedemption => write!(f, "Proving Redemption"),
            RedeemFeeTaskState::SubmittingRedemption => write!(f, "Submitting Redemption"),
            RedeemFeeTaskState::FindingWalletOpening => write!(f, "Finding Opening"),
            RedeemFeeTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<RedeemFeeTaskState> for StateWrapper {
    fn from(value: RedeemFeeTaskState) -> Self {
        StateWrapper::RedeemFee(value)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the redeem relayer fee task
#[derive(Clone, Debug)]
pub enum RedeemFeeError {
    /// An error interacting with the darkpool
    Darkpool(String),
    /// An error generating a proof for fee payment
    ProofGeneration(String),
    /// An error signing the commitment to the new wallet
    Signature(String),
    /// An error interacting with the state
    State(String),
    /// An error updating validity proofs after the fees are settled
    UpdateValidityProofs(String),
}

impl TaskError for RedeemFeeError {
    fn retryable(&self) -> bool {
        match self {
            RedeemFeeError::Darkpool(_)
            | RedeemFeeError::ProofGeneration(_)
            | RedeemFeeError::State(_)
            | RedeemFeeError::UpdateValidityProofs(_) => true,
            RedeemFeeError::Signature(_) => false,
        }
    }
}

impl Display for RedeemFeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for RedeemFeeError {}

impl From<StateError> for RedeemFeeError {
    fn from(err: StateError) -> Self {
        RedeemFeeError::State(err.to_string())
    }
}

impl From<DarkpoolClientError> for RedeemFeeError {
    fn from(error: DarkpoolClientError) -> Self {
        RedeemFeeError::Darkpool(error.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the redeem relayer fee task
pub struct RedeemFeeTask {
    /// The note to redeem
    pub note: Note,
    /// The decryption key authorized to redeem the wallet
    pub decryption_key: DecryptionKey,
    /// The Merkle opening of the note
    pub note_opening: Option<MerkleAuthenticationPath>,
    /// The wallet before the note is settled
    pub old_wallet: Wallet,
    /// The wallet after the note is settled
    pub new_wallet: Wallet,
    /// The proof of `VALID FEE REDEMPTION` used to pay the fee
    pub proof: Option<FeeRedemptionBundle>,
    /// The transaction receipt of the note redemption
    pub tx: Option<TransactionReceipt>,
    /// The current state of the task
    pub task_state: RedeemFeeTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for RedeemFeeTask {
    type State = RedeemFeeTaskState;
    type Error = RedeemFeeError;
    type Descriptor = RedeemFeeTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        let state = &ctx.state;
        let old_wallet = state
            .get_wallet(&descriptor.wallet_id)
            .await
            .map_err(err_str!(RedeemFeeError::State))?
            .ok_or(RedeemFeeError::State(ERR_WALLET_NOT_FOUND.to_string()))?;

        let new_wallet = Self::get_new_wallet(&descriptor.note, &old_wallet)?;

        Ok(Self {
            note: descriptor.note,
            decryption_key: descriptor.decryption_key,
            note_opening: None,
            old_wallet,
            new_wallet,
            proof: None,
            tx: None,
            task_state: RedeemFeeTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(
        task = self.name(),
        state = %self.state(),
        old_wallet = %self.old_wallet.wallet_id,
        new_wallet = %self.new_wallet.wallet_id,
    ))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        match self.task_state {
            RedeemFeeTaskState::Pending => {
                self.task_state = RedeemFeeTaskState::FindingNoteOpening;
            },
            RedeemFeeTaskState::FindingNoteOpening => {
                self.find_note_opening().await?;
                self.task_state = RedeemFeeTaskState::ProvingRedemption;
            },
            RedeemFeeTaskState::ProvingRedemption => {
                self.generate_proof().await?;
                self.task_state = RedeemFeeTaskState::SubmittingRedemption;
            },
            RedeemFeeTaskState::SubmittingRedemption => {
                self.submit_redemption().await?;
                self.task_state = RedeemFeeTaskState::FindingWalletOpening;
            },
            RedeemFeeTaskState::FindingWalletOpening => {
                self.find_wallet_opening().await?;
                self.task_state = RedeemFeeTaskState::Completed;
            },
            RedeemFeeTaskState::Completed => panic!("step() called in `Completed` state"),
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

impl Descriptor for RedeemFeeTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl RedeemFeeTask {
    /// Find the Merkle opening for the note
    async fn find_note_opening(&mut self) -> Result<(), RedeemFeeError> {
        let note_comm = self.note.commitment();
        let opening = self.ctx.darkpool_client.find_merkle_authentication_path(note_comm).await?;
        self.note_opening = Some(opening);
        Ok(())
    }

    /// Generate a proof of `VALID RELAYER FEE REDEMPTION` for the relayer's
    /// wallet
    async fn generate_proof(&mut self) -> Result<(), RedeemFeeError> {
        let (statement, witness) = self.get_witness_statement()?;
        let job = ProofJob::ValidFeeRedemption { witness, statement };
        let proof =
            enqueue_proof_job(job, &self.ctx).map_err(err_str!(RedeemFeeError::ProofGeneration))?;

        // Await the proof
        let bundle = proof.await.map_err(err_str!(RedeemFeeError::ProofGeneration))?;
        self.proof = Some(bundle.into());

        Ok(())
    }

    /// Submit a `redeem_fee` transaction to the contract
    async fn submit_redemption(&mut self) -> Result<(), RedeemFeeError> {
        let proof = self.proof.as_ref().unwrap();

        // Sign a commitment to the new wallet after redemption
        let new_wallet_comm = self.new_wallet.get_wallet_share_commitment();
        let sig =
            self.old_wallet.sign_commitment(new_wallet_comm).map_err(RedeemFeeError::Signature)?;
        let sig_bytes = sig.as_bytes().to_vec();

        let tx = self.ctx.darkpool_client.redeem_fee(proof, sig_bytes).await?;
        self.tx = Some(tx);
        Ok(())
    }

    /// Find the opening for the relayer wallet
    async fn find_wallet_opening(&mut self) -> Result<(), RedeemFeeError> {
        let tx = self.tx.as_ref().unwrap();
        let opening = find_merkle_path_with_tx(&self.new_wallet, tx, &self.ctx)?;
        self.new_wallet.merkle_proof = Some(opening);

        let waiter = self.ctx.state.update_wallet(self.new_wallet.clone()).await?;
        waiter.await?;
        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the new wallet after the note is settled
    fn get_new_wallet(note: &Note, old_wallet: &Wallet) -> Result<Wallet, RedeemFeeError> {
        let mut new_wallet = old_wallet.clone();
        let bal = Balance::new_from_mint_and_amount(note.mint.clone(), note.amount);
        new_wallet.add_balance(bal).map_err(err_str!(RedeemFeeError::State))?;
        new_wallet.reblind_wallet();

        Ok(new_wallet)
    }

    /// Get the witness and statement for the proof of `VALID FEE REDEMPTION`
    fn get_witness_statement(
        &self,
    ) -> Result<(SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness), RedeemFeeError>
    {
        let old_wallet = &self.old_wallet;
        let new_wallet = &self.new_wallet;
        let old_wallet_private_shares = old_wallet.private_shares.clone();
        let old_wallet_public_shares = old_wallet.blinded_public_shares.clone();
        let new_wallet_private_shares = new_wallet.private_shares.clone();
        let new_wallet_public_shares = new_wallet.blinded_public_shares.clone();

        let wallet_opening = self
            .old_wallet
            .merkle_proof
            .clone()
            .ok_or(RedeemFeeError::State(ERR_NO_MERKLE_PROOF.to_string()))?;
        let note_opening = self.note_opening.clone().unwrap();

        let receive_index = self.new_wallet.get_balance_index(&self.note.mint).unwrap();

        let statement = SizedValidFeeRedemptionStatement {
            wallet_root: wallet_opening.compute_root(),
            note_root: note_opening.compute_root(),
            wallet_nullifier: self.old_wallet.get_wallet_nullifier(),
            note_nullifier: self.note.nullifier(),
            new_shares_commitment: self.new_wallet.get_wallet_share_commitment(),
            new_wallet_public_shares,
            recipient_root_key: self.old_wallet.key_chain.public_keys.pk_root.clone(),
        };

        let witness = SizedValidFeeRedemptionWitness {
            old_wallet_private_shares,
            old_wallet_public_shares,
            new_wallet_private_shares,
            wallet_opening: wallet_opening.into(),
            note_opening: note_opening.into(),
            note: self.note.clone(),
            recipient_key: self.decryption_key,
            receive_index,
        };

        Ok((statement, witness))
    }
}
