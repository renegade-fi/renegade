//! Redeems a fee into the relayer wallet

use std::{error::Error, fmt::Display};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::{balance::Balance, note::Note};
use circuits::zk_circuits::valid_fee_redemption::{
    SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness,
};
use common::types::{
    merkle::MerkleAuthenticationPath, proof_bundles::FeeRedemptionBundle,
    tasks::RedeemRelayerFeeTaskDescriptor, wallet::Wallet,
};
use job_types::{
    network_manager::NetworkManagerQueue,
    proof_manager::{ProofJob, ProofManagerQueue},
};
use serde::Serialize;
use state::{error::StateError, State};
use tracing::instrument;
use util::err_str;

use crate::{
    driver::StateWrapper,
    helpers::{enqueue_proof_job, find_merkle_path},
    tasks::ERR_NO_MERKLE_PROOF,
    traits::{Task, TaskContext, TaskError, TaskState},
};

use super::lookup_wallet::ERR_WALLET_NOT_FOUND;

/// The name of the task
const TASK_NAME: &str = "redeem-relayer-fee";

// --------------
// | Task State |
// --------------

/// Defines the state of the redeem relayer fee task
#[derive(Clone, Debug, PartialEq, PartialOrd, Eq, Ord, Serialize)]
pub enum RedeemRelayerFeeTaskState {
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

impl TaskState for RedeemRelayerFeeTaskState {
    fn commit_point() -> Self {
        RedeemRelayerFeeTaskState::SubmittingRedemption
    }

    fn completed(&self) -> bool {
        matches!(self, RedeemRelayerFeeTaskState::Completed)
    }
}

impl Display for RedeemRelayerFeeTaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl From<RedeemRelayerFeeTaskState> for StateWrapper {
    fn from(value: RedeemRelayerFeeTaskState) -> Self {
        StateWrapper::RedeemRelayerFee(value)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the redeem relayer fee task
#[derive(Clone, Debug)]
pub enum RedeemRelayerFeeError {
    /// An error interacting with Arbitrum
    Arbitrum(String),
    /// An error generating a proof for fee payment
    ProofGeneration(String),
    /// An error signing the commitment to the new wallet
    Signature(String),
    /// An error interacting with the state
    State(String),
    /// An error updating validity proofs after the fees are settled
    UpdateValidityProofs(String),
}

impl TaskError for RedeemRelayerFeeError {
    fn retryable(&self) -> bool {
        match self {
            RedeemRelayerFeeError::Arbitrum(_)
            | RedeemRelayerFeeError::ProofGeneration(_)
            | RedeemRelayerFeeError::State(_)
            | RedeemRelayerFeeError::UpdateValidityProofs(_) => true,
            RedeemRelayerFeeError::Signature(_) => false,
        }
    }
}

impl Display for RedeemRelayerFeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for RedeemRelayerFeeError {}

impl From<StateError> for RedeemRelayerFeeError {
    fn from(err: StateError) -> Self {
        RedeemRelayerFeeError::State(err.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the redeem relayer fee task
pub struct RedeemRelayerFeeTask {
    /// The note to redeem
    pub note: Note,
    /// The Merkle opening of the note
    pub note_opening: Option<MerkleAuthenticationPath>,
    /// The wallet before the note is settled
    pub old_wallet: Wallet,
    /// The wallet after the note is settled
    pub new_wallet: Wallet,
    /// The proof of `VALID FEE REDEMPTION` used to pay the fee
    pub proof: Option<FeeRedemptionBundle>,
    /// The arbitrum client used for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A handle on the global state
    pub state: State,
    /// The work queue for the proof manager
    pub proof_queue: ProofManagerQueue,
    /// A sender to the network manager's queue
    pub network_sender: NetworkManagerQueue,
    /// The current state of the task
    pub task_state: RedeemRelayerFeeTaskState,
}

#[async_trait]
impl Task for RedeemRelayerFeeTask {
    type State = RedeemRelayerFeeTaskState;
    type Error = RedeemRelayerFeeError;
    type Descriptor = RedeemRelayerFeeTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        let state = &ctx.state;
        let old_wallet = state
            .get_wallet(&descriptor.wallet_id)
            .map_err(err_str!(RedeemRelayerFeeError::State))?
            .ok_or(RedeemRelayerFeeError::State(ERR_WALLET_NOT_FOUND.to_string()))?;

        let new_wallet = Self::get_new_wallet(&descriptor.note, &old_wallet)?;

        Ok(Self {
            note: descriptor.note,
            note_opening: None,
            old_wallet,
            new_wallet,
            proof: None,
            arbitrum_client: ctx.arbitrum_client,
            state: ctx.state,
            proof_queue: ctx.proof_queue,
            network_sender: ctx.network_queue,
            task_state: RedeemRelayerFeeTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = self.name(), state = %self.state()))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        match self.task_state {
            RedeemRelayerFeeTaskState::Pending => {
                self.task_state = RedeemRelayerFeeTaskState::FindingNoteOpening;
            },
            RedeemRelayerFeeTaskState::FindingNoteOpening => {
                self.find_note_opening().await?;
                self.task_state = RedeemRelayerFeeTaskState::ProvingRedemption;
            },
            RedeemRelayerFeeTaskState::ProvingRedemption => {
                self.generate_proof().await?;
                self.task_state = RedeemRelayerFeeTaskState::SubmittingRedemption;
            },
            RedeemRelayerFeeTaskState::SubmittingRedemption => {
                self.submit_redemption().await?;
                self.task_state = RedeemRelayerFeeTaskState::FindingWalletOpening;
            },
            RedeemRelayerFeeTaskState::FindingWalletOpening => {
                self.find_wallet_opening().await?;
                self.task_state = RedeemRelayerFeeTaskState::Completed;
            },
            RedeemRelayerFeeTaskState::Completed => panic!("step() called in `Completed` state"),
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

impl RedeemRelayerFeeTask {
    /// Find the Merkle opening for the note
    async fn find_note_opening(&mut self) -> Result<(), RedeemRelayerFeeError> {
        let note_comm = self.note.commitment();
        let opening = self
            .arbitrum_client
            .find_merkle_authentication_path(note_comm)
            .await
            .map_err(err_str!(RedeemRelayerFeeError::Arbitrum))?;

        self.note_opening = Some(opening);
        Ok(())
    }

    /// Generate a proof of `VALID RELAYER FEE REDEMPTION` for the relayer's
    /// wallet
    async fn generate_proof(&mut self) -> Result<(), RedeemRelayerFeeError> {
        let (statement, witness) = self.get_witness_statement()?;
        let job = ProofJob::ValidFeeRedemption { witness, statement };
        let proof = enqueue_proof_job(job, &self.proof_queue)
            .map_err(err_str!(RedeemRelayerFeeError::ProofGeneration))?;

        // Await the proof
        let bundle = proof.await.map_err(err_str!(RedeemRelayerFeeError::ProofGeneration))?;
        self.proof = Some(bundle.proof.into());

        Ok(())
    }

    /// Submit a `redeem_fee` transaction to the contract
    async fn submit_redemption(&mut self) -> Result<(), RedeemRelayerFeeError> {
        let proof = self.proof.as_ref().unwrap();

        // Sign a commitment to the new wallet after redemption
        let new_wallet_comm = self.new_wallet.get_wallet_share_commitment();
        let sig = self
            .old_wallet
            .sign_commitment(new_wallet_comm)
            .map_err(RedeemRelayerFeeError::Signature)?;

        self.arbitrum_client
            .redeem_fee(proof, sig.to_vec())
            .await
            .map_err(err_str!(RedeemRelayerFeeError::Arbitrum))
    }

    /// Find the opening for the relayer wallet
    async fn find_wallet_opening(&mut self) -> Result<(), RedeemRelayerFeeError> {
        let opening = find_merkle_path(&self.new_wallet, &self.arbitrum_client)
            .await
            .map_err(err_str!(RedeemRelayerFeeError::Arbitrum))?;
        self.new_wallet.merkle_proof = Some(opening);

        self.state.update_wallet(self.new_wallet.clone())?.await?;
        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the new wallet after the note is settled
    fn get_new_wallet(note: &Note, old_wallet: &Wallet) -> Result<Wallet, RedeemRelayerFeeError> {
        let mut new_wallet = old_wallet.clone();
        let bal = Balance::new_from_mint_and_amount(note.mint.clone(), note.amount);
        new_wallet.add_balance(bal).map_err(err_str!(RedeemRelayerFeeError::State))?;
        new_wallet.reblind_wallet();

        Ok(new_wallet)
    }

    /// Get the witness and statement for the proof of `VALID FEE REDEMPTION`
    fn get_witness_statement(
        &self,
    ) -> Result<
        (SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness),
        RedeemRelayerFeeError,
    > {
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
            .ok_or(RedeemRelayerFeeError::State(ERR_NO_MERKLE_PROOF.to_string()))?;
        let note_opening = self.note_opening.clone().unwrap();

        let recipient_key =
            self.state.get_fee_decryption_key().map_err(err_str!(RedeemRelayerFeeError::State))?;
        let receive_index = self.new_wallet.get_balance_index(&self.note.mint).unwrap();

        let statement = SizedValidFeeRedemptionStatement {
            wallet_root: wallet_opening.compute_root(),
            note_root: note_opening.compute_root(),
            wallet_nullifier: self.old_wallet.get_wallet_nullifier(),
            note_nullifier: self.note.nullifier(),
            new_wallet_commitment: self.new_wallet.get_private_share_commitment(),
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
            recipient_key,
            receive_index,
        };

        Ok((statement, witness))
    }
}
