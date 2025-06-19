//! Pay a relayer fee for a balance

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};

use alloy::rpc::types::TransactionReceipt;
use async_trait::async_trait;
use circuit_types::balance::Balance;
use circuit_types::Amount;
use circuits::zk_circuits::valid_relayer_fee_settlement::{
    SizedValidRelayerFeeSettlementStatement, SizedValidRelayerFeeSettlementWitness,
};
use common::types::proof_bundles::RelayerFeeSettlementBundle;
use common::types::tasks::PayRelayerFeeTaskDescriptor;
use common::types::wallet::Wallet;
use darkpool_client::errors::DarkpoolClientError;
use darkpool_client::DarkpoolClient;
use job_types::network_manager::NetworkManagerQueue;
use job_types::proof_manager::{ProofJob, ProofManagerQueue};
use num_bigint::BigUint;
use renegade_metrics::helpers::record_relayer_fee_settlement;
use serde::Serialize;
use state::error::StateError;
use state::State;
use tracing::instrument;
use util::err_str;

use crate::task_state::StateWrapper;
use crate::traits::{Task, TaskContext, TaskError, TaskState};
use crate::utils::validity_proofs::{
    enqueue_proof_job, find_merkle_path_with_tx, update_wallet_validity_proofs,
};

use super::{ERR_BALANCE_MISSING, ERR_NO_MERKLE_PROOF, ERR_WALLET_MISSING};

/// The name of the task
const TASK_NAME: &str = "pay-relayer-fee";

/// The error message emitted by the task when the fee decryption key is missing
const ERR_FEE_KEY_MISSING: &str = "fee decryption key is missing";

// --------------
// | Task State |
// --------------

/// Defines the state of the relayer fee payment task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum PayRelayerFeeTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is proving fee payment for the balance
    ProvingPayment,
    /// The task is submitting a fee payment transaction
    SubmittingPayment,
    /// The task is finding the new Merkle opening for the wallet
    FindingOpening,
    /// The task is updating validity proofs for the wallet
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl TaskState for PayRelayerFeeTaskState {
    fn commit_point() -> Self {
        PayRelayerFeeTaskState::SubmittingPayment
    }

    fn completed(&self) -> bool {
        matches!(self, PayRelayerFeeTaskState::Completed)
    }
}

impl Display for PayRelayerFeeTaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PayRelayerFeeTaskState::Pending => write!(f, "Pending"),
            PayRelayerFeeTaskState::ProvingPayment => write!(f, "Proving Payment"),
            PayRelayerFeeTaskState::SubmittingPayment => write!(f, "Submitting Payment"),
            PayRelayerFeeTaskState::FindingOpening => write!(f, "Finding Opening"),
            PayRelayerFeeTaskState::UpdatingValidityProofs => write!(f, "Updating Validity Proofs"),
            PayRelayerFeeTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<PayRelayerFeeTaskState> for StateWrapper {
    fn from(value: PayRelayerFeeTaskState) -> Self {
        StateWrapper::PayRelayerFee(value)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the pay fees task
#[derive(Clone, Debug)]
pub enum PayRelayerFeeTaskError {
    /// An error interacting with the darkpool
    Darkpool(String),
    /// An error generating a proof for fee payment
    ProofGeneration(String),
    /// An error generating signatures for update
    Signature(String),
    /// An error interacting with the state
    State(String),
    /// An error updating validity proofs after the fees are settled
    UpdateValidityProofs(String),
}

impl TaskError for PayRelayerFeeTaskError {
    fn retryable(&self) -> bool {
        match self {
            PayRelayerFeeTaskError::Darkpool(_)
            | PayRelayerFeeTaskError::ProofGeneration(_)
            | PayRelayerFeeTaskError::State(_)
            | PayRelayerFeeTaskError::UpdateValidityProofs(_) => true,
            PayRelayerFeeTaskError::Signature(_) => false,
        }
    }
}

impl Display for PayRelayerFeeTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for PayRelayerFeeTaskError {}

impl From<StateError> for PayRelayerFeeTaskError {
    fn from(err: StateError) -> Self {
        PayRelayerFeeTaskError::State(err.to_string())
    }
}

impl From<DarkpoolClientError> for PayRelayerFeeTaskError {
    fn from(error: DarkpoolClientError) -> Self {
        PayRelayerFeeTaskError::Darkpool(error.to_string())
    }
}

// -------------------
// | Task Definition |
// -------------------

/// Defines the pay fees task
pub struct PayRelayerFeeTask {
    /// The balance to pay fees for
    pub mint: BigUint,
    /// The wallet that this task pays fees for
    pub old_sender_wallet: Wallet,
    /// The new wallet after fees have been paid
    pub new_sender_wallet: Wallet,
    /// The wallet that receives this fee payment
    pub old_recipient_wallet: Wallet,
    /// The new recipient wallet after fees have been paid
    pub new_recipient_wallet: Wallet,
    /// The proof of `VALID RELAYER FEE SETTLEMENT` used to pay the protocol fee
    pub proof: Option<RelayerFeeSettlementBundle>,
    /// The transaction receipt of the fee payment
    pub tx: Option<TransactionReceipt>,
    /// The darkpool client used for submitting transactions
    pub darkpool_client: DarkpoolClient,
    /// A hand to the global state
    pub state: State,
    /// The work queue for the proof manager
    pub proof_queue: ProofManagerQueue,
    /// A sender to the network manager's queue
    pub network_sender: NetworkManagerQueue,
    /// The current state of the task
    pub task_state: PayRelayerFeeTaskState,
}

#[async_trait]
impl Task for PayRelayerFeeTask {
    type State = PayRelayerFeeTaskState;
    type Error = PayRelayerFeeTaskError;
    type Descriptor = PayRelayerFeeTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        let state = &ctx.state;
        // Check that the fee decryption key is set, if not we cannot decrypt relayer
        // fees directly
        let key = state.get_fee_key().await?;
        if key.secret_key().is_none() {
            return Err(PayRelayerFeeTaskError::State(ERR_FEE_KEY_MISSING.to_string()));
        }

        let sender_wallet = state
            .get_wallet(&descriptor.wallet_id)
            .await?
            .ok_or_else(|| PayRelayerFeeTaskError::State(ERR_WALLET_MISSING.to_string()))?;
        let recipient_wallet = state
            .get_local_relayer_wallet()
            .await?
            .ok_or_else(|| PayRelayerFeeTaskError::State(ERR_WALLET_MISSING.to_string()))?;

        let (new_sender_wallet, new_recipient_wallet) =
            Self::get_new_wallets(&descriptor.balance_mint, &sender_wallet, &recipient_wallet)?;

        Ok(Self {
            mint: descriptor.balance_mint,
            old_sender_wallet: sender_wallet,
            new_sender_wallet,
            old_recipient_wallet: recipient_wallet,
            new_recipient_wallet,
            proof: None,
            tx: None,
            darkpool_client: ctx.darkpool_client,
            state: ctx.state,
            proof_queue: ctx.proof_queue,
            network_sender: ctx.network_queue,
            task_state: PayRelayerFeeTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(
        task = self.name(),
        state = %self.state(),
        old_sender_wallet = %self.old_sender_wallet.wallet_id,
        new_sender_wallet = %self.new_sender_wallet.wallet_id,
        old_recipient_wallet = %self.old_recipient_wallet.wallet_id,
        new_recipient_wallet = %self.new_recipient_wallet.wallet_id,
    ))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        match self.state() {
            PayRelayerFeeTaskState::Pending => {
                self.task_state = PayRelayerFeeTaskState::ProvingPayment;
            },
            PayRelayerFeeTaskState::ProvingPayment => {
                self.generate_proof().await?;
                self.task_state = PayRelayerFeeTaskState::SubmittingPayment;
            },
            PayRelayerFeeTaskState::SubmittingPayment => {
                self.submit_payment().await?;
                self.task_state = PayRelayerFeeTaskState::FindingOpening;
            },
            PayRelayerFeeTaskState::FindingOpening => {
                self.find_opening().await?;
                self.task_state = PayRelayerFeeTaskState::UpdatingValidityProofs;
            },
            PayRelayerFeeTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = PayRelayerFeeTaskState::Completed;

                // Record metrics for fee settlement
                let mint = &self.mint;
                let amt = self.old_sender_wallet.get_balance(mint).unwrap().relayer_fee_balance;
                record_relayer_fee_settlement(mint, amt)
            },
            PayRelayerFeeTaskState::Completed => panic!("step() called in state Completed"),
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

impl PayRelayerFeeTask {
    /// Generate a proof of `VALID RELAYER FEE SETTLEMENT` for the balance
    async fn generate_proof(&mut self) -> Result<(), PayRelayerFeeTaskError> {
        let (witness, statement) = self.get_witness_statement().await?;
        let job = ProofJob::ValidRelayerFeeSettlement { witness, statement };

        let proof_recv = enqueue_proof_job(job, &self.proof_queue)
            .map_err(PayRelayerFeeTaskError::ProofGeneration)?;

        // Await the proof
        let bundle = proof_recv.await.map_err(err_str!(PayRelayerFeeTaskError::ProofGeneration))?;
        self.proof = Some(bundle.proof.into());
        Ok(())
    }

    /// Submit a `settle_relayer_fee` transaction to the contract
    async fn submit_payment(&mut self) -> Result<(), PayRelayerFeeTaskError> {
        let proof = self.proof.clone().unwrap();

        // Sign the commitment to the new wallet, authorizing the fee receipt
        let new_wallet_comm = self.new_recipient_wallet.get_wallet_share_commitment();
        let sig = self
            .old_recipient_wallet
            .sign_commitment(new_wallet_comm)
            .map_err(err_str!(PayRelayerFeeTaskError::Signature))?;
        let sig_bytes = sig.as_bytes().to_vec();

        let tx = self.darkpool_client.settle_online_relayer_fee(&proof, sig_bytes).await?;
        self.tx = Some(tx);
        Ok(())
    }

    /// Find the new Merkle opening for the user and relayer's wallets
    async fn find_opening(&mut self) -> Result<(), PayRelayerFeeTaskError> {
        // Find the opening for the sender's wallet
        let tx = self.tx.as_ref().unwrap();
        let sender_opening =
            find_merkle_path_with_tx(&self.new_sender_wallet, &self.darkpool_client, tx)?;
        self.new_sender_wallet.merkle_proof = Some(sender_opening);

        // Find the opening for the recipient's wallet
        let recipient_opening =
            find_merkle_path_with_tx(&self.new_recipient_wallet, &self.darkpool_client, tx)?;
        self.new_recipient_wallet.merkle_proof = Some(recipient_opening);

        let waiter1 = self.state.update_wallet(self.new_sender_wallet.clone()).await?;
        let waiter2 = self.state.update_wallet(self.new_recipient_wallet.clone()).await?;
        waiter1.await?;
        waiter2.await?;
        Ok(())
    }

    /// Update the validity proofs for the user's wallet
    ///
    /// The recipient (relayer) wallet does not need to be updated as it holds
    /// no orders
    async fn update_validity_proofs(&self) -> Result<(), PayRelayerFeeTaskError> {
        update_wallet_validity_proofs(
            &self.new_sender_wallet,
            self.proof_queue.clone(),
            self.state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(PayRelayerFeeTaskError::UpdateValidityProofs)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Create a witness and statement for a proof of `VALID RELAYER FEE
    /// SETTLEMENT`
    async fn get_witness_statement(
        &self,
    ) -> Result<
        (SizedValidRelayerFeeSettlementWitness, SizedValidRelayerFeeSettlementStatement),
        PayRelayerFeeTaskError,
    > {
        let sender_wallet = &self.old_sender_wallet;
        let new_sender_wallet = &self.new_sender_wallet;
        let recipient_wallet = &self.old_recipient_wallet;
        let new_recipient_wallet = &self.new_recipient_wallet;

        let sender_public_shares = sender_wallet.blinded_public_shares.clone();
        let sender_private_shares = sender_wallet.private_shares.clone();
        let sender_updated_public_shares = new_sender_wallet.blinded_public_shares.clone();
        let sender_updated_private_shares = new_sender_wallet.private_shares.clone();
        let recipient_public_shares = recipient_wallet.blinded_public_shares.clone();
        let recipient_private_shares = recipient_wallet.private_shares.clone();
        let recipient_updated_public_shares = new_recipient_wallet.blinded_public_shares.clone();
        let recipient_updated_private_shares = new_recipient_wallet.private_shares.clone();

        let sender_opening = sender_wallet
            .merkle_proof
            .clone()
            .ok_or_else(|| PayRelayerFeeTaskError::State(ERR_NO_MERKLE_PROOF.to_string()))?;
        let recipient_opening = recipient_wallet
            .merkle_proof
            .clone()
            .ok_or_else(|| PayRelayerFeeTaskError::State(ERR_NO_MERKLE_PROOF.to_string()))?;

        let recipient_decryption_key =
            self.state.get_fee_key().await?.secret_key().expect("decryption key missing");
        let sender_balance_index = sender_wallet.get_balance_index(&self.mint).unwrap();
        let recipient_balance_index = new_recipient_wallet.get_balance_index(&self.mint).unwrap();

        let statement = SizedValidRelayerFeeSettlementStatement {
            sender_root: sender_opening.compute_root(),
            recipient_root: recipient_opening.compute_root(),
            sender_nullifier: self.old_sender_wallet.get_wallet_nullifier(),
            recipient_nullifier: self.old_recipient_wallet.get_wallet_nullifier(),
            sender_wallet_commitment: self.new_sender_wallet.get_private_share_commitment(),
            recipient_wallet_commitment: self.new_recipient_wallet.get_private_share_commitment(),
            sender_updated_public_shares,
            recipient_updated_public_shares,
            recipient_pk_root: recipient_wallet.key_chain.public_keys.pk_root.clone(),
        };

        let witness = SizedValidRelayerFeeSettlementWitness {
            sender_public_shares,
            sender_private_shares,
            sender_updated_private_shares,
            recipient_public_shares,
            recipient_private_shares,
            recipient_updated_private_shares,
            sender_opening: sender_opening.into(),
            recipient_opening: recipient_opening.into(),
            recipient_decryption_key,
            sender_balance_index,
            recipient_balance_index,
        };

        Ok((witness, statement))
    }

    /// Clone the old wallet and update it to reflect the fee payment
    fn get_new_wallets(
        mint: &BigUint,
        sender_wallet: &Wallet,
        recipient_wallet: &Wallet,
    ) -> Result<(Wallet, Wallet), PayRelayerFeeTaskError> {
        let mut new_sender_wallet = sender_wallet.clone();
        let mut new_recipient_wallet = recipient_wallet.clone();

        let balance = new_sender_wallet
            .get_balance_mut(mint)
            .ok_or_else(|| PayRelayerFeeTaskError::State(ERR_BALANCE_MISSING.to_string()))?;
        let relayer_fee = balance.relayer_fee_balance;

        // Update the sender wallet
        balance.relayer_fee_balance = Amount::from(0u8);
        new_sender_wallet.reblind_wallet();

        // Update the recipient wallet
        new_recipient_wallet
            .add_balance(Balance::new_from_mint_and_amount(mint.clone(), relayer_fee))
            .map_err(err_str!(PayRelayerFeeTaskError::State))?;
        new_recipient_wallet.reblind_wallet();

        Ok((new_sender_wallet, new_recipient_wallet))
    }
}
