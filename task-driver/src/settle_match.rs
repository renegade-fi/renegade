//! Broadly this breaks down into the following steps:
//!     - Build the notes that result from the match and encrypt them
//!     - Submit these notes and the relevant proofs to the contract in a `match` transaction
//!     - Await transaction finality, then lookup the notes in the commitment tree
//!     - Build a settlement proof, and submit this to the contract in a `settle` transaction
//!     - Await finality then update the wallets into the relayer-global state

use std::fmt::{Display, Formatter, Result as FmtResult};

use async_trait::async_trait;
use circuit_types::{balance::Balance, traits::LinkableType, SizedWalletShare};
use circuits::zk_circuits::valid_settle::{SizedValidSettleStatement, SizedValidSettleWitness};
use common::types::{
    handshake::{HandshakeResult, HandshakeState},
    proof_bundles::{OrderValidityProofBundle, ValidSettleBundle},
    wallet::WalletIdentifier,
};
use crossbeam::channel::Sender as CrossbeamSender;
use gossip_api::gossip::GossipOutbound;
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use renegade_crypto::fields::{scalar_to_biguint, scalar_to_u64, starknet_felt_to_biguint};
use serde::Serialize;
use starknet_client::client::StarknetClient;
use state::RelayerState;
use tokio::sync::{mpsc::UnboundedSender as TokioSender, oneshot};
use tracing::log;

use super::{
    driver::{StateWrapper, Task},
    helpers::{apply_match_to_wallets, find_merkle_path, update_wallet_validity_proofs},
};

/// The error message the contract emits when a nullifier has been used
pub(crate) const NULLIFIER_USED_ERROR_MSG: &str = "nullifier already used";

/// The party ID of the first party
const PARTY0: u64 = 0;
/// The party ID of the second party
const PARTY1: u64 = 1;
/// The match direction in which the first party buys the base
const PARTY0_BUYS_BASE: u64 = 0;
/// The match direction in which the second party buys the base
const PARTY1_BUYS_BASE: u64 = 1;
/// The displayable name for the settle match task
const SETTLE_MATCH_TASK_NAME: &str = "settle-match";

// -------------------
// | Task Definition |
// -------------------

/// Describes the settle task
pub struct SettleMatchTask {
    /// The ID of the wallet that the local node matched an order from
    pub wallet_id: WalletIdentifier,
    /// The state entry from the handshake manager that parameterizes the
    /// match process
    pub handshake_state: HandshakeState,
    /// The result of the match process
    pub handshake_result: Box<HandshakeResult>,
    /// The validity proofs submitted by the first party
    pub party0_validity_proof: OrderValidityProofBundle,
    /// The validity proofs submitted by the second party
    pub party1_validity_proof: OrderValidityProofBundle,
    /// The starknet client to use for submitting transactions
    pub starknet_client: StarknetClient,
    /// A sender to the network manager's work queue
    pub network_sender: TokioSender<GossipOutbound>,
    /// A copy of the relayer-global state
    pub global_state: RelayerState,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The state of the task
    pub task_state: SettleMatchTaskState,
}

/// The state of the settle match task
#[derive(Clone, Debug, Serialize)]
#[allow(clippy::large_enum_variant)]
pub enum SettleMatchTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is proving `VALID SETTLE`
    ProvingSettle,
    /// The task is submitting the match transaction
    SubmittingMatch {
        /// The proof of `VALID SETTLE` given in the last step
        proof: ValidSettleBundle,
    },
    /// The task is updating the wallet's state and Merkle proof
    UpdatingState,
    /// The task is updating order proofs after the settled walled is confirmed
    UpdatingValidityProofs,
    /// The task has finished
    Completed,
}

impl From<SettleMatchTaskState> for StateWrapper {
    fn from(state: SettleMatchTaskState) -> Self {
        StateWrapper::SettleMatch(state)
    }
}

/// Display implementation that removes variant fields
impl Display for SettleMatchTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            SettleMatchTaskState::SubmittingMatch { .. } => write!(f, "SubmittingMatch"),
            _ => write!(f, "{self:?}"),
        }
    }
}

/// The error type that this task emits
#[derive(Clone, Debug, Serialize)]
pub enum SettleMatchTaskError {
    /// Error generating a proof
    ProofGeneration(String),
    /// Error sending a message to another local worker
    SendMessage(String),
    /// Error interacting with Starknet
    StarknetClient(String),
    /// Error updating validity proofs for a wallet
    UpdatingValidityProofs(String),
}

impl Display for SettleMatchTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

#[async_trait]
impl Task for SettleMatchTask {
    type State = SettleMatchTaskState;
    type Error = SettleMatchTaskError;

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current task state
        match self.state() {
            SettleMatchTaskState::Pending => self.task_state = SettleMatchTaskState::ProvingSettle,

            SettleMatchTaskState::ProvingSettle => {
                let proof = self.prove_settle().await?;
                self.task_state = SettleMatchTaskState::SubmittingMatch { proof }
            }

            SettleMatchTaskState::SubmittingMatch { proof } => {
                self.submit_match(proof).await?;
                self.task_state = SettleMatchTaskState::UpdatingState;
            }

            SettleMatchTaskState::UpdatingState => {
                self.update_wallet_state().await?;
                self.task_state = SettleMatchTaskState::UpdatingValidityProofs;
            }

            SettleMatchTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = SettleMatchTaskState::Completed;
            }

            SettleMatchTaskState::Completed => {
                unreachable!("step called on completed task")
            }
        }

        Ok(())
    }

    fn name(&self) -> String {
        SETTLE_MATCH_TASK_NAME.to_string()
    }

    fn completed(&self) -> bool {
        matches!(self.state(), SettleMatchTaskState::Completed)
    }

    fn state(&self) -> SettleMatchTaskState {
        self.task_state.clone()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl SettleMatchTask {
    /// Constructor
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        handshake_state: HandshakeState,
        handshake_result: Box<HandshakeResult>,
        party0_validity_proof: OrderValidityProofBundle,
        party1_validity_proof: OrderValidityProofBundle,
        starknet_client: StarknetClient,
        network_sender: TokioSender<GossipOutbound>,
        global_state: RelayerState,
        proof_manager_work_queue: CrossbeamSender<ProofManagerJob>,
    ) -> Self {
        let wallet_id = global_state
            .read_wallet_index()
            .await
            .get_wallet_for_order(&handshake_state.local_order_id)
            .expect("could not find wallet for local matched order");

        Self {
            wallet_id,
            handshake_state,
            handshake_result,
            party0_validity_proof,
            party1_validity_proof,
            starknet_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_state: SettleMatchTaskState::Pending,
        }
    }

    /// Apply the match to the wallets and prove `VALID SETTLE`
    async fn prove_settle(&self) -> Result<ValidSettleBundle, SettleMatchTaskError> {
        // Modify the secret shares
        let mut party0_modified_shares: SizedWalletShare = self
            .handshake_result
            .party0_reblinded_shares
            .clone()
            .to_base_type();
        let mut party1_modified_shares: SizedWalletShare = self
            .handshake_result
            .party1_reblinded_shares
            .clone()
            .to_base_type();
        let party0_commit_proof = self.party0_validity_proof.commitment_proof.clone();
        let party1_commit_proof = self.party1_validity_proof.commitment_proof.clone();

        apply_match_to_wallets(
            &mut party0_modified_shares,
            &mut party1_modified_shares,
            &party0_commit_proof,
            &party1_commit_proof,
            &self.handshake_result.match_,
        );

        // Construct a witness and statement
        let witness = SizedValidSettleWitness {
            match_res: self.handshake_result.match_.clone(),
            party0_public_shares: self.handshake_result.party0_reblinded_shares.clone(),
            party1_public_shares: self.handshake_result.party1_reblinded_shares.clone(),
        };
        let statement = SizedValidSettleStatement {
            party0_modified_shares,
            party1_modified_shares,
            party0_send_balance_index: party0_commit_proof.statement.balance_send_index,
            party0_receive_balance_index: party0_commit_proof.statement.balance_receive_index,
            party0_order_index: party0_commit_proof.statement.order_index,
            party1_send_balance_index: party1_commit_proof.statement.balance_send_index,
            party1_receive_balance_index: party1_commit_proof.statement.balance_receive_index,
            party1_order_index: party1_commit_proof.statement.order_index,
        };

        // Dispatch a job to the proof manager
        let (proof_sender, proof_receiver) = oneshot::channel();
        self.proof_manager_work_queue
            .send(ProofManagerJob {
                response_channel: proof_sender,
                type_: ProofJob::ValidSettle { witness, statement },
            })
            .map_err(|err| SettleMatchTaskError::SendMessage(err.to_string()))?;

        // Await a response
        proof_receiver
            .await
            .map(|bundle| bundle.into())
            .map_err(|err| SettleMatchTaskError::ProofGeneration(err.to_string()))
    }

    /// Submit the match transaction to the contract
    async fn submit_match(&self, proof: ValidSettleBundle) -> Result<(), SettleMatchTaskError> {
        let party0_reblind_proof = &self.party0_validity_proof.reblind_proof.statement;
        let party1_reblind_proof = &self.party1_validity_proof.reblind_proof.statement;

        let tx_submit_res = self
            .starknet_client
            .submit_match(
                party0_reblind_proof.original_shares_nullifier,
                party1_reblind_proof.original_shares_nullifier,
                party0_reblind_proof.reblinded_private_share_commitment,
                party1_reblind_proof.reblinded_private_share_commitment,
                proof.statement.party0_modified_shares.clone(),
                proof.statement.party1_modified_shares.clone(),
                self.party0_validity_proof.clone(),
                self.party1_validity_proof.clone(),
                self.handshake_result.match_proof.clone(),
                proof,
            )
            .await;

        // If the transaction failed because a nullifier was already used, assume that the counterparty
        // already submitted a `match` and move on to settlement
        if let Err(ref tx_rejection) = tx_submit_res
            && tx_rejection.to_string().contains(NULLIFIER_USED_ERROR_MSG){
                return Ok(())
            }

        let tx_hash =
            tx_submit_res.map_err(|err| SettleMatchTaskError::StarknetClient(err.to_string()))?;

        log::info!("tx hash: 0x{:x}", starknet_felt_to_biguint(&tx_hash));
        self.starknet_client
            .poll_transaction_completed(tx_hash)
            .await
            .map_err(|err| SettleMatchTaskError::StarknetClient(err.to_string()))?;

        // If the transaction was successful, cancel all orders on both nullifiers, await new validity proofs
        self.global_state
            .nullify_orders(party0_reblind_proof.original_shares_nullifier)
            .await;
        self.global_state
            .nullify_orders(party1_reblind_proof.original_shares_nullifier)
            .await;

        Ok(())
    }

    /// Apply the match result to the local wallet, find the wallet's new
    /// Merkle opening, and update the global state
    async fn update_wallet_state(&self) -> Result<(), SettleMatchTaskError> {
        // Find the wallet that was matched
        let mut wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&self.wallet_id)
            .await
            .expect("unable to find wallet in global state");

        // True if the local party buys the base mint in the match
        let local_party_id = self.handshake_state.role.get_party_id();
        let match_direction = scalar_to_u64(&self.handshake_result.match_.direction.val);
        let local_buys_base = (local_party_id == PARTY0 && match_direction == PARTY0_BUYS_BASE)
            || (local_party_id == PARTY1 && match_direction == PARTY1_BUYS_BASE);

        let match_res = &self.handshake_result.match_;
        let (send_amount, send_mint, receive_amount, receive_mint) = if local_buys_base {
            (
                scalar_to_u64(&match_res.quote_amount.val),
                scalar_to_biguint(&match_res.quote_mint.val),
                scalar_to_u64(&match_res.base_amount.val),
                scalar_to_biguint(&match_res.base_mint.val),
            )
        } else {
            (
                scalar_to_u64(&match_res.base_amount.val),
                scalar_to_biguint(&match_res.base_mint.val),
                scalar_to_u64(&match_res.quote_amount.val),
                scalar_to_biguint(&match_res.quote_mint.val),
            )
        };
        let fill_size = scalar_to_u64(&self.handshake_result.match_.base_amount.val);

        // Update the balances and orders
        wallet.balances.get_mut(&send_mint).unwrap().amount -= send_amount;
        wallet
            .balances
            .entry(receive_mint.clone())
            .or_insert_with(|| Balance {
                mint: receive_mint,
                amount: 0u64,
            })
            .amount += receive_amount;
        wallet
            .orders
            .get_mut(&self.handshake_state.local_order_id)
            .unwrap()
            .amount -= fill_size;

        // Reblind the wallet
        wallet.reblind_wallet();

        // Find the wallet's new Merkle opening
        let opening = find_merkle_path(&wallet, &self.starknet_client)
            .await
            .map_err(|err| SettleMatchTaskError::StarknetClient(err.to_string()))?;
        wallet.merkle_proof = Some(opening);

        // Index the updated wallet in global state
        self.global_state.update_wallet(wallet).await;

        Ok(())
    }

    /// Update the validity proofs for all orders in the wallet after settlement
    async fn update_validity_proofs(&self) -> Result<(), SettleMatchTaskError> {
        let wallet = self
            .global_state
            .read_wallet_index()
            .await
            .get_wallet(&self.wallet_id)
            .await
            .unwrap();

        update_wallet_validity_proofs(
            &wallet,
            self.proof_manager_work_queue.clone(),
            self.global_state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(SettleMatchTaskError::UpdatingValidityProofs)
    }
}
