//! Broadly this breaks down into the following steps:
//!     - Build the notes that result from the match and encrypt them
//!     - Submit these notes and the relevant proofs to the contract in a
//!       `match` transaction
//!     - Await transaction finality, then lookup the notes in the commitment
//!       tree
//!     - Build a settlement proof, and submit this to the contract in a
//!       `settle` transaction
//!     - Await finality then update the wallets into the relayer-global state

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::sync::Arc;

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use circuit_types::{balance::Balance, SizedWalletShare};
use common::types::{
    handshake::{HandshakeResult, HandshakeState},
    proof_bundles::OrderValidityProofBundle,
    wallet::WalletIdentifier,
};
use crossbeam::channel::Sender as CrossbeamSender;
use futures::FutureExt;
use gossip_api::gossip::GossipOutbound;
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use renegade_crypto::fields::{scalar_to_biguint, scalar_to_u64};
use serde::Serialize;
use state::RelayerState;
use tokio::sync::{mpsc::UnboundedSender as TokioSender, oneshot};
use tracing::log;

use super::{
    driver::{StateWrapper, Task},
    helpers::{find_merkle_path, update_wallet_validity_proofs},
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
    /// The arbitrum client to use for submitting transactions
    pub arbitrum_client: ArbitrumClient,
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
    /// The task is submitting the match transaction
    SubmittingMatch,
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
    /// Error interacting with Arbitrum
    Arbitrum(String),
    /// Error updating validity proofs for a wallet
    UpdatingValidityProofs(String),
}

impl Display for SettleMatchTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for SettleMatchTaskError {}

#[async_trait]
impl Task for SettleMatchTask {
    type State = SettleMatchTaskState;
    type Error = SettleMatchTaskError;

    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current task state
        match self.state() {
            SettleMatchTaskState::Pending => {
                self.task_state = SettleMatchTaskState::SubmittingMatch
            },

            SettleMatchTaskState::SubmittingMatch => {
                self.submit_match().await?;
                self.task_state = SettleMatchTaskState::UpdatingState;
            },

            SettleMatchTaskState::UpdatingState => {
                self.update_wallet_state().await?;
                self.task_state = SettleMatchTaskState::UpdatingValidityProofs;
            },

            SettleMatchTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = SettleMatchTaskState::Completed;
            },

            SettleMatchTaskState::Completed => {
                unreachable!("step called on completed task")
            },
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
        arbitrum_client: ArbitrumClient,
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
            arbitrum_client,
            network_sender,
            global_state,
            proof_manager_work_queue,
            task_state: SettleMatchTaskState::Pending,
        }
    }

    // --------------
    // | Task Steps |
    // --------------

    /// Submit the match transaction to the contract
    async fn submit_match(&self) -> Result<(), SettleMatchTaskError> {
        let tx_submit_res = self
            .arbitrum_client
            .process_match_settle(
                self.party0_validity_proof.clone(),
                self.party1_validity_proof.clone(),
                self.handshake_result.match_settle_proof.clone(),
            )
            .await;

        // If the transaction failed because a nullifier was already used, assume that
        // the counterparty already submitted a `match` and move on to
        // settlement
        if let Err(ref tx_rejection) = tx_submit_res
            && tx_rejection.to_string().contains(NULLIFIER_USED_ERROR_MSG){
                return Ok(())
            }

        tx_submit_res.map_err(|e| SettleMatchTaskError::Arbitrum(e.to_string()))
    }

    /// Apply the match result to the local wallet, find the wallet's new
    /// Merkle opening, and update the global state
    async fn update_wallet_state(&self) -> Result<(), SettleMatchTaskError> {
        // Cancel all orders on both nullifiers, await new validity proofs
        let party0_reblind_statement = &self.party0_validity_proof.reblind_proof.statement;
        let party1_reblind_statement = &self.party1_validity_proof.reblind_proof.statement;
        self.global_state.nullify_orders(party0_reblind_statement.original_shares_nullifier).await;
        self.global_state.nullify_orders(party1_reblind_statement.original_shares_nullifier).await;

        // Find the wallet that was matched
        let mut wallet = self
            .global_state
            .read_wallet_index()
            .then(|index| async move { index.get_wallet(&self.wallet_id).await })
            .await
            .expect("unable to find wallet in global state");
        wallet.apply_match(&self.handshake_result.match_, &self.handshake_state.local_order_id);

        // Find the wallet's new Merkle opening
        let opening = find_merkle_path(&wallet, &self.arbitrum_client)
            .await
            .map_err(|err| SettleMatchTaskError::Arbitrum(err.to_string()))?;
        wallet.merkle_proof = Some(opening);

        // Reblind the wallet and index the updated wallet in global state
        wallet.reblind_wallet();
        self.global_state.update_wallet(wallet).await;

        Ok(())
    }

    /// Update the validity proofs for all orders in the wallet after settlement
    async fn update_validity_proofs(&self) -> Result<(), SettleMatchTaskError> {
        let wallet =
            self.global_state.read_wallet_index().await.get_wallet(&self.wallet_id).await.unwrap();

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
