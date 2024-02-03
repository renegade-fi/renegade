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

use arbitrum_client::client::ArbitrumClient;
use ark_mpc::PARTY0;
use async_trait::async_trait;
use circuit_types::SizedWalletShare;
use common::types::proof_bundles::MatchBundle;
use common::types::task_descriptors::SettleMatchTaskDescriptor;
use common::types::wallet::Wallet;
use common::types::{
    handshake::HandshakeState, proof_bundles::OrderValidityProofBundle, wallet::WalletIdentifier,
};
use job_types::network_manager::NetworkManagerQueue;
use job_types::proof_manager::ProofManagerQueue;
use serde::Serialize;
use state::error::StateError;
use state::State;

use crate::driver::StateWrapper;
use crate::traits::{Task, TaskContext, TaskError, TaskState};

use super::helpers::{find_merkle_path, update_wallet_validity_proofs};

/// The error message the contract emits when a nullifier has been used
pub(crate) const NULLIFIER_USED_ERROR_MSG: &str = "nullifier already used";
/// The error message emitted when a wallet cannot be found in state
const ERR_WALLET_NOT_FOUND: &str = "wallet not found in global state";
/// The error message emitted when a validity proof witness cannot be found in
/// state
const ERR_VALIDITY_WITNESS_NOT_FOUND: &str = "validity witness not found in global state";

/// The displayable name for the settle match task
const SETTLE_MATCH_TASK_NAME: &str = "settle-match";

// --------------
// | Task State |
// --------------

/// The state of the settle match task
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
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

impl TaskState for SettleMatchTaskState {
    fn commit_point() -> Self {
        SettleMatchTaskState::SubmittingMatch
    }

    fn completed(&self) -> bool {
        matches!(self, SettleMatchTaskState::Completed)
    }
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

// --------------
// | Task Error |
// --------------

/// The error type that this task emits
#[derive(Clone, Debug, Serialize)]
pub enum SettleMatchTaskError {
    /// Error generating a proof
    ProofGeneration(String),
    /// Error sending a message to another local worker
    SendMessage(String),
    /// Error when state is missing for settlement
    Missing(String),
    /// Error interacting with Arbitrum
    Arbitrum(String),
    /// Error updating validity proofs for a wallet
    UpdatingValidityProofs(String),
    /// Error interacting with global state
    State(String),
}

impl TaskError for SettleMatchTaskError {
    fn retryable(&self) -> bool {
        matches!(
            self,
            SettleMatchTaskError::ProofGeneration(_)
                | SettleMatchTaskError::Arbitrum(_)
                | SettleMatchTaskError::State(_)
                | SettleMatchTaskError::UpdatingValidityProofs(_)
        )
    }
}

impl Display for SettleMatchTaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{self:?}")
    }
}

impl Error for SettleMatchTaskError {}

impl From<StateError> for SettleMatchTaskError {
    fn from(err: StateError) -> Self {
        SettleMatchTaskError::State(err.to_string())
    }
}

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
    /// The proof that comes from the collaborative match-settle process
    pub match_bundle: MatchBundle,
    /// The validity proofs submitted by the first party
    pub party0_validity_proof: OrderValidityProofBundle,
    /// The validity proofs submitted by the second party
    pub party1_validity_proof: OrderValidityProofBundle,
    /// The arbitrum client to use for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// A copy of the relayer-global state
    pub global_state: State,
    /// The work queue to add proof management jobs to
    pub proof_queue: ProofManagerQueue,
    /// The state of the task
    pub task_state: SettleMatchTaskState,
}

#[async_trait]
impl Task for SettleMatchTask {
    type State = SettleMatchTaskState;
    type Error = SettleMatchTaskError;
    type Descriptor = SettleMatchTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, context: TaskContext) -> Result<Self, Self::Error> {
        let SettleMatchTaskDescriptor {
            wallet_id,
            handshake_state,
            match_bundle,
            party0_validity_proof,
            party1_validity_proof,
        } = descriptor;

        Ok(Self {
            wallet_id,
            handshake_state,
            match_bundle,
            party0_validity_proof,
            party1_validity_proof,
            arbitrum_client: context.arbitrum_client,
            network_sender: context.network_queue,
            global_state: context.state,
            proof_queue: context.proof_queue,
            task_state: SettleMatchTaskState::Pending,
        })
    }

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
    // --------------
    // | Task Steps |
    // --------------

    /// Submit the match transaction to the contract
    async fn submit_match(&self) -> Result<(), SettleMatchTaskError> {
        let tx_submit_res = self
            .arbitrum_client
            .process_match_settle(
                &self.party0_validity_proof,
                &self.party1_validity_proof,
                &self.match_bundle,
            )
            .await;

        // If the transaction failed because a nullifier was already used, assume that
        // the counterparty already submitted a `match` and move on to
        // settlement
        if let Err(ref tx_rejection) = tx_submit_res
            && tx_rejection.to_string().contains(NULLIFIER_USED_ERROR_MSG)
        {
            return Ok(());
        }

        tx_submit_res.map_err(|e| SettleMatchTaskError::Arbitrum(e.to_string()))
    }

    /// Apply the match result to the local wallet, find the wallet's new
    /// Merkle opening, and update the global state
    async fn update_wallet_state(&self) -> Result<(), SettleMatchTaskError> {
        // Find the wallet that was matched and the new private shares from its current
        // reblind proof
        let mut wallet = self.get_wallet()?;
        let (private_shares, blinded_public_shares) = self.get_new_shares()?;
        wallet.update_from_shares(&private_shares, &blinded_public_shares);

        // Cancel all orders on both nullifiers, await new validity proofs
        let party0_reblind_statement = &self.party0_validity_proof.reblind_proof.statement;
        let party1_reblind_statement = &self.party1_validity_proof.reblind_proof.statement;
        self.global_state.nullify_orders(party0_reblind_statement.original_shares_nullifier)?;
        self.global_state.nullify_orders(party1_reblind_statement.original_shares_nullifier)?;

        // Find the wallet's new Merkle opening
        let opening = find_merkle_path(&wallet, &self.arbitrum_client)
            .await
            .map_err(|err| SettleMatchTaskError::Arbitrum(err.to_string()))?;
        wallet.merkle_proof = Some(opening);

        // Index the updated wallet in global state
        self.global_state.update_wallet(wallet)?.await?;
        Ok(())
    }

    /// Update the validity proofs for all orders in the wallet after settlement
    async fn update_validity_proofs(&self) -> Result<(), SettleMatchTaskError> {
        let wallet = self.global_state.get_wallet(&self.wallet_id)?.unwrap();
        update_wallet_validity_proofs(
            &wallet,
            self.proof_queue.clone(),
            self.global_state.clone(),
            self.network_sender.clone(),
        )
        .await
        .map_err(SettleMatchTaskError::UpdatingValidityProofs)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the wallet that this settlement task is operating on
    fn get_wallet(&self) -> Result<Wallet, SettleMatchTaskError> {
        self.global_state
            .get_wallet(&self.wallet_id)?
            .ok_or_else(|| SettleMatchTaskError::State(ERR_WALLET_NOT_FOUND.to_string()))
    }

    /// Get the new private and blinded public shares for the wallet after
    /// update
    fn get_new_shares(&self) -> Result<(SizedWalletShare, SizedWalletShare), SettleMatchTaskError> {
        // Fetch private shares from the validity proof's witness
        let order_id = self.handshake_state.local_order_id;
        let validity_witness =
            self.global_state.get_validity_proof_witness(&order_id)?.ok_or_else(|| {
                SettleMatchTaskError::Missing(ERR_VALIDITY_WITNESS_NOT_FOUND.to_string())
            })?;

        let private_shares =
            validity_witness.reblind_witness.reblinded_wallet_private_shares.clone();

        // Fetch public shares from the match settle proof's statement
        let match_settle_statement = &self.match_bundle.match_proof.statement;
        let public_shares = if self.handshake_state.role.get_party_id() == PARTY0 {
            match_settle_statement.party0_modified_shares.clone()
        } else {
            match_settle_statement.party1_modified_shares.clone()
        };

        Ok((private_shares, public_shares))
    }
}
