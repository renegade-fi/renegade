//! The settle match task
//!
//! Broadly this breaks down into the following steps:
//! - Submit the match transaction
//! - Update the wallet's state
//! - Update the validity proofs for the wallet's orders

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::str::FromStr;

use alloy::rpc::types::TransactionReceipt;
use ark_mpc::PARTY0;
use async_trait::async_trait;
use circuit_types::SizedWalletShare;
use circuit_types::r#match::MatchResult;
use common::types::proof_bundles::ValidMatchSettleBundle;
use common::types::tasks::SettleMatchTaskDescriptor;
use common::types::wallet::Wallet;
use common::types::{
    handshake::HandshakeState, proof_bundles::OrderValidityProofBundle, wallet::WalletIdentifier,
};
use darkpool_client::errors::DarkpoolClientError;
use serde::Serialize;
use state::error::StateError;
use tracing::instrument;

use crate::task_state::StateWrapper;
use crate::traits::{Descriptor, Task, TaskContext, TaskError, TaskState};
use crate::utils::order_states::{record_order_fill, transition_order_settling};
use crate::utils::{
    merkle_path::{find_merkle_path, find_merkle_path_with_tx},
    validity_proofs::update_wallet_validity_proofs,
};

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
            SettleMatchTaskState::Pending => write!(f, "Pending"),
            SettleMatchTaskState::SubmittingMatch => write!(f, "Submitting Match"),
            SettleMatchTaskState::UpdatingState => write!(f, "Updating State"),
            SettleMatchTaskState::UpdatingValidityProofs => write!(f, "Updating Validity Proofs"),
            SettleMatchTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl FromStr for SettleMatchTaskState {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Pending" => Ok(SettleMatchTaskState::Pending),
            "Submitting Match" => Ok(SettleMatchTaskState::SubmittingMatch),
            "Updating State" => Ok(SettleMatchTaskState::UpdatingState),
            "Updating Validity Proofs" => Ok(SettleMatchTaskState::UpdatingValidityProofs),
            "Completed" => Ok(SettleMatchTaskState::Completed),
            _ => Err(format!("invalid {SETTLE_MATCH_TASK_NAME} task state: {s}")),
        }
    }
}

impl Descriptor for SettleMatchTaskDescriptor {}

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
    /// Error interacting with the darkpool client
    Darkpool(String),
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
                | SettleMatchTaskError::Darkpool(_)
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

impl From<DarkpoolClientError> for SettleMatchTaskError {
    fn from(err: DarkpoolClientError) -> Self {
        SettleMatchTaskError::Darkpool(err.to_string())
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
    /// The match result from the matching engine
    pub match_res: MatchResult,
    /// The proof that comes from the collaborative match-settle process
    pub match_bundle: ValidMatchSettleBundle,
    /// The validity proofs submitted by the first party
    pub party0_validity_proof: OrderValidityProofBundle,
    /// The validity proofs submitted by the second party
    pub party1_validity_proof: OrderValidityProofBundle,
    /// The transaction receipt of the match settlement transaction
    pub tx: Option<TransactionReceipt>,
    /// The state of the task
    pub task_state: SettleMatchTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for SettleMatchTask {
    type State = SettleMatchTaskState;
    type Error = SettleMatchTaskError;
    type Descriptor = SettleMatchTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        let SettleMatchTaskDescriptor {
            wallet_id,
            handshake_state,
            match_bundle,
            match_res,
            party0_validity_proof,
            party1_validity_proof,
        } = descriptor;

        Ok(Self {
            wallet_id,
            handshake_state,
            match_res,
            match_bundle,
            party0_validity_proof,
            party1_validity_proof,
            tx: None,
            task_state: SettleMatchTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.state()))]
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
    async fn submit_match(&mut self) -> Result<(), SettleMatchTaskError> {
        // Place the local order in the `SubmittingMatch` state
        transition_order_settling(self.handshake_state.local_order_id, &self.ctx.state)
            .await
            .map_err(SettleMatchTaskError::State)?;

        let tx_submit_res = self
            .ctx
            .darkpool_client
            .process_match_settle(
                &self.party0_validity_proof,
                &self.party1_validity_proof,
                self.match_bundle.clone(),
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

        self.tx = Some(tx_submit_res?);
        Ok(())
    }

    /// Apply the match result to the local wallet, find the wallet's new
    /// Merkle opening, and update the global state
    async fn update_wallet_state(&self) -> Result<(), SettleMatchTaskError> {
        // Find the local wallet that was matched
        let mut wallet = self.get_wallet().await?;

        // Transition the order state to filled if the new volume is zero
        let id = self.handshake_state.local_order_id;
        record_order_fill(
            id,
            &self.match_res,
            self.handshake_state.execution_price,
            &self.ctx.state,
        )
        .await
        .map_err(SettleMatchTaskError::State)?;

        // Update the shares of the wallet
        let (private_shares, blinded_public_shares) = self.get_new_shares().await?;
        wallet.update_from_shares(&private_shares, &blinded_public_shares);

        // Cancel all orders on both nullifiers, await new validity proofs
        let party0_reblind_statement = &self.party0_validity_proof.reblind_proof.statement;
        let party1_reblind_statement = &self.party1_validity_proof.reblind_proof.statement;
        self.ctx.state.nullify_orders(party0_reblind_statement.original_shares_nullifier).await?;
        self.ctx.state.nullify_orders(party1_reblind_statement.original_shares_nullifier).await?;

        // Find the wallet's new Merkle opening
        let opening = if let Some(tx) = self.tx.as_ref() {
            find_merkle_path_with_tx(&wallet, tx, &self.ctx)?
        } else {
            find_merkle_path(&wallet, &self.ctx).await?
        };
        wallet.merkle_proof = Some(opening);

        // Index the updated wallet in global state
        let waiter = self.ctx.state.update_wallet(wallet).await?;
        waiter.await?;
        Ok(())
    }

    /// Update the validity proofs for all orders in the wallet after settlement
    async fn update_validity_proofs(&self) -> Result<(), SettleMatchTaskError> {
        let wallet = self.ctx.state.get_wallet(&self.wallet_id).await?.unwrap();
        update_wallet_validity_proofs(&wallet, &self.ctx)
            .await
            .map_err(SettleMatchTaskError::UpdatingValidityProofs)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the wallet that this settlement task is operating on
    async fn get_wallet(&self) -> Result<Wallet, SettleMatchTaskError> {
        self.ctx
            .state
            .get_wallet(&self.wallet_id)
            .await?
            .ok_or_else(|| SettleMatchTaskError::State(ERR_WALLET_NOT_FOUND.to_string()))
    }

    /// Get the new private and blinded public shares for the wallet after
    /// update
    async fn get_new_shares(
        &self,
    ) -> Result<(SizedWalletShare, SizedWalletShare), SettleMatchTaskError> {
        // Fetch private shares from the validity proof's witness
        let order_id = self.handshake_state.local_order_id;
        let validity_witness =
            self.ctx.state.get_validity_proof_witness(&order_id).await?.ok_or_else(|| {
                SettleMatchTaskError::Missing(ERR_VALIDITY_WITNESS_NOT_FOUND.to_string())
            })?;

        let private_shares =
            validity_witness.reblind_witness.reblinded_wallet_private_shares.clone();

        // Fetch public shares from the match settle proof's statement
        let match_settle_statement = &self.match_bundle.statement;
        let public_shares = if self.handshake_state.role.get_party_id() == PARTY0 {
            match_settle_statement.party0_modified_shares.clone()
        } else {
            match_settle_statement.party1_modified_shares.clone()
        };

        Ok((private_shares, public_shares))
    }
}
