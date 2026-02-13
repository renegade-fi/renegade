//! Defines a task to settle a match using private settlement
//!
//! Private settlement uses the `IntentAndBalancePrivateSettlement` circuit,
//! which generates a single proof covering both parties simultaneously.
//! This is used when both orders are Ring 2 or Ring 3.

use std::fmt::{Display, Formatter, Result as FmtResult};

use ark_mpc::{PARTY0, PARTY1, network::PartyId};
use async_trait::async_trait;
use darkpool_client::errors::DarkpoolClientError;
use darkpool_types::settlement_obligation::SettlementObligation;
use serde::Serialize;
use state::error::StateError;
use tracing::instrument;
use types_account::OrderId;
use types_account::balance::Balance;
use types_account::order::Order;
use types_core::MatchResult;
use types_core::{AccountId, TimestampedPriceFp};
use types_tasks::SettlePrivateMatchTaskDescriptor;

use crate::hooks::RunMatchingEngineHook;
use crate::tasks::settlement::helpers::error::SettlementError;
use crate::tasks::settlement::helpers::{SettlementProcessor, branch_party};
use crate::tasks::validity_proofs::error::ValidityProofsError;
use crate::tasks::validity_proofs::intent_and_balance::update_intent_and_balance_validity_proof;
use crate::tasks::validity_proofs::output_balance::update_output_balance_validity_proof;
use crate::{
    hooks::{RefreshAccountHook, TaskHook},
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

/// The task name for the settle private match task
const SETTLE_PRIVATE_MATCH_TASK_NAME: &str = "settle-private-match";

// --------------
// | Task State |
// --------------

/// Represents the state of the private match settlement task
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettlePrivateMatchTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is submitting the transaction
    SubmittingTx,
    /// The task is updating the account state for both parties
    UpdatingState,
    /// The task is regenerating validity proofs for both orders
    UpdatingValidityProofs,
    /// The task is completed
    Completed,
}

impl TaskState for SettlePrivateMatchTaskState {
    fn commit_point() -> Self {
        SettlePrivateMatchTaskState::SubmittingTx
    }

    fn completed(&self) -> bool {
        matches!(self, SettlePrivateMatchTaskState::Completed)
    }
}

impl Display for SettlePrivateMatchTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            SettlePrivateMatchTaskState::Pending => write!(f, "Pending"),
            SettlePrivateMatchTaskState::SubmittingTx => write!(f, "SubmittingTx"),
            SettlePrivateMatchTaskState::UpdatingState => write!(f, "UpdatingState"),
            SettlePrivateMatchTaskState::UpdatingValidityProofs => {
                write!(f, "UpdatingValidityProofs")
            },
            SettlePrivateMatchTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<SettlePrivateMatchTaskState> for TaskStateWrapper {
    fn from(state: SettlePrivateMatchTaskState) -> Self {
        TaskStateWrapper::SettlePrivateMatch(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the settle private match task
#[derive(Clone, Debug, thiserror::Error)]
pub enum SettlePrivateMatchTaskError {
    /// A darkpool client error
    #[error("darkpool client error: {0}")]
    Darkpool(String),
    /// A settlement error
    #[error("settlement error: {0}")]
    Settlement(String),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
    /// A validity proof generation error
    #[error("validity proof error: {0}")]
    ValidityProofs(String),
}

impl TaskError for SettlePrivateMatchTaskError {
    fn retryable(&self) -> bool {
        matches!(self, SettlePrivateMatchTaskError::State(_))
    }
}

impl From<SettlementError> for SettlePrivateMatchTaskError {
    fn from(e: SettlementError) -> Self {
        SettlePrivateMatchTaskError::Settlement(e.to_string())
    }
}

impl From<StateError> for SettlePrivateMatchTaskError {
    fn from(e: StateError) -> Self {
        SettlePrivateMatchTaskError::State(e.to_string())
    }
}

impl From<DarkpoolClientError> for SettlePrivateMatchTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        SettlePrivateMatchTaskError::Darkpool(e.to_string())
    }
}

impl From<ValidityProofsError> for SettlePrivateMatchTaskError {
    fn from(e: ValidityProofsError) -> Self {
        SettlePrivateMatchTaskError::ValidityProofs(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, SettlePrivateMatchTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// A task that settles a match using private settlement
///
/// Both parties' data is fed into a single `IntentAndBalancePrivateSettlement`
/// proof. This task is used when both orders are in Ring 2 or Ring 3.
#[derive(Clone)]
pub struct SettlePrivateMatchTask {
    /// The account ID for the initiating order
    pub account_id: AccountId,
    /// The account ID for the counterparty order
    pub other_account_id: AccountId,
    /// The ID of the initiating order
    pub order_id: OrderId,
    /// The ID of the counterparty order
    pub other_order_id: OrderId,
    /// The price at which the match was executed
    pub execution_price: TimestampedPriceFp,
    /// The match result
    pub match_result: MatchResult,
    /// The initiating order after settlement-derived intent updates
    pub updated_order0: Option<Order>,
    /// The counterparty order after settlement-derived intent updates
    pub updated_order1: Option<Order>,
    /// The updated input balance for party 0
    pub updated_input_balance0: Option<Balance>,
    /// The updated input balance for party 1
    pub updated_input_balance1: Option<Balance>,
    /// The updated output balance for party 0
    pub updated_output_balance0: Option<Balance>,
    /// The updated output balance for party 1
    pub updated_output_balance1: Option<Balance>,
    /// The state of the task's execution
    pub task_state: SettlePrivateMatchTaskState,
    /// The settlement processor
    pub processor: SettlementProcessor,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for SettlePrivateMatchTask {
    type State = SettlePrivateMatchTaskState;
    type Error = SettlePrivateMatchTaskError;
    type Descriptor = SettlePrivateMatchTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        let processor = SettlementProcessor::new(ctx.clone());
        Ok(Self {
            account_id: descriptor.account_id,
            other_account_id: descriptor.other_account_id,
            order_id: descriptor.order_id,
            other_order_id: descriptor.other_order_id,
            execution_price: descriptor.execution_price,
            match_result: descriptor.match_result,
            updated_order0: None,
            updated_order1: None,
            updated_input_balance0: None,
            updated_input_balance1: None,
            updated_output_balance0: None,
            updated_output_balance1: None,
            task_state: SettlePrivateMatchTaskState::Pending,
            processor,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        match self.task_state {
            SettlePrivateMatchTaskState::Pending => {
                self.task_state = SettlePrivateMatchTaskState::SubmittingTx;
            },
            SettlePrivateMatchTaskState::SubmittingTx => {
                self.submit_tx().await?;
                self.task_state = SettlePrivateMatchTaskState::UpdatingState;
            },
            SettlePrivateMatchTaskState::UpdatingState => {
                self.update_state().await?;
                self.task_state = SettlePrivateMatchTaskState::UpdatingValidityProofs;
            },
            SettlePrivateMatchTaskState::UpdatingValidityProofs => {
                self.update_validity_proofs().await?;
                self.task_state = SettlePrivateMatchTaskState::Completed;
            },
            SettlePrivateMatchTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        SETTLE_PRIVATE_MATCH_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    // Re-run the matching engine on both orders for recursive fills
    fn success_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let engine_run1 = RunMatchingEngineHook::new(self.account_id, vec![self.order_id]);
        let engine_run2 =
            RunMatchingEngineHook::new(self.other_account_id, vec![self.other_order_id]);
        vec![Box::new(engine_run1), Box::new(engine_run2)]
    }

    // Refresh both accounts after a failure
    fn failure_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let refresh = RefreshAccountHook::new(vec![self.account_id, self.other_account_id]);
        vec![Box::new(refresh)]
    }
}

impl Descriptor for SettlePrivateMatchTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl SettlePrivateMatchTask {
    /// Submit the private settlement transaction and extract Merkle proofs
    ///
    /// Unlike the public settlement task, this builds a single
    /// `IntentAndBalancePrivateSettlement` proof covering both parties, then
    /// splits the result into two `SettlementBundle` values.
    async fn submit_tx(&mut self) -> Result<()> {
        let obligation0 = self.get_obligation(PARTY0)?.clone();
        let obligation1 = self.get_obligation(PARTY1)?.clone();
        let (settlement_bundle0, settlement_bundle1, obligation_bundle) = self
            .processor
            .build_private_fill_calldata_bundle(
                self.order_id,
                self.other_order_id,
                obligation0.clone(),
                obligation1.clone(),
            )
            .await?;

        // Send the transaction
        let receipt = self
            .ctx
            .darkpool_client
            .settle_match(obligation_bundle, settlement_bundle0, settlement_bundle1)
            .await?;

        // Get updated post-settlement intents for both parties
        let order0 = self.processor.build_updated_intent(self.order_id, &obligation0).await?;
        let order1 = self.processor.build_updated_intent(self.other_order_id, &obligation1).await?;
        self.updated_order0 = Some(order0);
        self.updated_order1 = Some(order1);

        // Build updated post-settlement darkpool balances for both parties
        self.build_updated_balances_for_party(PARTY0, &obligation0).await?;
        self.build_updated_balances_for_party(PARTY1, &obligation1).await?;

        // Extract and store post-settlement Merkle proofs
        self.update_merkle_proofs(&receipt).await?;

        Ok(())
    }

    /// Extract and store Merkle proofs for both parties from the settlement
    /// receipt
    async fn update_merkle_proofs(
        &self,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Result<()> {
        let party0_fut = self.update_merkle_proof_for_party(PARTY0, receipt);
        let party1_fut = self.update_merkle_proof_for_party(PARTY1, receipt);
        tokio::try_join!(party0_fut, party1_fut)?;
        Ok(())
    }

    /// Extract and store the Merkle proof for a single party's order and
    /// both input and output balance Merkle proofs
    async fn update_merkle_proof_for_party(
        &self,
        party_id: PartyId,
        receipt: &alloy::rpc::types::TransactionReceipt,
    ) -> Result<()> {
        let order =
            branch_party!(party_id, &self.updated_order0, &self.updated_order1).as_ref().unwrap();
        self.processor.update_intent_merkle_proof_after_match(order, receipt).await?;

        // Both parties use darkpool balances in private settlement
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let input_balance =
            branch_party!(party_id, &self.updated_input_balance0, &self.updated_input_balance1)
                .as_ref()
                .unwrap();
        let output_balance =
            branch_party!(party_id, &self.updated_output_balance0, &self.updated_output_balance1)
                .as_ref()
                .unwrap();

        self.processor
            .update_ring2_balance_merkle_proofs_after_match(
                account_id,
                input_balance,
                output_balance,
                receipt,
            )
            .await?;

        Ok(())
    }

    /// Update the account state for both parties
    ///
    /// Both parties use darkpool balances, so we write the pre-computed
    /// input and output balances to state for each party.
    async fn update_state(&self) -> Result<()> {
        let party0_fut = self.update_state_for_party(PARTY0);
        let party1_fut = self.update_state_for_party(PARTY1);
        tokio::try_join!(party0_fut, party1_fut)?;
        Ok(())
    }

    /// Update the state for a given party
    async fn update_state_for_party(&self, party_id: PartyId) -> Result<()> {
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let obligation = self.get_obligation(party_id)?;
        let order =
            branch_party!(party_id, &self.updated_order0, &self.updated_order1).clone().unwrap();

        let updated_balances = self.get_updated_balances(party_id);
        self.processor
            .update_balances_after_match(account_id, &order, obligation, updated_balances)
            .await?;

        self.processor.update_order_after_match(order).await?;
        Ok(())
    }

    /// Regenerate validity proofs for both orders after settlement
    ///
    /// Both parties use `INTENT AND BALANCE VALIDITY` and
    /// `OUTPUT BALANCE VALIDITY` proofs (same as Ring 2).
    async fn update_validity_proofs(&self) -> Result<()> {
        let party0_fut = self.update_validity_proofs_for_party(PARTY0);
        let party1_fut = self.update_validity_proofs_for_party(PARTY1);
        tokio::try_join!(party0_fut, party1_fut)?;
        Ok(())
    }

    /// Regenerate the validity proofs for a single party's order
    async fn update_validity_proofs_for_party(&self, party_id: PartyId) -> Result<()> {
        let order_id = branch_party!(party_id, self.order_id, self.other_order_id);
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);

        let (intent_sig, out_balance_sig) =
            self.processor.get_renegade_settled_auth(order_id).await?;

        update_intent_and_balance_validity_proof(account_id, order_id, intent_sig, &self.ctx)
            .await?;

        update_output_balance_validity_proof(
            account_id,
            order_id,
            out_balance_sig,
            false, // force
            &self.ctx,
        )
        .await?;

        Ok(())
    }
}

// -----------
// | Helpers |
// -----------

impl SettlePrivateMatchTask {
    /// Get the pre-computed updated balances for a party, if any
    ///
    /// Returns `Some((input, output))` for parties whose darkpool balances
    /// were pre-computed (always the case in private settlement).
    fn get_updated_balances(&self, party_id: PartyId) -> Option<(Balance, Balance)> {
        let input =
            branch_party!(party_id, &self.updated_input_balance0, &self.updated_input_balance1)
                .clone();
        let output =
            branch_party!(party_id, &self.updated_output_balance0, &self.updated_output_balance1)
                .clone();
        input.zip(output)
    }

    /// Get the obligation for a given party
    fn get_obligation(&self, party_id: PartyId) -> Result<&SettlementObligation> {
        let obligation = branch_party!(
            party_id,
            &self.match_result.party0_obligation,
            &self.match_result.party1_obligation
        );
        Ok(obligation)
    }

    /// Build updated input and output balances for a party
    ///
    /// Both parties in a private settlement use darkpool balances, so this
    /// always computes updated balances (unlike the internal match task
    /// which skips this for Ring 0/1).
    async fn build_updated_balances_for_party(
        &mut self,
        party_id: PartyId,
        obligation: &SettlementObligation,
    ) -> Result<()> {
        let order =
            branch_party!(party_id, &self.updated_order0, &self.updated_order1).as_ref().unwrap();
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);

        let input_balance =
            self.processor.build_updated_input_balance(account_id, obligation).await?;
        let output_balance = self
            .processor
            .build_updated_output_balance(account_id, order, obligation, true /* apply_fees */)
            .await?;

        match party_id {
            PARTY0 => {
                self.updated_input_balance0 = Some(input_balance);
                self.updated_output_balance0 = Some(output_balance);
            },
            PARTY1 => {
                self.updated_input_balance1 = Some(input_balance);
                self.updated_output_balance1 = Some(output_balance);
            },
            _ => unreachable!("invalid party ID: {party_id}"),
        }

        Ok(())
    }
}
