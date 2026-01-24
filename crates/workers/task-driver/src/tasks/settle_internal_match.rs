//! Defines a task to settle an internal match

use std::fmt::{Display, Formatter, Result as FmtResult};

use alloy::primitives::Address;
use alloy::signers::local::PrivateKeySigner;
use ark_mpc::{PARTY0, PARTY1, network::PartyId};
use async_trait::async_trait;
use darkpool_client::errors::DarkpoolClientError;
use darkpool_types::settlement_obligation::SettlementObligation;
use renegade_solidity_abi::v2::IDarkpoolV2::{
    self, FeeRate, ObligationBundle, PublicIntentAuthBundle, PublicIntentPermit, SettlementBundle,
    SignatureWithNonce, SignedPermitSingle,
};
use serde::Serialize;
use state::error::StateError;
use tracing::{info, instrument};
use types_account::balance::Balance;
use types_account::{OrderId, order::Order, order_auth::OrderAuth};
use types_core::MatchResult;
use types_core::{AccountId, TimestampedPriceFp};
use types_tasks::SettleInternalMatchTaskDescriptor;
use util::on_chain::get_chain_id;

use crate::hooks::RunMatchingEngineHook;
use crate::{
    hooks::{RefreshAccountHook, TaskHook},
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

/// The task name for the settle internal match task
const SETTLE_INTERNAL_MATCH_TASK_NAME: &str = "settle-internal-match";

/// A helper to branch on party ID
macro_rules! branch_party {
    ($party_id:expr, $expr0:expr, $expr1:expr) => {
        match $party_id {
            0 => $expr0,
            1 => $expr1,
            _ => unreachable!("invalid party ID: {}", $party_id),
        }
    };
}

// --------------
// | Task State |
// --------------

/// Represents the state of the task through its async execution
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettleInternalMatchTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is submitting the transaction
    SubmittingTx,
    /// The task is updating the account state for the parties involved in the
    /// match
    UpdatingState,
    /// The task is completed
    Completed,
}

impl TaskState for SettleInternalMatchTaskState {
    fn commit_point() -> Self {
        SettleInternalMatchTaskState::SubmittingTx
    }

    fn completed(&self) -> bool {
        matches!(self, SettleInternalMatchTaskState::Completed)
    }
}

impl Display for SettleInternalMatchTaskState {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            SettleInternalMatchTaskState::Pending => write!(f, "Pending"),
            SettleInternalMatchTaskState::SubmittingTx => write!(f, "SubmittingTx"),
            SettleInternalMatchTaskState::UpdatingState => write!(f, "UpdatingState"),
            SettleInternalMatchTaskState::Completed => write!(f, "Completed"),
        }
    }
}

impl From<SettleInternalMatchTaskState> for TaskStateWrapper {
    fn from(state: SettleInternalMatchTaskState) -> Self {
        TaskStateWrapper::SettleInternalMatch(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type thrown by the settle internal match task
#[derive(Clone, Debug, thiserror::Error)]
pub enum SettleInternalMatchTaskError {
    /// A darkpool client error
    #[error("darkpool client error: {0}")]
    Darkpool(String),
    /// A signing error
    #[error("signing error: {0}")]
    Signing(String),
    /// Error interacting with global state
    #[error("state error: {0}")]
    State(String),
    /// A miscellaneous error
    #[error("error: {0}")]
    Misc(String),
}

impl SettleInternalMatchTaskError {
    /// Create a signing error
    #[allow(clippy::needless_pass_by_value)]
    pub fn signing<T: ToString>(e: T) -> Self {
        Self::Signing(e.to_string())
    }

    /// Create a state error
    #[allow(clippy::needless_pass_by_value)]
    pub fn state<T: ToString>(e: T) -> Self {
        Self::State(e.to_string())
    }

    /// Create a miscellaneous error
    #[allow(clippy::needless_pass_by_value)]
    pub fn misc<T: ToString>(e: T) -> Self {
        Self::Misc(e.to_string())
    }

    /// Create an order not found error
    pub fn order_not_found(order_id: OrderId) -> Self {
        Self::State(format!("Order not found: {order_id}"))
    }

    /// Create an order auth not found error
    pub fn order_auth_not_found(order_id: OrderId) -> Self {
        Self::State(format!("Order auth not found: {order_id}"))
    }
}

impl TaskError for SettleInternalMatchTaskError {
    fn retryable(&self) -> bool {
        matches!(self, SettleInternalMatchTaskError::State(_))
    }
}

impl From<StateError> for SettleInternalMatchTaskError {
    fn from(e: StateError) -> Self {
        SettleInternalMatchTaskError::State(e.to_string())
    }
}

impl From<DarkpoolClientError> for SettleInternalMatchTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        SettleInternalMatchTaskError::Darkpool(e.to_string())
    }
}

/// A type alias for a result in this task
type Result<T> = std::result::Result<T, SettleInternalMatchTaskError>;

// -------------------
// | Task Definition |
// -------------------

/// Represents a task to settle an internal match
#[derive(Clone)]
pub struct SettleInternalMatchTask {
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
    /// The state of the task's execution
    pub task_state: SettleInternalMatchTaskState,
    /// The context of the task
    pub ctx: TaskContext,
}

#[async_trait]
impl Task for SettleInternalMatchTask {
    type State = SettleInternalMatchTaskState;
    type Error = SettleInternalMatchTaskError;
    type Descriptor = SettleInternalMatchTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self> {
        Ok(Self {
            account_id: descriptor.account_id,
            other_account_id: descriptor.other_account_id,
            order_id: descriptor.order_id,
            other_order_id: descriptor.other_order_id,
            execution_price: descriptor.execution_price,
            match_result: descriptor.match_result,
            task_state: SettleInternalMatchTaskState::Pending,
            ctx,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(task = %self.name(), state = %self.task_state()))]
    async fn step(&mut self) -> Result<()> {
        // Dispatch based on task state
        match self.task_state {
            SettleInternalMatchTaskState::Pending => {
                self.task_state = SettleInternalMatchTaskState::SubmittingTx;
            },
            SettleInternalMatchTaskState::SubmittingTx => {
                self.submit_tx().await?;
                self.task_state = SettleInternalMatchTaskState::UpdatingState;
            },
            SettleInternalMatchTaskState::UpdatingState => {
                self.update_state().await?;
                self.task_state = SettleInternalMatchTaskState::Completed;
            },
            SettleInternalMatchTaskState::Completed => {
                unreachable!("step called on task in Completed state")
            },
        }

        Ok(())
    }

    fn name(&self) -> String {
        SETTLE_INTERNAL_MATCH_TASK_NAME.to_string()
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    // Re-run the matching engine on both orders for recursive fills
    fn success_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let engine_run = RunMatchingEngineHook::new(vec![self.order_id, self.other_order_id]);
        vec![Box::new(engine_run)]
    }

    // Refresh both accounts after a failure
    fn failure_hooks(&self) -> Vec<Box<dyn TaskHook>> {
        let refresh = RefreshAccountHook::new(vec![self.account_id, self.other_account_id]);
        vec![Box::new(refresh)]
    }
}

impl Descriptor for SettleInternalMatchTaskDescriptor {}

// -----------------------
// | Task Implementation |
// -----------------------

impl SettleInternalMatchTask {
    /// Submit the transaction to the contract
    async fn submit_tx(&self) -> Result<()> {
        let obligation_bundle = self.create_obligation_bundle();
        let settlement_bundle0 = self.build_settlement_bundle(PARTY0).await?;
        let settlement_bundle1 = self.build_settlement_bundle(PARTY1).await?;

        // Submit the transaction
        let tx = self
            .ctx
            .darkpool_client
            .settle_match(obligation_bundle, settlement_bundle0, settlement_bundle1)
            .await?;

        info!("Settled match with tx hash: {}", tx.transaction_hash);
        Ok(())
    }

    /// Update the account state for the parties involved in the match
    ///
    /// This involves decreasing the amount remaining on the matched orders and
    /// the input balances.
    ///
    /// The output balances are not updated except by the chain events listener
    /// as we only update balances for amounts approved to the darkpool for
    /// matching.
    async fn update_state(&self) -> Result<()> {
        self.update_state_for_party(PARTY0).await?;
        self.update_state_for_party(PARTY1).await?;
        Ok(())
    }

    /// Update the state for a given party
    async fn update_state_for_party(&self, party_id: PartyId) -> Result<()> {
        self.update_input_balance(party_id).await?;
        self.update_order_amount_in(party_id).await
    }

    /// Update the amount remaining on the order for a given party
    async fn update_order_amount_in(&self, party_id: PartyId) -> Result<()> {
        let obligation = self.get_obligation(party_id)?;
        let mut order = self.get_order(party_id).await?;
        order.decrement_amount_in(obligation.amount_in);

        let waiter = self.ctx.state.update_order(order).await?;
        waiter.await.map_err(SettleInternalMatchTaskError::state)?;
        Ok(())
    }

    /// Update the input balance for a given party
    async fn update_input_balance(&self, party_id: PartyId) -> Result<()> {
        let state = &self.ctx.state;
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let obligation = self.get_obligation(party_id)?;

        let mut balance = self.get_input_balance(party_id, obligation.input_token).await?;
        *balance.amount_mut() -= obligation.amount_in;

        // Write the balance back to the state
        let waiter = state.update_account_balance(account_id, balance).await?;
        waiter.await.map_err(SettleInternalMatchTaskError::state)?;
        Ok(())
    }
}

// -----------
// | Helpers |
// -----------

impl SettleInternalMatchTask {
    // === Bundle Creation === //

    /// Create an obligation bundle for the match
    fn create_obligation_bundle(&self) -> ObligationBundle {
        let obligation1 = self.match_result.party0_obligation.clone();
        let obligation2 = self.match_result.party1_obligation.clone();
        ObligationBundle::new_public(obligation1.into(), obligation2.into())
    }

    /// Build the first party's settlement bundle
    async fn build_settlement_bundle(&self, party_id: PartyId) -> Result<SettlementBundle> {
        let relayer_fee = self.relayer_fee().await?;
        let order = self.get_order(party_id).await?;

        // Get signatures from the executor and user
        let executor = self.get_executor_key().await?;
        let executor_sig = self.build_executor_signature(party_id, &relayer_fee).await?;
        let user_sig = self.get_intent_signature(party_id).await?;

        // Build the intent permit
        let intent_permit = PublicIntentPermit {
            intent: order.intent().clone().into(),
            executor: executor.address(),
        };

        // Build the auth and settlement bundle
        let auth_bundle = PublicIntentAuthBundle {
            intentPermit: intent_permit,
            intentSignature: user_sig,
            executorSignature: executor_sig,
            allowancePermit: SignedPermitSingle::default(),
        };
        Ok(SettlementBundle::public_intent_settlement(auth_bundle, relayer_fee))
    }

    /// Build an executor signature for the match
    async fn build_executor_signature(
        &self,
        party_id: PartyId,
        fee: &FeeRate,
    ) -> Result<SignatureWithNonce> {
        let obligation = self.get_obligation(party_id)?;
        let contract_obligation = IDarkpoolV2::SettlementObligation::from(obligation.clone());

        let chain_id = get_chain_id();
        let signer = self.get_executor_key().await?;
        let sig = contract_obligation
            .create_executor_signature(fee, chain_id, &signer)
            .map_err(SettleInternalMatchTaskError::signing)?;

        Ok(sig)
    }

    // === State Access === //

    /// Get the order for an order ID
    async fn get_order(&self, party_id: PartyId) -> Result<Order> {
        let order_id = branch_party!(party_id, self.order_id, self.other_order_id);
        self.ctx
            .state
            .get_account_order(&order_id)
            .await?
            .ok_or_else(|| SettleInternalMatchTaskError::order_not_found(order_id))
    }

    /// Get the input balance for a given party
    async fn get_input_balance(&self, party_id: PartyId, token: Address) -> Result<Balance> {
        let account_id = branch_party!(party_id, self.account_id, self.other_account_id);
        let balance = self.ctx.state.get_account_balance(&account_id, &token).await?;
        balance.ok_or_else(|| {
            SettleInternalMatchTaskError::state(format!(
                "input balance not found for party {party_id}"
            ))
        })
    }

    /// Get the order authorization for an order ID
    async fn get_intent_signature(&self, party_id: PartyId) -> Result<SignatureWithNonce> {
        let order_id = branch_party!(party_id, self.order_id, self.other_order_id);
        let auth = self
            .ctx
            .state
            .get_order_auth(&order_id)
            .await?
            .ok_or_else(|| SettleInternalMatchTaskError::order_auth_not_found(order_id))?;

        let sig = match auth {
            OrderAuth::PublicOrder { intent_signature } => intent_signature,
            _ => {
                return Err(SettleInternalMatchTaskError::state(format!(
                    "invalid order auth type for party {party_id}"
                )));
            },
        };
        Ok(sig)
    }

    /// Get the executor key to sign the match
    async fn get_executor_key(&self) -> Result<PrivateKeySigner> {
        self.ctx.state.get_executor_key().map_err(SettleInternalMatchTaskError::from)
    }

    /// Get the relayer fee for the match
    async fn relayer_fee(&self) -> Result<FeeRate> {
        let base = self.match_result.base_token();
        let ticker = self.ctx.darkpool_client.get_erc20_ticker(base.get_alloy_address()).await?;

        let rate = self.ctx.state.get_relayer_fee(&ticker)?;
        let recipient = self.ctx.state.get_relayer_fee_addr()?;

        Ok(FeeRate { rate: rate.into(), recipient })
    }

    // === Misc Helpers === //

    /// Get the obligation for a given party
    fn get_obligation(&self, party_id: PartyId) -> Result<&SettlementObligation> {
        let obligation = branch_party!(
            party_id,
            &self.match_result.party0_obligation,
            &self.match_result.party1_obligation
        );
        Ok(obligation)
    }
}
