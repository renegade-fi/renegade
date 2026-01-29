//! Settlement helpers

use alloy::{primitives::Address, signers::local::PrivateKeySigner};
use darkpool_types::settlement_obligation::SettlementObligation;
use renegade_solidity_abi::v2::IDarkpoolV2::FeeRate;
use types_account::{OrderId, balance::Balance, order::Order};
use types_core::{AccountId, Token};

use crate::{tasks::settlement::helpers::error::SettlementError, traits::TaskContext};

pub mod error;
pub mod obligation_bundle;
pub mod ring0;

/// A macro that branches between two parties in a settlement
///
/// This is useful for pulling fields conditionally on the party ID.
macro_rules! branch_party {
    ($party_id:expr, $expr0:expr, $expr1:expr) => {
        match $party_id {
            0 => $expr0,
            1 => $expr1,
            _ => unreachable!("invalid party ID: {}", $party_id),
        }
    };
}
pub(crate) use branch_party;

/// A helper struct for processing settlements
#[derive(Clone)]
pub struct SettlementProcessor {
    /// The task context    
    pub ctx: TaskContext,
}

impl SettlementProcessor {
    /// Create a new settlement processor
    pub fn new(ctx: TaskContext) -> Self {
        Self { ctx }
    }

    // --- Helper Methods --- //

    /// Get the order for an order ID
    async fn get_order(&self, order_id: OrderId) -> Result<Order, SettlementError> {
        self.ctx
            .state
            .get_account_order(&order_id)
            .await?
            .ok_or_else(|| SettlementError::state(format!("order not found: {order_id}")))
    }

    /// Get the input balance for a given party
    async fn get_input_balance(
        &self,
        account_id: AccountId,
        token: Address,
    ) -> Result<Balance, SettlementError> {
        let balance = self.ctx.state.get_account_balance(&account_id, &token).await?;
        balance.ok_or_else(|| {
            SettlementError::state(format!("input balance not found for account {account_id}"))
        })
    }

    /// Get the executor key to sign a settlement
    async fn get_executor_key(&self) -> Result<PrivateKeySigner, SettlementError> {
        self.ctx.state.get_executor_key().map_err(SettlementError::from)
    }

    /// Get the relayer fee for the match
    async fn relayer_fee(&self, base_token: Token) -> Result<FeeRate, SettlementError> {
        let ticker = base_token.get_ticker().ok_or_else(|| {
            SettlementError::state(format!("base token {base_token} has no ticker"))
        })?;

        let rate = self.ctx.state.get_relayer_fee(&ticker)?;
        let recipient = self.ctx.state.get_relayer_fee_addr()?;

        Ok(FeeRate { rate: rate.into(), recipient })
    }

    // --- State Updates --- //

    /// Update the amount remaining on the order for a given party
    pub async fn update_order_amount_in(
        &self,
        order_id: OrderId,
        obligation: &SettlementObligation,
    ) -> Result<(), SettlementError> {
        let mut order = self.get_order(order_id).await?;
        order.decrement_amount_in(obligation.amount_in);

        // Pass None for cursor - this is an internal update, not from an on-chain event
        let waiter = self.ctx.state.update_order(order, None).await?;
        waiter.await.map_err(SettlementError::from)?;
        Ok(())
    }

    /// Update the input balance for a given party
    pub async fn update_input_balance(
        &self,
        account_id: AccountId,
        token: Address,
        obligation: &SettlementObligation,
    ) -> Result<(), SettlementError> {
        let state = &self.ctx.state;
        let mut balance = self.get_input_balance(account_id, obligation.input_token).await?;
        *balance.amount_mut() -= obligation.amount_in;

        // Write the balance back to the state
        // Pass None for cursor - this is an internal update, not from an on-chain event
        let waiter = state.update_account_balance(account_id, balance, None).await?;
        waiter.await.map_err(SettlementError::from)?;
        Ok(())
    }
}
