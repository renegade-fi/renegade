//! ERC20 Transfer event handling and subscription management

use std::cmp;

use alloy::{
    primitives::{Address, B256, TxHash},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use circuit_types::Amount;
use darkpool_client::client::erc20::abis::erc20::IERC20;
use futures_util::Stream;
use job_types::matching_engine::MatchingEngineWorkerJob;
use tracing::{info, warn};
use types_account::balance::Balance;
use types_core::{AccountId, get_all_tokens};

use crate::{error::OnChainEventListenerError, executor::OnChainEventListenerExecutor};

/// Error message for balance overflow
const ERR_BALANCE_OVERFLOW: &str = "Balance overflow";

impl OnChainEventListenerExecutor {
    /// Create transfer subscriptions for current tracked owners
    pub(crate) async fn create_transfer_subscriptions(
        &self,
        client: &DynProvider,
    ) -> Result<(impl Stream<Item = Log>, impl Stream<Item = Log>), OnChainEventListenerError> {
        let owners = self.state().get_all_tracked_owners().await?;
        info!("Tracking {} owners", owners.len());

        // Convert owners to topic format for log filtering
        let owner_topics: Vec<B256> = owners.into_iter().map(|addr| addr.into_word()).collect();
        let token_addresses: Vec<Address> =
            get_all_tokens().into_iter().map(|t| t.get_alloy_address()).collect();

        // Build separate filters for from/to since topic positions differ
        let from_filter = Filter::new()
            .address(token_addresses.clone())
            .event_signature(IERC20::Transfer::SIGNATURE_HASH)
            .topic1(owner_topics.clone());
        let to_filter = Filter::new()
            .address(token_addresses)
            .event_signature(IERC20::Transfer::SIGNATURE_HASH)
            .topic2(owner_topics);

        // Subscribe to both streams
        let from_stream = client.subscribe_logs(&from_filter).await?.into_stream();
        let to_stream = client.subscribe_logs(&to_filter).await?.into_stream();

        Ok((from_stream, to_stream))
    }

    /// Handle a Transfer event
    pub(crate) async fn handle_transfer_event(
        &self,
        log: Log,
    ) -> Result<(), OnChainEventListenerError> {
        let token = log.address();
        let Some(tx_hash) = log.transaction_hash else {
            warn!("Transfer event missing transaction hash, skipping");
            return Ok(());
        };

        // Decode the transfer event
        let event = log.log_decode::<IERC20::Transfer>()?;
        let from = event.inner.from;
        let to = event.inner.to;
        info!(
            "Handling ERC20 transfer: token={token:#x}, from={from:#x}, to={to:#x}, tx={tx_hash:#x}"
        );

        // Look up accounts for both parties
        let from_account = self.state().get_account_by_owner(&from).await?;
        let to_account = self.state().get_account_by_owner(&to).await?;

        // Process balance updates for any accounts we manage
        if let Some(account_id) = from_account {
            let orders = self.state().get_orders_with_input_token(&account_id, &token).await?;
            if !orders.is_empty() {
                self.handle_balance_update(account_id, from, token, tx_hash).await?;
            }
        }
        if let Some(account_id) = to_account {
            let orders = self.state().get_orders_with_input_token(&account_id, &token).await?;
            if !orders.is_empty() {
                self.handle_balance_update(account_id, to, token, tx_hash).await?;
            }
        }

        Ok(())
    }

    /// Handle the balance update for an account affected by a transfer event
    async fn handle_balance_update(
        &self,
        account_id: AccountId,
        owner: Address,
        token: Address,
        tx_hash: TxHash,
    ) -> Result<(), OnChainEventListenerError> {
        let amount = self.fetch_usable_amount(token, owner).await?;

        // Get or create balance (returns None if amount == 0 and no record)
        let Some(mut balance) =
            self.get_or_create_balance(account_id, owner, token, amount).await?
        else {
            return Ok(());
        };

        // Update amount and cache
        *balance.amount_mut() = amount;
        self.state().update_matching_engine_for_balance(account_id, &balance).await?;

        // Crash recovery: non-selected nodes wait and recheck
        if !self.should_execute_update(tx_hash).await? {
            self.sleep_for_crash_recovery().await;

            let local_amount = self.fetch_usable_amount(token, owner).await?;
            let Some(mut balance) =
                self.get_or_create_balance(account_id, owner, token, local_amount).await?
            else {
                return Ok(());
            };

            // Already handled by selected node
            if balance.amount() == local_amount {
                return Ok(());
            }

            *balance.amount_mut() = local_amount;
            self.state().update_matching_engine_for_balance(account_id, &balance).await?;
        }

        self.apply_balance_update(account_id, balance, token).await
    }

    /// Fetch usable balance from chain and convert to Amount
    async fn fetch_usable_amount(
        &self,
        token: Address,
        owner: Address,
    ) -> Result<Amount, OnChainEventListenerError> {
        let client = self.darkpool_client();
        let erc20_balance = client.get_erc20_balance(token, owner).await?;
        let permit_allowance = client.get_darkpool_allowance(owner, token).await?;
        let usable = cmp::min(erc20_balance, permit_allowance);
        usable.try_into().map_err(|_| OnChainEventListenerError::State(ERR_BALANCE_OVERFLOW.into()))
    }

    /// Get existing balance or create Ring 0 balance if amount > 0
    ///
    /// Returns None if no balance exists and amount == 0 (nothing to create)
    async fn get_or_create_balance(
        &self,
        account_id: AccountId,
        owner: Address,
        token: Address,
        amount: Amount,
    ) -> Result<Option<Balance>, OnChainEventListenerError> {
        // Try to get existing balance
        if let Some(balance) = self.state().get_account_balance(&account_id, &token).await? {
            return Ok(Some(balance));
        }

        // No existing balance - only create if amount > 0
        if amount == 0 {
            return Ok(None);
        }

        // Create new Ring 0 balance
        let relayer_fee_recipient = self.state().get_relayer_fee_addr()?;
        let balance = Balance::new_ring0(token, owner, relayer_fee_recipient, amount);
        Ok(Some(balance))
    }

    /// Apply balance update: run matching engine jobs and persist
    async fn apply_balance_update(
        &self,
        account_id: AccountId,
        balance: Balance,
        token: Address,
    ) -> Result<(), OnChainEventListenerError> {
        self.run_matching_engine_for_account_and_balance(account_id, token).await?;
        self.state().update_account_balance(account_id, balance).await?.await?;
        Ok(())
    }

    /// Run the matching engine on orders that use the given token as input
    async fn run_matching_engine_for_account_and_balance(
        &self,
        account_id: AccountId,
        token: Address,
    ) -> Result<(), OnChainEventListenerError> {
        // Find all orders using this token as input
        let order_ids = self.state().get_orders_with_input_token(&account_id, &token).await?;

        // Enqueue matching engine jobs for each affected order
        // Note: When private orders (Ring 2/3) are enabled, filter to only enqueue
        // orders that use public balance - private orders aren't affected by ERC20
        // changes
        for order_id in order_ids {
            let job = MatchingEngineWorkerJob::run_internal_engine(account_id, order_id);
            self.config
                .matching_engine_queue
                .clone()
                .send(job)
                .map_err(|e| OnChainEventListenerError::SendMessage(e.to_string()))?;
        }

        Ok(())
    }
}
