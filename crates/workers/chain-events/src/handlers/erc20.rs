//! ERC20 Transfer event handling and subscription management

use alloy::{
    primitives::{Address, B256, TxHash},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use circuit_types::{Amount, schnorr::SchnorrPublicKey};
use constants::Scalar;
use darkpool_client::client::erc20::abis::erc20::IERC20;
use darkpool_types::{balance::DarkpoolBalance, state_wrapper::StateWrapper};
use futures_util::{
    StreamExt,
    stream::{self, LocalBoxStream},
};
use job_types::matching_engine::MatchingEngineWorkerJob;
use renegade_solidity_abi::v2::relayer_types::u256_to_u128;
use tracing::{debug, info, warn};
use types_account::balance::{Balance, BalanceLocation};
use types_core::{AccountId, get_all_tokens};

use crate::{error::OnChainEventListenerError, executor::OnChainEventListenerExecutor};

/// Boxed local stream type for chain event log subscriptions.
type LogStream = LocalBoxStream<'static, Log>;
impl OnChainEventListenerExecutor {
    /// Create transfer subscriptions for current tracked owners
    pub(crate) async fn create_transfer_subscriptions(
        &self,
        client: &DynProvider,
    ) -> Result<(LogStream, LogStream), OnChainEventListenerError> {
        let owners = self.get_tracked_owners();
        info!("Tracking {} owners", owners.len());

        // Convert owners to topic format for log filtering
        let owner_topics: Vec<B256> = owners.into_iter().map(|addr| addr.into_word()).collect();
        if owner_topics.is_empty() {
            info!("No tracked owners; skipping ERC20 transfer subscriptions");
            return Ok((stream::empty().boxed_local(), stream::empty().boxed_local()));
        }

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
        let from_stream = client.subscribe_logs(&from_filter).await?.into_stream().boxed_local();
        let to_stream = client.subscribe_logs(&to_filter).await?.into_stream().boxed_local();

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
        debug!(
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
    pub(crate) async fn handle_balance_update(
        &self,
        account_id: AccountId,
        owner: Address,
        token: Address,
        tx_hash: TxHash,
    ) -> Result<(), OnChainEventListenerError> {
        let amount = self.get_usable_balance(token, owner).await?;

        // Get or create balance (returns None if amount == 0 and no record)
        let Some(mut balance) =
            self.get_or_create_balance(account_id, owner, token, amount).await?
        else {
            return Ok(());
        };

        // Update amount and cache
        *balance.amount_mut() = amount;
        self.state().update_matching_engine_for_balance(account_id, &balance).await?;

        // Non-selected nodes wait for the primary, then verify and apply if needed
        if !self.should_execute_update(tx_hash).await? {
            self.sleep_for_crash_recovery().await;

            let local_amount = self.get_usable_balance(token, owner).await?;
            let Some(mut local_balance) =
                self.get_or_create_balance(account_id, owner, token, local_amount).await?
            else {
                return Ok(());
            };

            // Primary already applied the update
            if local_balance.amount() == local_amount {
                return Ok(());
            }

            *local_balance.amount_mut() = local_amount;
            self.state().update_matching_engine_for_balance(account_id, &local_balance).await?;
            return self.apply_balance_update(account_id, local_balance, token).await;
        }

        self.apply_balance_update(account_id, balance, token).await
    }

    /// Fetch the current usable balance from chain for an owner/token pair.
    async fn get_usable_balance(
        &self,
        token: Address,
        owner: Address,
    ) -> Result<Amount, OnChainEventListenerError> {
        let usable_u256 = self.darkpool_client().get_erc20_usable_balance(token, owner).await?;
        Ok(u256_to_u128(usable_u256))
    }

    /// Get existing balance or create Ring 0 balance if amount > 0
    ///
    /// Callers must verify an order exists for this token before calling.
    /// If amount > 0, we create a balance to make the order matchable.
    async fn get_or_create_balance(
        &self,
        account_id: AccountId,
        owner: Address,
        token: Address,
        amount: Amount,
    ) -> Result<Option<Balance>, OnChainEventListenerError> {
        // Try to get existing balance
        if let Some(balance) =
            self.state().get_account_balance(&account_id, &token, BalanceLocation::EOA).await?
        {
            return Ok(Some(balance));
        }

        // No existing balance - only create if amount > 0
        if amount == 0 {
            return Ok(None);
        }

        // Create new Ring 0 balance
        // TODO: When Ring 2/3 orders are enabled, gate creation
        let relayer_fee_recipient = self.state().get_relayer_fee_addr()?;
        let balance = create_ring0_balance(token, owner, relayer_fee_recipient, amount);
        Ok(Some(balance))
    }

    /// Persist balance to state and enqueue matching engine jobs
    async fn apply_balance_update(
        &self,
        account_id: AccountId,
        balance: Balance,
        token: Address,
    ) -> Result<(), OnChainEventListenerError> {
        self.state().update_account_balance(account_id, balance).await?.await?;
        self.run_matching_engine_for_account_and_balance(account_id, token).await?;
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

/// Create a ring 0 balance from a usable balance
///
/// We mock the authority and share/recovery stream seeds since Ring 0
/// doesn't use secret sharing
fn create_ring0_balance(
    mint: Address,
    owner: Address,
    relayer_fee_recipient: Address,
    amount: Amount,
) -> Balance {
    let mock_authority = SchnorrPublicKey::default();
    let bal = DarkpoolBalance::new(mint, owner, relayer_fee_recipient, mock_authority)
        .with_amount(amount);

    let share_stream_seed = Scalar::zero();
    let recovery_stream_seed = Scalar::zero();
    let state_wrapper = StateWrapper::new(bal, share_stream_seed, recovery_stream_seed);
    Balance::new_eoa(state_wrapper)
}
