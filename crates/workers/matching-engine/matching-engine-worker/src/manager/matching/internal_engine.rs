//! Defines logic for running the internal matching engine on a given order

use circuit_types::Amount;
use matching_engine_core::SuccessfulMatch;
use tracing::{error, info, instrument, warn};
use types_account::order::PrivacyRing;
use types_account::{MatchingPoolName, OrderId, order::Order};
use types_core::AccountId;
use types_tasks::{
    SettleInternalMatchTaskDescriptor, SettlePrivateMatchTaskDescriptor, TaskDescriptor,
};

use crate::{error::MatchingEngineError, executor::MatchingEngineExecutor};

// ------------------------
// | Matching Engine Impl |
// ------------------------

impl MatchingEngineExecutor {
    /// Run the internal matching engine on the given order
    ///
    /// TODO: This could be optimized by indexing orders by asset pairs in the
    /// global state, but this would require further denormalizing the order
    /// book index. We will hold off on this optimization until we either:
    ///     1. Determine this code path to be a bottleneck
    ///     2. Have a better state management abstraction that makes
    ///        denormalization easier
    #[instrument(name = "run_internal_matching_engine", skip_all)]
    pub async fn run_internal_matching_engine(
        &self,
        account_id: AccountId,
        order_id: OrderId,
    ) -> Result<(), MatchingEngineError> {
        info!("Running internal matching engine on order {order_id}");
        // Lookup the order, matchable amount, and matching pool
        let (order, matchable_amount) = self.fetch_order_and_matchable_amount(&order_id).await?;
        let matching_pool = self.fetch_matching_pool(&order_id).await?;

        // Check if either asset in the pair is disabled for matching
        let pair = order.pair();
        if self.is_asset_disabled(&pair.in_token) || self.is_asset_disabled(&pair.out_token) {
            warn!("Asset disabled for matching, skipping internal matching engine for {order_id}");
            return Ok(());
        }

        // Find a match
        let res = self.find_internal_match(account_id, &order, matchable_amount, matching_pool)?;
        let successful_match = match res {
            Some(match_res) => match_res,
            None => {
                info!("No internal matches found for {order_id:?}");
                return Ok(());
            },
        };

        // TODO: maybe iteratively attempt to find a match and blacklist an order if
        // settlement fails?
        let other_id = successful_match.other_order_id;
        match self.try_settle_match(order_id, successful_match).await {
            Ok(()) => {
                // Stop matching if a match was found
                return Ok(());
            },
            Err(e) => {
                error!("internal match settlement failed for {} x {}: {e}", other_id, order_id,);

                // Check whether matching should continue
                if !self.order_still_valid(&order_id, &order, matchable_amount).await? {
                    info!("account has changed, stopping internal matching engine...");
                    return Ok(());
                }
            },
        }

        Ok(())
    }

    /// Try a match and settle it if the two orders cross
    async fn try_settle_match(
        &self,
        user_order: OrderId,
        match_result: SuccessfulMatch,
    ) -> Result<(), MatchingEngineError> {
        // Lookup account IDs and order rings for both orders
        let account_id = self.get_account_id_for_order(&user_order).await?;
        let other_account_id = self.get_account_id_for_order(&match_result.other_order_id).await?;

        let order0_ring = self.get_order_ring(&user_order).await?;
        let order1_ring = self.get_order_ring(&match_result.other_order_id).await?;
        let use_private = PrivacyRing::supports_private_settlement(order0_ring, order1_ring);

        let descriptor = if use_private {
            TaskDescriptor::from(SettlePrivateMatchTaskDescriptor {
                account_id,
                other_account_id,
                order_id: user_order,
                other_order_id: match_result.other_order_id,
                execution_price: match_result.price,
                match_result: match_result.match_result,
            })
        } else {
            TaskDescriptor::from(SettleInternalMatchTaskDescriptor {
                account_id,
                other_account_id,
                order_id: user_order,
                other_order_id: match_result.other_order_id,
                execution_price: match_result.price,
                match_result: match_result.match_result,
            })
        };

        // Enqueue the task as a preemptive task through raft
        self.forward_queued_task(descriptor).await?;
        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the wallet for an order
    pub(crate) async fn get_account_id_for_order(
        &self,
        order_id: &OrderId,
    ) -> Result<AccountId, MatchingEngineError> {
        self.state.get_account_id_for_order(order_id).await?.ok_or_else(|| {
            MatchingEngineError::state(format!("no account id found for order {order_id:?}"))
        })
    }

    /// Fetch the order and wallet for the given order identifier
    async fn fetch_order_and_matchable_amount(
        &self,
        id: &OrderId,
    ) -> Result<(Order, Amount), MatchingEngineError> {
        let (order, matchable_amount) =
            self.state.get_account_order_and_matchable_amount(id).await?.ok_or_else(|| {
                MatchingEngineError::state(format!("failed to fetch order and balance for {id:?}"))
            })?;

        Ok((order, matchable_amount))
    }

    /// Fetch the matching pool for an order
    async fn fetch_matching_pool(
        &self,
        order_id: &OrderId,
    ) -> Result<MatchingPoolName, MatchingEngineError> {
        self.state.get_matching_pool_for_order(order_id).await.map_err(|e| {
            MatchingEngineError::state(format!(
                "failed to fetch matching pool for {order_id:?}: {e}"
            ))
        })
    }

    /// Check whether the database rows used to choose an attempted match still
    /// describe the same order after settlement fails.
    ///
    /// This preserves the v1 behavior of re-reading the database before
    /// deciding whether matching may continue on the same order:
    ///     1. `order_id -> account_id` must still exist
    ///     2. the account's serial queue length must still be zero
    ///     3. the account index must still contain the order row
    ///     4. the stored `Order` and matchable amount must still equal the
    ///        values used to choose the attempted match
    async fn order_still_valid(
        &self,
        order_id: &OrderId,
        attempted_order: &Order,
        attempted_matchable_amount: Amount,
    ) -> Result<bool, MatchingEngineError> {
        let Some(account_id) = self.state.get_account_id_for_order(order_id).await? else {
            info!("order {order_id} no longer maps to an account, stopping internal match retry");
            return Ok(false);
        };

        // Preserve the v1 guarantee that we stop if the order owner's serial
        // queue is already busy.
        let queue_len = self.state.serial_tasks_queue_len(&account_id).await?;
        if queue_len > 0 {
            info!(
                "order {order_id} account queue is busy (len = {queue_len}), stopping internal match retry"
            );
            return Ok(false);
        }

        let Some((current_order, current_matchable_amount)) =
            self.state.get_account_order_and_matchable_amount(order_id).await?
        else {
            info!(
                "order {order_id} no longer exists in the account index, stopping internal match retry"
            );
            return Ok(false);
        };

        if current_matchable_amount == 0 {
            info!(
                "order {order_id} no longer has positive matchable amount, stopping internal match retry"
            );
            return Ok(false);
        }

        if &current_order != attempted_order {
            info!(
                "order {order_id} changed since settlement was attempted (amount_in {} -> {}), stopping internal match retry",
                attempted_order.amount_in(),
                current_order.amount_in(),
            );
            return Ok(false);
        }

        if current_matchable_amount != attempted_matchable_amount {
            info!(
                "order {order_id} matchable amount changed since settlement was attempted ({} -> {}), stopping internal match retry",
                attempted_matchable_amount, current_matchable_amount,
            );
            return Ok(false);
        }

        Ok(true)
    }

    /// Fetch the privacy ring for an order
    async fn get_order_ring(&self, order_id: &OrderId) -> Result<PrivacyRing, MatchingEngineError> {
        self.state.get_order_ring(order_id).await?.ok_or_else(|| {
            MatchingEngineError::state(format!("no order found for order {order_id:?}"))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use circuit_types::Amount;
    use constants::GLOBAL_MATCHING_POOL;
    use job_types::{
        matching_engine::new_matching_engine_worker_queue, task_driver::new_task_driver_queue,
    };
    use matching_engine_core::MatchingEngine;
    use price_state::PriceStreamStates;
    use state::{State, test_helpers::mock_state};
    use system_bus::SystemBus;
    use test_helpers::mocks::mock_cancel;
    use types_account::{
        account::mocks::mock_empty_account,
        balance::mocks::mock_balance,
        order::{Order, mocks::mock_order},
        order_auth::mocks::mock_order_auth,
    };
    use types_tasks::{RefreshAccountTaskDescriptor, TaskDescriptor};

    use crate::executor::MatchingEngineExecutor;

    async fn mock_executor(state: State) -> MatchingEngineExecutor {
        let (_job_queue, job_receiver) = new_matching_engine_worker_queue();
        let (task_queue, _task_receiver) = new_task_driver_queue();

        MatchingEngineExecutor::new(
            0,              // min_fill_size
            0,              // external_match_validity_window
            HashSet::new(), // disabled_assets
            job_receiver,
            PriceStreamStates::new(vec![], vec![]),
            state,
            MatchingEngine::new(),
            task_queue,
            SystemBus::new(),
            mock_cancel(),
        )
        .unwrap()
    }

    async fn setup_executor_with_order()
    -> (MatchingEngineExecutor, State, types_core::AccountId, Order, Amount) {
        let state = mock_state().await;

        let account = mock_empty_account();
        let waiter = state.new_account(account.clone()).await.unwrap();
        waiter.await.unwrap();

        let order = mock_order();
        let auth = mock_order_auth();
        let mut balance = mock_balance();
        balance.state_wrapper.inner.mint = order.input_token();
        *balance.amount_mut() = order.amount_in() + 100;

        let waiter = state.update_account_balance(account.id, balance).await.unwrap();
        waiter.await.unwrap();

        let waiter = state
            .add_order_to_account(account.id, order.clone(), auth, GLOBAL_MATCHING_POOL.to_string())
            .await
            .unwrap();
        waiter.await.unwrap();

        let matchable_amount = state.get_order_matchable_amount(&order.id).await.unwrap();
        let executor = mock_executor(state.clone()).await;
        (executor, state, account.id, order, matchable_amount)
    }

    #[tokio::test]
    async fn test_order_still_valid_false_when_order_removed() {
        let (executor, state, account_id, order, attempted_matchable_amount) =
            setup_executor_with_order().await;

        let waiter = state.remove_order_from_account(account_id, order.id).await.unwrap();
        waiter.await.unwrap();

        let valid = executor
            .order_still_valid(&order.id, &order, attempted_matchable_amount)
            .await
            .unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_order_still_valid_false_when_order_amount_changes() {
        let (executor, state, _account_id, order, attempted_matchable_amount) =
            setup_executor_with_order().await;

        let mut updated_order = order.clone();
        updated_order.decrement_amount_in(1);
        let waiter = state.update_order(updated_order).await.unwrap();
        waiter.await.unwrap();

        let valid = executor
            .order_still_valid(&order.id, &order, attempted_matchable_amount)
            .await
            .unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_order_still_valid_false_when_matchable_amount_zero() {
        let (executor, state, account_id, order, attempted_matchable_amount) =
            setup_executor_with_order().await;

        let mut balance = state
            .get_account_balance(&account_id, &order.input_token(), order.ring.balance_location())
            .await
            .unwrap()
            .unwrap();
        *balance.amount_mut() = 0;
        let waiter = state.update_account_balance(account_id, balance).await.unwrap();
        waiter.await.unwrap();

        let valid = executor
            .order_still_valid(&order.id, &order, attempted_matchable_amount)
            .await
            .unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_order_still_valid_false_when_serial_queue_busy() {
        let (executor, state, account_id, order, attempted_matchable_amount) =
            setup_executor_with_order().await;

        let keychain = state.get_account_keychain(&account_id).await.unwrap().unwrap();
        let descriptor =
            TaskDescriptor::from(RefreshAccountTaskDescriptor::new(account_id, keychain));
        let (_task_id, waiter) =
            state.enqueue_preemptive_task(vec![account_id], descriptor, true).await.unwrap();
        waiter.await.unwrap();

        let valid = executor
            .order_still_valid(&order.id, &order, attempted_matchable_amount)
            .await
            .unwrap();
        assert!(!valid);
    }

    #[tokio::test]
    async fn test_order_still_valid_true_when_state_unchanged() {
        let (executor, _state, _account_id, order, attempted_matchable_amount) =
            setup_executor_with_order().await;

        let valid = executor
            .order_still_valid(&order.id, &order, attempted_matchable_amount)
            .await
            .unwrap();
        assert!(valid);
    }
}
