//! Defines logic for running the internal matching engine on a given order

use circuit_types::Amount;
use matching_engine_core::SuccessfulMatch;
use renegade_metrics::record_internal_match_settle;
use tracing::instrument;
use types_account::order::PrivacyRing;
use types_account::{MatchingPoolName, OrderId, order::Order};
use types_core::AccountId;
use types_tasks::{
    SettleInternalMatchTaskDescriptor, SettlePrivateMatchTaskDescriptor, TaskDescriptor,
};
use util::log_task;
use util::logging::Outcome;

use crate::logging::Task;
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
        log_task!(Task::InternalMatch, Outcome::Started, subject = %order_id, "running internal matching engine on order");
        // Lookup the order, matchable amount, and matching pool
        let (order, matchable_amount) = self.fetch_order_and_matchable_amount(&order_id).await?;
        let matching_pool = self.fetch_matching_pool(&order_id).await?;
        // Captured for the per-pool settlement metric (the pool name is moved
        // into `find_internal_match` below).
        let pool_label = matching_pool.clone();

        // Check if either asset in the pair is disabled for matching
        let pair = order.pair();
        if self.is_asset_disabled(&pair.in_token) || self.is_asset_disabled(&pair.out_token) {
            let in_tok = pair.in_token().ticker_or_addr();
            let out_tok = pair.out_token().ticker_or_addr();
            log_task!(
                Task::InternalMatch,
                Outcome::Skipped,
                subject = %order_id,
                in_token = %in_tok,
                in_addr = %pair.in_token,
                out_token = %out_tok,
                out_addr = %pair.out_token,
                "asset disabled for matching, skipping internal matching engine for {in_tok}/{out_tok}"
            );
            return Ok(());
        }

        // Find a match
        let res = self.find_internal_match(account_id, &order, matchable_amount, matching_pool)?;
        let successful_match = match res {
            Some(match_res) => match_res,
            None => {
                let base = pair.base_token().ticker_or_addr();
                let quote = pair.quote_token().ticker_or_addr();
                log_task!(
                    Task::InternalMatch,
                    Outcome::Ok,
                    subject = %order_id,
                    base = %base,
                    quote = %quote,
                    "no internal matches found for {base}/{quote} order"
                );
                return Ok(());
            },
        };

        // TODO: maybe iteratively attempt to find a match and blacklist an order if
        // settlement fails?
        let other_id = successful_match.other_order_id;
        match self.try_settle_match(order_id, successful_match).await {
            Ok(()) => {
                // Per-pool settlement demand signal (success).
                record_internal_match_settle(&pool_label, true /* settled */);
                // Stop matching if a match was found
                return Ok(());
            },
            Err(e) => {
                // Per-pool settlement demand signal (failure — largely preemption
                // contention under load). The failed/total ratio per pool is the
                // conflict rate used to size sharding.
                record_internal_match_settle(&pool_label, false /* settled */);
                let base = pair.base_token().ticker_or_addr();
                let quote = pair.quote_token().ticker_or_addr();
                log_task!(
                    Task::SettleInternalMatch,
                    Outcome::Failed,
                    subject = %order_id,
                    other_order_id = %other_id,
                    base = %base,
                    quote = %quote,
                    error = %e,
                    "internal match settlement failed for {base}/{quote} order pair"
                );

                // Check whether matching should continue
                if !self.order_still_valid(&order_id).await? {
                    log_task!(
                        Task::InternalMatch,
                        Outcome::Skipped,
                        subject = %order_id,
                        base = %base,
                        quote = %quote,
                        "account has changed for {base}/{quote}, stopping internal matching engine"
                    );
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

    /// TODO: Update this comment when we re-implement
    /// Check whether a wallet is still valid. This amounts to checking:
    ///     1. Whether the wallet's known nullifier is still valid. This may be
    ///        false if the wallet has been updated since a match was attempted
    ///     2. Whether the wallet's queue is still empty and unpaused.
    ///        Concurrent matches from elsewhere in the relayer may cause this
    ///        second condition to be false
    ///
    /// This check may be executed after a match settlement fails
    async fn order_still_valid(&self, _order_id: &OrderId) -> Result<bool, MatchingEngineError> {
        log_task!(Task::CheckOrderValid, Outcome::Partial, subject = %_order_id, "re-implement order still valid check");
        Ok(true)
    }

    /// Fetch the privacy ring for an order
    async fn get_order_ring(&self, order_id: &OrderId) -> Result<PrivacyRing, MatchingEngineError> {
        self.state.get_order_ring(order_id).await?.ok_or_else(|| {
            MatchingEngineError::state(format!("no order found for order {order_id:?}"))
        })
    }
}
