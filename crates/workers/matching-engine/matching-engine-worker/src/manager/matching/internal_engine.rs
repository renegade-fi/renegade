//! Defines logic for running the internal matching engine on a given order

use std::time::Duration;

use circuit_types::Amount;
use matching_engine_core::SuccessfulMatch;
use rand::Rng;
use tracing::{error, info, instrument, warn};
use types_account::order::PrivacyRing;
use types_account::{MatchingPoolName, OrderId, order::Order};
use types_core::AccountId;
use types_tasks::{
    SettleInternalMatchTaskDescriptor, SettlePrivateMatchTaskDescriptor, TaskDescriptor,
};

use crate::{error::MatchingEngineError, executor::MatchingEngineExecutor};

// -------------------
// | Retry Constants |
// -------------------

/// Max settlement attempts before giving up on a single matching run. A wallet
/// queue can be transiently held by a concurrent (or committed) settlement; we
/// re-find and retry rather than stranding the match.
pub(crate) const MAX_SETTLE_RETRIES: u32 = 5;
/// Base backoff between settlement retries.
pub(crate) const RETRY_BASE_DELAY: Duration = Duration::from_millis(100);
/// Cap on the exponential backoff. A committed (on-chain) settlement may take a
/// few seconds to clear the queue, so allow the wait to grow to ~1.5s.
pub(crate) const RETRY_MAX_DELAY: Duration = Duration::from_millis(1500);

/// Jittered exponential backoff for settlement retries. `attempt` is 0-indexed.
/// Kept well under the consumer fill timeout so retries resolve in-window.
pub(crate) fn next_backoff(attempt: u32) -> Duration {
    let exp = RETRY_BASE_DELAY.saturating_mul(2u32.saturating_pow(attempt));
    let capped = std::cmp::min(exp, RETRY_MAX_DELAY);
    // Half the capped delay plus full jitter in [0, capped].
    let half = capped / 2;
    let jitter_ms = rand::thread_rng().gen_range(0..=(capped.as_millis() as u64).max(1));
    half + Duration::from_millis(jitter_ms)
}

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

        for attempt in 0..MAX_SETTLE_RETRIES {
            // Re-fetch + re-find each attempt: a competitor that already settled
            // this order is then observed as "no match" and we stop cleanly, so
            // we never enqueue a settlement for an already-filled order.
            let (order, matchable_amount) =
                self.fetch_order_and_matchable_amount(&order_id).await?;
            let matching_pool = self.fetch_matching_pool(&order_id).await?;

            // Check if either asset in the pair is disabled for matching
            let pair = order.pair();
            if self.is_asset_disabled(&pair.in_token) || self.is_asset_disabled(&pair.out_token) {
                warn!(
                    "Asset disabled for matching, skipping internal matching engine for {order_id}"
                );
                return Ok(());
            }

            // Find a match
            let successful_match = match self.find_internal_match(
                account_id,
                &order,
                matchable_amount,
                matching_pool,
            )? {
                Some(match_res) => match_res,
                None => {
                    info!("No internal matches found for {order_id:?}");
                    return Ok(());
                },
            };
            let other_id = successful_match.other_order_id;

            match self.try_settle_match(order_id, successful_match).await {
                // Stop matching if a match was settled
                Ok(()) => return Ok(()),
                // Transient: a concurrent or committed settlement holds a wallet
                // queue. Back off and re-evaluate. Expected under contention --
                // not a real failure (the external engine already downgrades
                // these to a warning; see commit 0539005d65).
                Err(MatchingEngineError::PreemptionConflict) => {
                    warn!(
                        "settlement for {other_id} x {order_id} preempted (attempt {}/{}); retrying",
                        attempt + 1,
                        MAX_SETTLE_RETRIES
                    );
                    if !self.order_still_valid(&order_id).await? {
                        info!("account has changed, stopping internal matching engine...");
                        return Ok(());
                    }
                    tokio::time::sleep(next_backoff(attempt)).await;
                    continue;
                },
                // A genuine settlement failure (not contention).
                Err(e) => {
                    error!("internal match settlement failed for {other_id} x {order_id}: {e}");
                    return Ok(());
                },
            }
        }

        warn!(
            "internal match settlement for {order_id} exhausted {MAX_SETTLE_RETRIES} preemption \
             retries; will settle on a subsequent matching run"
        );
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
        warn!("Re-implement order still valid check");
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
mod retry_test {
    use std::time::Duration;

    use super::{MAX_SETTLE_RETRIES, RETRY_BASE_DELAY, RETRY_MAX_DELAY, next_backoff};

    #[test]
    fn test_next_backoff_bounds_and_growth() {
        // Floor is base/2 (half the capped delay); ceiling is cap + full jitter.
        for attempt in 0..MAX_SETTLE_RETRIES {
            let d = next_backoff(attempt);
            assert!(d >= RETRY_BASE_DELAY / 2, "delay below floor at attempt {attempt}");
            assert!(d <= RETRY_MAX_DELAY * 2, "delay exceeds cap+jitter at attempt {attempt}");
        }
        // Worst-case total retry budget stays well under the 45s fill timeout.
        let total: Duration = (0..MAX_SETTLE_RETRIES).map(next_backoff).sum();
        assert!(total < Duration::from_secs(15), "total retry budget too large: {total:?}");
    }
}
