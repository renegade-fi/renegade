//! Defines logic for running the internal matching engine on a given order

use circuit_types::Amount;
use matching_engine_core::SuccessfulMatch;
use tracing::{error, info, instrument};
use types_account::{MatchingPoolName, OrderId, order::Order};
use types_core::AccountId;

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
        order_id: OrderId,
    ) -> Result<(), MatchingEngineError> {
        info!("Running internal matching engine on order {order_id}");
        // Lookup the order, matchable amount, and matching pool
        let (order, matchable_amount) = self.fetch_order_and_matchable_amount(&order_id).await?;
        let matching_pool = self.fetch_matching_pool(&order_id).await?;

        // Find a match
        let res = self.find_internal_match(&order, matchable_amount, matching_pool)?;
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
                if !self.order_still_valid(&order_id).await? {
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
        println!("Found match for {user_order}: {match_result:?}");
        todo!("Add settlement task")
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
    async fn order_still_valid(&self, order_id: &OrderId) -> Result<bool, MatchingEngineError> {
        todo!("Re-implement order still valid check")
    }
}
