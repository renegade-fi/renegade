//! State interface for matching pools

// -------------
// | Constants |
// -------------

use types_account::MatchingPoolName;
use types_account::account::OrderId;
use types_core::AccountId;

use crate::{
    StateInner, applicator::return_type::ApplicatorReturnType, error::StateError,
    notifications::ProposalWaiter, state_transition::StateTransition,
};

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Get the name of the matching pool the given order is in, if it's been
    /// assigned to one
    pub async fn get_matching_pool_for_order(
        &self,
        order_id: &OrderId,
    ) -> Result<MatchingPoolName, StateError> {
        let order_id = *order_id;
        self.with_read_tx(move |tx| {
            let matching_pool = tx.get_matching_pool_for_order(&order_id)?;
            Ok(matching_pool)
        })
        .await
    }

    /// Whether or not a pool with the given name exists
    pub async fn matching_pool_exists(
        &self,
        pool_name: MatchingPoolName,
    ) -> Result<bool, StateError> {
        self.with_read_tx(move |tx| {
            let exists = tx.matching_pool_exists(&pool_name)?;
            Ok(exists)
        })
        .await
    }

    /// Whether or not a matching pool is empty (has no orders assigned to it)
    pub async fn matching_pool_is_empty(
        &self,
        pool_name: MatchingPoolName,
    ) -> Result<bool, StateError> {
        self.with_read_tx(move |tx| {
            let is_empty = tx.matching_pool_is_empty(&pool_name)?;
            Ok(is_empty)
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Create a matching pool with the given name
    ///
    /// Idempotent: matching pools are persisted in `POOL_TABLE`, but quoters
    /// re-issue `create_matching_pool` for every pool on each boot. Those creates
    /// are redundant, and a burst of them floods the sequential raft apply loop ->
    /// proposals exceed the `ProposalWaiter` deadline and the quoter boot rebalance
    /// fails (no book -> no matches). Short-circuit with an already-resolved waiter
    /// when the pool already exists, so no proposal is enqueued.
    pub async fn create_matching_pool(
        &self,
        pool_name: MatchingPoolName,
    ) -> Result<ProposalWaiter, StateError> {
        if self.matching_pool_exists(pool_name.clone()).await? {
            return Ok(ProposalWaiter::resolved(Ok(ApplicatorReturnType::None)));
        }
        self.send_proposal(StateTransition::CreateMatchingPool { pool_name }).await
    }

    /// Destroy a matching pool
    pub async fn destroy_matching_pool(
        &self,
        pool_name: MatchingPoolName,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::DestroyMatchingPool { pool_name }).await
    }

    /// Assign an order to a matching pool
    pub async fn assign_order_to_matching_pool(
        &self,
        order_id: OrderId,
        pool_name: MatchingPoolName,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AssignOrderToMatchingPool { order_id, pool_name }).await
    }

    /// Set the default matching pool for an account
    ///
    /// Pass `None` to clear the binding so future orders use the global pool.
    pub async fn set_account_default_matching_pool(
        &self,
        account_id: AccountId,
        pool: Option<MatchingPoolName>,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::SetAccountDefaultMatchingPool { account_id, pool })
            .await
    }
}
