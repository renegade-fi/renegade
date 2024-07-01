//! State interface for matching pools

// -------------
// | Constants |
// -------------

use common::types::{wallet::OrderIdentifier, MatchingPoolName};

use crate::{error::StateError, notifications::ProposalWaiter, State, StateTransition};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the name of the matching pool the given order is in, if it's been
    /// assigned to one
    pub async fn get_matching_pool_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<MatchingPoolName>, StateError> {
        let order_id = *order_id;
        self.with_read_tx(move |tx| {
            let matching_pool = tx.get_matching_pool_for_order(&order_id)?;
            Ok(matching_pool)
        })
        .await
    }

    /// Whether or not a pool with the given name exists
    pub async fn matching_pool_exists(&self, pool_name: &str) -> Result<bool, StateError> {
        let pool_name = pool_name.to_string();
        self.with_read_tx(move |tx| {
            let exists = tx.matching_pool_exists(&pool_name)?;
            Ok(exists)
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// Create a matching pool with the given name
    pub async fn create_matching_pool(
        &self,
        pool_name: MatchingPoolName,
    ) -> Result<ProposalWaiter, StateError> {
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
        order_id: OrderIdentifier,
        pool_name: MatchingPoolName,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AssignOrderToMatchingPool { order_id, pool_name }).await
    }
}
