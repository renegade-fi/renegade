//! State interface for matching pools

// -------------
// | Constants |
// -------------

use common::types::wallet::OrderIdentifier;

use crate::{error::StateError, notifications::ProposalWaiter, State};

/// The name of the global matching pool
pub const GLOBAL_MATCHING_POOL: &str = "global";

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the name of the matching pool the given order is in, if it's been
    /// assigned to one
    pub async fn get_matching_pool_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<String>, StateError> {
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
        _pool_name: &str,
    ) -> Result<ProposalWaiter, StateError> {
        todo!()
    }

    /// Destroy a matching pool
    pub async fn destroy_matching_pool(
        &self,
        _pool_name: &str,
    ) -> Result<ProposalWaiter, StateError> {
        todo!()
    }

    /// Assign an order to a matching pool
    pub async fn assign_order_to_matching_pool(
        &self,
        _order_id: &OrderIdentifier,
        _pool_name: &str,
    ) -> Result<ProposalWaiter, StateError> {
        todo!()
    }

    /// Create the global matching pool
    pub async fn create_global_matching_pool(&self) -> Result<ProposalWaiter, StateError> {
        self.create_matching_pool(GLOBAL_MATCHING_POOL).await
    }

    /// Assign an order to the global matching pool
    pub async fn assign_order_to_global_matching_pool(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<ProposalWaiter, StateError> {
        self.assign_order_to_matching_pool(order_id, GLOBAL_MATCHING_POOL).await
    }
}

#[cfg(test)]
mod test {
    use common::types::wallet::OrderIdentifier;

    use crate::{matching_pools::GLOBAL_MATCHING_POOL, test_helpers::mock_state};

    /// Test creating the global matching pool
    #[tokio::test]
    async fn test_create_global_matching_pool() {
        let state = mock_state().await;

        // Create the global matching pool
        let waiter = state.create_global_matching_pool().await.unwrap();
        waiter.await.unwrap();

        // Assert the global matching pool exists
        let exists = state.matching_pool_exists(GLOBAL_MATCHING_POOL).await.unwrap();
        assert!(exists);
    }

    #[tokio::test]
    async fn test_assign_order_to_global_matching_pool() {
        let state = mock_state().await;

        // Create the global matching pool
        state.create_global_matching_pool().await.unwrap();

        // Assign an order into it
        let order_id = OrderIdentifier::new_v4();
        let waiter = state.assign_order_to_global_matching_pool(&order_id).await.unwrap();
        waiter.await.unwrap();

        // Assert the order is in the global matching pool
        let pool = state.get_matching_pool_for_order(&order_id).await.unwrap().unwrap();
        assert_eq!(pool, GLOBAL_MATCHING_POOL);
    }
}
