//! Helpers for working with the integration node's state

use common::types::{MatchingPoolName, wallet::OrderIdentifier};
use eyre::Result;
use state::State;

use crate::ctx::IntegrationTestCtx;

/// The tables that are cleared when the state is cleared
///
/// We'd rather keep the constants in the state private, so we copy them here
const TABLES_TO_CLEAR: [&str; 6] = [
    "orders",
    "order-history",
    "matching-pools",
    "order-to-wallet",
    "nullifier-to-wallet",
    "wallet-info",
];

impl IntegrationTestCtx {
    /// Get the state of the integration node
    pub fn state(&self) -> State {
        self.mock_node.state()
    }

    /// Setup the state of the mock node
    pub async fn setup_state(&mut self) -> Result<()> {
        let state = self.state();
        let this_peer = state.get_peer_id()?;
        state.initialize_raft(vec![this_peer] /* this_peer */).await?;
        Ok(())
    }

    /// Clear the state of the mock node
    pub async fn clear_state(&mut self) -> Result<()> {
        self.mock_node.clear_state(&TABLES_TO_CLEAR).await
    }

    /// Move a given order into the given matching pool
    pub async fn move_order_into_pool(
        &self,
        oid: OrderIdentifier,
        pool: MatchingPoolName,
    ) -> Result<()> {
        let state = self.state();
        let pool_exists = state.matching_pool_exists(pool.clone()).await?;
        if !pool_exists {
            state.create_matching_pool(pool.clone()).await?;
        }

        let waiter = state.assign_order_to_matching_pool(oid, pool).await?;
        waiter.await?;
        Ok(())
    }
}
