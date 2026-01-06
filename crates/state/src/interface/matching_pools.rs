//! State interface for matching pools

// -------------
// | Constants |
// -------------

use types_account::account::OrderId;
use types_runtime::MatchingPoolName;

use crate::{StateInner, StateTransition, error::StateError, notifications::ProposalWaiter};

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Get the name of the matching pool the given intent is in, if it's been
    /// assigned to one
    pub async fn get_matching_pool_for_intent(
        &self,
        intent_id: &OrderId,
    ) -> Result<MatchingPoolName, StateError> {
        let intent_id = *intent_id;
        self.with_read_tx(move |tx| {
            let matching_pool = tx.get_matching_pool_for_intent(&intent_id)?;
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

    /// Assign an intent to a matching pool
    pub async fn assign_intent_to_matching_pool(
        &self,
        intent_id: OrderId,
        pool_name: MatchingPoolName,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::AssignIntentToMatchingPool { intent_id, pool_name })
            .await
    }
}
