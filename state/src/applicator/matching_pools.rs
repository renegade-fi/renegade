//! Applicator methods for matching pools

use common::types::wallet::OrderIdentifier;

use crate::storage::tx::matching_pools::MATCHING_POOL_DOES_NOT_EXIST_ERR;

use super::{StateApplicator, error::StateApplicatorError, return_type::ApplicatorReturnType};

impl StateApplicator {
    /// Create a matching pool with the given name
    pub fn create_matching_pool(
        &self,
        pool_name: &str,
    ) -> Result<ApplicatorReturnType, StateApplicatorError> {
        let tx = self.db().new_write_tx()?;
        tx.create_matching_pool(pool_name)?;
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }

    /// Destroy a matching pool
    pub fn destroy_matching_pool(
        &self,
        pool_name: &str,
    ) -> Result<ApplicatorReturnType, StateApplicatorError> {
        let tx = self.db().new_write_tx()?;

        if !tx.matching_pool_exists(pool_name)? {
            return Err(StateApplicatorError::reject(MATCHING_POOL_DOES_NOT_EXIST_ERR));
        }

        tx.destroy_matching_pool(pool_name)?;
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }

    /// Assign an order to a matching pool
    ///
    /// Returns a rejection (non-fatal) if the pool does not exist on this
    /// node. The previous behavior was to propagate a `StorageError`, which
    /// the raft state machine treats as fatal and panics the RaftCore. This
    /// can happen when a node joins the cluster via `initialize_raft`
    /// without install_snapshot and its state machine is missing pools that
    /// the leader's state machine has.
    pub fn assign_order_to_matching_pool(
        &self,
        order_id: &OrderIdentifier,
        pool_name: &str,
    ) -> Result<ApplicatorReturnType, StateApplicatorError> {
        let tx = self.db().new_write_tx()?;

        if !tx.matching_pool_exists(pool_name)? {
            return Err(StateApplicatorError::reject(MATCHING_POOL_DOES_NOT_EXIST_ERR));
        }

        tx.assign_order_to_matching_pool(order_id, pool_name)?;
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }
}
