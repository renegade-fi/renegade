//! Applicator methods for matching pools

use common::types::wallet::OrderIdentifier;
use tracing::instrument;

use crate::storage::tx::matching_pools::MATCHING_POOL_DOES_NOT_EXIST_ERR;

use super::{StateApplicator, error::StateApplicatorError, return_type::ApplicatorReturnType};

impl StateApplicator {
    /// Create a matching pool with the given name
    #[instrument(skip_all, fields(pool_name = %pool_name))]
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
    #[instrument(skip_all, fields(pool_name = %pool_name))]
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
    #[instrument(skip_all, fields(order_id = %order_id, pool_name = %pool_name))]
    pub fn assign_order_to_matching_pool(
        &self,
        order_id: &OrderIdentifier,
        pool_name: &str,
    ) -> Result<ApplicatorReturnType, StateApplicatorError> {
        let tx = self.db().new_write_tx()?;
        tx.assign_order_to_matching_pool(order_id, pool_name)?;
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }
}
