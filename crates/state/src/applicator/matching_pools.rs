//! Applicator methods for matching pools

use types_account::account::OrderId;

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
    pub fn assign_order_to_matching_pool(
        &self,
        order_id: &OrderId,
        pool_name: &str,
    ) -> Result<ApplicatorReturnType, StateApplicatorError> {
        let tx = self.db().new_write_tx()?;
        tx.assign_order_to_matching_pool(order_id, pool_name)?;
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }
}

#[cfg(test)]
mod test {
    use types_account::{MatchingPoolName, account::OrderId};

    use crate::applicator::test_helpers::mock_applicator;

    /// A test matching pool name
    const TEST_POOL_NAME: &str = "test-pool";

    /// Tests creating a matching pool via the applicator
    #[test]
    fn test_create_matching_pool() {
        let applicator = mock_applicator();
        let pool_name: MatchingPoolName = TEST_POOL_NAME.to_string();

        // Create a matching pool
        applicator.create_matching_pool(&pool_name).unwrap();

        // Assert the matching pool exists
        let tx = applicator.db().new_read_tx().unwrap();
        let pool_exists = tx.matching_pool_exists(&pool_name).unwrap();
        assert!(pool_exists);
    }

    /// Tests destroying a matching pool via the applicator
    #[test]
    fn test_destroy_matching_pool() {
        let applicator = mock_applicator();
        let pool_name: MatchingPoolName = TEST_POOL_NAME.to_string();

        // Create then destroy the matching pool
        applicator.create_matching_pool(&pool_name).unwrap();
        applicator.destroy_matching_pool(&pool_name).unwrap();

        // Assert the matching pool does not exist
        let tx = applicator.db().new_read_tx().unwrap();
        let pool_exists = tx.matching_pool_exists(&pool_name).unwrap();
        assert!(!pool_exists);
    }

    /// Tests assigning an order to a matching pool via the applicator
    #[test]
    fn test_assign_order_to_matching_pool() {
        let applicator = mock_applicator();
        let pool_name: MatchingPoolName = TEST_POOL_NAME.to_string();
        let order_id = OrderId::new_v4();

        // Create a matching pool, then assign the order
        applicator.create_matching_pool(&pool_name).unwrap();
        applicator.assign_order_to_matching_pool(&order_id, &pool_name).unwrap();

        // Assert that the order is in the matching pool
        let tx = applicator.db().new_read_tx().unwrap();
        let pool_for_order = tx.get_matching_pool_for_order(&order_id).unwrap();
        assert_eq!(pool_for_order, pool_name);
    }

    /// Tests re-assigning an order to a different matching pool
    #[test]
    fn test_reassign_order_matching_pool() {
        let applicator = mock_applicator();
        let pool_1_name: MatchingPoolName = "pool-1".to_string();
        let pool_2_name: MatchingPoolName = "pool-2".to_string();
        let order_id = OrderId::new_v4();

        // Create both matching pools
        applicator.create_matching_pool(&pool_1_name).unwrap();
        applicator.create_matching_pool(&pool_2_name).unwrap();

        // Assign then re-assign the order
        applicator.assign_order_to_matching_pool(&order_id, &pool_1_name).unwrap();
        applicator.assign_order_to_matching_pool(&order_id, &pool_2_name).unwrap();

        // Assert that the order is in the second matching pool
        let tx = applicator.db().new_read_tx().unwrap();
        let pool_for_order = tx.get_matching_pool_for_order(&order_id).unwrap();
        assert_eq!(pool_for_order, pool_2_name);
    }

    /// Tests destroying a nonexistent matching pool
    #[test]
    fn test_destroy_nonexistent_matching_pool() {
        let applicator = mock_applicator();
        let pool_name: MatchingPoolName = TEST_POOL_NAME.to_string();

        // Try to destroy a nonexistent matching pool
        let result = applicator.destroy_matching_pool(&pool_name);
        assert!(result.is_err());
    }

    /// Tests assigning an order to a nonexistent matching pool
    #[test]
    fn test_assign_order_to_nonexistent_matching_pool() {
        let applicator = mock_applicator();
        let pool_name: MatchingPoolName = TEST_POOL_NAME.to_string();
        let order_id = OrderId::new_v4();

        // Try assigning the order to a nonexistent matching pool
        let result = applicator.assign_order_to_matching_pool(&order_id, &pool_name);
        assert!(result.is_err());
    }
}
