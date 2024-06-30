//! Helpers for accessing information about matching pools in the database

use common::types::wallet::OrderIdentifier;
use libmdbx::{TransactionKind, RW};

use crate::{storage::error::StorageError, POOL_TABLE};

use super::StateTxn;

/// The prefix of all matching pool keys
pub const POOL_KEY_PREFIX: &str = "matching-pool/";

/// The error message used when trying to create a matching pool that already
/// exists
const MATCHING_POOL_EXISTS_ERR: &str = "matching pool already exists";
/// The error message used when assigning an order to a nonexistent matching
/// pool
const MATCHING_POOL_DOES_NOT_EXIST_ERR: &str = "matching pool does not exist";
/// The error message used when a non-empty matching pool is attempted to be
/// destroyed
const MATCHING_POOL_NOT_EMPTY_ERR: &str = "matching pool not empty";

// ---------------
// | Key Helpers |
// ---------------

/// The key for the set of all matching pools
pub fn all_matching_pools_key() -> String {
    "all-matching-pools".to_string()
}

/// The key for the given order's matching pool
pub fn matching_pool_key(order_id: &OrderIdentifier) -> String {
    format!("{}{}", POOL_KEY_PREFIX, order_id)
}

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Get the name of the matching pool the given order is in, if it's been
    /// assigned to one
    pub fn get_matching_pool_for_order(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<String>, StorageError> {
        let pool_key = matching_pool_key(order_id);
        self.inner().read(POOL_TABLE, &pool_key)
    }

    /// Whether or not a pool with the given name exists
    pub fn matching_pool_exists(&self, pool_name: &str) -> Result<bool, StorageError> {
        let all_pools_key = all_matching_pools_key();
        let all_pools: Vec<String> = self.read_set(POOL_TABLE, &all_pools_key)?;
        Ok(all_pools.contains(&pool_name.to_string()))
    }

    /// Whether or not the given matching pool is empty
    pub fn matching_pool_is_empty(&self, pool_name: &str) -> Result<bool, StorageError> {
        // We iterate over the mapping from orders -> their matching pool, and check
        // if any orders are in the given pool
        let cursor = self
            .inner()
            .cursor::<String, String>(POOL_TABLE)?
            .with_key_filter(|key| key.starts_with(POOL_KEY_PREFIX));

        let mut pool_in_use = false;
        for pool_for_order in cursor.into_iter().values() {
            if pool_for_order? == pool_name {
                pool_in_use = true;
                break;
            }
        }

        Ok(!pool_in_use)
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Create a matching pool with the given name
    pub fn create_matching_pool(&self, pool_name: &str) -> Result<(), StorageError> {
        // Check that the pool does not already exist
        if self.matching_pool_exists(pool_name)? {
            return Err(StorageError::Other(MATCHING_POOL_EXISTS_ERR.to_string()));
        }

        let all_pools_key = all_matching_pools_key();
        self.add_to_set(POOL_TABLE, &all_pools_key, &pool_name.to_string())
    }

    /// Destroy a matching pool
    pub fn destroy_matching_pool(&self, pool_name: &str) -> Result<(), StorageError> {
        // Check that the pool is empty
        if !self.matching_pool_is_empty(pool_name)? {
            return Err(StorageError::Other(MATCHING_POOL_NOT_EMPTY_ERR.to_string()));
        }

        let all_pools_key = all_matching_pools_key();
        self.remove_from_set(POOL_TABLE, &all_pools_key, &pool_name.to_string())
    }

    /// Assign an order to a matching pool.
    ///
    /// Note that we allow overwriting an order's pool, this signifies moving
    /// the order from one pool to another.
    pub fn assign_order_to_matching_pool(
        &self,
        order_id: &OrderIdentifier,
        pool_name: &str,
    ) -> Result<(), StorageError> {
        // Check that the pool exists
        if !self.matching_pool_exists(pool_name)? {
            return Err(StorageError::Other(MATCHING_POOL_DOES_NOT_EXIST_ERR.to_string()));
        }

        let pool_key = matching_pool_key(order_id);
        self.inner().write(POOL_TABLE, &pool_key, &pool_name.to_string())
    }
}

#[cfg(test)]
mod test {
    use common::types::wallet::OrderIdentifier;

    use crate::{matching_pools::GLOBAL_MATCHING_POOL, test_helpers::mock_db};

    /// Tests creating a matching pool
    #[test]
    fn test_create_matching_pool() {
        let db = mock_db();

        let pool_name = GLOBAL_MATCHING_POOL.to_string();

        // Create a matching pool
        let tx = db.new_write_tx().unwrap();
        tx.create_matching_pool(&pool_name).unwrap();
        tx.commit().unwrap();

        // Assert the matching pool exists
        let tx = db.new_read_tx().unwrap();
        let pool_exists = tx.matching_pool_exists(&pool_name).unwrap();
        tx.commit().unwrap();

        assert!(pool_exists);
    }

    /// Tests creating a duplicate matching pool
    #[test]
    fn test_double_create_matching_pool() {
        let db = mock_db();

        let pool_name = GLOBAL_MATCHING_POOL.to_string();

        // Create a matching pool
        let tx = db.new_write_tx().unwrap();
        tx.create_matching_pool(&pool_name).unwrap();
        tx.commit().unwrap();

        // Try creating it again
        let tx = db.new_write_tx().unwrap();
        let res = tx.create_matching_pool(&pool_name);
        tx.commit().unwrap();

        assert!(res.is_err())
    }

    /// Tests destroying a matching pool
    #[test]
    fn test_destroy_matching_pool() {
        let db = mock_db();

        let pool_name = GLOBAL_MATCHING_POOL.to_string();

        // Create a matching pool
        let tx = db.new_write_tx().unwrap();
        tx.create_matching_pool(&pool_name).unwrap();
        tx.commit().unwrap();

        // Destroy the matching pool
        let tx = db.new_write_tx().unwrap();
        tx.destroy_matching_pool(&pool_name).unwrap();
        tx.commit().unwrap();

        // Assert the matching pool does not exist
        let tx = db.new_read_tx().unwrap();
        let pool_exists = tx.matching_pool_exists(&pool_name).unwrap();
        tx.commit().unwrap();

        assert!(!pool_exists);
    }

    /// Tests destroying a non-empty matching pool
    #[test]
    fn test_destroy_non_empty_matching_pool() {
        let db = mock_db();

        let pool_name = GLOBAL_MATCHING_POOL.to_string();
        let order_id = OrderIdentifier::new_v4();

        // Create a matching pool
        let tx = db.new_write_tx().unwrap();
        tx.create_matching_pool(&pool_name).unwrap();
        tx.commit().unwrap();

        // Assign the order to the matching pool
        let tx = db.new_write_tx().unwrap();
        tx.assign_order_to_matching_pool(&order_id, &pool_name).unwrap();
        tx.commit().unwrap();

        // Try destroying the matching pool
        let tx = db.new_write_tx().unwrap();
        let res = tx.destroy_matching_pool(&pool_name);
        tx.commit().unwrap();

        assert!(res.is_err());
    }

    /// Tests assigning an order to a matching pool
    #[test]
    fn test_assign_order_to_matching_pool() {
        let db = mock_db();

        let pool_name = GLOBAL_MATCHING_POOL.to_string();
        let order_id = OrderIdentifier::new_v4();

        // Create a matching pool
        let tx = db.new_write_tx().unwrap();
        tx.create_matching_pool(&pool_name).unwrap();
        tx.commit().unwrap();

        // Assign the order to the matching pool
        let tx = db.new_write_tx().unwrap();
        tx.assign_order_to_matching_pool(&order_id, &pool_name).unwrap();
        tx.commit().unwrap();

        // Assert that the order is in the matching pool
        let tx = db.new_read_tx().unwrap();
        let pool_for_order = tx.get_matching_pool_for_order(&order_id).unwrap().unwrap();
        tx.commit().unwrap();

        assert_eq!(pool_for_order, pool_name);
    }

    /// Tests re-assigning an order to a different matching pool
    #[test]
    fn test_reassign_order_matching_pool() {
        let db = mock_db();

        let pool_1_name = "pool-1".to_string();
        let pool_2_name = "pool-2".to_string();

        // Create both matching pools
        let tx = db.new_write_tx().unwrap();
        tx.create_matching_pool(&pool_1_name).unwrap();
        tx.create_matching_pool(&pool_2_name).unwrap();
        tx.commit().unwrap();

        let order_id = OrderIdentifier::new_v4();

        // Assign the order to the first matching pool
        let tx = db.new_write_tx().unwrap();
        tx.assign_order_to_matching_pool(&order_id, &pool_1_name).unwrap();
        tx.commit().unwrap();

        // Re-assign the order to the second matching pool
        let tx = db.new_write_tx().unwrap();
        tx.assign_order_to_matching_pool(&order_id, &pool_2_name).unwrap();
        tx.commit().unwrap();

        // Assert that the order is in the second matching pool
        let tx = db.new_read_tx().unwrap();
        let pool_for_order = tx.get_matching_pool_for_order(&order_id).unwrap().unwrap();
        tx.commit().unwrap();

        assert_eq!(pool_for_order, pool_2_name);
    }

    #[test]
    fn test_assign_order_to_nonexistent_matching_pool() {
        let db = mock_db();

        let pool_name = GLOBAL_MATCHING_POOL.to_string();
        let order_id = OrderIdentifier::new_v4();

        // Try assigning the order to the matching pool (before creating it)
        let tx = db.new_write_tx().unwrap();
        let res = tx.assign_order_to_matching_pool(&order_id, &pool_name);
        tx.commit().unwrap();

        assert!(res.is_err());
    }
}
