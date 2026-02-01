//! Helpers for accessing order authorization information in the database

use libmdbx::{RW, TransactionKind};
use types_account::{account::OrderId, order_auth::OrderAuth};

use crate::{
    ORDER_AUTH_TABLE,
    storage::{ArchivedValue, error::StorageError},
};

use super::StateTxn;

/// Type alias for an archived order auth value with transaction lifetime
pub type OrderAuthValue<'a> = ArchivedValue<'a, OrderAuth>;

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Get the order authorization for the given order ID
    pub fn get_order_auth(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<OrderAuthValue<'_>>, StorageError> {
        self.inner().read(ORDER_AUTH_TABLE, order_id)
    }

    /// Check if order authorization exists for the given order ID
    pub fn contains_order_auth(&self, order_id: &OrderId) -> Result<bool, StorageError> {
        let auth_value = self.inner().read::<_, OrderAuth>(ORDER_AUTH_TABLE, order_id)?;
        Ok(auth_value.is_some())
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Write order authorization to the table
    pub fn write_order_auth(
        &self,
        order_id: &OrderId,
        auth: &OrderAuth,
    ) -> Result<(), StorageError> {
        self.inner().write(ORDER_AUTH_TABLE, order_id, auth)
    }

    /// Delete order authorization for the given order ID
    pub fn delete_order_auth(&self, order_id: &OrderId) -> Result<(), StorageError> {
        self.inner().delete(ORDER_AUTH_TABLE, order_id)?;
        Ok(())
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use circuit_types::{primitives::baby_jubjub::BabyJubJubPoint, schnorr::SchnorrSignature};
    use constants::EmbeddedScalarField;
    use types_account::{
        account::OrderId,
        order_auth::{OrderAuth, mocks::mock_order_auth},
    };

    use crate::{ORDER_AUTH_TABLE, test_helpers::mock_db};

    /// Create a dummy Schnorr signature for testing
    fn dummy_schnorr_signature() -> SchnorrSignature {
        SchnorrSignature { s: EmbeddedScalarField::from(0u64), r: BabyJubJubPoint::default() }
    }

    /// Tests adding order auth then retrieving it
    #[test]
    fn test_write_and_get_order_auth() {
        let db = mock_db();
        db.create_table(ORDER_AUTH_TABLE).unwrap();

        // Write the order auth
        let order_id = OrderId::new_v4();
        let auth = mock_order_auth();

        let tx = db.new_write_tx().unwrap();
        tx.write_order_auth(&order_id, &auth).unwrap();
        tx.commit().unwrap();

        // Read the order auth
        let tx = db.new_read_tx().unwrap();
        let auth_res = tx.get_order_auth(&order_id).unwrap();
        assert!(auth_res.is_some());
        let retrieved = auth_res.unwrap().deserialize().unwrap();
        assert_eq!(retrieved, auth);
    }

    /// Tests checking if order auth exists
    #[test]
    fn test_contains_order_auth() {
        let db = mock_db();
        db.create_table(ORDER_AUTH_TABLE).unwrap();

        let order_id = OrderId::new_v4();
        let auth =
            OrderAuth::NativelySettledPrivateOrder { intent_signature: dummy_schnorr_signature() };

        // Check that auth doesn't exist initially
        let tx = db.new_read_tx().unwrap();
        assert!(!tx.contains_order_auth(&order_id).unwrap());
        drop(tx);

        // Write the auth
        let tx = db.new_write_tx().unwrap();
        tx.write_order_auth(&order_id, &auth).unwrap();
        tx.commit().unwrap();

        // Check that auth exists now
        let tx = db.new_read_tx().unwrap();
        assert!(tx.contains_order_auth(&order_id).unwrap());
    }

    /// Tests deleting order auth
    #[test]
    fn test_delete_order_auth() {
        let db = mock_db();
        db.create_table(ORDER_AUTH_TABLE).unwrap();

        let order_id = OrderId::new_v4();
        let auth = OrderAuth::RenegadeSettledOrder {
            intent_signature: dummy_schnorr_signature(),
            new_output_balance_signature: dummy_schnorr_signature(),
        };

        // Write the auth
        let tx = db.new_write_tx().unwrap();
        tx.write_order_auth(&order_id, &auth).unwrap();
        tx.commit().unwrap();

        // Verify it exists
        let tx = db.new_read_tx().unwrap();
        assert!(tx.contains_order_auth(&order_id).unwrap());
        drop(tx);

        // Delete the auth
        let tx = db.new_write_tx().unwrap();
        tx.delete_order_auth(&order_id).unwrap();
        tx.commit().unwrap();

        // Verify it's deleted
        let tx = db.new_read_tx().unwrap();
        assert!(!tx.contains_order_auth(&order_id).unwrap());
        let auth_res = tx.get_order_auth(&order_id).unwrap();
        assert!(auth_res.is_none());
    }
}
