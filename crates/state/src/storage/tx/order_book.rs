//! Helpers for accessing network order book information in the database

use alloy_primitives::map::HashSet;
use circuit_types::Nullifier;
use libmdbx::{RW, TransactionKind};
use types_account::OrderId;
use types_gossip::{
    ClusterId,
    network_order::{
        CLUSTER_DEFAULT_PRIORITY, NetworkOrder, ORDER_DEFAULT_PRIORITY, OrderPriority,
    },
};
use uuid::Uuid;

use crate::{
    ORDERS_TABLE, PRIORITIES_TABLE,
    storage::{
        ArchivedValue,
        error::StorageError,
        traits::{RkyvValue, WithScalar},
    },
};

use super::StateTxn;

/// An archived order ID type
#[allow(dead_code)]
type ArchivedUuid = <Uuid as RkyvValue>::ArchivedType;
/// A type alias for an archived network order
type NetworkOrderValue<'a> = ArchivedValue<'a, NetworkOrder>;
/// A type alias for an archived order ID
type OrderIdValue<'a> = ArchivedValue<'a, OrderId>;
/// A type alias for an order set
type OrderSetValue<'a> = ArchivedValue<'a, HashSet<Uuid>>;

/// Create an order not found error
fn order_not_found(id: &OrderId) -> StorageError {
    StorageError::NotFound(format!("Order not found: {id}"))
}

// -----------
// | Helpers |
// -----------

/// Create an order key from an order ID
pub fn order_key(id: &OrderId) -> String {
    format!("order:{id}")
}

/// Create a nullifier key from a nullifier
pub fn nullifier_key(nullifier: Nullifier) -> String {
    format!("nullifier:{nullifier}")
}

/// The key for the set of locally managed open orders
pub fn locally_managed_key() -> String {
    "local-orders".to_string()
}

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    // --- Interface --- //

    /// Check if the order book contains an order
    pub fn contains_order(&self, order_id: &OrderId) -> Result<bool, StorageError> {
        let key = order_key(order_id);
        let order_value = self.inner.read::<_, NetworkOrder>(ORDERS_TABLE, &key)?;

        Ok(order_value.is_some())
    }

    /// Get the order associated with the given ID
    pub fn get_order_info(
        &self,
        order_id: &OrderId,
    ) -> Result<Option<NetworkOrderValue<'_>>, StorageError> {
        let key = order_key(order_id);
        self.inner().read(ORDERS_TABLE, &key)
    }

    /// Get the priority for an order
    pub fn get_order_priority(&self, order_id: &OrderId) -> Result<OrderPriority, StorageError> {
        // Lookup the order info
        let info = self.get_order_info(order_id)?.ok_or_else(|| order_not_found(order_id))?;
        let cluster = ClusterId::from_archived(&info.cluster)?;

        let cluster_priority = self.get_cluster_priority(&cluster)?;
        let priority = self.inner().read::<_, OrderPriority>(PRIORITIES_TABLE, order_id)?;
        let order_priority = match priority {
            Some(priority) => priority.deserialize()?.order_priority,
            None => ORDER_DEFAULT_PRIORITY,
        };

        Ok(OrderPriority { cluster_priority, order_priority })
    }

    /// Get the IDs of open orders managed by the local peer's cluster
    pub fn get_local_orders(&self) -> Result<Option<OrderSetValue>, StorageError> {
        let key = locally_managed_key();
        self.inner().read(ORDERS_TABLE, &key)
    }

    /// Get the order associated with a given nullifier
    pub fn get_order_by_nullifier(
        &self,
        nullifier: Nullifier,
    ) -> Result<Option<OrderIdValue<'_>>, StorageError> {
        let key = nullifier_key(nullifier);
        self.inner().read(ORDERS_TABLE, &key)
    }

    /// Get all orders in the book
    ///
    /// Warning: this can be very slow when the state has a medium to large
    /// number of orders
    pub fn get_all_orders(&self) -> Result<Vec<NetworkOrderValue>, StorageError> {
        // Build a cursor over the table with order prefix
        let cursor =
            self.inner().cursor::<String, NetworkOrder>(ORDERS_TABLE)?.with_key_prefix("order:");

        // Destructure the result and handle errors
        let mut res = Vec::new();
        for elem in cursor.into_iter().values() {
            let order = elem?;
            res.push(order);
        }

        Ok(res)
    }

    // --- Helpers --- //

    /// Get an order and error if it is not present
    fn get_order_info_or_err(&self, order_id: &OrderId) -> Result<NetworkOrderValue, StorageError> {
        self.get_order_info(order_id)?.ok_or(order_not_found(order_id))
    }

    /// Get the priority of a cluster
    fn get_cluster_priority(&self, cluster_id: &ClusterId) -> Result<u32, StorageError> {
        let maybe_priority = self.inner().read::<_, u32>(PRIORITIES_TABLE, cluster_id)?;

        let cluster_priority = match maybe_priority {
            Some(value) => value.deserialize()?,
            None => CLUSTER_DEFAULT_PRIORITY,
        };
        Ok(cluster_priority)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    // --- Interface --- //

    /// Add an order to the order book
    pub fn write_order(&self, order: &NetworkOrder) -> Result<(), StorageError> {
        // First, update the nullifier -> order mapping
        self.update_order_nullifier(&order.id, order.nullifier)?;

        let key = order_key(&order.id);
        let order = order.clone();
        self.inner().write(ORDERS_TABLE, &key, &order)
    }

    /// Write the priority of an order
    pub fn write_order_priority(&self, order: &NetworkOrder) -> Result<(), StorageError> {
        let cluster_priority = self.get_cluster_priority(&order.cluster)?;
        let order_priority = ORDER_DEFAULT_PRIORITY;

        self.inner().write(
            PRIORITIES_TABLE,
            &order.id,
            &OrderPriority { cluster_priority, order_priority },
        )
    }

    /// Attach a validity proof to an order
    ///
    /// Assumed that the proof has been successfully verified higher in the
    /// callstack
    pub fn attach_validity_proof(
        &self,
        order_id: &OrderId,
        proof: Nullifier,
    ) -> Result<(), StorageError> {
        // TODO: Implement validity proof storage
        // self.write_validity_proof_bundle(order_id, proof)?;
        let nullifier = proof; // TODO: delete this
        // Update the nullifier as per the proof
        self.update_order_nullifier(order_id, nullifier)?;

        // Update the order itself
        let order_value = self.get_order_info_or_err(order_id)?;
        let mut order = order_value.deserialize()?;
        order.transition_verified(nullifier);

        self.write_order(&order)
    }

    /// Delete an order from the order book
    pub fn delete_order(&self, order_id: &OrderId) -> Result<(), StorageError> {
        let order_key = order_key(order_id);
        let order_info = self.get_order_info(order_id)?.ok_or(order_not_found(order_id))?;

        // Deserialize the nullifier before deleting the order
        let nullifier: Nullifier = WithScalar::from_archived(&order_info.nullifier)?.into_inner();
        let is_local = order_info.local;
        self.inner().delete(ORDERS_TABLE, &order_key)?;

        // Remove from the nullifier mapping
        self.remove_nullifier_mapping(nullifier)?;
        if is_local {
            self.remove_local_order(order_id)?;
        }

        // Remove from the priority table
        self.inner().delete(PRIORITIES_TABLE, order_id)?;
        // Remove order authorization
        self.delete_order_auth(order_id)?;
        Ok(())
    }

    /// Nullify the order indexed by the given nullifier.
    /// Returns the ID of the deleted order if one was found.
    pub fn nullify_order(&self, nullifier: Nullifier) -> Result<Option<OrderId>, StorageError> {
        // Get the order for this nullifier
        let order_id = match self.get_order_by_nullifier(nullifier)? {
            Some(id) => id.deserialize()?,
            None => return Ok(None),
        };

        // Delete the order; this also removes the nullifier mapping
        self.delete_order(&order_id)?;
        Ok(Some(order_id))
    }

    /// Update the nullifier mapping after a (potential) nullifier change
    pub fn update_order_nullifier(
        &self,
        order_id: &OrderId,
        new_nullifier: Nullifier,
    ) -> Result<(), StorageError> {
        // Remove the old nullifier mapping if it exists
        if let Some(order_info) = self.get_order_info(order_id)? {
            let old_nullifier = WithScalar::from_archived(&order_info.nullifier)?;
            self.remove_nullifier_mapping(old_nullifier.into_inner())?;
        }

        // Set the new nullifier mapping
        self.set_nullifier_mapping(new_nullifier, order_id)
    }

    /// Add an order to the locally managed orders set
    pub fn mark_order_local(&self, order_id: &OrderId) -> Result<(), StorageError> {
        let key = locally_managed_key();

        // Read-modify-write the local orders set
        let mut set = match self.get_local_orders()? {
            Some(archived) => archived.deserialize()?,
            None => HashSet::default(),
        };
        set.insert(*order_id);
        self.inner().write(ORDERS_TABLE, &key, &set)
    }

    /// Remove an order from the locally managed orders set
    pub fn remove_local_order(&self, order_id: &OrderId) -> Result<(), StorageError> {
        let key = locally_managed_key();

        // Read-modify-write the local orders set
        let set = match self.get_local_orders()? {
            Some(archived) => archived.deserialize()?,
            None => return Ok(()),
        };

        let mut set: HashSet<Uuid> = set;
        set.remove(order_id);
        self.inner().write(ORDERS_TABLE, &key, &set)
    }

    // --- Helpers --- //

    /// Set a nullifier -> order mapping
    fn set_nullifier_mapping(
        &self,
        nullifier: Nullifier,
        order_id: &OrderId,
    ) -> Result<(), StorageError> {
        let key = nullifier_key(nullifier);
        self.inner().write(ORDERS_TABLE, &key, order_id)
    }

    /// Remove a nullifier mapping
    fn remove_nullifier_mapping(&self, nullifier: Nullifier) -> Result<(), StorageError> {
        let key = nullifier_key(nullifier);
        self.inner().delete(ORDERS_TABLE, &key).map(|_| ())
    }
}

#[cfg(test)]
mod test {
    use constants::Scalar;
    use itertools::Itertools;
    use rand::thread_rng;
    use types_gossip::network_order::{
        ArchivedNetworkOrderState, test_helpers::dummy_network_order,
    };

    use crate::{ORDERS_TABLE, PRIORITIES_TABLE, test_helpers::mock_db};

    /// Tests adding an order to the order book
    #[test]
    fn test_write_order() {
        let db = mock_db();
        db.create_table(ORDERS_TABLE).unwrap();

        // Write the order to the book
        let order = dummy_network_order();
        let tx = db.new_write_tx().unwrap();
        tx.write_order(&order).unwrap();
        tx.commit().unwrap();

        let tx = db.new_read_tx().unwrap();
        assert!(tx.contains_order(&order.id).unwrap());

        let stored_order = tx.get_order_info(&order.id).unwrap().unwrap();
        assert_eq!(order, stored_order.deserialize().unwrap());
    }

    /// Tests getting all orders in the book
    #[test]
    fn test_get_all_orders() {
        let db = mock_db();
        db.create_table(ORDERS_TABLE).unwrap();

        // Write a handful of orders to the book
        const N: usize = 10;
        let mut orders = (0..N).map(|_| dummy_network_order()).collect_vec();
        let tx = db.new_write_tx().unwrap();
        for order in orders.iter() {
            tx.write_order(order).unwrap();
        }
        tx.commit().unwrap();

        // Read back all the orders
        let tx = db.new_read_tx().unwrap();
        let mut all_orders: Vec<_> =
            tx.get_all_orders().unwrap().into_iter().map(|o| o.deserialize().unwrap()).collect();

        // Sort the orders by ID and compare
        all_orders.sort_by(|a, b| a.id.cmp(&b.id));
        orders.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(all_orders, orders);
    }

    /// Tests attaching a validity proof to an order
    #[test]
    fn test_attach_validity_proof() {
        let db = mock_db();
        db.create_table(ORDERS_TABLE).unwrap();
        db.create_table(PRIORITIES_TABLE).unwrap();

        // Write the order to the book
        let order = dummy_network_order();
        let original_nullifier = order.nullifier;
        let tx = db.new_write_tx().unwrap();
        tx.write_order(&order).unwrap();
        tx.commit().unwrap();

        // Attach a validity proof to the order
        let mut rng = thread_rng();
        let new_nullifier = Scalar::random(&mut rng);

        let tx = db.new_write_tx().unwrap();
        tx.attach_validity_proof(&order.id, new_nullifier).unwrap();
        tx.commit().unwrap();

        // Check that the order is updated
        let tx = db.new_read_tx().unwrap();
        let stored_order = tx.get_order_info(&order.id).unwrap().unwrap();
        assert!(matches!(stored_order.state, ArchivedNetworkOrderState::Verified));
        assert_eq!(stored_order.nullifier, new_nullifier);

        // Check that the nullifier mappings are updated correctly
        let original_order = tx.get_order_by_nullifier(original_nullifier).unwrap();
        assert!(original_order.is_none());

        let new_order = tx.get_order_by_nullifier(new_nullifier).unwrap();
        assert!(new_order.is_some());
        assert_eq!(new_order.unwrap().deserialize().unwrap(), order.id);
    }

    /// Tests nullifying an order
    #[test]
    fn test_nullify_order() {
        let db = mock_db();
        db.create_table(ORDERS_TABLE).unwrap();

        // Write two orders to the book, one that is nullified, one that is not
        let order1 = dummy_network_order();
        let order2 = dummy_network_order();
        let tx = db.new_write_tx().unwrap();
        tx.write_order(&order1).unwrap();
        tx.write_order(&order2).unwrap();
        tx.commit().unwrap();

        // Nullify the first order
        let tx = db.new_write_tx().unwrap();
        let nullified = tx.nullify_order(order1.nullifier).unwrap();
        tx.commit().unwrap();

        assert_eq!(nullified, Some(order1.id));

        // Check that the orders are updated correctly
        let tx = db.new_read_tx().unwrap();
        let stored_order = tx.get_order_info(&order1.id).unwrap();
        let order_by_nullifier = tx.get_order_by_nullifier(order1.nullifier).unwrap();
        assert!(stored_order.is_none());
        assert!(order_by_nullifier.is_none());

        let stored_order = tx.get_order_info(&order2.id).unwrap().unwrap();
        let order_by_nullifier = tx.get_order_by_nullifier(order2.nullifier).unwrap();
        assert_eq!(stored_order.deserialize().unwrap(), order2);
        assert!(order_by_nullifier.is_some());
        assert_eq!(order_by_nullifier.unwrap().deserialize().unwrap(), order2.id);
    }

    /// Tests adding and removing local orders
    #[test]
    fn test_local_orders() {
        use alloy_primitives::map::HashSet;
        use uuid::Uuid;

        let db = mock_db();
        db.create_table(ORDERS_TABLE).unwrap();

        // Write a few orders to the book and mark them as local
        let order1 = dummy_network_order();
        let order2 = dummy_network_order();
        let tx = db.new_write_tx().unwrap();
        tx.write_order(&order1).unwrap();
        tx.write_order(&order2).unwrap();
        tx.mark_order_local(&order1.id).unwrap();
        tx.mark_order_local(&order2.id).unwrap();
        tx.commit().unwrap();

        // Check that all orders are marked as local
        let tx = db.new_read_tx().unwrap();
        let local_orders = tx.get_local_orders().unwrap().unwrap();
        let local_orders: HashSet<Uuid> = local_orders.deserialize().unwrap();
        assert!(local_orders.contains(&order1.id));
        assert!(local_orders.contains(&order2.id));
        assert_eq!(local_orders.len(), 2);

        // Remove one order from the local orders set
        let tx = db.new_write_tx().unwrap();
        tx.remove_local_order(&order2.id).unwrap();
        tx.commit().unwrap();

        // Check that the correct order is removed and the others remain
        let tx = db.new_read_tx().unwrap();
        let local_orders = tx.get_local_orders().unwrap().unwrap();
        let local_orders: HashSet<Uuid> = local_orders.deserialize().unwrap();
        assert!(local_orders.contains(&order1.id));
        assert!(!local_orders.contains(&order2.id));
        assert_eq!(local_orders.len(), 1);
    }

    /// Tests deleting an order
    #[test]
    fn test_delete_order() {
        use types_gossip::network_order::OrderPriority;

        let db = mock_db();
        db.create_table(ORDERS_TABLE).unwrap();
        db.create_table(PRIORITIES_TABLE).unwrap();

        // Write an order to the book
        let order = dummy_network_order();
        let tx = db.new_write_tx().unwrap();
        tx.write_order(&order).unwrap();
        tx.commit().unwrap();

        // Delete the order
        let tx = db.new_write_tx().unwrap();
        tx.delete_order(&order.id).unwrap();
        tx.commit().unwrap();

        // Check that the order is deleted
        let tx = db.new_read_tx().unwrap();
        assert!(!tx.contains_order(&order.id).unwrap());

        let order_by_nullifier = tx.get_order_by_nullifier(order.nullifier).unwrap();
        assert!(order_by_nullifier.is_none());

        let local_orders = tx.get_local_orders().unwrap();
        assert!(local_orders.is_none());

        let priority = tx.inner().read::<_, OrderPriority>(PRIORITIES_TABLE, &order.id).unwrap();
        assert!(priority.is_none());
    }
}
