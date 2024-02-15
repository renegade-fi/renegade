//! Helpers for accessing network order book information in the database

use circuit_types::wallet::Nullifier;
use common::types::{
    gossip::ClusterId,
    network_order::{NetworkOrder, NetworkOrderState},
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::OrderIdentifier,
};
use libmdbx::{TransactionKind, RW};

use crate::{
    applicator::order_book::{OrderPriority, CLUSTER_DEFAULT_PRIORITY, ORDER_DEFAULT_PRIORITY},
    storage::error::StorageError,
    ORDERS_TABLE, PRIORITIES_TABLE,
};

use super::StateTxn;

/// Error emitted when an order is not found in the book
const ERR_ORDER_NOT_FOUND: &str = "Order not found";

// -----------
// | Helpers |
// -----------

/// Create an order key from an order ID
pub fn order_key(id: &OrderIdentifier) -> String {
    format!("order:{id}")
}

/// Create a nullifier key from a nullifier
pub fn nullifier_key(nullifier: Nullifier) -> String {
    format!("nullifier:{nullifier}")
}

/// The key for the locally managed order set
pub fn locally_managed_key() -> String {
    "local-orders".to_string()
}

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    // --- Interface --- //

    /// Check if the order book contains an order
    pub fn contains_order(&self, order_id: &OrderIdentifier) -> Result<bool, StorageError> {
        self.get_order_info(order_id).map(|res| res.is_some())
    }

    /// Get the order associated with the given ID
    pub fn get_order_info(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<Option<NetworkOrder>, StorageError> {
        let key = order_key(order_id);

        // The `NetworkOrder` type skips the validity proof witnesses when serializing
        // for gossip layer safety, so we store them adjacently and must here re-attach
        // the witness
        let res = self
            .inner()
            .read::<_, (NetworkOrder, Option<OrderValidityWitnessBundle>)>(ORDERS_TABLE, &key)?
            .map(|(mut order, witness)| {
                order.validity_proof_witnesses = witness;
                order
            });

        Ok(res)
    }

    /// Get the priority for an order
    pub fn get_order_priority(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<OrderPriority, StorageError> {
        // Lookup the order info
        let info = self
            .get_order_info(order_id)?
            .ok_or_else(|| StorageError::NotFound(ERR_ORDER_NOT_FOUND.to_string()))?;

        let cluster_priority = self.get_cluster_priority(&info.cluster)?;
        let order_priority =
            self.inner().read(PRIORITIES_TABLE, order_id)?.unwrap_or(ORDER_DEFAULT_PRIORITY);

        Ok(OrderPriority { cluster_priority, order_priority })
    }

    /// Get the IDs of orders managed by the local peer's cluster
    pub fn get_local_orders(&self) -> Result<Vec<OrderIdentifier>, StorageError> {
        let key = locally_managed_key();
        self.read_set(ORDERS_TABLE, &key)
    }

    /// Get the orders associated with a given nullifier
    pub fn get_orders_by_nullifier(
        &self,
        nullifier: Nullifier,
    ) -> Result<Vec<OrderIdentifier>, StorageError> {
        let key = nullifier_key(nullifier);
        self.read_set(ORDERS_TABLE, &key)
    }

    /// Get all orders in the book
    pub fn get_all_orders(&self) -> Result<Vec<NetworkOrder>, StorageError> {
        // Build a cursor over the table
        let cursor = self
            .inner()
            .cursor::<String, (NetworkOrder, Option<OrderValidityWitnessBundle>)>(ORDERS_TABLE)?
            .with_key_filter(|key| key.starts_with("order:"));

        // Destructure the result and handle errors
        let mut res = Vec::new();
        for elem in cursor.into_iter().values() {
            let (order, _) = elem?;
            res.push(order);
        }

        Ok(res)
    }

    // --- Helpers --- //

    /// Get an order and error if it is not present
    fn get_order_info_or_err(
        &self,
        order_id: &OrderIdentifier,
    ) -> Result<NetworkOrder, StorageError> {
        self.get_order_info(order_id)?
            .ok_or(StorageError::NotFound(ERR_ORDER_NOT_FOUND.to_string()))
    }

    /// Get the priority of a cluster
    fn get_cluster_priority(&self, cluster_id: &ClusterId) -> Result<u32, StorageError> {
        self.inner()
            .read(PRIORITIES_TABLE, cluster_id)
            .map(|priority| priority.unwrap_or(CLUSTER_DEFAULT_PRIORITY))
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    // --- Interface --- //

    /// Add an order to the order book
    pub fn write_order(&self, order: &NetworkOrder) -> Result<(), StorageError> {
        let key = order_key(&order.id);

        // The `NetworkOrder` type skips the validity proof witnesses when serializing
        // for gossip layer safety, so we store them adjacently
        let mut order = order.clone();
        let validity_witness = order.validity_proof_witnesses.take();
        self.inner().write(ORDERS_TABLE, &key, &(order, validity_witness))
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
        order_id: &OrderIdentifier,
        proof: OrderValidityProofBundle,
    ) -> Result<(), StorageError> {
        // Update the nullifier as per the proof
        let new_nullifier = proof.reblind_proof.statement.original_shares_nullifier;
        self.update_order_nullifier_set(order_id, new_nullifier)?;

        // Update the order itself
        let mut order = self.get_order_info_or_err(order_id)?;
        order.validity_proofs = Some(proof);
        order.public_share_nullifier = new_nullifier;
        order.state = NetworkOrderState::Verified;

        self.write_order(&order)
    }

    /// Attach a validity witness to an order
    pub fn attach_validity_witness(
        &self,
        order_id: &OrderIdentifier,
        witness: OrderValidityWitnessBundle,
    ) -> Result<(), StorageError> {
        let mut order = self.get_order_info_or_err(order_id)?;
        order.validity_proof_witnesses = Some(witness);

        self.write_order(&order)
    }

    /// Cancel an order in the order book
    pub fn cancel_order(&self, order_id: &OrderIdentifier) -> Result<(), StorageError> {
        let mut order = self.get_order_info_or_err(order_id)?;
        order.state = NetworkOrderState::Cancelled;
        order.validity_proof_witnesses = None;
        order.validity_proofs = None;

        self.write_order(&order)?;
        self.remove_from_nullifier_set(order.public_share_nullifier, order_id)
    }

    /// Nullify the orders indexed by the given nullifier
    pub fn nullify_orders(&self, nullifier: Nullifier) -> Result<(), StorageError> {
        let orders = self.get_orders_by_nullifier(nullifier)?;
        for order_id in orders {
            self.cancel_order(&order_id)?;
        }

        Ok(())
    }

    /// Update the nullifier sets after a (potential) nullifier change
    pub fn update_order_nullifier_set(
        &self,
        order_id: &OrderIdentifier,
        new_nullifier: Nullifier,
    ) -> Result<(), StorageError> {
        // Remove from the old nullifier set and add to the new one
        if let Some(order_info) = self.get_order_info(order_id)? {
            self.remove_from_nullifier_set(order_info.public_share_nullifier, order_id)?;
        }

        self.add_to_nullifier_set(new_nullifier, order_id)
    }

    /// Add an order to the locally managed orders set
    pub fn mark_order_local(&self, order_id: &OrderIdentifier) -> Result<(), StorageError> {
        let key = locally_managed_key();
        self.add_to_set(ORDERS_TABLE, &key, order_id)
    }

    /// Remove an order from the locally managed orders set
    pub fn remove_local_order(&self, order_id: &OrderIdentifier) -> Result<(), StorageError> {
        let key = locally_managed_key();
        self.remove_from_set(ORDERS_TABLE, &key, order_id)
    }

    // --- Helpers --- //

    /// Add an order to a nullifier set
    fn add_to_nullifier_set(
        &self,
        nullifier: Nullifier,
        order_id: &OrderIdentifier,
    ) -> Result<(), StorageError> {
        let key = nullifier_key(nullifier);
        self.add_to_set(ORDERS_TABLE, &key, order_id)
    }

    /// Remove an order from a nullifier set
    fn remove_from_nullifier_set(
        &self,
        nullifier: Nullifier,
        order_id: &OrderIdentifier,
    ) -> Result<(), StorageError> {
        let key = nullifier_key(nullifier);
        self.remove_from_set(ORDERS_TABLE, &key, order_id)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use common::types::{
        network_order::{test_helpers::dummy_network_order, NetworkOrderState},
        proof_bundles::mocks::{
            dummy_valid_reblind_bundle, dummy_validity_proof_bundle, dummy_validity_witness_bundle,
        },
    };
    use constants::Scalar;
    use itertools::Itertools;
    use rand::thread_rng;

    use crate::{test_helpers::mock_db, ORDERS_TABLE, PRIORITIES_TABLE};

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
        assert_eq!(order, stored_order);
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
        let mut all_orders = tx.get_all_orders().unwrap();

        // Sort the orders by ID and compare
        all_orders.sort_by(|a, b| a.id.cmp(&b.id));
        orders.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(all_orders, orders);
    }

    /// Tests attaching a validity proof to an order
    #[test]
    fn test_write_validity_proof() {
        let db = mock_db();
        db.create_table(ORDERS_TABLE).unwrap();
        db.create_table(PRIORITIES_TABLE).unwrap();

        // Write the order to the book
        let order = dummy_network_order();
        let original_nullifier = order.public_share_nullifier;
        let tx = db.new_write_tx().unwrap();
        tx.write_order(&order).unwrap();
        tx.commit().unwrap();

        // Attach a validity proof to the order
        let mut rng = thread_rng();
        let mut proof = dummy_validity_proof_bundle();
        let nullifier = Scalar::random(&mut rng);
        let mut reblind_proof = dummy_valid_reblind_bundle();
        reblind_proof.statement.original_shares_nullifier = nullifier;
        proof.reblind_proof = Arc::new(reblind_proof);

        let tx = db.new_write_tx().unwrap();
        tx.attach_validity_proof(&order.id, proof).unwrap();
        tx.commit().unwrap();

        // Check that the order is updated
        let tx = db.new_read_tx().unwrap();
        let stored_order = tx.get_order_info(&order.id).unwrap().unwrap();
        assert_eq!(stored_order.state, NetworkOrderState::Verified);
        assert!(stored_order.validity_proofs.is_some());
        assert_eq!(stored_order.public_share_nullifier, nullifier);

        // Check that the nullifier sets are updated correctly
        let original_nullifiers = tx.get_orders_by_nullifier(original_nullifier).unwrap();
        assert!(original_nullifiers.is_empty());

        let new_nullifiers = tx.get_orders_by_nullifier(nullifier).unwrap();
        assert_eq!(new_nullifiers, vec![order.id]);
    }

    /// Tests attaching a validity witness to an order
    #[test]
    fn test_write_validity_witness() {
        let db = mock_db();
        db.create_table(ORDERS_TABLE).unwrap();
        db.create_table(PRIORITIES_TABLE).unwrap();

        // Write the order to the book
        let order = dummy_network_order();
        let tx = db.new_write_tx().unwrap();
        tx.write_order(&order).unwrap();
        tx.commit().unwrap();

        // Attach a validity proof to the order
        let witness = dummy_validity_witness_bundle();

        let tx = db.new_write_tx().unwrap();
        tx.attach_validity_witness(&order.id, witness).unwrap();
        tx.commit().unwrap();

        // Check that the order is updated
        let tx = db.new_read_tx().unwrap();
        let stored_order = tx.get_order_info(&order.id).unwrap().unwrap();
        assert!(stored_order.validity_proof_witnesses.is_some());
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
        tx.update_order_nullifier_set(&order1.id, order1.public_share_nullifier).unwrap();
        tx.update_order_nullifier_set(&order2.id, order2.public_share_nullifier).unwrap();
        tx.commit().unwrap();

        // Nullify the first order
        let tx = db.new_write_tx().unwrap();
        tx.nullify_orders(order1.public_share_nullifier).unwrap();
        tx.commit().unwrap();

        // Check that the orders are updated correctly
        let tx = db.new_read_tx().unwrap();
        let stored_order = tx.get_order_info(&order1.id).unwrap().unwrap();
        assert_eq!(stored_order.state, NetworkOrderState::Cancelled);
        assert!(stored_order.validity_proofs.is_none());

        let stored_order = tx.get_order_info(&order2.id).unwrap().unwrap();
        assert_eq!(stored_order, order2);
    }

    /// Tests adding and removing local orders
    #[test]
    fn test_local_orders() {
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
        let local_orders = tx.get_local_orders().unwrap();
        assert!(local_orders.contains(&order1.id));
        assert!(local_orders.contains(&order2.id));
        assert_eq!(local_orders.len(), 2);

        // Remove one order from the local orders set
        let tx = db.new_write_tx().unwrap();
        tx.remove_local_order(&order2.id).unwrap();
        tx.commit().unwrap();

        // Check that the correct order is removed and the others remain
        let tx = db.new_read_tx().unwrap();
        let local_orders = tx.get_local_orders().unwrap();
        assert!(local_orders.contains(&order1.id));
        assert!(!local_orders.contains(&order2.id));
        assert_eq!(local_orders.len(), 1);
    }
}
