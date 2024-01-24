//! Applicator methods for the network order book, separated out for
//! discoverability
//!
//! TODO: For the order book in particular, it is likely to our advantage to
//! index orders outside of the DB as well in an in-memory data structure for
//! efficient lookup

use circuit_types::wallet::Nullifier;
use common::types::{
    network_order::NetworkOrder, proof_bundles::OrderValidityProofBundle, wallet::OrderIdentifier,
};
use constants::ORDER_STATE_CHANGE_TOPIC;
use external_api::bus_message::SystemBusMessage;
use libmdbx::RW;
use serde::{Deserialize, Serialize};

use crate::{applicator::error::StateApplicatorError, storage::tx::StateTxn};

use super::{Result, StateApplicator};

// -------------
// | Constants |
// -------------

/// The default priority for a cluster
pub const CLUSTER_DEFAULT_PRIORITY: u32 = 1;
/// The default priority for an order
pub const ORDER_DEFAULT_PRIORITY: u32 = 1;

/// The error message emitted when an order is missing from the message
const ERR_ORDER_MISSING: &str = "Order missing from message";

// ----------------------------
// | Orderbook Implementation |
// ----------------------------

/// A type that represents the match priority for an order, including its
/// cluster priority
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderPriority {
    /// The priority of the cluster that the order is managed by
    pub cluster_priority: u32,
    /// The priority of the order itself
    pub order_priority: u32,
}

impl Default for OrderPriority {
    fn default() -> Self {
        OrderPriority {
            cluster_priority: CLUSTER_DEFAULT_PRIORITY,
            order_priority: ORDER_DEFAULT_PRIORITY,
        }
    }
}

impl OrderPriority {
    /// Compute the effective scheduling priority for an order
    pub fn get_effective_priority(&self) -> u32 {
        self.cluster_priority * self.order_priority
    }
}

impl StateApplicator {
    // -------------
    // | Interface |
    // -------------

    /// Add a new order to the network order book
    pub fn new_order(&self, order: NetworkOrder) -> Result<()> {
        // Index the order, it's priority, and its nullifier
        let tx = self.db().new_write_tx()?;
        Self::add_order_with_tx(&order, &tx)?;
        tx.commit()?;

        // Push a message to the bus
        self.system_bus()
            .publish(ORDER_STATE_CHANGE_TOPIC.to_string(), SystemBusMessage::NewOrder { order });
        Ok(())
    }

    /// Add a validity proof for an order
    pub fn add_order_validity_proof(
        &self,
        order_id: OrderIdentifier,
        proof: OrderValidityProofBundle,
    ) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        tx.attach_validity_proof(&order_id, proof)?;
        let order_info = tx
            .get_order_info(&order_id)?
            .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_ORDER_MISSING.to_string()))?;

        tx.commit()?;

        self.system_bus().publish(
            ORDER_STATE_CHANGE_TOPIC.to_string(),
            SystemBusMessage::OrderStateChange { order: order_info },
        );
        Ok(())
    }

    /// Nullify orders indexed by a given wallet share nullifier
    pub fn nullify_orders(&self, nullifier: Nullifier) -> Result<()> {
        let tx = self.db().new_write_tx()?;
        tx.nullify_orders(nullifier)?;
        Ok(tx.commit()?)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Add an order within a given transaction
    pub(crate) fn add_order_with_tx(order: &NetworkOrder, tx: &StateTxn<RW>) -> Result<()> {
        // Update the order priority, the order, and its nullifier
        tx.write_order_priority(order)?;
        tx.write_order(order)?;
        Ok(tx.update_order_nullifier_set(&order.id, order.public_share_nullifier)?)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(all(test, feature = "all-tests"))]
mod test {
    use common::types::{
        network_order::{test_helpers::dummy_network_order, NetworkOrder, NetworkOrderState},
        proof_bundles::mocks::dummy_validity_proof_bundle,
        wallet::OrderIdentifier,
    };

    use crate::{
        applicator::{order_book::OrderPriority, test_helpers::mock_applicator},
        storage::tx::order_book::{nullifier_key, order_key},
        ORDERS_TABLE, PRIORITIES_TABLE,
    };

    /// Tests adding an order to the order book
    #[test]
    fn test_add_order() {
        let applicator = mock_applicator();

        // Add an order to the book
        let expected_order = dummy_network_order();
        applicator.new_order(expected_order.clone()).unwrap();

        // Verify the order is indexed
        let db = applicator.db();
        let order = db
            .read::<_, NetworkOrder>(ORDERS_TABLE, &order_key(&expected_order.id))
            .unwrap()
            .unwrap();

        assert_eq!(order, expected_order);

        // Verify that the order is indexed by its nullifier
        let orders: Vec<OrderIdentifier> = db
            .read(ORDERS_TABLE, &nullifier_key(expected_order.public_share_nullifier))
            .unwrap()
            .unwrap();

        assert_eq!(orders, vec![expected_order.id]);

        // Verify that the priority of the order is set to the default
        let priority: OrderPriority =
            db.read(PRIORITIES_TABLE, &expected_order.id).unwrap().unwrap();
        assert_eq!(priority, OrderPriority::default());
    }

    /// Test adding a validity proof to an order
    #[test]
    fn test_add_validity_proof() {
        let applicator = mock_applicator();

        // First add an order
        let order = dummy_network_order();
        applicator.new_order(order.clone()).unwrap();

        // Then add a validity proof
        let proof = dummy_validity_proof_bundle();
        applicator.add_order_validity_proof(order.id, proof).unwrap();

        // Verify that the order's state is updated
        let db = applicator.db();
        let tx: NetworkOrder = db.read(ORDERS_TABLE, &order_key(&order.id)).unwrap().unwrap();

        assert_eq!(tx.state, NetworkOrderState::Verified);
        assert!(tx.validity_proofs.is_some());
    }

    /// Test nullifying orders
    #[test]
    fn test_nullify_orders() {
        let applicator = mock_applicator();

        // Add two orders to the book
        let order1 = dummy_network_order();
        let order2 = dummy_network_order();

        applicator.new_order(order1.clone()).unwrap();
        applicator.new_order(order2.clone()).unwrap();

        // Nullify the first order
        applicator.nullify_orders(order1.public_share_nullifier).unwrap();

        // Verify that the first order is cancelled
        let db = applicator.db();
        let order1: NetworkOrder = db.read(ORDERS_TABLE, &order_key(&order1.id)).unwrap().unwrap();

        assert_eq!(order1.state, NetworkOrderState::Cancelled);

        // Verify that the second order is unmodified
        let expected_order2: NetworkOrder = order2;
        let order2: NetworkOrder =
            db.read(ORDERS_TABLE, &order_key(&expected_order2.id)).unwrap().unwrap();

        assert_eq!(order2, expected_order2);
    }
}
