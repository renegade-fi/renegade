//! Applicator methods for the network order book, separated out for discoverability
//!
//! TODO: For the order book in particular, it is likely to our advantage to index orders outside
//! of the DB as well in an in-memory data structure for efficient lookup

use common::types::{gossip::ClusterId, network_order::NetworkOrder, wallet::OrderIdentifier};
use constants::ORDER_STATE_CHANGE_TOPIC;
use external_api::bus_message::SystemBusMessage;
use libmdbx::{TransactionKind, RW};
use mpc_stark::algebra::scalar::Scalar;
use serde::{Deserialize, Serialize};
use state_proto::{
    AddOrder as AddOrderMsg, AddOrderValidityProof as AddOrderValidityProofMsg,
    NullifyOrders as NullifyOrdersMsg,
};

use crate::{
    applicator::{error::StateApplicatorError, ORDERS_TABLE, PRIORITIES_TABLE},
    storage::db::DbTxn,
};

use super::{Result, StateApplicator};

// -------------
// | Constants |
// -------------

/// The default priority for a cluster
const CLUSTER_DEFAULT_PRIORITY: u32 = 1;
/// The default priority for an order
const ORDER_DEFAULT_PRIORITY: u32 = 1;

/// The error message emitted when an order is missing from the message
const ERR_ORDER_MISSING: &str = "Order missing from message";

// ----------------------------
// | Orderbook Implementation |
// ----------------------------

/// A type that represents the priority for an order, including its cluster
/// priority
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrderPriority {
    /// The priority of the cluster that the order is managed by
    cluster_priority: u32,
    /// The priority of the order itself
    order_priority: u32,
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
    pub fn new_order(&self, msg: AddOrderMsg) -> Result<()> {
        // Parse the order from the message to a runtime type
        let order: NetworkOrder = msg
            .order
            .ok_or_else(|| StateApplicatorError::Parse(ERR_ORDER_MISSING.to_string()))
            .and_then(|order| NetworkOrder::try_from(order).map_err(StateApplicatorError::Proto))?;

        // Index the order
        let tx = self
            .db()
            .new_write_tx()
            .map_err(StateApplicatorError::Storage)?;
        Self::write_order_priority_with_tx(&order, &tx)?;
        Self::add_order_with_tx(&order, &tx)?;

        tx.commit().map_err(StateApplicatorError::Storage)?;

        // Push a message to the bus
        self.system_bus().publish(
            ORDER_STATE_CHANGE_TOPIC.to_string(),
            SystemBusMessage::NewOrder { order },
        );
        Ok(())
    }

    /// Add a validity proof for an order
    pub fn add_order_validity_proof(&self, msg: AddOrderValidityProofMsg) -> Result<()> {
        unimplemented!()
    }

    /// Nullify orders indexed by a given wallet share nullifier
    pub fn nullify_orders(&self, msg: NullifyOrdersMsg) -> Result<()> {
        unimplemented!()
    }

    // -----------
    // | Helpers |
    // -----------

    /// Get the priority of a cluster
    fn get_cluster_priority_with_tx<T: TransactionKind>(
        cluster_id: &ClusterId,
        tx: &DbTxn<'_, T>,
    ) -> Result<u32> {
        tx.read(PRIORITIES_TABLE, cluster_id)
            .map_err(StateApplicatorError::Storage)
            .map(|priority| priority.unwrap_or(CLUSTER_DEFAULT_PRIORITY))
    }

    /// Write an order priority to the DB
    fn write_order_priority_with_tx(order: &NetworkOrder, tx: &DbTxn<'_, RW>) -> Result<()> {
        // Lookup the cluster priority and write the order's priority
        let cluster_priority = Self::get_cluster_priority_with_tx(&order.cluster, tx)?;
        let priority = OrderPriority {
            cluster_priority,
            order_priority: ORDER_DEFAULT_PRIORITY,
        };

        tx.write(PRIORITIES_TABLE, &order.id, &priority)
            .map_err(StateApplicatorError::Storage)
    }

    /// Add an order to the book
    ///
    /// TODO: For an initial implementation we do not re-index based on local orders or
    /// verified orders. This will be added with the getter implementations
    fn add_order_with_tx(order: &NetworkOrder, tx: &DbTxn<'_, RW>) -> Result<()> {
        // Write the order to storage
        let order_key = Self::order_key(&order.id);
        tx.write(ORDERS_TABLE, &order_key, order)
            .map_err(StateApplicatorError::Storage)?;

        // Add the order to the set of orders indexed by the nullifier
        let nullifier_key = Self::nullifier_key(order.public_share_nullifier);
        let mut nullifier_set: Vec<OrderIdentifier> = tx
            .read(ORDERS_TABLE, &nullifier_key)
            .map_err(StateApplicatorError::Storage)?
            .unwrap_or_default();
        if !nullifier_set.contains(&order.id) {
            nullifier_set.push(order.id);
            tx.write(ORDERS_TABLE, &nullifier_key, &nullifier_set)
                .map_err(StateApplicatorError::Storage)?;
        }

        Ok(())
    }

    /// Create an order key from an order ID
    fn order_key(id: &OrderIdentifier) -> String {
        format!("order:{id}")
    }

    /// Create a nullifier key from a nullifier
    fn nullifier_key(nullifier: Scalar) -> String {
        format!("nullifier:{nullifier}")
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use common::types::{network_order::NetworkOrder, wallet::OrderIdentifier};
    use mpc_stark::algebra::scalar::Scalar;
    use rand::thread_rng;
    use state_proto::{AddOrder, NetworkOrderBuilder, NetworkOrderState};
    use uuid::Uuid;

    use crate::applicator::{
        order_book::OrderPriority, test_helpers::mock_applicator, StateApplicator, ORDERS_TABLE,
        PRIORITIES_TABLE,
    };

    /// Creates a dummy `AddOrder` message for testing
    fn add_order_msg() -> AddOrder {
        let mut rng = thread_rng();
        let order = NetworkOrderBuilder::default()
            .id(Uuid::new_v4().into())
            .cluster("cluster".to_string().into())
            .nullifier(Scalar::random(&mut rng).into())
            .state(NetworkOrderState::Received.into())
            .build()
            .unwrap();

        AddOrder { order: Some(order) }
    }

    /// Tests adding an order to the order book
    #[test]
    fn test_add_order() {
        let applicator = mock_applicator();

        // Add an order to the book
        let msg = add_order_msg();
        applicator.new_order(msg.clone()).unwrap();

        // Verify the order is indexed
        let db = applicator.db();

        let expected_order: NetworkOrder = msg.order.unwrap().try_into().unwrap();
        let order = db
            .read::<_, NetworkOrder>(
                ORDERS_TABLE,
                &StateApplicator::order_key(&expected_order.id),
            )
            .unwrap()
            .unwrap();

        assert_eq!(order, expected_order);

        // Verify that the order is indexed by its nullifier
        let orders: Vec<OrderIdentifier> = db
            .read(
                ORDERS_TABLE,
                &StateApplicator::nullifier_key(expected_order.public_share_nullifier),
            )
            .unwrap()
            .unwrap();

        assert_eq!(orders, vec![expected_order.id]);

        // Verify that the priority of the order is set to the default
        let priority: OrderPriority = db
            .read(PRIORITIES_TABLE, &expected_order.id)
            .unwrap()
            .unwrap();
        assert_eq!(priority, OrderPriority::default());
    }
}
