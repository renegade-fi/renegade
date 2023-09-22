//! Applicator methods for the network order book, separated out for discoverability
//!
//! TODO: For the order book in particular, it is likely to our advantage to index orders outside
//! of the DB as well in an in-memory data structure for efficient lookup

use common::types::{
    gossip::ClusterId,
    network_order::{NetworkOrder, NetworkOrderState},
    proof_bundles::OrderValidityProofBundle,
    wallet::OrderIdentifier,
};
use constants::ORDER_STATE_CHANGE_TOPIC;
use external_api::bus_message::SystemBusMessage;
use itertools::Itertools;
use libmdbx::{TransactionKind, RW};
use mpc_stark::algebra::scalar::Scalar;
use serde::{Deserialize, Serialize};
use state_proto::{
    AddOrder as AddOrderMsg, AddOrderValidityProof as AddOrderValidityProofMsg,
    NullifyOrders as NullifyOrdersMsg,
};
use uuid::Error as UuidError;

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

/// A type that represents the match priority for an order, including its cluster priority
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
        // Deserialize the proof bundle
        let id: OrderIdentifier = msg
            .order_id
            .unwrap_or_default()
            .try_into()
            .map_err(|e: UuidError| StateApplicatorError::Parse(e.to_string()))?;

        let bundle: OrderValidityProofBundle = serde_json::from_slice(&msg.proof)
            .map_err(|e| StateApplicatorError::Parse(e.to_string()))?;

        let tx = self
            .db()
            .new_write_tx()
            .map_err(StateApplicatorError::Storage)?;
        Self::attach_validity_proof_with_tx(&id, bundle, &tx)?;
        let order_info = Self::read_order_info(&id, &tx)?;
        tx.commit().map_err(StateApplicatorError::Storage)?;

        self.system_bus().publish(
            ORDER_STATE_CHANGE_TOPIC.to_string(),
            SystemBusMessage::OrderStateChange { order: order_info },
        );
        Ok(())
    }

    /// Nullify orders indexed by a given wallet share nullifier
    pub fn nullify_orders(&self, msg: NullifyOrdersMsg) -> Result<()> {
        let nullifier: Scalar = msg.nullifier.unwrap_or_default().into();
        let tx = self
            .db()
            .new_write_tx()
            .map_err(StateApplicatorError::Storage)?;

        self.nullify_orders_with_tx(nullifier, &tx)?;
        tx.commit().map_err(StateApplicatorError::Storage)
    }

    // ------------------------
    // | Order Update Helpers |
    // ------------------------

    /// Add an order to the book
    ///
    /// TODO: For an initial implementation we do not re-index based on local orders or
    /// verified orders. This will be added with the getter implementations
    fn add_order_with_tx(order: &NetworkOrder, tx: &DbTxn<'_, RW>) -> Result<()> {
        // Write the order to storage
        Self::write_order_info(order, tx)?;
        // Add the order to the set of orders indexed by the nullifier
        Self::append_to_nullifier_set(order.public_share_nullifier, order.id, tx)
    }

    /// Update the validity proof for an order
    ///
    /// It is assumed that the proof has been verified before this method is called
    fn attach_validity_proof_with_tx(
        order_id: &OrderIdentifier,
        proof: OrderValidityProofBundle,
        tx: &DbTxn<'_, RW>,
    ) -> Result<()> {
        // Read the order's current info
        let mut order_info = Self::read_order_info(order_id, tx)?;

        // Re-index based on the proof's nullifier
        let prev_nullifier = order_info.public_share_nullifier;
        let new_nullifier = proof.reblind_proof.statement.original_shares_nullifier;
        if prev_nullifier != new_nullifier {
            Self::update_order_nullifier(order_id, prev_nullifier, new_nullifier, tx)?;
        }

        // Update the order's info
        order_info.state = NetworkOrderState::Verified;
        order_info.public_share_nullifier = proof.reblind_proof.statement.original_shares_nullifier;
        order_info.validity_proofs = Some(proof);
        Self::write_order_info(&order_info, tx)
    }

    /// Cancel an order
    fn cancel_order_with_tx(&self, order_id: &OrderIdentifier, tx: &DbTxn<'_, RW>) -> Result<()> {
        let mut order = Self::read_order_info(order_id, tx)?;
        order.state = NetworkOrderState::Cancelled;
        order.validity_proof_witnesses = None;
        order.validity_proofs = None;

        Self::write_order_info(&order, tx)?;
        self.system_bus().publish(
            ORDER_STATE_CHANGE_TOPIC.to_string(),
            SystemBusMessage::OrderStateChange { order },
        );

        Ok(())
    }

    // ----------------------
    // | Order Info Helpers |
    // ----------------------

    /// Reads the order info for the given order from storage
    ///
    /// Errors if the order is not present
    fn read_order_info<T: TransactionKind>(
        order_id: &OrderIdentifier,
        tx: &DbTxn<'_, T>,
    ) -> Result<NetworkOrder> {
        let order_key = Self::order_key(order_id);
        tx.read(ORDERS_TABLE, &order_key)
            .map_err(StateApplicatorError::Storage)?
            .ok_or_else(|| StateApplicatorError::MissingEntry(order_key))
    }

    /// Writes the order info for the given order to storage
    fn write_order_info(order: &NetworkOrder, tx: &DbTxn<'_, RW>) -> Result<()> {
        let order_key = Self::order_key(&order.id);
        tx.write(ORDERS_TABLE, &order_key, order)
            .map_err(StateApplicatorError::Storage)
    }

    // --------------------------
    // | Order Priority Helpers |
    // --------------------------

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

    // -------------------------
    // | Nullifier Set Helpers |
    // -------------------------

    /// Cancel all orders on a given nullifier
    fn nullify_orders_with_tx(&self, nullifier: Scalar, tx: &DbTxn<'_, RW>) -> Result<()> {
        let set = Self::read_nullifier_set(nullifier, tx)?;
        for order_id in set.into_iter() {
            self.cancel_order_with_tx(&order_id, tx)?;
        }

        Ok(())
    }

    /// Update the nullifier an order is indexed by
    fn update_order_nullifier(
        order_id: &OrderIdentifier,
        old_nullifier: Scalar,
        new_nullifier: Scalar,
        tx: &DbTxn<'_, RW>,
    ) -> Result<()> {
        // Read the nullifier set for the old nullifier and remove the order
        let old_set = Self::read_nullifier_set(old_nullifier, tx)?;
        let updated_old_set = old_set
            .into_iter()
            .filter(|id| id != order_id)
            .collect_vec();
        Self::write_nullifier_set(old_nullifier, updated_old_set, tx)?;

        // Add the order to the new nullifier set
        Self::append_to_nullifier_set(new_nullifier, *order_id, tx)
    }

    /// Read the nullifier set for a given nullifier
    fn read_nullifier_set<T: TransactionKind>(
        nullifier: Scalar,
        tx: &DbTxn<'_, T>,
    ) -> Result<Vec<OrderIdentifier>> {
        let nullifier_key = Self::nullifier_key(nullifier);
        tx.read(ORDERS_TABLE, &nullifier_key)
            .map_err(StateApplicatorError::Storage)
            .map(|set| set.unwrap_or_default())
    }

    /// Append an order to a given nullifier set
    fn append_to_nullifier_set(
        nullifier: Scalar,
        order_id: OrderIdentifier,
        tx: &DbTxn<'_, RW>,
    ) -> Result<()> {
        let key = Self::nullifier_key(nullifier);
        let mut nullifier_set = Self::read_nullifier_set(nullifier, tx)?;
        if !nullifier_set.contains(&order_id) {
            nullifier_set.push(order_id);
            tx.write(ORDERS_TABLE, &key, &nullifier_set)
                .map_err(StateApplicatorError::Storage)?;
        }

        Ok(())
    }

    /// Write the nullifier set for a given nullifier
    fn write_nullifier_set(
        nullifier: Scalar,
        nullifier_set: Vec<OrderIdentifier>,
        tx: &DbTxn<'_, RW>,
    ) -> Result<()> {
        let key = Self::nullifier_key(nullifier);
        tx.write(ORDERS_TABLE, &key, &nullifier_set)
            .map_err(StateApplicatorError::Storage)
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

#[cfg(all(test, feature = "all-tests"))]
mod test {

    use common::types::{
        network_order::NetworkOrder, proof_bundles::mocks::dummy_validity_proof_bundle,
        wallet::OrderIdentifier,
    };
    use mpc_stark::algebra::scalar::Scalar;
    use rand::thread_rng;
    use state_proto::{
        AddOrder, AddOrderValidityProof, AddOrderValidityProofBuilder, NetworkOrderBuilder,
        NetworkOrderState, NullifyOrdersBuilder,
    };
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

    /// Creates a dummy `AddOrderValidityProof` message for testing
    fn add_proof_msg(order_id: OrderIdentifier) -> AddOrderValidityProof {
        let mock_proof = dummy_validity_proof_bundle();
        let proof_bytes = serde_json::to_vec(&mock_proof).unwrap();

        AddOrderValidityProofBuilder::default()
            .order_id(order_id.into())
            .proof(proof_bytes)
            .build()
            .unwrap()
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

    /// Test adding a validity proof to an order
    #[test]
    fn test_add_validity_proof() {
        let applicator = mock_applicator();

        // First add an order
        let order_msg = add_order_msg();
        applicator.new_order(order_msg.clone()).unwrap();

        // Then add a validity proof
        let order_id: Uuid = order_msg.order.unwrap().id.unwrap().try_into().unwrap();
        let proof_msg = add_proof_msg(order_id);
        applicator.add_order_validity_proof(proof_msg).unwrap();

        // Verify that the order's state is updated
        let db = applicator.db();
        let tx: NetworkOrder = db
            .read(ORDERS_TABLE, &StateApplicator::order_key(&order_id))
            .unwrap()
            .unwrap();

        assert_eq!(tx.state, NetworkOrderState::Verified.into());
        assert!(tx.validity_proofs.is_some());
    }

    /// Test nullifying orders
    #[test]
    fn test_nullify_orders() {
        let applicator = mock_applicator();

        // Add two orders to the book
        let order_msg1 = add_order_msg();
        let order_msg2 = add_order_msg();

        applicator.new_order(order_msg1.clone()).unwrap();
        applicator.new_order(order_msg2.clone()).unwrap();

        // Nullify the first order
        let first_order: NetworkOrder = order_msg1.order.unwrap().try_into().unwrap();
        let msg = NullifyOrdersBuilder::default()
            .nullifier(first_order.public_share_nullifier.into())
            .build()
            .unwrap();
        applicator.nullify_orders(msg).unwrap();

        // Verify that the first order is cancelled
        let db = applicator.db();
        let order1: NetworkOrder = db
            .read(ORDERS_TABLE, &StateApplicator::order_key(&first_order.id))
            .unwrap()
            .unwrap();

        assert_eq!(order1.state, NetworkOrderState::Cancelled.into());

        // Verify that the second order is unmodified
        let expected_order2: NetworkOrder = order_msg2.order.unwrap().try_into().unwrap();
        let order2: NetworkOrder = db
            .read(
                ORDERS_TABLE,
                &StateApplicator::order_key(&expected_order2.id),
            )
            .unwrap()
            .unwrap();

        assert_eq!(order2, expected_order2);
    }
}
