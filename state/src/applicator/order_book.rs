//! Applicator methods for the network order book, separated out for
//! discoverability
//!
//! TODO: For the order book in particular, it is likely to our advantage to
//! index orders outside of the DB as well in an in-memory data structure for
//! efficient lookup

use common::types::{
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::OrderIdentifier,
};
use constants::ORDER_STATE_CHANGE_TOPIC;
use external_api::bus_message::SystemBusMessage;
use serde::{Deserialize, Serialize};

use crate::applicator::error::StateApplicatorError;

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

    /// Add a validity proof for an order
    pub fn add_order_validity_proof(
        &self,
        order_id: OrderIdentifier,
        proof: OrderValidityProofBundle,
        witness: OrderValidityWitnessBundle,
    ) -> Result<()> {
        let tx = self.db().new_write_tx()?;

        tx.attach_validity_proof(&order_id, proof)?;
        tx.attach_validity_witness(&order_id, witness)?;

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
}

// ---------
// | Tests |
// ---------

#[cfg(all(test, feature = "all-tests"))]
mod test {
    use common::types::{
        network_order::{test_helpers::dummy_network_order, NetworkOrderState},
        proof_bundles::mocks::{dummy_validity_proof_bundle, dummy_validity_witness_bundle},
    };

    use crate::applicator::test_helpers::mock_applicator;

    /// Test adding a validity proof to an order
    #[test]
    fn test_add_validity_proof() {
        let applicator = mock_applicator();

        // First add an order
        let order = dummy_network_order();
        let tx = applicator.db().new_write_tx().unwrap();
        tx.write_order(&order).unwrap();
        tx.commit().unwrap();

        // Then add a validity proof
        let proof = dummy_validity_proof_bundle();
        let witness = dummy_validity_witness_bundle();
        applicator.add_order_validity_proof(order.id, proof, witness).unwrap();

        // Verify that the order's state is updated
        let db = applicator.db();
        let tx = db.new_read_tx().unwrap();
        let order = tx.get_order_info(&order.id).unwrap().unwrap();

        assert_eq!(order.state, NetworkOrderState::Verified);
        assert!(order.validity_proofs.is_some());
    }
}
