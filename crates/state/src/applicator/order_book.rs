//! Applicator methods for the network order book, separated out for
//! discoverability

use circuit_types::Nullifier;
use serde::{Deserialize, Serialize};
use tracing::warn;
use types_account::{OrderId, order::Order};

use crate::{applicator::error::StateApplicatorError, storage::traits::RkyvValue};

use super::{Result, StateApplicator, return_type::ApplicatorReturnType};

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
        order_id: OrderId,
        proof: Nullifier,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        if tx.get_order_info(&order_id)?.is_none() {
            warn!("Order {order_id} not found in state, aborting `add_order_validity_proof`");
            return Ok(ApplicatorReturnType::None);
        }

        // Write the proof and witness
        tx.attach_validity_proof(&order_id, proof)?;
        // tx.write_validity_proof_witness(&order_id, witness)?;

        // Get the order and matchable amount
        let order = tx
            .get_order(&order_id)?
            .ok_or_else(|| StateApplicatorError::reject(ERR_ORDER_MISSING))?;
        let matchable_amount = tx.get_order_matchable_amount(&order_id)?.unwrap_or_default();
        let order_deser = Order::from_archived(&order)?;

        // Get the account ID and matching pool for the order
        let account_id = tx
            .get_account_id_for_order(&order_id)?
            .ok_or_else(|| StateApplicatorError::reject("order not associated with account"))?;
        let matching_pool = tx.get_matching_pool_for_order(&order_id)?;

        // Update the matching engine
        let matching_engine = self.matching_engine();
        matching_engine.upsert_order(account_id, &order_deser, matchable_amount, matching_pool);
        tx.commit()?;

        Ok(ApplicatorReturnType::None)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use constants::{GLOBAL_MATCHING_POOL, Scalar};
    use rand::thread_rng;
    use types_account::{
        account::mocks::mock_empty_account, order::mocks::mock_order,
        order_auth::mocks::mock_order_auth,
    };
    use types_gossip::network_order::{
        ArchivedNetworkOrderState, test_helpers::dummy_network_order,
    };

    use crate::applicator::test_helpers::mock_applicator;

    /// Test adding a validity proof to an order
    ///
    /// Run in a Tokio test as lower level components assume a Tokio runtime
    /// exists
    #[tokio::test]
    async fn test_add_validity_proof() {
        let applicator = mock_applicator();

        // Create an account with an order
        let account = mock_empty_account();
        let order = mock_order();
        let order_id = order.id;
        let auth = mock_order_auth();

        // Add the account to the state
        applicator.create_account(&account).unwrap();
        applicator
            .add_order_to_account(account.id, &order, &auth, GLOBAL_MATCHING_POOL.to_string())
            .unwrap();

        // Create a network order and add it to the order book
        // The order must exist in the order book for add_order_validity_proof to work
        let mut network_order = dummy_network_order();
        network_order.id = order_id;
        let tx = applicator.db().new_write_tx().unwrap();
        tx.write_order(&network_order).unwrap();
        tx.commit().unwrap();

        // Add a validity proof (using a random nullifier)
        let mut rng = thread_rng();
        let proof_nullifier = Scalar::random(&mut rng);
        applicator.add_order_validity_proof(order_id, proof_nullifier).unwrap();

        // Verify that the order's state is updated
        let db = applicator.db();
        let tx = db.new_read_tx().unwrap();
        let order_info = tx.get_order_info(&order_id).unwrap().unwrap();
        assert!(matches!(order_info.state, ArchivedNetworkOrderState::Verified));
    }
}
