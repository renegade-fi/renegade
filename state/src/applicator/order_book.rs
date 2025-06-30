//! Applicator methods for the network order book, separated out for
//! discoverability

use common::types::{
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle},
    wallet::{OrderIdentifier, order_metadata::OrderState},
};
use constants::ORDER_STATE_CHANGE_TOPIC;
use external_api::bus_message::SystemBusMessage;
use libmdbx::RW;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{applicator::error::StateApplicatorError, storage::tx::StateTxn};

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
/// The error message emitted when a wallet cannot be found for an order
const ERR_WALLET_MISSING: &str = "Cannot find wallet for order";
/// The error message emitted when the order metadata cannot be found
const ERR_ORDER_META_MISSING: &str = "Cannot find order metadata";

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
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;
        if tx.get_order_info(&order_id)?.is_none() {
            warn!("Order {order_id} not found in state, aborting `add_order_validity_proof`");
            return Ok(ApplicatorReturnType::None);
        }

        tx.attach_validity_proof(&order_id, proof)?;
        tx.attach_validity_witness(&order_id, witness)?;

        // Transition the order into a `Matching` state
        self.transition_order_matching(order_id, &tx)?;

        // Get the order info for update message
        let order_info = tx
            .get_order_info(&order_id)?
            .ok_or_else(|| StateApplicatorError::MissingEntry(ERR_ORDER_MISSING))?;
        let wallet = tx
            .get_wallet_for_order(&order_id)?
            .ok_or_else(|| StateApplicatorError::reject(ERR_WALLET_MISSING))?;
        tx.commit()?;

        // Cache the order
        let order = wallet
            .get_order(&order_id)
            .ok_or_else(|| StateApplicatorError::reject(ERR_ORDER_MISSING))?;
        let matchable_amount = wallet.get_matchable_amount_for_order(order);
        // If order exists, update its matchable amount
        // Otherwise, add it to the cache
        if self.order_cache().order_exists(order_id) {
            self.order_cache().update_order_blocking(order_id, matchable_amount);
        } else {
            self.order_cache().add_order_blocking(order_id, order, matchable_amount);
        }

        // Publish the order state change
        self.system_bus().publish(
            ORDER_STATE_CHANGE_TOPIC.to_string(),
            SystemBusMessage::OrderStateChange { order: order_info },
        );
        Ok(ApplicatorReturnType::None)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Update the order metadata into the `Matching` state
    fn transition_order_matching(
        &self,
        order_id: OrderIdentifier,
        tx: &StateTxn<RW>,
    ) -> Result<()> {
        let wallet = tx
            .get_wallet_id_for_order(&order_id)?
            .ok_or(StateApplicatorError::MissingEntry(ERR_WALLET_MISSING))?;

        let mut meta = tx
            .get_order_metadata(wallet, order_id)?
            .ok_or(StateApplicatorError::MissingEntry(ERR_ORDER_META_MISSING))?;

        if !meta.state.is_terminal() {
            meta.state = OrderState::Matching;
        }
        self.update_order_metadata_with_tx(meta, tx)?;

        Ok(())
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use common::types::{
        network_order::NetworkOrderState,
        proof_bundles::mocks::{dummy_validity_proof_bundle, dummy_validity_witness_bundle},
        wallet::OrderIdentifier,
        wallet_mocks::{mock_empty_wallet, mock_order},
    };

    use crate::applicator::test_helpers::mock_applicator;

    /// Test adding a validity proof to an order
    ///
    /// Run in a Tokio test as lower level components assume a Tokio runtime
    /// exists
    #[tokio::test]
    async fn test_add_validity_proof() {
        let base_applicator = mock_applicator();

        // Add an order via a wallet
        let mut wallet = mock_empty_wallet();
        let order_id = OrderIdentifier::new_v4();
        wallet.add_order(order_id, mock_order()).unwrap();
        let applicator = base_applicator.clone();
        tokio::task::spawn_blocking(move || applicator.update_wallet(&wallet).unwrap())
            .await
            .unwrap();

        // Then add a validity proof
        let proof = dummy_validity_proof_bundle();
        let witness = dummy_validity_witness_bundle();
        let applicator = base_applicator.clone();
        tokio::task::spawn_blocking(move || {
            applicator.add_order_validity_proof(order_id, proof, witness).unwrap()
        })
        .await
        .unwrap();

        // Verify that the order's state is updated
        let db = base_applicator.db();
        let tx = db.new_read_tx().unwrap();
        let order = tx.get_order_info(&order_id).unwrap().unwrap();

        assert_eq!(order.state, NetworkOrderState::Verified);
        assert!(order.validity_proofs.is_some());
    }
}
