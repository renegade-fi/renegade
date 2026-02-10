//! Applicator methods for the network order book, separated out for
//! discoverability

use serde::{Deserialize, Serialize};
use tracing::warn;
use types_proofs::{ValidityProofBundle, ValidityProofLocator};

use super::{Result, StateApplicator, return_type::ApplicatorReturnType};

// -------------
// | Constants |
// -------------

/// The default priority for a cluster
pub const CLUSTER_DEFAULT_PRIORITY: u32 = 1;
/// The default priority for an order
pub const ORDER_DEFAULT_PRIORITY: u32 = 1;

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

    /// Add a validity proof bundle at the given locator
    pub fn add_validity_proof(
        &self,
        locator: &ValidityProofLocator,
        bundle: &ValidityProofBundle,
    ) -> Result<ApplicatorReturnType> {
        let tx = self.db().new_write_tx()?;

        // For intent-located proofs, ensure the order exists before writing
        if let ValidityProofLocator::Intent { order_id } = locator
            && tx.get_order(order_id)?.is_none()
        {
            warn!("Order {order_id} not found in state, aborting `add_validity_proof`");
            return Ok(ApplicatorReturnType::None);
        }

        tx.write_validity_proof_bundle(locator, bundle)?;
        tx.commit()?;
        Ok(ApplicatorReturnType::None)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use constants::GLOBAL_MATCHING_POOL;
    use types_account::{
        account::mocks::mock_empty_account, order::mocks::mock_order,
        order_auth::mocks::mock_order_auth,
    };
    use types_proofs::{
        ValidityProofBundle, ValidityProofLocator, mocks::mock_intent_only_validity_bundle,
    };

    use crate::applicator::test_helpers::mock_applicator;

    /// Test adding a validity proof bundle at an intent locator
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

        let locator = ValidityProofLocator::Intent { order_id };
        let bundle = ValidityProofBundle::IntentOnly(mock_intent_only_validity_bundle());
        applicator.add_validity_proof(&locator, &bundle).unwrap();

        // Verify that the bundle is stored
        let db = applicator.db();
        let tx = db.new_read_tx().unwrap();
        let stored =
            tx.get_validity_proof::<types_proofs::IntentOnlyValidityBundle>(&locator).unwrap();
        assert!(stored.is_some());
    }
}
