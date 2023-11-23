//! Integration tests for the settlement circuit

use circuits::{test_helpers::random_orders_and_match, mpc_circuits::r#match::compute_match};
use eyre::Result;
use test_helpers::integration_test_async;
use util::matching_engine::match_orders;

use crate::IntegrationTestArgs;

/// Tests settling a match into a set of wallet shares
///
/// Validates that the resultant shares satisfy the `VALID MATCH SETTLE`
/// circuit's constraints
async fn test_match_settle_witness_generation(test_args: IntegrationTestArgs) -> Result<()> {
    // Sample random orders and a crossing price
    let (o1, o2, price, match_res) = random_orders_and_match();
    let authenticated_match = compute_match(order1, order2, amount1, amount2, price, fabric)

    Ok(())
}

integration_test_async!(test_match_settle_witness_generation);
