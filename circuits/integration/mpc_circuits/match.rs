//! Groups integration tests for the match circuitry

use ark_mpc::PARTY0;
use circuit_types::traits::{BaseType, MpcBaseType, MpcType};
use circuits::{mpc_circuits::r#match::compute_match, test_helpers::random_orders_and_match};
use eyre::Result;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::IntegrationTestArgs;

// --------------
// | Test Cases |
// --------------

/// Tests that a valid match is found when one exists
async fn test_match(test_args: IntegrationTestArgs) -> Result<()> {
    let fabric = &test_args.mpc_fabric;

    // Compute a match on two random orders using the internal engine
    let (o1, o2, price, expected) = random_orders_and_match();

    // Compute a match in a circuit
    let order1 = o1.allocate(PARTY0, fabric);
    let order2 = o2.allocate(PARTY0, fabric);
    let price_shared = price.allocate(PARTY0, fabric);
    let res = compute_match(
        &order1,
        &order2,
        &order1.amount,
        &order2.amount,
        &price_shared,
        fabric,
    )
    .open_and_authenticate()
    .await?;

    // Party 0 shares their expected match
    let expected = expected.share_public(PARTY0, fabric).await;
    assert_eq_result!(res, expected)
}

integration_test_async!(test_match);
