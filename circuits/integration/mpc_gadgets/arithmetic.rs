//! Groups integration tests for arithmetic gadets used in the MPC circuits

use circuits::mpc_gadgets::arithmetic::prefix_mul;
use integration_helpers::types::IntegrationTest;
use mpc_ristretto::authenticated_scalar::AuthenticatedScalar;

use crate::{IntegrationTestArgs, TestWrapper};

use super::check_equal_vec;

/// Tests the prefix-mul gadget
fn test_prefix_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Compute powers of 3
    let n = 25;
    let value = 3;
    let shared_values = test_args
        .borrow_fabric()
        .batch_allocate_private_u64s(0 /* owning_party */, &vec![value; n])
        .map_err(|err| format!("Error allocating inputs: {:?}", err))?;

    // Run the prefix_mul gadget
    let prefixes = prefix_mul(&shared_values, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing prefix products: {:?}", err))?;

    // Open the prefixes and verify the result
    let opened_prefix_products = AuthenticatedScalar::batch_open_and_authenticate(&prefixes)
        .map_err(|err| format!("Error opening prefixes: {:?}", err))?;

    let mut expected_result = Vec::with_capacity(n);
    let mut acc = 1;
    for _ in 0..n {
        acc *= value;
        expected_result.push(acc);
    }

    check_equal_vec(&opened_prefix_products, &expected_result)?;
    Ok(())
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::arithmetic::test_previx_mul",
    test_fn: test_prefix_mul
}));
