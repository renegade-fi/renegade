//! Groups integration tests for comparators

use circuits::mpc_gadgets::comparators::{
    greater_than, greater_than_equal, less_than, less_than_equal,
};
use integration_helpers::types::IntegrationTest;
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use rand::{thread_rng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

use super::check_equal;

/// TODO: (@joeykraut) Look into this more, it may fail in certain cases
/// Tests all the inequality comparators
fn test_inequalities(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 chooses a, party 1 chooses b
    let my_random_value = thread_rng().next_u64();
    let shared_a = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, my_random_value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_b = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, my_random_value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;

    let opened_a = scalar_to_u64(
        &shared_a
            .open_and_authenticate()
            .map_err(|err| format!("Error opening a: {:?}", err))?
            .to_scalar(),
    );
    let opened_b = scalar_to_u64(
        &shared_b
            .open_and_authenticate()
            .map_err(|err| format!("Error opening shared b: {:?}", err))?
            .to_scalar(),
    );

    // Test <
    let lt_result = less_than::<64, _, _>(&shared_a, &shared_b, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing a < 0: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening a < 0 result: {:?}", err))?;
    let mut expected_result = (opened_a < opened_b) as u64;
    check_equal(&lt_result, expected_result)?;

    // Test <= with equal values
    let mut lte_result =
        less_than_equal::<64, _, _>(&shared_a, &shared_a, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error computing a <= a: {:?}", err))?
            .open_and_authenticate()
            .map_err(|err| format!("Error opening a <= a result: {:?}", err))?;
    check_equal(&lte_result, 1)?;

    // Test <= with random values
    lte_result = less_than_equal::<64, _, _>(&shared_a, &shared_b, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing a <= b: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening a <= b result: {:?}", err))?;
    expected_result = (opened_a <= opened_b) as u64;
    check_equal(&lte_result, expected_result)?;

    // Test >
    let gt_result = greater_than::<64, _, _>(&shared_a, &shared_b, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing a > b: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening a > b result: {:?}", err))?;
    expected_result = (opened_a > opened_b) as u64;
    check_equal(&gt_result, expected_result)?;

    // Test >= with equal values
    let mut gte_result =
        greater_than_equal::<64, _, _>(&shared_a, &shared_a, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error computing a >= a: {:?}", err))?
            .open_and_authenticate()
            .map_err(|err| format!("Error opening a >= a result: {:?}", err))?;
    check_equal(&gte_result, 1)?;

    // Test >= with random values
    gte_result = greater_than_equal::<64, _, _>(&shared_a, &shared_b, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing a >= b: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening a >= b result: {:?}", err))?;
    expected_result = (opened_a >= opened_b) as u64;
    check_equal(&gte_result, expected_result)?;

    Ok(())
}

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_inequalities",
    test_fn: test_inequalities
}));
