//! Groups integration tests for modulo MPC gadgets
use circuits::mpc_gadgets::modulo::{mod_2m, truncate};
use integration_helpers::types::IntegrationTest;
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use rand::{thread_rng, Rng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

use super::check_equal;

/// Test the mod_2m method
fn test_mod_2m(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let m = 5;

    // Clean multiple of 2^m
    let value: u64 = (1 << m) * thread_rng().next_u32() as u64;
    let shared_value = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let value_mod_2m = mod_2m(&shared_value, m, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing mod_2m: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening the result of mod_2m: {:?}", err))?;

    check_equal(&value_mod_2m, 0)?;

    // Random value
    let random_value = thread_rng().next_u64();
    let shared_random_value = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, random_value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let random_value_mod_2m = mod_2m(&shared_random_value, m, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing mod_2m: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening the result of mod_2m: {:?}", err))?;

    let expected_result = scalar_to_u64(
        &shared_random_value
            .open_and_authenticate()
            .map_err(|err| format!("Error opening value: {:?}", err))?
            .to_scalar(),
    ) % (1 << m);
    check_equal(&random_value_mod_2m, expected_result)?;

    Ok(())
}

/// Tests truncation circuit
fn test_truncate(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = thread_rng();
    let random_value = rng.next_u64();
    let random_m = rng.gen_range(1..=63) as u64;

    // Party 0 chooses truncated value, party 1 chooses truncation amount
    let shared_random_value = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, random_value)
        .map_err(|err| format!("Error sharing random value: {:?}", err))?;
    let shared_m = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, random_m)
        .map_err(|err| format!("Error sharing shared_m value: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening shared_m value: {:?}", err))?;

    let m = scalar_to_u64(&shared_m.to_scalar());

    let res = truncate(
        &shared_random_value,
        m.try_into().unwrap(),
        test_args.mpc_fabric.clone(),
    )
    .map_err(|err| format!("Error truncating value: {:?}", err))?
    .open_and_authenticate()
    .map_err(|err| format!("Error opening truncate result: {:?}", err))?;

    // Open the original value and compute the expected result
    let random_value = shared_random_value
        .open_and_authenticate()
        .map_err(|err| format!("Error opening shared random value: {:?}", err))?
        .to_scalar();

    let expected_result = scalar_to_u64(&random_value) >> m;
    check_equal(&res, expected_result)?;

    Ok(())
}

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_mod_2m",
    test_fn: test_mod_2m,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_truncate",
    test_fn: test_truncate
}));
