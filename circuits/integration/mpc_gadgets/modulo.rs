//! Groups integration tests for modulo MPC gadgets
use circuits::mpc_gadgets::modulo::{mod_2m, shift_right, truncate};
use crypto::fields::{bigint_to_scalar, scalar_to_bigint};
use num_bigint::{BigInt, RandomBits};
use rand::{thread_rng, Rng, RngCore};
use test_helpers::types::IntegrationTest;

use crate::{IntegrationTestArgs, TestWrapper};

use super::assert_scalar_eq;

/// Test the mod_2m method
fn test_mod_2m(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let m = 5;

    // Clean multiple of 2^m
    let value: u64 = (1 << m) * thread_rng().next_u32() as u64;
    let shared_value = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let value_mod_2m = mod_2m::<5_usize, _, _>(&shared_value, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing mod_2m: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening the result of mod_2m: {:?}", err))?;

    assert_scalar_eq(&value_mod_2m, 0)?;

    // Random value
    let random_value: BigInt = thread_rng().sample(RandomBits::new(250));
    let shared_random_value = test_args
        .borrow_fabric()
        .allocate_private_scalar(1 /* owning_party */, bigint_to_scalar(&random_value))
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let random_value_mod_2m = mod_2m::<5, _, _>(&shared_random_value, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing mod_2m: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening the result of mod_2m: {:?}", err))?;

    let expected_result: BigInt = scalar_to_bigint(
        &shared_random_value
            .open_and_authenticate()
            .map_err(|err| format!("Error opening value: {:?}", err))?
            .to_scalar(),
    ) % (1 << m);
    let expected_result_u64: u64 = expected_result.try_into().unwrap();
    assert_scalar_eq(&random_value_mod_2m, expected_result_u64)?;

    Ok(())
}

/// Tests truncation circuit
fn test_truncate(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = thread_rng();
    let random_value: BigInt = rng.sample(RandomBits::new(250));
    let m = 190;

    // Party 0 chooses truncated value, party 1 chooses truncation amount
    let shared_random_value = test_args
        .borrow_fabric()
        .allocate_private_scalar(0 /* owning_party */, bigint_to_scalar(&random_value))
        .map_err(|err| format!("Error sharing random value: {:?}", err))?;

    let res = truncate::<190, _, _>(&shared_random_value, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error truncating value: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening truncate result: {:?}", err))?;

    // Open the original value and compute the expected result
    let random_value = shared_random_value
        .open_and_authenticate()
        .map_err(|err| format!("Error opening shared random value: {:?}", err))?
        .to_scalar();

    let expected_result = scalar_to_bigint(&random_value) >> m;
    if bigint_to_scalar(&expected_result).ne(&res.to_scalar()) {
        return Err(format!(
            "Expected {:?}, got {:?}",
            expected_result,
            scalar_to_bigint(&res.to_scalar()),
        ));
    }

    Ok(())
}

/// Tests the shift right gadget
fn test_shift_right(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a random value and shift it right
    let shift_amount = 3;
    let mut rng = thread_rng();
    let random_value = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, rng.next_u32() as u64)
        .map_err(|err| format!("Error sharing private random value: {:?}", err))?;

    let res = shift_right::<3, _, _>(&random_value, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error computing the right shifted result: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening and authenticating the result: {:?}", err))?;

    // Open the random value and compute the expected result
    let random_value_open = &random_value.open_and_authenticate();

    assert_scalar_eq(&res, random_value_open >> shift_amount)
}

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_mod_2m",
    test_fn: test_mod_2m,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_truncate",
    test_fn: test_truncate
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_shift_right",
    test_fn: test_shift_right
}));
