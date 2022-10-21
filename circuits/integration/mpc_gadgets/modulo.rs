//! Groups integration tests for modulo MPC gadgets

use circuits::mpc_gadgets::modulo::mod_2m;
use curve25519_dalek::scalar::Scalar;
use integration_helpers::types::IntegrationTest;
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use rand::{thread_rng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

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

    if value_mod_2m.to_scalar().ne(&Scalar::zero()) {
        return Err(format!(
            "Expected {:?}, got {:?}",
            0,
            scalar_to_u64(&value_mod_2m.to_scalar())
        ));
    }

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
    if random_value_mod_2m
        .to_scalar()
        .ne(&Scalar::from(expected_result))
    {
        return Err(format!(
            "Expected: {:?}, got {:?}",
            expected_result,
            scalar_to_u64(&random_value_mod_2m.to_scalar())
        ));
    }

    Ok(())
}

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_mod_2m",
    test_fn: test_mod_2m,
}));
