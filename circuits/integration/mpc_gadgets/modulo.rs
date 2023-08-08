//! Groups integration tests for modulo MPC gadgets
use circuits::mpc_gadgets::modulo::{mod_2m, shift_right, truncate};
use mpc_stark::{algebra::scalar::Scalar, PARTY0, PARTY1};
use num_bigint::{BigUint, RandomBits};
use rand::{thread_rng, Rng, RngCore};
use renegade_crypto::fields::scalar_to_biguint;
use test_helpers::{
    mpc_network::{await_result, await_result_with_error},
    types::IntegrationTest,
};

use crate::{IntegrationTestArgs, TestWrapper};

use super::assert_scalar_eq;

/// Test the mod_2m method
fn test_mod_2m(test_args: &IntegrationTestArgs) -> Result<(), String> {
    const M: usize = 5;

    // Clean multiple of 2^m
    let fabric = &test_args.mpc_fabric;
    let value: u64 = (1 << M) * thread_rng().next_u32() as u64;
    let shared_value = fabric.share_scalar(value, PARTY0);
    let value_mod_2m =
        await_result_with_error(mod_2m::<M>(&shared_value, fabric).open_authenticated())?;

    assert_scalar_eq(&value_mod_2m, &Scalar::zero())?;

    // Random value
    let random_value: BigUint = thread_rng().sample(RandomBits::new(250));
    let shared_random_value = fabric.share_scalar(random_value, PARTY1);
    let random_value_mod_2m =
        await_result_with_error(mod_2m::<M>(&shared_random_value, fabric).open_authenticated())?;

    let value_opened = await_result_with_error(shared_random_value.open_authenticated())?;
    let expected_result: BigUint = scalar_to_biguint(&value_opened) % (1u64 << M);

    assert_scalar_eq(&random_value_mod_2m, &expected_result.into())
}

/// Tests truncation circuit
fn test_truncate(test_args: &IntegrationTestArgs) -> Result<(), String> {
    const M: usize = 190;
    let fabric = &test_args.mpc_fabric;

    let mut rng = thread_rng();
    let random_value: BigUint = rng.sample(RandomBits::new(250));

    // Party 0 chooses truncated value, party 1 chooses truncation amount
    let shared_random_value = fabric.share_scalar(random_value, PARTY0);
    let res =
        await_result_with_error(truncate::<M>(&shared_random_value, fabric).open_authenticated())?;

    // Open the original value and compute the expected result
    let random_value = await_result_with_error(shared_random_value.open_authenticated())?;
    let expected_result = scalar_to_biguint(&random_value) >> M;

    assert_scalar_eq(&res, &expected_result.into())
}

/// Tests the shift right gadget
fn test_shift_right(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a random value and shift it right
    const SHIFT_AMOUNT: usize = 3;
    let fabric = &test_args.mpc_fabric;
    let mut rng = thread_rng();
    let random_value = fabric.share_scalar(rng.next_u32(), PARTY0);

    let res = await_result_with_error(
        shift_right::<SHIFT_AMOUNT>(&random_value, fabric).open_authenticated(),
    )?;

    // Open the random value and compute the expected result
    let random_value_open = await_result(random_value.open());
    let expected_res = scalar_to_biguint(&random_value_open) >> SHIFT_AMOUNT;
    assert_scalar_eq(&res, &expected_res.into())
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
