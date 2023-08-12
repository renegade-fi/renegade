//! Groups integration tests for modulo MPC gadgets
use circuits::mpc_gadgets::modulo::{mod_2m, shift_right, truncate};
use eyre::Result;
use mpc_stark::{algebra::scalar::Scalar, PARTY0, PARTY1};
use num_bigint::{BigUint, RandomBits};
use rand::{thread_rng, Rng, RngCore};
use renegade_crypto::fields::scalar_to_biguint;
use test_helpers::{integration_test_async, types::IntegrationTest};

use crate::IntegrationTestArgs;

use super::assert_scalar_eq;

/// Test the mod_2m method
async fn test_mod_2m(test_args: IntegrationTestArgs) -> Result<()> {
    const M: usize = 5;

    // Clean multiple of 2^m
    let fabric = &test_args.mpc_fabric;
    let value: u64 = (1 << M) * thread_rng().next_u32() as u64;
    let shared_value = fabric.share_scalar(value, PARTY0);
    let value_mod_2m = mod_2m::<M>(&shared_value, fabric)
        .open_authenticated()
        .await?;

    assert_scalar_eq(&value_mod_2m, &Scalar::zero())?;

    // Random value
    let random_value: BigUint = thread_rng().sample(RandomBits::new(250));
    let shared_random_value = fabric.share_scalar(random_value, PARTY1);
    let random_value_mod_2m = mod_2m::<M>(&shared_random_value, fabric)
        .open_authenticated()
        .await?;

    let value_opened = shared_random_value.open_authenticated().await?;
    let expected_result: BigUint = scalar_to_biguint(&value_opened) % (1u64 << M);

    assert_scalar_eq(&random_value_mod_2m, &expected_result.into())
}

/// Tests truncation circuit
async fn test_truncate(test_args: IntegrationTestArgs) -> Result<()> {
    const M: usize = 190;
    let fabric = &test_args.mpc_fabric;

    let mut rng = thread_rng();
    let random_value: BigUint = rng.sample(RandomBits::new(250));

    // Party 0 chooses truncated value, party 1 chooses truncation amount
    let shared_random_value = fabric.share_scalar(random_value, PARTY0);
    let res = truncate::<M>(&shared_random_value, fabric)
        .open_authenticated()
        .await?;

    // Open the original value and compute the expected result
    let random_value = shared_random_value.open_authenticated().await?;
    let expected_result = scalar_to_biguint(&random_value) >> M;

    assert_scalar_eq(&res, &expected_result.into())
}

/// Tests the shift right gadget
async fn test_shift_right(test_args: IntegrationTestArgs) -> Result<()> {
    // Sample a random value and shift it right
    const SHIFT_AMOUNT: usize = 3;
    let fabric = &test_args.mpc_fabric;
    let mut rng = thread_rng();
    let random_value = fabric.share_scalar(rng.next_u32(), PARTY0);

    let res = shift_right::<SHIFT_AMOUNT>(&random_value, fabric)
        .open_authenticated()
        .await?;

    // Open the random value and compute the expected result
    let random_value_open = random_value.open().await;
    let expected_res = scalar_to_biguint(&random_value_open) >> SHIFT_AMOUNT;
    assert_scalar_eq(&res, &expected_res.into())
}

integration_test_async!(test_mod_2m);
integration_test_async!(test_truncate);
integration_test_async!(test_shift_right);
