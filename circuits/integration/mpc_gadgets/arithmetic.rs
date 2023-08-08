//! Groups integration tests for arithmetic gadgets used in the MPC circuits

use circuits::mpc_gadgets::arithmetic::{pow, prefix_mul, product};
use mpc_stark::{
    algebra::{authenticated_scalar::AuthenticatedScalarResult, scalar::Scalar},
    PARTY0, PARTY1,
};
use num_bigint::BigUint;
use rand::{thread_rng, Rng, RngCore};
use renegade_crypto::fields::{get_scalar_field_modulus, scalar_to_u64};
use test_helpers::{
    mpc_network::{
        await_result, await_result_batch, await_result_batch_with_error, await_result_with_error,
    },
    types::IntegrationTest,
};

use crate::{IntegrationTestArgs, TestWrapper};

use super::{assert_scalar_batch_eq, assert_scalar_eq};

/// Tests the product gadget
fn test_product(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party decided on `n` values
    let n = 5;
    let fabric = &test_args.mpc_fabric;
    let mut rng = thread_rng();
    let my_values = (0..n)
        .map(|_| (rng.gen_range(0..100)) as u64)
        .collect::<Vec<u64>>();

    // Share the values
    let p1_values = fabric.batch_share_scalar(my_values.clone(), PARTY0);
    let p2_values = fabric.batch_share_scalar(my_values, PARTY1);

    let mut all_values = Vec::new();
    all_values.append(&mut p1_values.clone());
    all_values.append(&mut p2_values.clone());

    // Compute the product
    let res = await_result_with_error(product(&all_values, fabric).open_authenticated())?;

    // Open the shared values and compute the expected result
    let p1_values_prod = await_result_batch(AuthenticatedScalarResult::open_batch(&p1_values))
        .iter()
        .fold(Scalar::one(), |acc, val| acc * val);

    let p2_values_prod = await_result_batch(AuthenticatedScalarResult::open_batch(&p2_values))
        .iter()
        .fold(Scalar::one(), |acc, val| acc * val);
    let expected_result = p1_values_prod * p2_values_prod;

    assert_scalar_eq(&expected_result, &res)
}

/// Tests the prefix-mul gadget
fn test_prefix_mul(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Compute powers of 3
    let n = 25;
    let fabric = &test_args.mpc_fabric;
    let value = 3;
    let shared_values = fabric.batch_share_scalar(vec![value; n], PARTY0);

    // Run the prefix_mul gadget
    let prefixes = prefix_mul(&shared_values, fabric);

    // Open the prefixes and verify the result
    let opened_prefix_products = await_result_batch_with_error(
        AuthenticatedScalarResult::open_authenticated_batch(&prefixes),
    )?;

    let mut expected_result = Vec::with_capacity(n);
    let mut acc = Scalar::one();
    for _ in 0..n {
        acc *= Scalar::from(value);
        expected_result.push(acc);
    }

    assert_scalar_batch_eq(&expected_result, &opened_prefix_products)
}

/// Tests the exponentiation gadget
fn test_pow(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 selects a base and party 0 selects an exponent
    let fabric = &test_args.mpc_fabric;
    let mut rng = thread_rng();

    let random_base = fabric.share_scalar(rng.next_u64(), PARTY0);
    let random_exp = await_result(fabric.share_plaintext(Scalar::from(rng.next_u32()), PARTY1));

    let res = await_result_with_error(
        pow(&random_base, scalar_to_u64(&random_exp), fabric).open_authenticated(),
    )?;

    // Open the random input and compute the expected result
    let random_base_open = await_result(random_base.open());
    let expected_res = random_base_open.to_biguint().modpow(
        &BigUint::from(scalar_to_u64(&random_exp)),
        &get_scalar_field_modulus(),
    );

    assert_scalar_eq(&Scalar::from(expected_res), &res)
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::arithmetic::test_product",
    test_fn: test_product
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::arithmetic::test_prefix_mul",
    test_fn: test_prefix_mul
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::arithmetic::test_pow",
    test_fn: test_pow
}));
