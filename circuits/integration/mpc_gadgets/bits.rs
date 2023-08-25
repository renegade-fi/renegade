//! Groups integration tests for bitwise operating MPC gadgets

use circuits::mpc_gadgets::bits::{bit_add, bit_lt, bit_xor, to_bits_le};
use eyre::{eyre, Result};
use futures::future::join_all;
use itertools::Itertools;
use mpc_stark::{
    algebra::{authenticated_scalar::AuthenticatedScalarResult, scalar::Scalar},
    PARTY0, PARTY1,
};
use rand::{thread_rng, RngCore};
use renegade_crypto::fields::scalar_to_u64;
use test_helpers::integration_test_async;

use crate::IntegrationTestArgs;

use super::{assert_scalar_batch_eq, assert_scalar_eq};

// -----------
// | Helpers |
// -----------

/// Converts a u64 to a bit representation as a vector of u64s.
fn u64_to_bits_le(mut a: u64) -> Vec<u64> {
    let mut bits = Vec::with_capacity(64);
    for _ in 0..64 {
        bits.push(a & 1);
        a >>= 1;
    }

    bits
}

// ---------
// | Tests |
// ---------

/// Tests the bit xor gadget
async fn test_bit_xor(test_args: IntegrationTestArgs) -> Result<()> {
    // Try all combinations of zero and one
    let fabric = &test_args.mpc_fabric;
    let shared_zero = fabric.zero_authenticated();
    let shared_one = fabric.one_authenticated();

    // 0 XOR 0 == 0
    let zero_xor_zero = bit_xor(&shared_zero, &shared_zero)
        .open_authenticated()
        .await?;
    assert_scalar_eq(&zero_xor_zero, &Scalar::zero())?;

    // 1 XOR 0 == 1
    let one_xor_zero = bit_xor(&shared_one, &shared_zero)
        .open_authenticated()
        .await?;
    assert_scalar_eq(&one_xor_zero, &Scalar::one())?;

    // 0 XOR 1 == 1
    let zero_xor_one = bit_xor(&shared_zero, &shared_one)
        .open_authenticated()
        .await?;
    assert_scalar_eq(&zero_xor_one, &Scalar::one())?;

    // 1 XOR 1 == 0
    let one_xor_one = bit_xor(&shared_one, &shared_one)
        .open_authenticated()
        .await?;
    assert_scalar_eq(&one_xor_one, &Scalar::zero())?;

    Ok(())
}

/// Tests the bit_add method
async fn test_bit_add(test_args: IntegrationTestArgs) -> Result<()> {
    // Each party samples a random number, converts it to bits, then shares and adds it
    // For the sake of the test (because we convert back to u64 to compare) make sure both
    // numbers have log2(x) < 63
    let fabric = &test_args.mpc_fabric;
    let my_random_number = thread_rng().next_u64() / 2;
    let my_random_bits = u64_to_bits_le(my_random_number);

    // Share the bits, party 0 holds a, party 1 holds b
    let shared_bits_a = fabric.batch_share_scalar(
        my_random_bits
            .iter()
            .cloned()
            .map(Scalar::from)
            .collect::<Vec<_>>(),
        PARTY0,
    );
    let shared_bits_b = fabric.batch_share_scalar(
        my_random_bits
            .into_iter()
            .map(Scalar::from)
            .collect::<Vec<_>>(),
        PARTY1,
    );

    // Add the bits and open the result
    let res_bits = bit_add(
        shared_bits_a.as_slice()[..64].try_into().unwrap(),
        shared_bits_b.as_slice()[..64].try_into().unwrap(),
        fabric,
    )
    .0;
    let result = join_all(AuthenticatedScalarResult::open_authenticated_batch(
        &res_bits,
    ))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    // Open the original random numbers and bitify the sum
    let random_number1 = fabric
        .share_plaintext(Scalar::from(my_random_number), PARTY0)
        .await;
    let random_number2 = fabric
        .share_plaintext(Scalar::from(my_random_number), PARTY1)
        .await;

    let expected_result = scalar_to_u64(&(random_number1 + random_number2));
    let expected_bits = u64_to_bits_le(expected_result)
        .into_iter()
        .map(Scalar::from)
        .collect_vec();

    assert_scalar_batch_eq(&expected_bits, &result)
}

/// Tests that getting the bits of 0 returns all zeros
async fn test_bits_le_zero(test_args: IntegrationTestArgs) -> Result<()> {
    let fabric = &test_args.mpc_fabric;
    let shared_zero = fabric.zero_authenticated();

    let shared_bits = to_bits_le::<250>(&shared_zero, fabric);
    let shared_bits_open = join_all(AuthenticatedScalarResult::open_authenticated_batch(
        &shared_bits,
    ))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    assert_scalar_batch_eq(&shared_bits_open, &vec![Scalar::zero(); shared_bits.len()])
}

/// Tests the to_bits_le gadget
async fn test_to_bits_le(test_args: IntegrationTestArgs) -> Result<()> {
    let fabric = &test_args.mpc_fabric;
    let value = 119;

    let shared_value = fabric.share_scalar(value, PARTY0);
    let shared_bits = to_bits_le::<8>(&shared_value, fabric);

    // Open the bits and compare
    let opened_bits = join_all(AuthenticatedScalarResult::open_authenticated_batch(
        &shared_bits,
    ))
    .await
    .into_iter()
    .collect::<Result<Vec<_>, _>>()?;

    if !opened_bits[..8].eq(&vec![
        Scalar::one(),
        Scalar::one(),
        Scalar::one(),
        Scalar::zero(),
        Scalar::one(),
        Scalar::one(),
        Scalar::one(),
        Scalar::zero(),
    ]) {
        return Err(eyre!(
            "Expected 0b11101110, Got {:?}",
            opened_bits[..8]
                .iter()
                .map(scalar_to_u64)
                .fold("0b".to_string(), |acc, val| acc + &val.to_string())
        ));
    }

    Ok(())
}

/// Tests the bitwise less than comparator
async fn test_bit_lt(test_args: IntegrationTestArgs) -> Result<()> {
    // Test equal values
    let fabric = &test_args.mpc_fabric;
    let value = 15;

    let equal_value1 = fabric.share_scalar(value, PARTY0);
    let equal_value2 = fabric.share_scalar(value, PARTY1);

    let res = bit_lt(
        &to_bits_le::<250>(&equal_value1, fabric),
        &to_bits_le::<250>(&equal_value2, fabric),
        fabric,
    )
    .open_authenticated()
    .await?;

    assert_scalar_eq(&res, &Scalar::zero())?;

    // Test unequal values
    let mut rng = thread_rng();
    let my_value = rng.next_u64();

    let shared_value1 = fabric.share_scalar(my_value, PARTY0);
    let shared_value2 = fabric.share_scalar(my_value, PARTY1);

    let res = bit_lt(
        &to_bits_le::<250>(&shared_value1, fabric),
        &to_bits_le::<250>(&shared_value2, fabric),
        fabric,
    )
    .open_authenticated()
    .await?;

    // Open the original values to get the expected result
    let value1 = fabric.share_plaintext(Scalar::from(my_value), PARTY0).await;
    let value2 = fabric.share_plaintext(Scalar::from(my_value), PARTY1).await;
    let expected_res = scalar_to_u64(&value1) < scalar_to_u64(&value2);

    assert_scalar_eq(&res, &Scalar::from(expected_res))
}

// Take inventory
integration_test_async!(test_bit_xor);
integration_test_async!(test_bit_add);
integration_test_async!(test_bits_le_zero);
integration_test_async!(test_to_bits_le);
integration_test_async!(test_bit_lt);
