//! Groups integration tests for MPC gadgets

use circuits::mpc_gadgets::bits::{bit_add, bit_xor, to_bits_le};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::types::IntegrationTest;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, error::MpcError as FabricError,
    mpc_scalar::scalar_to_u64,
};
use rand::{thread_rng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

/**
 * Helpers
 */

/// Converts a u64 to a bit representation as a vector of u64s.
fn u64_to_bits_le(mut a: u64) -> Vec<u64> {
    let mut bits = Vec::with_capacity(64);
    for _ in 0..64 {
        bits.push(a & 1);
        a >>= 1;
    }

    bits
}

/**
 * Tests
 */

/// Tests the bit xor gadget
fn test_bit_xor(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Try all combinations of zero and one
    let shared_zero = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_pargy */, 0 /* value */)
        .map_err(|err| format!("Error sharing shared zero: {:?}", err))?;
    let shared_one = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, 1 /* value */)
        .map_err(|err| format!("Error sharing shared one: {:?}", err))?;

    // 0 XOR 0 == 0
    let zero_xor_zero = bit_xor(&shared_zero, &shared_zero)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening 0 \\xor 0: {:?}", err))?;
    if zero_xor_zero.to_scalar().ne(&Scalar::zero()) {
        return Err(format!(
            "Expected {:?}, got {:?}",
            0,
            scalar_to_u64(&zero_xor_zero.to_scalar()),
        ));
    }

    // 1 XOR 0 == 1
    let one_xor_zero = bit_xor(&shared_one, &shared_zero)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening 1 \\xor 0: {:?}", err))?;
    if one_xor_zero.to_scalar().ne(&Scalar::one()) {
        return Err(format!(
            "Expected {:?}, got {:?}",
            1,
            scalar_to_u64(&one_xor_zero.to_scalar())
        ));
    }

    // 0 XOR 1 == 1
    let zero_xor_one = bit_xor(&shared_zero, &shared_one)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening 0 \\xor 1: {:?}", err))?;
    if zero_xor_one.to_scalar().ne(&Scalar::one()) {
        return Err(format!(
            "Expected {:?}, got {:?}",
            1,
            scalar_to_u64(&zero_xor_one.to_scalar())
        ));
    }

    // 1 XOR 1 == 0
    let one_xor_one = bit_xor(&shared_one, &shared_one)
        .open_and_authenticate()
        .map_err(|err| format!("Error opening 1 \\xor 1: {:?}", err))?;
    if one_xor_one.to_scalar().ne(&Scalar::zero()) {
        return Err(format!(
            "Expected {:?}, got {:?}",
            0,
            scalar_to_u64(&one_xor_one.to_scalar())
        ));
    }

    Ok(())
}

/// Tests the bit_add method
fn test_bit_add(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a random number, converts it to bits, then shares and adds it
    // For the sake of the test (because we convert back to u64 to compare) make sure both
    // numbers have log2(x) < 63
    let my_random_number = thread_rng().next_u64() / 2;
    let my_random_bits = u64_to_bits_le(my_random_number);

    // Share the bits, party 0 holds a, party 1 holds b
    let shared_bits_a = test_args
        .borrow_fabric()
        .batch_allocate_private_scalars(
            0, /* owning_party */
            &my_random_bits
                .iter()
                .cloned()
                .map(Scalar::from)
                .collect::<Vec<_>>(),
        )
        .map_err(|err| format!("Error sharing `a` bits: {:?}", err))?;

    let shared_bits_b = test_args
        .borrow_fabric()
        .batch_allocate_private_scalars(
            1, /* owning_party */
            &my_random_bits
                .into_iter()
                .map(Scalar::from)
                .collect::<Vec<_>>(),
        )
        .map_err(|err| format!("Error sharing `b` bits: {:?}", err))?;

    // Add the bits and open the result
    let res_bits = bit_add::<64, _, _>(
        shared_bits_a.as_slice()[..64].try_into().unwrap(),
        shared_bits_b.as_slice()[..64].try_into().unwrap(),
        test_args.mpc_fabric.clone(),
    )
    .0;
    let result = AuthenticatedScalar::batch_open_and_authenticate(&res_bits)
        .map_err(|err| format!("Error opening addition result: {:?}", err))?;

    // Open the original random numbers and bitify the sum
    let random_number1 = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, my_random_number)
        .map_err(|err| format!("Error sharing random number: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening party0's random number: {:?}", err))?;

    let random_number2 = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, my_random_number)
        .map_err(|err| format!("Error sharing random number: {:?}", err))?
        .open_and_authenticate()
        .map_err(|err| format!("Error opening party1's random number: {:?}", err))?;

    let expected_result = scalar_to_u64(&(random_number1.to_scalar() + random_number2.to_scalar()));
    let expected_bits = u64_to_bits_le(expected_result);

    let all_equal = result
        .iter()
        .zip(expected_bits.iter().cloned())
        .all(|(res, expected)| res.to_scalar().eq(&Scalar::from(expected)));

    if !all_equal {
        return Err(format!(
            "Expected: {:?}, got {:?}",
            expected_bits,
            result
                .iter()
                .map(|bit| scalar_to_u64(&bit.to_scalar()))
                .collect::<Vec<_>>(),
        ));
    }

    Ok(())
}

/// Tests the to_bits_le gadget
fn test_to_bits_le(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let value = 119;

    // The parties share the value 10 with little endian byte representation 0b0101
    let shared_value = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_bits = to_bits_le::<8, _, _>(shared_value, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error in to_bits_le(): {:?}", err))?;

    // Open the bits and compare
    let opened_bits: Vec<Scalar> = shared_bits
        .iter()
        .map(|bit| Ok(bit.open_and_authenticate()?.to_scalar()))
        .collect::<Result<Vec<_>, FabricError>>()
        .map_err(|err| format!("Error opening shared bits: {:?}", err))?;

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
        return Err(format!(
            "Expected 0b11101110, Got {:?}",
            opened_bits[..8]
                .iter()
                .map(scalar_to_u64)
                .fold("0b".to_string(), |acc, val| acc + &val.to_string())
        ));
    }

    Ok(())
}

// Take inventory

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_bit_xor",
    test_fn: test_bit_xor,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_bit_add",
    test_fn: test_bit_add
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_to_bits_le",
    test_fn: test_to_bits_le
}));
