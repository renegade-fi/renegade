//! Groups integration tests for Poseidon hashing

use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use circuits::mpc_gadgets::poseidon::AuthenticatedPoseidonHasher;
use crypto::hash::{default_poseidon_params, PoseidonParams};
use itertools::Itertools;
use mpc_stark::{
    algebra::{authenticated_scalar::AuthenticatedScalarResult, scalar::Scalar},
    PARTY0, PARTY1,
};
use rand::{thread_rng, RngCore};
use test_helpers::{
    mpc_network::{await_result, await_result_batch},
    types::IntegrationTest,
};

use crate::{IntegrationTestArgs, TestWrapper};

// -----------
// | Helpers |
// -----------

/// Helper to check that a given result is the correct hash of the input sequence.
///
/// Uses the Arkworks Poseidon implementation for comparison
fn check_against_arkworks_hash(
    result: &AuthenticatedScalarResult,
    input_sequence: &[AuthenticatedScalarResult],
    hasher_params: &PoseidonParams,
) -> Result<(), String> {
    // Open the input sequence and cast it to field elements
    let arkworks_input = await_result_batch(&AuthenticatedScalarResult::open_batch(input_sequence))
        .into_iter()
        .map(|s| s.inner())
        .collect_vec();

    // Build the arkworks hasher
    let mut arkworks_poseidon = PoseidonSponge::new(hasher_params);
    for input_elem in arkworks_input.iter() {
        // Arkworks Fp256 does not implement From<u64> so we have to
        // cast to i128 first to ensure that the value is not represented as a negative
        arkworks_poseidon.absorb(input_elem);
    }

    let arkworks_squeezed: Scalar::Field =
        arkworks_poseidon.squeeze_field_elements(1 /* num_elements */)[0];
    let expected = Scalar::from(arkworks_squeezed);

    // Open the given result and compare to the computed result
    let result_open = await_result(result.open_authenticated())
        .map_err(|err| format!("Error opening result: {err:?}"))?;

    if result_open != expected {
        return Err(format!("Expected {expected:?}, got {result_open:?}",));
    }

    Ok(())
}

// ---------
// | Tests |
// ---------

// Tests that a collaboratively computed poseidon hash works properly
fn test_hash(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a random string of 5 values to hash and shares them
    let n = 5;
    let fabric = &test_args.mpc_fabric;
    let mut rng = thread_rng();
    let my_values = (0..n).map(|_| rng.next_u64()).collect::<Vec<_>>();

    let party0_values = fabric.batch_share_scalar(my_values.clone(), PARTY0);
    let party1_values = fabric.batch_share_scalar(my_values, PARTY1);

    let hasher_params = default_poseidon_params();
    let mut hasher = AuthenticatedPoseidonHasher::new(&hasher_params, test_args.mpc_fabric.clone());

    // Interleave the party's input values
    // Track the input sequence to compute the expected result afterwards
    let mut input_sequence = Vec::with_capacity(2 * n);
    for (p0_value, p1_value) in party0_values.into_iter().zip(party1_values.into_iter()) {
        // Store the inputs for the expected result hash
        input_sequence.push(p0_value.clone());
        input_sequence.push(p1_value.clone());

        // Absorb the inputs
        hasher.absorb_batch(&[p0_value, p1_value]);
    }

    let res = hasher.squeeze();
    check_against_arkworks_hash(&res, &input_sequence, &hasher_params)?;

    Ok(())
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_hash",
    test_fn: test_hash
}));
