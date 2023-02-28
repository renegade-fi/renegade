//! Groups integration tests for Poseidon hashing

use ark_crypto_primitives::sponge::{
    poseidon::{PoseidonConfig, PoseidonSponge},
    CryptographicSponge,
};
use circuits::mpc_gadgets::poseidon::{AuthenticatedPoseidonHasher, PoseidonSpongeParameters};
use crypto::fields::{prime_field_to_bigint, scalar_to_bigint};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::types::IntegrationTest;
use mpc_ristretto::{
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use rand::{thread_rng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

use super::{
    compare_scalar_to_felt, convert_scalars_nested_vec, scalar_to_prime_field, DalekRistrettoField,
};

/**
 * Helpers
 */

/// Converts a set of Poseidon parameters encoded as scalars to parameters encoded as field elements
pub(crate) fn convert_params(
    native_params: &PoseidonSpongeParameters,
) -> PoseidonConfig<DalekRistrettoField> {
    PoseidonConfig::new(
        native_params.full_rounds,
        native_params.parital_rounds,
        native_params.alpha,
        convert_scalars_nested_vec(&native_params.mds_matrix),
        convert_scalars_nested_vec(&native_params.round_constants),
        native_params.rate,
        native_params.capacity,
    )
}

/// Helper to check that a given result is the correct hash of the input sequence.
///
/// Uses the Arkworks Poseidon implementation for comparison
fn check_against_arkworks_hash<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    result: &AuthenticatedScalar<N, S>,
    input_sequence: &[AuthenticatedScalar<N, S>],
    hasher_params: &PoseidonSpongeParameters,
) -> Result<(), String> {
    // Open the input sequence and cast it to field elements
    let arkworks_input_seq = input_sequence
        .iter()
        .map(|val| scalar_to_prime_field(&val.open_and_authenticate().unwrap().to_scalar()))
        .collect::<Vec<_>>();

    // Build the arkworks hasher
    let mut arkworks_poseidon = PoseidonSponge::new(&convert_params(hasher_params));
    for input_elem in arkworks_input_seq.iter() {
        // Arkworks Fp256 does not implement From<u64> so we have to
        // cast to i128 first to ensure that the value is not represented as a negative
        arkworks_poseidon.absorb(input_elem);
    }

    let arkworks_squeezed: DalekRistrettoField =
        arkworks_poseidon.squeeze_field_elements(1 /* num_elements */)[0];

    // Open the given result and compare to the computed result
    let result_open = result
        .open_and_authenticate()
        .map_err(|err| format!("Error opening expected result: {:?}", err))?;

    if !compare_scalar_to_felt(&result_open.to_scalar(), &arkworks_squeezed) {
        return Err(format!(
            "Expected {:?}, got {:?}",
            scalar_to_bigint(&result_open.to_scalar()),
            prime_field_to_bigint(&arkworks_squeezed)
        ));
    }

    Ok(())
}

/**
 * Tests
 */

// Tests that a collaboratively computed poseidon hash works properly
fn test_hash(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a random string of 5 values to hash and shares them
    let mut rng = thread_rng();
    let n = 5;
    let my_values = (0..n).map(|_| rng.next_u64()).collect::<Vec<_>>();

    let party0_values = test_args
        .borrow_fabric()
        .batch_allocate_private_u64s(0 /* owning_party */, &my_values)
        .map_err(|err| format!("Error sharing party 0 values: {:?}", err))?;

    let party1_values = test_args
        .borrow_fabric()
        .batch_allocate_private_u64s(1 /* owning_party */, &my_values)
        .map_err(|err| format!("Error sharing party 1 values: {:?}", err))?;

    let hasher_params = PoseidonSpongeParameters::default();
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
