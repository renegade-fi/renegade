//! Groups integration tests for multiprover poseidon gadget

use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use circuits::{
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    zk_gadgets::poseidon::{
        MultiproverPoseidonHashGadget, MultiproverPoseidonWitness, PoseidonGadgetStatement,
    },
};

use curve25519_dalek::scalar::Scalar;
use integration_helpers::types::IntegrationTest;
use itertools::Itertools;
use mpc_bulletproof::r1cs_mpc::{MultiproverError, R1CSError};
use mpc_ristretto::authenticated_scalar::AuthenticatedScalar;
use rand_core::{OsRng, RngCore};

use crate::{
    mpc_gadgets::{poseidon::convert_params, prime_field_to_scalar, scalar_to_prime_field},
    IntegrationTestArgs, TestWrapper,
};

use super::multiprover_prove_and_verify;

/// Tests the poseidon hash gadget
fn test_poseidon_multiprover(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a random set of 5 values
    let mut rng = OsRng {};
    let n = 1;
    let my_values = (0..n).map(|_| rng.next_u64()).collect_vec();

    // Secret share the values
    let party0_values = test_args
        .borrow_fabric()
        .batch_allocate_private_u64s(0 /* owning_party */, &my_values)
        .map_err(|err| format!("Error sharing party 0 values: {:?}", err))?;

    let party1_values = test_args
        .borrow_fabric()
        .batch_allocate_private_u64s(1 /* owning_party */, &my_values)
        .map_err(|err| format!("Error sharing party 1 values: {:?}", err))?;

    // Compute the expected result via Arkworks hash
    let inputs_open: Vec<AuthenticatedScalar<_, _>> =
        AuthenticatedScalar::batch_open(&party0_values)
            .map_err(|err| format!("Error opening party 0 inputs: {:?}", err))?
            .into_iter()
            .chain(
                AuthenticatedScalar::batch_open_and_authenticate(&party1_values)
                    .map_err(|err| format!("Error opening party 1 values: {:?}", err))?
                    .into_iter(),
            )
            .collect_vec();

    let arkworks_input = inputs_open
        .iter()
        .map(|hash_input| scalar_to_prime_field(&hash_input.to_scalar()));

    let hasher_params = PoseidonSpongeParameters::default();
    let arkworks_params = convert_params(&hasher_params);
    let mut arkworks_hasher = PoseidonSponge::new(&arkworks_params);

    for input in arkworks_input {
        arkworks_hasher.absorb(&input);
    }
    let expected_scalar =
        prime_field_to_scalar(&arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0]);

    // Prove the statement
    let witness = MultiproverPoseidonWitness {
        preimage: party0_values
            .into_iter()
            .chain(party1_values.into_iter())
            .collect_vec(),
    };
    let statement = PoseidonGadgetStatement {
        expected_out: expected_scalar,
        params: hasher_params,
    };
    multiprover_prove_and_verify::<'_, _, _, MultiproverPoseidonHashGadget<'_, _, _>>(
        witness,
        statement,
        test_args.mpc_fabric.clone(),
    )
    .map_err(|err| format!("Error proving and verifying statement: {:?}", err))?;

    Ok(())
}

/// Tests the case in which the witness is invalid; i.e. not the correct pre-image
fn test_poseidon_multiprover_invalid(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a random input
    // Each party samples a random set of 5 values
    let mut rng = OsRng {};
    let n = 1;
    let my_values = (0..n).map(|_| rng.next_u64()).collect_vec();

    // Secret share the values
    let party0_values = test_args
        .borrow_fabric()
        .batch_allocate_private_u64s(0 /* owning_party */, &my_values)
        .map_err(|err| format!("Error sharing party 0 values: {:?}", err))?;

    let party1_values = test_args
        .borrow_fabric()
        .batch_allocate_private_u64s(1 /* owning_party */, &my_values)
        .map_err(|err| format!("Error sharing party 1 values: {:?}", err))?;

    // Prove the statement
    let hasher_params = PoseidonSpongeParameters::default();
    let witness = MultiproverPoseidonWitness {
        preimage: party0_values
            .into_iter()
            .chain(party1_values.into_iter())
            .collect_vec(),
    };
    let statement = PoseidonGadgetStatement {
        expected_out: Scalar::from(1u64),
        params: hasher_params,
    };
    let res = multiprover_prove_and_verify::<'_, _, _, MultiproverPoseidonHashGadget<'_, _, _>>(
        witness,
        statement,
        test_args.mpc_fabric.clone(),
    );

    if let Err(MultiproverError::ProverError(R1CSError::VerificationError)) = res {
        Ok(())
    } else {
        Err(format!("Expected verification error, got {:?}", res))
    }
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::poseidon::test_poseidon_multiprover",
    test_fn: test_poseidon_multiprover
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::poseidon::test_poseidon_multiprover_invalid",
    test_fn: test_poseidon_multiprover_invalid,
}));
