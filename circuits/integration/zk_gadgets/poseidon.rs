//! Groups integration tests for multiprover poseidon gadget

use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use circuit_types::traits::MultiproverCircuitBaseType;
use circuits::{
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    zk_gadgets::poseidon::MultiproverPoseidonHashGadget,
};

use curve25519_dalek::scalar::Scalar;
use integration_helpers::types::IntegrationTest;
use itertools::Itertools;
use merlin::Transcript;
use mpc_bulletproof::{
    r1cs_mpc::{MpcLinearCombination, MpcProver},
    PedersenGens,
};
use mpc_ristretto::authenticated_scalar::AuthenticatedScalar;
use rand_core::{OsRng, RngCore};
use renegade_cryptofields::{prime_field_to_scalar, scalar_to_prime_field, DalekRistrettoField};

use crate::{mpc_gadgets::poseidon::convert_params, IntegrationTestArgs, TestWrapper};

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
    let expected_scalar = prime_field_to_scalar(
        &arkworks_hasher.squeeze_field_elements::<DalekRistrettoField>(1 /* num_elements */)[0],
    );

    // Prove the statement
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"test");
    let mut prover =
        MpcProver::new_with_fabric(test_args.mpc_fabric.clone().0, &mut transcript, &pc_gens);
    let hash_input: Vec<MpcLinearCombination<_, _>> = party0_values
        .into_iter()
        .chain(party1_values.into_iter())
        .map(|v| v.commit_shared(&mut rng, &mut prover).unwrap())
        .map(|(var, _)| var.into())
        .collect_vec();

    let mut hasher =
        MultiproverPoseidonHashGadget::new(hasher_params, test_args.mpc_fabric.clone());
    hasher
        .hash(
            &hash_input,
            &MpcLinearCombination::from_scalar(expected_scalar, test_args.mpc_fabric.clone().0),
            &mut prover,
        )
        .map_err(|err| format!("Error computing poseidon hash circuit: {:?}", err))?;

    if prover.constraints_satisfied().unwrap() {
        Ok(())
    } else {
        Err("Constraints not satisfied".to_string())
    }
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
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"test");
    let mut prover =
        MpcProver::new_with_fabric(test_args.mpc_fabric.clone().0, &mut transcript, &pc_gens);
    let hash_input: Vec<MpcLinearCombination<_, _>> = party0_values
        .iter()
        .chain(party1_values.iter())
        .map(|v| v.commit_shared(&mut rng, &mut prover).unwrap())
        .map(|(var, _)| var.into())
        .collect_vec();
    let expected_out = MpcLinearCombination::from_scalar(
        Scalar::from(rng.next_u64()),
        test_args.mpc_fabric.clone().0,
    );

    let mut hasher =
        MultiproverPoseidonHashGadget::new(hasher_params, test_args.mpc_fabric.clone());
    hasher
        .hash(&hash_input, &expected_out, &mut prover)
        .map_err(|err| format!("Error computing poseidon hash circuit: {:?}", err))?;

    if prover.constraints_satisfied().unwrap() {
        Err("Constraints satisfied".to_string())
    } else {
        Ok(())
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
