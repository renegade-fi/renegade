//! Groups integration tests for multiprover poseidon gadget

use circuit_types::traits::MultiproverCircuitBaseType;
use circuits::zk_gadgets::poseidon::MultiproverPoseidonHashGadget;

use itertools::Itertools;
use merlin::HashChainTranscript as Transcript;
use mpc_bulletproof::{
    r1cs_mpc::{MpcLinearCombination, MpcProver},
    PedersenGens,
};
use mpc_stark::{
    algebra::{authenticated_scalar::AuthenticatedScalarResult, scalar::Scalar},
    PARTY0, PARTY1,
};
use rand::{thread_rng, RngCore};
use renegade_crypto::hash::{compute_poseidon_hash, default_poseidon_params};
use test_helpers::{
    mpc_network::{await_result, await_result_batch},
    types::IntegrationTest,
};

use crate::{IntegrationTestArgs, TestWrapper};

/// Tests the poseidon hash gadget
fn test_poseidon_multiprover(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Each party samples a random set of 5 values
    let n = 1;
    let mut rng = thread_rng();
    let fabric = &test_args.mpc_fabric;
    let my_values = (0..n).map(|_| rng.next_u64()).collect_vec();

    // Secret share the values
    let party0_values = fabric.batch_share_scalar(my_values.clone(), PARTY0);
    let party1_values = fabric.batch_share_scalar(my_values, PARTY1);

    // Compute the expected result via Arkworks hash
    let inputs_open = await_result_batch(AuthenticatedScalarResult::open_batch(
        &party0_values
            .iter()
            .cloned()
            .chain(party1_values.iter().cloned())
            .collect_vec(),
    ));
    let expected_result = compute_poseidon_hash(&inputs_open);

    // Prove the statement
    let pc_gens = PedersenGens::default();
    let transcript = Transcript::new(b"test");
    let mut prover = MpcProver::new_with_fabric(test_args.mpc_fabric.clone(), transcript, pc_gens);
    let hash_input: Vec<MpcLinearCombination> = party0_values
        .into_iter()
        .chain(party1_values.into_iter())
        .map(|v| v.commit_shared(&mut rng, &mut prover).unwrap())
        .map(|(var, _)| var.into())
        .collect_vec();

    let params = default_poseidon_params();
    let mut hasher = MultiproverPoseidonHashGadget::new(params, test_args.mpc_fabric.clone());
    hasher
        .hash(
            &hash_input,
            &MpcLinearCombination::from_scalar(expected_result, test_args.mpc_fabric.clone()),
            &mut prover,
        )
        .map_err(|err| format!("Error computing poseidon hash circuit: {:?}", err))?;

    if await_result(prover.constraints_satisfied()) {
        Ok(())
    } else {
        Err("Constraints not satisfied".to_string())
    }
}

/// Tests the case in which the witness is invalid; i.e. not the correct pre-image
fn test_poseidon_multiprover_invalid(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Sample a random input
    // Each party samples a random set of 5 values
    let n = 1;
    let mut rng = thread_rng();
    let fabric = &test_args.mpc_fabric;
    let my_values = (0..n).map(|_| rng.next_u64()).collect_vec();

    // Secret share the values
    let party0_values = fabric.batch_share_scalar(my_values.clone(), PARTY0);
    let party1_values = fabric.batch_share_scalar(my_values, PARTY1);

    // Prove the statement
    let hasher_params = default_poseidon_params();
    let pc_gens = PedersenGens::default();
    let transcript = Transcript::new(b"test");
    let mut prover = MpcProver::new_with_fabric(test_args.mpc_fabric.clone(), transcript, pc_gens);

    let hash_input: Vec<MpcLinearCombination> = party0_values
        .iter()
        .chain(party1_values.iter())
        .map(|v| v.commit_shared(&mut rng, &mut prover).unwrap())
        .map(|(var, _)| var.into())
        .collect_vec();

    let expected_out = MpcLinearCombination::from_scalar(
        Scalar::from(rng.next_u64()),
        test_args.mpc_fabric.clone(),
    );

    let mut hasher =
        MultiproverPoseidonHashGadget::new(hasher_params, test_args.mpc_fabric.clone());
    hasher
        .hash(&hash_input, &expected_out, &mut prover)
        .map_err(|err| format!("Error computing poseidon hash circuit: {:?}", err))?;

    if await_result(prover.constraints_satisfied()) {
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
