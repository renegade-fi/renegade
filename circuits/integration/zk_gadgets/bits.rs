//! Groups integration tests for the circuitry that converts between scalars and their
//! bit representations

use circuit_types::traits::MultiproverCircuitBaseType;
use circuits::zk_gadgets::bits::MultiproverToBitsGadget;
use merlin::HashChainTranscript as Transcript;
use mpc_bulletproof::{
    r1cs_mpc::{MpcConstraintSystem, MpcLinearCombination, MpcProver},
    PedersenGens,
};
use mpc_stark::{algebra::scalar::Scalar, PARTY0};
use rand::{thread_rng, RngCore};
use renegade_crypto::fields::{bigint_to_scalar_bits, scalar_to_bigint};
use test_helpers::{mpc_network::await_result, types::IntegrationTest};

use crate::{IntegrationTestArgs, TestWrapper};

/// Tests the to_bits gadget
fn test_to_bits(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Generate a random scalar to bitify
    let mut rng = thread_rng();
    let fabric = &test_args.mpc_fabric;
    let random_scalar = Scalar::from(rng.next_u64());

    // Party 0 shares the scalar as a private input
    let shared_scalar = fabric.share_scalar(random_scalar, PARTY0);

    // Bitify the input and share the result to build a circuit statement
    let bits = &bigint_to_scalar_bits::<64 /* bits */>(&scalar_to_bigint(&random_scalar))[..64];
    let expected_bits = await_result(fabric.batch_share_plaintext(bits.to_vec(), PARTY0));

    let pc_gens = PedersenGens::default();
    let transcript = Transcript::new(b"test");
    let mut prover = MpcProver::new_with_fabric(test_args.mpc_fabric.clone(), transcript, &pc_gens);
    let (shared_scalar_var, _) = shared_scalar.commit_shared(&mut rng, &mut prover).unwrap();
    let res_bits = MultiproverToBitsGadget::<64 /* bits */>::to_bits(
        shared_scalar_var,
        test_args.mpc_fabric.clone(),
        &mut prover,
    )
    .map_err(|err| format!("Error computing to_bits circuit: {:?}", err))?;

    for (expected_bit, bit) in expected_bits.iter().zip(res_bits.iter()) {
        let allocated_bit =
            MpcLinearCombination::from_scalar(*expected_bit, test_args.mpc_fabric.clone());

        prover.constrain(bit.clone() - allocated_bit);
    }

    if prover.constraints_satisfied().unwrap() {
        Ok(())
    } else {
        Err("Constraints not satisfied".to_string())
    }
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::bits::test_to_bits",
    test_fn: test_to_bits
}));
