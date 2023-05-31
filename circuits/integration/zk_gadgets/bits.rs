//! Groups integration tests for the circuitry that converts between scalars and their
//! bit representations

use circuits::{traits::MultiproverCircuitBaseType, zk_gadgets::bits::MultiproverToBitsGadget};
use crypto::fields::{bigint_to_scalar_bits, scalar_to_bigint};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{mpc_network::batch_share_plaintext_scalar, types::IntegrationTest};
use merlin::Transcript;
use mpc_bulletproof::{
    r1cs_mpc::{MpcConstraintSystem, MpcLinearCombination, MpcProver},
    PedersenGens,
};
use rand_core::{OsRng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

/// A debug macro used for printing wires in an MPC-ZK circuit during execution
#[allow(unused)]
macro_rules! print_multiprover_wire {
    ($x:expr, $cs:ident, $party_id:expr) => {{
        use crypto::fields::scalar_to_biguint;
        let x_eval = $cs.eval(&$x.into()).unwrap().open().unwrap().to_scalar();
        if $party_id == 0 {
            println!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
        }
    }};
}

/// Tests the to_bits gadget
fn test_to_bits(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Generate a random scalar to bitify
    let mut rng = OsRng {};
    let random_scalar = Scalar::from(rng.next_u64());

    // Party 0 shares the scalar as a private input
    let shared_scalar = test_args
        .borrow_fabric()
        .allocate_private_scalar(0 /* owning_party */, random_scalar)
        .map_err(|err| format!("Error sharing scalar to bitify: {:?}", err))?;

    // Bitify the input and share the result to build a circuit statement
    let bits = &bigint_to_scalar_bits::<64 /* bits */>(&scalar_to_bigint(&random_scalar))[..64];
    let expected_bits = batch_share_plaintext_scalar(
        bits,
        0, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );

    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"test");
    let mut prover =
        MpcProver::new_with_fabric(test_args.mpc_fabric.clone().0, &mut transcript, &pc_gens);
    let (shared_scalar_var, _) = shared_scalar.commit_shared(&mut rng, &mut prover).unwrap();
    let res_bits = MultiproverToBitsGadget::<64 /* bits */, _, _>::to_bits(
        shared_scalar_var,
        test_args.mpc_fabric.clone(),
        &mut prover,
    )
    .map_err(|err| format!("Error computing to_bits circuit: {:?}", err))?;

    for (expected_bit, bit) in expected_bits.iter().zip(res_bits.iter()) {
        let allocated_bit =
            MpcLinearCombination::from_scalar(*expected_bit, test_args.mpc_fabric.clone().0);

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
