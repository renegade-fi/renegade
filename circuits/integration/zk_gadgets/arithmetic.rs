//! Groups gadgets around arithmetic integration tests
use circuit_types::traits::MultiproverCircuitBaseType;
use circuits::zk_gadgets::arithmetic::MultiproverExpGadget;
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{
    mpc_network::field::get_ristretto_group_modulus, types::IntegrationTest,
};
use merlin::Transcript;
use mpc_bulletproof::{
    r1cs::Variable,
    r1cs_mpc::{MpcConstraintSystem, MpcLinearCombination, MpcProver, MpcVariable},
    PedersenGens,
};
use rand_core::{OsRng, RngCore};
use renegade_cryptofields::{bigint_to_scalar, scalar_to_bigint};

use crate::{IntegrationTestArgs, TestWrapper};

/// Tests that the exponentiation gadget works properly on valid inputs
fn test_exp_multiprover(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 1 chooses an exponent, party 0 chooses the base
    let mut rng = OsRng {};
    let shared_base = test_args
        .borrow_fabric()
        .allocate_private_scalar(0 /* owning_party */, Scalar::random(&mut rng))
        .map_err(|err| format!("Error sharing base: {:?}", err))?;
    let shared_exp = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, rng.next_u32() as u64)
        .map_err(|err| format!("Error sharing exponent: {:?}", err))?;

    // Compute the expected result
    let base_open = scalar_to_bigint(&shared_base.open_and_authenticate().unwrap().to_scalar());
    let exp_open = scalar_to_bigint(&shared_exp.open_and_authenticate().unwrap().to_scalar());

    let expected_res = base_open.modpow(&exp_open, &get_ristretto_group_modulus().into());
    let expected_scalar = bigint_to_scalar(&expected_res);

    // Prove and verify the exp statement
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"test");
    let mut prover =
        MpcProver::new_with_fabric(test_args.mpc_fabric.clone().0, &mut transcript, &pc_gens);
    let (shared_base_var, _) = shared_base.commit_shared(&mut rng, &mut prover).unwrap();
    let res = MultiproverExpGadget::exp(
        shared_base_var,
        exp_open.try_into().unwrap(),
        test_args.mpc_fabric.clone(),
        &mut prover,
    )
    .map_err(|err| format!("Error computing exp circuit: {:?}", err))?;
    prover.constrain(
        res - MpcLinearCombination::from_scalar(expected_scalar, test_args.mpc_fabric.clone().0),
    );

    if prover.constraints_satisfied().unwrap() {
        Ok(())
    } else {
        Err("Constraints not satisfied".to_string())
    }
}

/// Tests the exp gadget on an invalid witness
fn test_exp_multiprover_invalid(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = OsRng {};

    let shared_base = test_args
        .borrow_fabric()
        .allocate_private_scalar(0 /* owning_party */, Scalar::random(&mut rng))
        .map_err(|err| format!("Error sharing base: {:?}", err))?;
    let shared_exp = test_args
        .borrow_fabric()
        .allocate_private_u64(1 /* owning_party */, rng.next_u32() as u64)
        .map_err(|err| format!("Error sharing exponent: {:?}", err))?;

    // Compute the expected result
    let exp_open = scalar_to_bigint(&shared_exp.open_and_authenticate().unwrap().to_scalar());

    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"test");
    let mut prover =
        MpcProver::new_with_fabric(test_args.mpc_fabric.clone().0, &mut transcript, &pc_gens);
    let (shared_base_var, _) = shared_base.commit_shared(&mut rng, &mut prover).unwrap();

    let res = MultiproverExpGadget::exp(
        shared_base_var,
        exp_open.try_into().unwrap(),
        test_args.mpc_fabric.clone(),
        &mut prover,
    )
    .map_err(|err| format!("Error computing exp circuit: {:?}", err))?;
    prover.constrain(
        res - MpcVariable::new_with_type(Variable::One(), test_args.mpc_fabric.clone().0),
    );

    if prover.constraints_satisfied().unwrap() {
        Err("Constraints satisfied".to_string())
    } else {
        Ok(())
    }
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::arithmetic::test_exp_multiprover",
    test_fn: test_exp_multiprover,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::arithmetic::test_exp_multiprover_invalid",
    test_fn: test_exp_multiprover_invalid
}));
