//! Groups gadgets around arithmetic integration tests
use circuit_types::traits::MultiproverCircuitBaseType;
use circuits::zk_gadgets::arithmetic::MultiproverExpGadget;
use eyre::{eyre, Result};
use merlin::HashChainTranscript as Transcript;
use mpc_bulletproof::{
    r1cs::Variable,
    r1cs_mpc::{MpcConstraintSystem, MpcLinearCombination, MpcProver, MpcVariable},
    PedersenGens,
};
use mpc_stark::{algebra::scalar::Scalar, PARTY0, PARTY1};
use rand::{thread_rng, RngCore};
use renegade_crypto::fields::get_scalar_field_modulus;
use test_helpers::{integration_test_async, types::IntegrationTest};

use crate::IntegrationTestArgs;

/// Tests that the exponentiation gadget works properly on valid inputs
async fn test_exp_multiprover(test_args: IntegrationTestArgs) -> Result<()> {
    // Party 1 chooses an exponent, party 0 chooses the base
    let mut rng = thread_rng();
    let fabric = &test_args.mpc_fabric;
    let shared_base = fabric.share_scalar(Scalar::random(&mut rng), PARTY0);
    let shared_exp = fabric.share_scalar(rng.next_u32(), PARTY1);

    // Compute the expected result
    let base_open = shared_base.open().await.to_biguint();
    let exp_open = shared_exp.open().await.to_biguint();

    let expected_res = base_open.modpow(&exp_open, &get_scalar_field_modulus());
    let expected_scalar = expected_res.into();

    // Prove and verify the exp statement
    let pc_gens = PedersenGens::default();
    let transcript = Transcript::new(b"test");
    let mut prover = MpcProver::new_with_fabric(test_args.mpc_fabric.clone(), transcript, pc_gens);
    let (shared_base_var, _) = shared_base.commit_shared(&mut rng, &mut prover).unwrap();
    let res = MultiproverExpGadget::exp(
        shared_base_var,
        exp_open.try_into().unwrap(),
        fabric,
        &mut prover,
    )?;
    prover.constrain(
        res - MpcLinearCombination::from_scalar(expected_scalar, test_args.mpc_fabric.clone()),
    );

    if prover.constraints_satisfied().await {
        Ok(())
    } else {
        Err(eyre!("Constraints not satisfied"))
    }
}

/// Tests the exp gadget on an invalid witness
async fn test_exp_multiprover_invalid(test_args: IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();
    let fabric = &test_args.mpc_fabric;

    let shared_base = fabric.share_scalar(Scalar::random(&mut rng), PARTY0);
    let shared_exp = fabric.share_scalar(rng.next_u32(), PARTY1);

    // Compute the expected result
    let exp_open = shared_exp.open().await.to_biguint();

    let pc_gens = PedersenGens::default();
    let transcript = Transcript::new(b"test");
    let mut prover = MpcProver::new_with_fabric(test_args.mpc_fabric.clone(), transcript, pc_gens);
    let (shared_base_var, _) = shared_base.commit_shared(&mut rng, &mut prover).unwrap();

    let res = MultiproverExpGadget::exp(
        shared_base_var,
        exp_open.try_into().unwrap(),
        fabric,
        &mut prover,
    )?;
    prover
        .constrain(res - MpcVariable::new_with_type(Variable::One(), test_args.mpc_fabric.clone()));

    if prover.constraints_satisfied().await {
        Err(eyre!("Constraints satisfied"))
    } else {
        Ok(())
    }
}

// Take inventory
integration_test_async!(test_exp_multiprover);
integration_test_async!(test_exp_multiprover_invalid);
