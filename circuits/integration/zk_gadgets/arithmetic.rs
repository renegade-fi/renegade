//! Groups gadgets around arithemtic integration tests
use circuits::zk_gadgets::arithmetic::{
    ExpGadgetStatement, MultiproverExpGadget, MultiproverExpWitness,
};
use crypto::fields::{bigint_to_scalar, scalar_to_bigint};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{
    mpc_network::field::get_ristretto_group_modulus, types::IntegrationTest,
};
use mpc_bulletproof::r1cs_mpc::{MultiproverError, R1CSError};
use rand_core::{OsRng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

use super::multiprover_prove_and_verify;

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
    let witness = MultiproverExpWitness { x: shared_base };
    let statement = ExpGadgetStatement {
        alpha: exp_open.try_into().unwrap(),
        expected_out: expected_scalar,
    };

    multiprover_prove_and_verify::<'_, _, _, MultiproverExpGadget<'_, _, _>>(
        witness,
        statement,
        test_args.mpc_fabric.clone(),
    )
    .map_err(|err| format!("Error proving and verifying: {:?}", err))?;

    Ok(())
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

    let witness = MultiproverExpWitness { x: shared_base };
    let statement = ExpGadgetStatement {
        expected_out: Scalar::from(5u64), // Incorrect output
        alpha: exp_open.try_into().unwrap(),
    };

    let res = multiprover_prove_and_verify::<'_, _, _, MultiproverExpGadget<'_, _, _>>(
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
    name: "zk_gadgets::arithmetic::test_exp_multiprover",
    test_fn: test_exp_multiprover,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::arithmetic::test_exp_multiprover_invalid",
    test_fn: test_exp_multiprover_invalid
}));
