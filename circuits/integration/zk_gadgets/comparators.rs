//! Groups integration tests for comparator circuits

use std::cmp;

use circuits::{
    bigint_to_scalar, scalar_to_bigint,
    zk_gadgets::comparators::{MultiproverMinGadget, MultiproverMinWitness},
};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{mpc_network::share_plaintext_scalar, types::IntegrationTest};
use rand_core::OsRng;

use crate::{IntegrationTestArgs, TestWrapper};

use super::multiprover_prove_and_verify;

/// Test the min gadget
fn test_min(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Party 0 decides a and b
    let mut rng = OsRng {};
    let a = Scalar::random(&mut rng);
    let b = Scalar::random(&mut rng);

    // Share the witness
    let a_shared = test_args
        .borrow_fabric()
        .allocate_private_scalar(0 /* owning_party */, a)
        .map_err(|err| format!("Error sharing a: {:?}", err))?;
    let b_shared = test_args
        .borrow_fabric()
        .allocate_private_scalar(0 /* owning_party */, b)
        .map_err(|err| format!("Error sharing b: {:?}", err))?;

    // Share the statement
    let min_val = bigint_to_scalar(&cmp::min(scalar_to_bigint(&a), scalar_to_bigint(&b)));
    let min_val_shared = share_plaintext_scalar(
        min_val,
        0, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );

    // Prove and verify
    let witness = MultiproverMinWitness {
        a: a_shared,
        b: b_shared,
    };

    multiprover_prove_and_verify::<'_, _, _, MultiproverMinGadget<'_, 253, _, _>>(
        witness,
        min_val_shared,
        test_args.mpc_fabric.clone(),
    )
    .map_err(|err| format!("Error proving statement: {:?}", err))
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::comparators::test_min",
    test_fn: test_min
}));
