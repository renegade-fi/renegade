//! Groups integration tests for the circuitry that converts between scalars and their
//! bit representations

use circuits::zk_gadgets::bits::{MultiproverToBitsGadget, ToBitsStatement};
use crypto::fields::{bigint_to_scalar_bits, scalar_to_bigint};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{mpc_network::batch_share_plaintext_scalar, types::IntegrationTest};
use rand_core::{OsRng, RngCore};

use crate::{IntegrationTestArgs, TestWrapper};

use super::multiprover_prove_and_verify;

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
    let statement_bits = batch_share_plaintext_scalar(
        bits,
        0, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );

    let statement = ToBitsStatement {
        bits: statement_bits,
    };

    multiprover_prove_and_verify::<'_, _, _, MultiproverToBitsGadget<'_, 64 /* bits */, _, _>>(
        shared_scalar,
        statement,
        test_args.mpc_fabric.clone(),
    )
    .map_err(|err| format!("Error proving: {:?}", err))
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_gadgets::bits::test_to_bits",
    test_fn: test_to_bits
}));
