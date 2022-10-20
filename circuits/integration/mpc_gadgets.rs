//! Groups integration tests for MPC gadgets

use circuits::mpc_gadgets::bits::to_bits_le;
use curve25519_dalek::scalar::Scalar;
use integration_helpers::types::IntegrationTest;
use mpc_ristretto::{error::MpcError as FabricError, mpc_scalar::scalar_to_u64};

use crate::{IntegrationTestArgs, TestWrapper};

/// Tests the to_bits_le gadget
fn test_to_bits_le(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let value = 119;

    // The parties share the value 10 with little endian byte representation 0b0101
    let shared_value = test_args
        .borrow_fabric()
        .allocate_private_u64(0 /* owning_party */, value)
        .map_err(|err| format!("Error sharing value: {:?}", err))?;
    let shared_bits = to_bits_le::<8, _, _>(shared_value, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error in to_bits_le(): {:?}", err))?;

    // Open the bits and compare
    let opened_bits: Vec<Scalar> = shared_bits
        .iter()
        .map(|bit| Ok(bit.open_and_authenticate()?.to_scalar()))
        .collect::<Result<Vec<_>, FabricError>>()
        .map_err(|err| format!("Error opening shared bits: {:?}", err))?;

    if !opened_bits[..8].eq(&vec![
        Scalar::one(),
        Scalar::one(),
        Scalar::one(),
        Scalar::zero(),
        Scalar::one(),
        Scalar::one(),
        Scalar::one(),
        Scalar::zero(),
    ]) {
        return Err(format!(
            "Expected 0b11101110, Got {:?}",
            opened_bits[..8]
                .iter()
                .map(scalar_to_u64)
                .fold("0b".to_string(), |acc, val| acc + &val.to_string())
        ));
    }

    Ok(())
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_gadgets::test_to_bits_le",
    test_fn: test_to_bits_le
}));
