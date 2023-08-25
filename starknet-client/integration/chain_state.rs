//! Integration tests for client functionality that searches contract state

use eyre::Result;
use num_bigint::BigUint;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::IntegrationTestArgs;

/// Find a pre-allocated commitment in the Merkle state
async fn test_find_commitment(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;

    // Test the zeroth index commitment
    let commitment_index = client
        .find_commitment_in_state(test_args.pre_allocated_state.index0_commitment)
        .await?;
    assert_eq_result!(commitment_index, BigUint::from(0u8))?;

    // Test the first index commitment
    let commitment_index = client
        .find_commitment_in_state(test_args.pre_allocated_state.index1_commitment)
        .await?;
    assert_eq_result!(commitment_index, BigUint::from(1u8))
}
integration_test_async!(test_find_commitment);
