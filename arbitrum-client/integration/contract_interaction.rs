//! Integration tests for contract interaction client functionality

use circuit_types::traits::BaseType;
use circuits::zk_circuits::{
    test_helpers::{MAX_BALANCES, MAX_FEES, MAX_ORDERS},
    valid_wallet_update::ValidWalletUpdateStatement,
};
use constants::Scalar;
use eyre::Result;
use rand::thread_rng;
use std::iter;
use test_helpers::{assert_true_result, integration_test_async};

use crate::{helpers::dummy_proof, IntegrationTestArgs};

/// Test checking whether a Merkle root is valid
async fn test_merkle_root_valid(test_args: IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();
    let client = &test_args.client;

    // Check that a random root is not in the contract root history
    let random_root = Scalar::random(&mut rng);
    let valid_root = client.check_merkle_root_valid(random_root).await?;
    assert_true_result!(!valid_root)?;

    // Get the current Merkle root then check that it is valid
    let current_root = client.get_merkle_root().await?;
    let valid_root = client.check_merkle_root_valid(current_root).await?;
    assert_true_result!(valid_root)
}
integration_test_async!(test_merkle_root_valid);

/// Test checking whether a nullifier is used
async fn test_nullifier_used(test_args: IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();
    let client = &test_args.client;

    // Check that a random nullifier is not used
    let random_nullifier = Scalar::random(&mut rng);
    let nullifier_used = client.check_nullifier_used(random_nullifier).await?;
    assert_true_result!(!nullifier_used)?;

    // Call `update_wallet` with a dummy statement then check that
    // the nullifier is used
    let statement = ValidWalletUpdateStatement::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>::from_scalars(
        &mut iter::repeat(Scalar::random(&mut rng)),
    );
    client
        .update_wallet(
            statement.new_public_shares.blinder,
            statement.clone().into(),
            vec![], // statement_signature
            dummy_proof(),
        )
        .await?;

    let nullifier_used = client
        .check_nullifier_used(statement.old_shares_nullifier)
        .await?;
    assert_true_result!(nullifier_used)
}
integration_test_async!(test_nullifier_used);
