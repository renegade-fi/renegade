//! Defines integration tests for `StarknetClient` methods that interact
//! directly with darkpool contract methods

use common::types::proof_bundles::mocks::{
    dummy_valid_match_mpc_bundle, dummy_valid_settle_bundle, dummy_valid_wallet_update_bundle,
    dummy_validity_proof_bundle,
};
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};

use crate::{
    helpers::{deploy_new_wallet, dummy_wallet_share},
    IntegrationTestArgs,
};

/// Test checking whether a Merkle root is valid
async fn test_merkle_root_valid(test_args: IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();
    let client = &test_args.starknet_client;

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
    let client = &test_args.starknet_client;

    // Check that a random nullifier is not used
    let random_nullifier = Scalar::random(&mut rng);
    let nullifier_unused = client.check_nullifier_unused(random_nullifier).await?;
    assert_true_result!(nullifier_unused)?;

    // Call `update_wallet` with a dummy nullifier then check that it is used
    let dummy_nullifier = Scalar::random(&mut rng);
    let tx_hash = client
        .update_wallet(
            Scalar::one(),
            dummy_nullifier,
            None, // external_transfer
            dummy_wallet_share(),
            dummy_valid_wallet_update_bundle(),
        )
        .await?;
    client.poll_transaction_completed(tx_hash).await?;

    let nullifier_unused = client.check_nullifier_unused(dummy_nullifier).await?;
    assert_true_result!(!nullifier_unused)
}
integration_test_async!(test_nullifier_used);

/// Tests submitting a new wallet and then recovering its shares from the
/// contract
async fn test_new_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;

    // Deploy a new wallet
    let (_commitment, public_shares) = deploy_new_wallet(client).await?;

    // Find the transaction that updated the wallet
    let tx_hash = client
        .get_public_blinder_tx(public_shares.blinder)
        .await?
        .ok_or(eyre::eyre!("No transaction found for public blinder"))?;
    let recovered_public_shares = client
        .fetch_public_shares_from_tx(public_shares.blinder, tx_hash)
        .await?;

    // Check that the recovered public shares are the same as the original ones
    assert_eq_result!(public_shares, recovered_public_shares)
}
integration_test_async!(test_new_wallet);

/// Test submitting a wallet update that succeeds and then recovering its shares
async fn test_update_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();
    let client = &test_args.starknet_client;

    // Update a wallet with a mock nullifier
    let nullifier = Scalar::random(&mut rng);
    let new_shares = dummy_wallet_share();

    // Update the wallet
    let tx_hash = client
        .update_wallet(
            Scalar::random(&mut rng), // new_private_shares_commitment
            nullifier,
            None, // external_transfer
            new_shares.clone(),
            dummy_valid_wallet_update_bundle(),
        )
        .await?;
    client.poll_transaction_completed(tx_hash).await?;

    // Check that the nullifier is used
    let nullifier_unused = client.check_nullifier_unused(nullifier).await?;
    assert_true_result!(!nullifier_unused)?;

    // Find the transaction that updated the wallet
    let tx_hash = client
        .get_public_blinder_tx(new_shares.blinder)
        .await?
        .ok_or(eyre::eyre!("No transaction found for public blinder"))?;
    let recovered_public_shares = client
        .fetch_public_shares_from_tx(new_shares.blinder, tx_hash)
        .await?;

    // Check that the recovered public shares are the same as the original ones
    assert_eq_result!(new_shares, recovered_public_shares)
}
integration_test_async!(test_update_wallet);

/// Tests submitting a match and then recovering both of the wallets' shares
/// shares from the contract
async fn test_match(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;

    // Deploy two new wallets
    let (commitment_1, _shares) = deploy_new_wallet(client).await?;
    let (commitment_2, _shares) = deploy_new_wallet(client).await?;
    let nullifier1 = Scalar::random(&mut thread_rng());
    let nullifier2 = Scalar::random(&mut thread_rng());

    // Submit a match between the two wallets
    let new_shares1 = dummy_wallet_share();
    let new_shares2 = dummy_wallet_share();
    let tx_hash = client
        .submit_match(
            nullifier1,
            nullifier2,
            commitment_1,
            commitment_2,
            new_shares1.clone(),
            new_shares2.clone(),
            dummy_validity_proof_bundle(),
            dummy_validity_proof_bundle(),
            dummy_valid_match_mpc_bundle(),
            dummy_valid_settle_bundle(),
        )
        .await?;
    client.poll_transaction_completed(tx_hash).await?;

    // Find the transaction that updated the first wallet
    let tx_hash = client
        .get_public_blinder_tx(new_shares1.blinder)
        .await?
        .ok_or(eyre::eyre!("No transaction found for public blinder"))?;
    let recovered_public_shares_1 = client
        .fetch_public_shares_from_tx(new_shares1.blinder, tx_hash)
        .await?;

    // Check that the recovered public shares are the same as the original ones
    assert_eq_result!(new_shares1, recovered_public_shares_1)?;

    // Find the transaction that updated the second wallet
    let tx_hash = client
        .get_public_blinder_tx(new_shares2.blinder)
        .await?
        .ok_or(eyre::eyre!("No transaction found for public blinder"))?;
    let recovered_public_shares_2 = client
        .fetch_public_shares_from_tx(new_shares2.blinder, tx_hash)
        .await?;

    // Check that the recovered public shares are the same as the original ones
    assert_eq_result!(new_shares2, recovered_public_shares_2)
}
integration_test_async!(test_match);
