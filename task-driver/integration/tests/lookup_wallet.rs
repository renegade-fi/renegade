//! Integration tests for the `LookupWalletTask`

use eyre::{eyre, Result};
use mpc_stark::algebra::scalar::Scalar;
use rand::{distributions::uniform::SampleRange, thread_rng};
use task_driver::lookup_wallet::LookupWalletTask;
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};
use uuid::Uuid;

use crate::{
    helpers::{
        allocate_wallet_in_darkpool, create_empty_api_wallet, empty_wallet_from_seed,
        mock_wallet_update,
    },
    IntegrationTestArgs,
};

/// Tests looking up a wallet that has not been created yet, the task should fail
#[allow(non_snake_case)]
async fn test_lookup_wallet__invalid_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let wallet = create_empty_api_wallet();
    let task = LookupWalletTask::new(
        Uuid::new_v4(),
        Scalar::zero(), /* blinder_stream_seed */
        Scalar::zero(), /* secret_share_stream_seed */
        wallet.key_chain,
        test_args.starknet_client.clone(),
        test_args.network_sender.clone(),
        test_args.global_state.clone(),
        test_args.proof_job_queue.clone(),
    );

    let (_task_id, handle) = test_args.driver.start_task(task).await;
    let success = handle.await?;

    assert_true_result!(!success)
}
integration_test_async!(test_lookup_wallet__invalid_wallet);

/// Tests looking up a wallet that has previously been created
#[allow(non_snake_case)]
async fn test_lookup_wallet__valid_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    // Create a wallet from a blinder seed
    let mut rng = thread_rng();
    let client = &test_args.starknet_client;

    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let mut wallet = empty_wallet_from_seed(blinder_seed, share_seed);
    allocate_wallet_in_darkpool(&wallet, client).await?;

    // Reblind the wallet to emulate a sequence of updates to the wallet
    // then send it to the contract
    let num_reblinds = (0..10).sample_single(&mut rng);
    for _ in 0..num_reblinds {
        mock_wallet_update(&mut wallet, client).await?;
    }

    let task = LookupWalletTask::new(
        wallet.wallet_id,
        blinder_seed,
        share_seed,
        wallet.key_chain,
        test_args.starknet_client.clone(),
        test_args.network_sender.clone(),
        test_args.global_state.clone(),
        test_args.proof_job_queue.clone(),
    );
    let (_task_id, handle) = test_args.driver.start_task(task).await;
    let success = handle.await?;

    assert_true_result!(success)?;

    // Check the global state for the wallet and verify that it was correctly recovered
    let state_wallet = test_args
        .global_state
        .read_wallet_index()
        .await
        .read_wallet(&wallet.wallet_id)
        .await
        .ok_or_else(|| eyre!("Wallet not found in global state"))?
        .clone();

    // Compare the secret shares directly
    assert_eq_result!(
        state_wallet.blinded_public_shares,
        wallet.blinded_public_shares
    )?;
    assert_eq_result!(state_wallet.private_shares, wallet.private_shares)
}
integration_test_async!(test_lookup_wallet__valid_wallet);
