//! Integration tests for the `LookupWalletTask`

use constants::Scalar;
use eyre::Result;
use rand::{distributions::uniform::SampleRange, thread_rng};
use task_driver::lookup_wallet::LookupWalletTask;
use test_helpers::{assert_true_result, integration_test_async};
use uuid::Uuid;

use crate::{
    helpers::{
        allocate_wallet_in_darkpool, create_empty_api_wallet, empty_wallet_from_seed,
        lookup_wallet_and_check_result, mock_wallet_update,
    },
    IntegrationTestArgs,
};

/// Tests looking up a wallet that has not been created yet, the task should
/// fail
#[allow(non_snake_case)]
async fn test_lookup_wallet__invalid_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let wallet = create_empty_api_wallet();
    let task = LookupWalletTask::new(
        Uuid::new_v4(),
        Scalar::zero(), // blinder_stream_seed
        Scalar::zero(), // secret_share_stream_seed
        wallet.key_chain,
        test_args.arbitrum_client.clone(),
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
    let client = &test_args.arbitrum_client;

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

    // Check that the wallet is discoverable from contract state and correctly
    // constructed
    lookup_wallet_and_check_result(&wallet, blinder_seed, share_seed, test_args).await
}
integration_test_async!(test_lookup_wallet__valid_wallet);
