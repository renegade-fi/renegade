//! Integration tests for the `NewWalletTask`

use eyre::{eyre, Result};
use task_driver::create_new_wallet::NewWalletTask;
use test_helpers::{integration_test_async, types::IntegrationTest};

use crate::{helpers::create_empty_api_wallet, IntegrationTestArgs};

// ---------
// | Tests |
// ---------

/// Basic functionality test of creating a valid new wallet
async fn valid_new_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let wallet = create_empty_api_wallet();
    let task = NewWalletTask::new(
        wallet.id,
        wallet,
        test_args.starknet_client.clone(),
        test_args.global_state.clone(),
        test_args.proof_job_queue.clone(),
    )?;

    let (_task_id, handle) = test_args.driver.start_task(task).await;
    let success = handle.await?;

    if success {
        Ok(())
    } else {
        Err(eyre!("task failed"))
    }
}

integration_test_async!(valid_new_wallet);
