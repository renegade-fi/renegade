//! Integration tests for the `NewWalletTask`

use eyre::{eyre, Result};
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use task_driver::create_new_wallet::NewWalletTask;
use test_helpers::integration_test_async;

use crate::{helpers::create_empty_api_wallet, IntegrationTestArgs};

// ---------
// | Tests |
// ---------

/// Basic functionality test of creating a valid new wallet
async fn create_new_wallet(test_args: IntegrationTestArgs) -> Result<()> {
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
integration_test_async!(create_new_wallet);

/// Tests creating a new wallet with invalid secret shares, the task should fail
/// in the constructor
#[allow(non_snake_case)]
async fn create_new_wallet__invalid_shares(test_args: IntegrationTestArgs) -> Result<()> {
    let mut wallet = create_empty_api_wallet();
    wallet.blinded_public_shares[0] = Scalar::random(&mut thread_rng()).to_biguint();

    let task = NewWalletTask::new(
        wallet.id,
        wallet,
        test_args.starknet_client.clone(),
        test_args.global_state.clone(),
        test_args.proof_job_queue.clone(),
    );

    if task.is_ok() {
        Err(eyre!("task constructor should have failed"))
    } else {
        Ok(())
    }
}
integration_test_async!(create_new_wallet__invalid_shares);
