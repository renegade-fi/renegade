//! Integration tests for the `NewWalletTask`

use common::types::{tasks::NewWalletTaskDescriptor, wallet_mocks::mock_empty_wallet};
use constants::Scalar;
use eyre::{eyre, Result};
use rand::thread_rng;
use test_helpers::integration_test_async;

use crate::{helpers::await_task, IntegrationTestArgs};

// ---------
// | Tests |
// ---------

/// Basic functionality test of creating a valid new wallet
async fn create_valid_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let wallet = mock_empty_wallet();
    let descriptor = NewWalletTaskDescriptor { wallet };

    await_task(descriptor.into(), &test_args).await
}
integration_test_async!(create_valid_wallet);

/// Tests creating a new wallet with invalid secret shares, the task should fail
/// in the constructor
#[allow(non_snake_case)]
async fn create_invalid_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let mut wallet = mock_empty_wallet();
    wallet.blinded_public_shares.balances[0].amount = Scalar::random(&mut thread_rng());
    let descriptor = NewWalletTaskDescriptor { wallet };

    // Run the task, should fail
    let res = await_task(descriptor.into(), &test_args).await;
    if res.is_ok() {
        Err(eyre!("task constructor should have failed"))
    } else {
        Ok(())
    }
}
integration_test_async!(create_invalid_wallet);
