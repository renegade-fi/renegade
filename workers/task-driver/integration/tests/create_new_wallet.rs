//! Integration tests for the `NewWalletTask`

use common::types::{tasks::NewWalletTaskDescriptor, wallet_mocks::mock_empty_wallet};
use eyre::Result;
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
