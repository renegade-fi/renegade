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
    // Create a wallet and reblind it so that we can easily use the previous blinder
    // private share as the blinder seed
    let mut wallet = mock_empty_wallet();
    let blinder_seed = wallet.private_shares.blinder;
    wallet.reblind_wallet();

    let descriptor = NewWalletTaskDescriptor { wallet, blinder_seed };

    await_task(descriptor.into(), &test_args).await
}
integration_test_async!(create_valid_wallet);
