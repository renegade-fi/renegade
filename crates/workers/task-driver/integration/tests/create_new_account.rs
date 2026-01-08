//! Integration tests for the `CreateNewAccountTask`

use eyre::Result;
use test_helpers::integration_test_async;
use types_account::account::mocks::mock_empty_account;
use types_tasks::NewAccountTaskDescriptor;

use crate::{IntegrationTestArgs, helpers::await_task};

// ---------
// | Tests |
// ---------

/// Basic functionality test of creating a new account
async fn create_new_account(test_args: IntegrationTestArgs) -> Result<()> {
    // Create a mock account
    let account = mock_empty_account();
    let account_id = account.id;
    let keychain = account.keychain;

    let descriptor = NewAccountTaskDescriptor { account_id, keychain };
    await_task(descriptor.into(), &test_args).await
}
integration_test_async!(create_new_account);
