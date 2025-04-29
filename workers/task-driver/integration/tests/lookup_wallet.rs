//! Integration tests for the `LookupWalletTask`

use common::types::{tasks::LookupWalletTaskDescriptor, wallet_mocks::mock_empty_wallet};
use constants::Scalar;
use eyre::Result;
use rand::{distributions::uniform::SampleRange, thread_rng};
use test_helpers::{
    assert_true_result, contract_interaction::new_wallet_in_darkpool, integration_test_async,
};
use uuid::Uuid;

use crate::{
    helpers::{await_task, lookup_wallet_and_check_result, mock_wallet_update},
    IntegrationTestArgs,
};

/// Tests looking up a wallet that has not been created yet, the task should
/// fail
#[allow(non_snake_case)]
async fn test_lookup_wallet__invalid_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    let wallet = mock_empty_wallet();
    let descriptor = LookupWalletTaskDescriptor::new(
        Uuid::new_v4(),
        Scalar::zero(),
        Scalar::zero(),
        wallet.key_chain.secret_keys,
    )
    .unwrap();

    assert_true_result!(await_task(descriptor.into(), &test_args).await.is_err())
}
integration_test_async!(test_lookup_wallet__invalid_wallet);

/// Tests looking up a wallet that has previously been created
#[allow(non_snake_case)]
async fn test_lookup_wallet__valid_wallet(test_args: IntegrationTestArgs) -> Result<()> {
    // Create a wallet from a blinder seed
    let mut rng = thread_rng();
    let client = &test_args.darkpool_client;
    let (mut wallet, blinder_seed, share_seed) = new_wallet_in_darkpool(client).await?;

    // Reblind the wallet to emulate a sequence of updates to the wallet
    // then send it to the contract
    let num_reblinds = (0..10).sample_single(&mut rng);
    for _ in 0..num_reblinds {
        mock_wallet_update(&mut wallet, client).await?;
    }

    // Check that the wallet is discoverable from contract state and correctly
    // constructed
    lookup_wallet_and_check_result(&wallet, blinder_seed, share_seed, &test_args).await
}
integration_test_async!(test_lookup_wallet__valid_wallet);
