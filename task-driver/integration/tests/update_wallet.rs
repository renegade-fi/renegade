//! Integration tests for the `UpdateWallet` task

use circuit_types::{
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
};
use eyre::Result;
use mpc_stark::algebra::scalar::Scalar;
use rand::thread_rng;
use task_driver::update_wallet::UpdateWalletTask;
use test_helpers::{assert_true_result, integration_test_async};
use util::get_current_time_seconds;
use uuid::Uuid;

use crate::{
    helpers::{
        allocate_wallet_in_darkpool, empty_wallet_from_seed, lookup_wallet_and_check_result,
    },
    IntegrationTestArgs,
};

/// Tests updating a wallet then recovering it from on-chain state
async fn test_update_wallet_then_recover(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;
    let mut rng = thread_rng();

    // Create a new wallet and post it on-chain
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let mut wallet = empty_wallet_from_seed(blinder_seed, share_seed);

    allocate_wallet_in_darkpool(&wallet, client).await?;

    // Update the wallet by reblinding it
    let old_wallet = wallet.clone();
    wallet.reblind_wallet();
    let task = UpdateWalletTask::new(
        get_current_time_seconds(),
        None, /* external_transfer */
        old_wallet,
        wallet.clone(),
        client.clone(),
        test_args.network_sender.clone(),
        test_args.global_state.clone(),
        test_args.proof_job_queue.clone(),
    )?;

    let (_task_id, handle) = test_args.driver.start_task(task).await;
    let success = handle.await?;
    assert_true_result!(success)?;

    // Now attempt to lookup the wallet and verify its construction
    lookup_wallet_and_check_result(&wallet, blinder_seed, share_seed, test_args).await
}
integration_test_async!(test_update_wallet_then_recover);

/// Tests placing an order in a wallet
#[allow(non_snake_case)]
async fn test_update_wallet__place_order(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;
    let mut rng = thread_rng();

    // Create a new wallet and post it on-chain
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let mut wallet = empty_wallet_from_seed(blinder_seed, share_seed);

    allocate_wallet_in_darkpool(&wallet, client).await?;

    // Update the wallet by inserting an order
    let old_wallet = wallet.clone();
    wallet.orders.insert(
        Uuid::new_v4(),
        Order {
            quote_mint: 0u8.into(),
            base_mint: 1u8.into(),
            side: OrderSide::Buy,
            amount: 10,
            worst_case_price: FixedPoint::from_integer(10),
            timestamp: get_current_time_seconds(),
        },
    );
    wallet.reblind_wallet();

    let task = UpdateWalletTask::new(
        get_current_time_seconds(),
        None, /* external_transfer */
        old_wallet,
        wallet.clone(),
        client.clone(),
        test_args.network_sender.clone(),
        test_args.global_state.clone(),
        test_args.proof_job_queue.clone(),
    )?;

    let (_task_id, handle) = test_args.driver.start_task(task).await;
    let success = handle.await?;
    assert_true_result!(success)?;

    // Now attempt to lookup the wallet and verify its correctness
    lookup_wallet_and_check_result(&wallet, blinder_seed, share_seed, test_args).await
}
integration_test_async!(test_update_wallet__place_order);
