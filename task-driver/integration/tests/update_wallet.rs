//! Integration tests for the `UpdateWallet` task

use circuit_types::{
    fee::Fee,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
};
use eyre::Result;
use lazy_static::lazy_static;
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::BigUint;
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

lazy_static! {
    /// A dummy order that is allocated in a wallet as an update
    static ref DUMMY_ORDER: Order = Order {
        quote_mint: 0u8.into(),
        base_mint: 1u8.into(),
        side: OrderSide::Buy,
        amount: 10,
        worst_case_price: FixedPoint::from_integer(10),
        timestamp: get_current_time_seconds(),
    };

    /// A dummy fee that is allocated in a wallet
    static ref DUMMY_FEE: Fee = Fee {
        gas_addr: BigUint::from(0u8),
        gas_token_amount: 10,
        settle_key: BigUint::from(15u8),
        percentage_fee: FixedPoint::from_f32_round_down(0.01),
    };
}

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
    wallet.orders.insert(Uuid::new_v4(), DUMMY_ORDER.clone());
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

/// Tests cancelling an order in a wallet
#[allow(non_snake_case)]
async fn test_update_wallet__cancel_order(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;
    let mut rng = thread_rng();

    // Create a new wallet with a non-empty order and post it on-chain
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let mut wallet = empty_wallet_from_seed(blinder_seed, share_seed);

    let order_id = Uuid::new_v4();
    wallet.orders.insert(order_id, DUMMY_ORDER.clone());

    allocate_wallet_in_darkpool(&wallet, client).await?;

    // Update the wallet by removing an order
    let old_wallet = wallet.clone();
    wallet.orders.remove(&order_id);
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
integration_test_async!(test_update_wallet__cancel_order);

/// Tests updating a wallet by adding a fee to the wallet
#[allow(non_snake_case)]
async fn test_update_wallet__add_fee(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;
    let mut rng = thread_rng();

    // Create a new wallet and post it on-chain
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let mut wallet = empty_wallet_from_seed(blinder_seed, share_seed);

    allocate_wallet_in_darkpool(&wallet, client).await?;

    // Update the wallet by adding a fee
    let old_wallet = wallet.clone();
    wallet.fees.push(DUMMY_FEE.clone());
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
integration_test_async!(test_update_wallet__add_fee);

/// Tests updating a wallet by removing a fee from the wallet
#[allow(non_snake_case)]
async fn test_update_wallet__remove_fee(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.starknet_client;
    let mut rng = thread_rng();

    // Create a new wallet with a non-empty fee and post it on-chain
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let mut wallet = empty_wallet_from_seed(blinder_seed, share_seed);

    wallet.fees.push(DUMMY_FEE.clone());

    allocate_wallet_in_darkpool(&wallet, client).await?;

    // Update the wallet by removing a fee
    let old_wallet = wallet.clone();
    wallet.fees.pop();
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
integration_test_async!(test_update_wallet__remove_fee);
