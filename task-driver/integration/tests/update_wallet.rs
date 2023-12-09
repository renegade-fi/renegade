//! Integration tests for the `UpdateWallet` task

use circuit_types::{
    balance::Balance,
    fee::Fee,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use common::types::wallet::Wallet;
use constants::Scalar;
use eyre::Result;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use rand::thread_rng;
use task_driver::update_wallet::UpdateWalletTask;
use test_helpers::{assert_true_result, integration_test_async};
use util::{get_current_time_seconds, hex::biguint_from_hex_string};
use uuid::Uuid;

use crate::{
    helpers::{
        allocate_wallet_in_darkpool, biguint_from_address, empty_wallet_from_seed,
        increase_erc20_allowance, lookup_wallet_and_check_result, new_wallet_in_darkpool,
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

// -----------
// | Helpers |
// -----------

/// Perform a wallet update task and verify that it succeeds
pub(crate) async fn execute_wallet_update(
    old_wallet: Wallet,
    new_wallet: Wallet,
    transfer: Option<ExternalTransfer>,
    test_args: IntegrationTestArgs,
) -> Result<()> {
    let client = &test_args.arbitrum_client;
    let task = UpdateWalletTask::new(
        get_current_time_seconds(),
        transfer,
        old_wallet,
        new_wallet,
        vec![], // wallet_update_signature
        client.clone(),
        test_args.network_sender.clone(),
        test_args.global_state.clone(),
        test_args.proof_job_queue.clone(),
    )?;

    let (_task_id, handle) = test_args.driver.start_task(task).await;
    let success = handle.await?;
    assert_true_result!(success)
}

/// Execute a wallet update, then lookup the new wallet from on-chain state and
/// verify it has been correctly constructed
async fn execute_wallet_update_and_verify_shares(
    old_wallet: Wallet,
    new_wallet: Wallet,
    transfer: Option<ExternalTransfer>,
    blinder_seed: Scalar,
    share_seed: Scalar,
    test_args: IntegrationTestArgs,
) -> Result<()> {
    execute_wallet_update(old_wallet, new_wallet.clone(), transfer, test_args.clone()).await?;
    lookup_wallet_and_check_result(&new_wallet, blinder_seed, share_seed, test_args).await
}

// ---------
// | Tests |
// ---------

/// Tests updating a wallet then recovering it from on-chain state
async fn test_update_wallet_then_recover(test_args: IntegrationTestArgs) -> Result<()> {
    // Create a new wallet and post it on-chain
    let client = &test_args.arbitrum_client;
    let (mut wallet, blinder_seed, share_seed) = new_wallet_in_darkpool(client).await?;

    // Update the wallet by reblinding it
    let old_wallet = wallet.clone();
    wallet.reblind_wallet();
    execute_wallet_update_and_verify_shares(
        old_wallet,
        wallet,
        None, // transfer
        blinder_seed,
        share_seed,
        test_args,
    )
    .await
}
integration_test_async!(test_update_wallet_then_recover);

// ----------
// | Orders |
// ----------

/// Tests placing an order in a wallet
#[allow(non_snake_case)]
async fn test_update_wallet__place_order(test_args: IntegrationTestArgs) -> Result<()> {
    // Create a new wallet and post it on-chain
    let client = &test_args.arbitrum_client;
    let (mut wallet, blinder_seed, share_seed) = new_wallet_in_darkpool(client).await?;

    // Update the wallet by inserting an order
    let old_wallet = wallet.clone();
    wallet.orders.insert(Uuid::new_v4(), DUMMY_ORDER.clone());
    wallet.reblind_wallet();

    execute_wallet_update_and_verify_shares(
        old_wallet,
        wallet,
        None, // transfer
        blinder_seed,
        share_seed,
        test_args,
    )
    .await
}
integration_test_async!(test_update_wallet__place_order);

/// Tests cancelling an order in a wallet
#[allow(non_snake_case)]
async fn test_update_wallet__cancel_order(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.arbitrum_client;
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

    execute_wallet_update_and_verify_shares(
        old_wallet,
        wallet,
        None, // transfer
        blinder_seed,
        share_seed,
        test_args,
    )
    .await
}
integration_test_async!(test_update_wallet__cancel_order);

// --------
// | Fees |
// --------

/// Tests updating a wallet by adding a fee to the wallet
#[allow(non_snake_case)]
async fn test_update_wallet__add_fee(test_args: IntegrationTestArgs) -> Result<()> {
    // Create a new wallet and post it on-chain
    let client = &test_args.arbitrum_client;
    let (mut wallet, blinder_seed, share_seed) = new_wallet_in_darkpool(client).await?;

    // Update the wallet by adding a fee
    let old_wallet = wallet.clone();
    wallet.fees.push(DUMMY_FEE.clone());
    wallet.reblind_wallet();

    execute_wallet_update_and_verify_shares(
        old_wallet,
        wallet,
        None, // transfer
        blinder_seed,
        share_seed,
        test_args,
    )
    .await
}
integration_test_async!(test_update_wallet__add_fee);

/// Tests updating a wallet by removing a fee from the wallet
#[allow(non_snake_case)]
async fn test_update_wallet__remove_fee(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.arbitrum_client;
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

    execute_wallet_update_and_verify_shares(
        old_wallet,
        wallet,
        None, // transfer
        blinder_seed,
        share_seed,
        test_args,
    )
    .await
}
integration_test_async!(test_update_wallet__remove_fee);

// ------------
// | Balances |
// ------------

/// Tests updating a wallet by depositing into the pool
#[allow(non_snake_case)]
async fn test_update_wallet__deposit_and_withdraw(test_args: IntegrationTestArgs) -> Result<()> {
    let client = &test_args.arbitrum_client;

    // Create a new wallet and post it on-chain
    let (mut wallet, blinder_seed, share_seed) = new_wallet_in_darkpool(client).await?;

    // Update the wallet by depositing into the pool
    let old_wallet = wallet.clone();

    let mint = biguint_from_hex_string(&test_args.erc20_addr).unwrap();
    let amount = 10u64;

    wallet.balances.insert(mint.clone(), Balance { mint: mint.clone(), amount });
    wallet.reblind_wallet();

    // Approve the deposit on the ERC20 contract
    increase_erc20_allowance(amount, &test_args.erc20_addr, test_args.clone()).await?;

    let account_addr = biguint_from_address(client.wallet_address());
    execute_wallet_update_and_verify_shares(
        old_wallet,
        wallet.clone(),
        Some(ExternalTransfer {
            mint: mint.clone(),
            amount: amount.into(),
            account_addr: account_addr.clone(),
            direction: ExternalTransferDirection::Deposit,
        }),
        blinder_seed,
        share_seed,
        test_args.clone(),
    )
    .await?;

    // Now, withdraw the same amount
    let old_wallet = wallet.clone();
    wallet.balances.remove(&mint);
    wallet.reblind_wallet();

    execute_wallet_update_and_verify_shares(
        old_wallet,
        wallet,
        Some(ExternalTransfer {
            mint,
            amount: amount.into(),
            account_addr,
            direction: ExternalTransferDirection::Withdrawal,
        }),
        blinder_seed,
        share_seed,
        test_args,
    )
    .await
}
integration_test_async!(test_update_wallet__deposit_and_withdraw);
