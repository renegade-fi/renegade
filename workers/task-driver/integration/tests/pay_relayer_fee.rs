//! Tests the `PayRelayerFee` task

use circuit_types::balance::Balance;
use circuits::test_helpers::random_wallet_amount;
use common::types::{
    tasks::PayRelayerFeeTaskDescriptor, wallet::Wallet, wallet_mocks::mock_empty_wallet,
};
use constants::Scalar;
use eyre::{eyre, Result};
use num_bigint::BigUint;
use rand::thread_rng;
use renegade_crypto::fields::scalar_to_biguint;
use test_helpers::{
    assert_eq_result, contract_interaction::new_wallet_in_darkpool, integration_test_async,
};

use crate::{
    helpers::{await_task, lookup_wallet_and_check_result, setup_initial_wallet},
    IntegrationTestArgs,
};

/// A dummy initial balance for the relayer to hold in their wallet
const DUMMY_INITIAL_BALANCE: u128 = 100;

// -----------
// | Helpers |
// -----------

/// Returns a balance with a non-zero relayer fee
fn random_balance_with_relayer_fee() -> Balance {
    let mut rng = thread_rng();
    let mint = scalar_to_biguint(&Scalar::random(&mut rng));
    let amount = random_wallet_amount();
    let protocol_fee_balance = random_wallet_amount();
    let relayer_fee_balance = random_wallet_amount();

    Balance { mint, amount, relayer_fee_balance, protocol_fee_balance }
}

/// Setup a user wallet with a non-zero balance and allocate it in the darkpool
///
/// Returns the wallet and the mint of the balance to pay
async fn setup_trader_wallet(
    blinder_seed: Scalar,
    share_seed: Scalar,
    test_args: &IntegrationTestArgs,
) -> Result<(Wallet, BigUint)> {
    let state = &test_args.state;

    // Read the local relayer's decryption key from the state to manage the wallet
    let decryption_key = state.get_fee_key().await?.secret_key().unwrap();

    // Create a wallet in the darkpool with a non-zero fee
    let mut wallet = mock_empty_wallet();
    wallet.managing_cluster = decryption_key.public_key();
    let bal = random_balance_with_relayer_fee();
    wallet.add_balance(bal.clone()).unwrap();

    // Allocate the wallet
    setup_initial_wallet(blinder_seed, share_seed, &mut wallet, test_args).await?;
    Ok((wallet, bal.mint))
}

/// Set the local node's wallet in the global state
async fn set_local_relayer_wallet(wallet: Wallet, args: &IntegrationTestArgs) {
    let state = &args.state;
    state.set_local_relayer_wallet_id(wallet.wallet_id).await.unwrap();
    let waiter = state.update_wallet(wallet).await.unwrap();
    waiter.await.unwrap();
}

/// Check a wallet in both the global state and by looking it up on-chain
async fn check_result_wallet(
    expected: Wallet,
    blinder_seed: Scalar,
    secret_share_seed: Scalar,
    args: &IntegrationTestArgs,
) -> Result<()> {
    let state = &args.state;
    let wallet =
        state.get_wallet(&expected.wallet_id).await?.ok_or_else(|| eyre!("wallet not found"))?;

    // We only compare the public and private shares, other metadata fields on the
    // wallets may differ
    assert_eq_result!(wallet.blinded_public_shares, expected.blinded_public_shares)?;
    assert_eq_result!(wallet.private_shares, expected.private_shares)?;

    // Lookup the wallet from on-chain, and verify its construction
    lookup_wallet_and_check_result(&expected, blinder_seed, secret_share_seed, args).await
}

// --------------
// | Test Cases |
// --------------

/// Tests paying a relayer fee when the relayer initially has no balance
#[allow(non_snake_case)]
async fn test_pay_relayer_fee__zero_initial_balance(test_args: IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();

    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let (trader_wallet, fee_mint) =
        setup_trader_wallet(blinder_seed, share_seed, &test_args).await?;

    // Create an empty relayer wallet
    let (relayer_wallet, relayer_blinder_seed, relayer_share_seed) =
        new_wallet_in_darkpool(&test_args.darkpool_client).await?;
    set_local_relayer_wallet(relayer_wallet.clone(), &test_args).await;

    // Pay the relayer fee
    let desc = PayRelayerFeeTaskDescriptor::new(trader_wallet.wallet_id, fee_mint.clone())
        .expect("infallible");
    await_task(desc.into(), &test_args).await?;

    // Check the trader's wallet
    let mut expected_trader_wallet = trader_wallet.clone();
    let amt = expected_trader_wallet.get_balance_mut(&fee_mint).unwrap().relayer_fee_balance;
    expected_trader_wallet.get_balance_mut(&fee_mint).unwrap().relayer_fee_balance = 0;
    expected_trader_wallet.reblind_wallet();

    check_result_wallet(expected_trader_wallet, blinder_seed, share_seed, &test_args).await?;

    // Check the relayer wallet
    let mut expected_relayer_wallet = relayer_wallet.clone();
    let bal = Balance::new_from_mint_and_amount(fee_mint, amt);
    expected_relayer_wallet.add_balance(bal).unwrap();
    expected_relayer_wallet.reblind_wallet();

    check_result_wallet(
        expected_relayer_wallet,
        relayer_blinder_seed,
        relayer_share_seed,
        &test_args,
    )
    .await
}
integration_test_async!(test_pay_relayer_fee__zero_initial_balance);

/// Tests paying a relayer fee when the relayer initially has a non-zero balance
#[allow(non_snake_case)]
async fn test_pay_relayer_fee__non_zero_initial_balance(
    test_args: IntegrationTestArgs,
) -> Result<()> {
    let mut rng = thread_rng();

    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let (trader_wallet, fee_mint) =
        setup_trader_wallet(blinder_seed, share_seed, &test_args).await?;

    // Create a relayer wallet with a non-zero balance
    let relayer_blinder_seed = Scalar::random(&mut rng);
    let relayer_share_seed = Scalar::random(&mut rng);
    let mut relayer_wallet = mock_empty_wallet();
    relayer_wallet
        .add_balance(Balance::new_from_mint_and_amount(fee_mint.clone(), DUMMY_INITIAL_BALANCE))
        .unwrap();

    setup_initial_wallet(relayer_blinder_seed, relayer_share_seed, &mut relayer_wallet, &test_args)
        .await?;
    set_local_relayer_wallet(relayer_wallet.clone(), &test_args).await;

    // Pay the relayer fee
    let desc = PayRelayerFeeTaskDescriptor::new(trader_wallet.wallet_id, fee_mint.clone())
        .expect("infallible");
    await_task(desc.into(), &test_args).await?;

    // Check the trader's wallet
    let mut expected_trader_wallet = trader_wallet.clone();
    let amt = expected_trader_wallet.get_balance_mut(&fee_mint).unwrap().relayer_fee_balance;
    expected_trader_wallet.get_balance_mut(&fee_mint).unwrap().relayer_fee_balance = 0;
    expected_trader_wallet.reblind_wallet();

    check_result_wallet(expected_trader_wallet, blinder_seed, share_seed, &test_args).await?;

    // Check the relayer wallet
    let mut expected_relayer_wallet = relayer_wallet.clone();
    let bal = Balance::new_from_mint_and_amount(fee_mint, amt);
    expected_relayer_wallet.add_balance(bal).unwrap();
    expected_relayer_wallet.reblind_wallet();

    check_result_wallet(
        expected_relayer_wallet,
        relayer_blinder_seed,
        relayer_share_seed,
        &test_args,
    )
    .await
}
integration_test_async!(test_pay_relayer_fee__non_zero_initial_balance);
