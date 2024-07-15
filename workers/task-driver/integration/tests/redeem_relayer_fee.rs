//! Integration tests for redeeming relayer fees

use circuit_types::balance::Balance;
use circuits::test_helpers::random_wallet_amount;
use common::types::{
    tasks::PayOfflineFeeTaskDescriptor, wallet::Wallet, wallet_mocks::mock_empty_wallet,
};
use constants::Scalar;
use eyre::{eyre, Result};
use rand::thread_rng;
use renegade_crypto::fields::scalar_to_biguint;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::{
    helpers::{
        await_task, await_wallet_task_queue_flush, setup_initial_wallet, setup_relayer_wallet,
    },
    IntegrationTestArgs,
};

// -----------
// | Helpers |
// -----------

/// Get a random balance with a relayer fee
fn random_balance() -> Balance {
    let mut rng = thread_rng();
    let mint = scalar_to_biguint(&Scalar::random(&mut rng));
    let amount = random_wallet_amount();
    let relayer_fee_balance = random_wallet_amount();
    let protocol_fee_balance = 0;

    Balance { mint, amount, relayer_fee_balance, protocol_fee_balance }
}

/// Setup the trader's wallet
///
/// Returns the wallet and the balance that was added to it
async fn setup_trader_wallet(test_args: &IntegrationTestArgs) -> Result<(Balance, Wallet)> {
    let mut rng = thread_rng();
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);

    let mut wallet = mock_empty_wallet();
    let bal = random_balance();
    wallet.add_balance(bal.clone()).unwrap();

    // Set the managing cluster of the wallet to the local relayer
    let key = test_args.state.get_fee_key().await?.public_key();
    wallet.managing_cluster = key;

    setup_initial_wallet(blinder_seed, share_seed, &mut wallet, test_args).await?;
    Ok((bal, wallet))
}

// ---------
// | Tests |
// ---------

/// Settle a relayer fee from a trader's wallet, and await automatic redemption
/// by the relayer
async fn test_auto_redeem_relayer_fee(test_args: IntegrationTestArgs) -> Result<()> {
    setup_relayer_wallet(&test_args).await?;
    let state = &test_args.state;

    // Setup the trader's wallet in the darkpool with a non-zero relayer fee
    let (bal, wallet) = setup_trader_wallet(&test_args).await?;

    // Pay the relayer fee for the balance
    let descriptor =
        PayOfflineFeeTaskDescriptor::new_relayer_fee(wallet.wallet_id, bal.clone()).unwrap();
    await_task(descriptor.into(), &test_args).await?;

    // Await for the relayer's queue to flush
    let relayer_wallet_id = state.get_relayer_wallet_id().await?;
    await_wallet_task_queue_flush(relayer_wallet_id, &test_args).await?;

    // Check that the relayer has redeemed the fee
    let wallet = state.get_wallet(&relayer_wallet_id).await?.unwrap();
    let new_bal = wallet.get_balance(&bal.mint).ok_or(eyre!("redeem balance not found"))?.clone();

    let expected_balance = Balance::new_from_mint_and_amount(bal.mint, bal.relayer_fee_balance);
    assert_eq_result!(new_bal, expected_balance)
}
integration_test_async!(test_auto_redeem_relayer_fee);
