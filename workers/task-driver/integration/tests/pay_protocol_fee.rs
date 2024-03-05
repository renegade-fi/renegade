//! Protocol fee payment tests
use circuit_types::balance::Balance;
use circuits::test_helpers::random_wallet_amount;
use common::types::{tasks::PayProtocolFeeTaskDescriptor, wallet_mocks::mock_empty_wallet};
use constants::Scalar;
use eyre::{eyre, Result};
use rand::thread_rng;
use renegade_crypto::fields::scalar_to_biguint;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::{
    helpers::{await_task, lookup_wallet_and_check_result, setup_initial_wallet},
    IntegrationTestArgs,
};

// -----------
// | Helpers |
// -----------

/// Generate a random balance with a non-zero protocol fee
fn random_balance_with_protocol_fee() -> Balance {
    let mut rng = thread_rng();
    let mint = scalar_to_biguint(&Scalar::random(&mut rng));
    let amount = random_wallet_amount();
    let protocol_fee_balance = random_wallet_amount();
    let relayer_fee_balance = random_wallet_amount();

    Balance { mint, amount, relayer_fee_balance, protocol_fee_balance }
}

// ---------
// | Tests |
// ---------

/// Tests paying a protocol fee then recovering the wallet from on-chain
async fn test_pay_protocol_fee(test_args: IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();
    let state = &test_args.state;

    // Create a wallet in the darkpool with a non-zero fee
    let mut wallet = mock_empty_wallet();
    let bal = random_balance_with_protocol_fee();
    wallet.add_balance(bal.clone()).unwrap();

    // Allocate the wallet
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    setup_initial_wallet(blinder_seed, share_seed, &mut wallet, &test_args).await?;

    // Pay the protocol fee
    let descriptor = PayProtocolFeeTaskDescriptor::new(wallet.wallet_id, bal.mint.clone());
    await_task(descriptor.into(), &test_args).await?;

    // Check the wallet, first from global state
    let mut expected_wallet = wallet.clone();
    expected_wallet.get_balance_mut(&bal.mint).unwrap().protocol_fee_balance = 0;
    expected_wallet.reblind_wallet();

    let wallet =
        state.get_wallet(&wallet.wallet_id)?.ok_or_else(|| eyre!("wallet not found in state"))?;

    // We only compare the public and private shares, other metadata fields on the
    // wallets may differ
    assert_eq_result!(wallet.blinded_public_shares, expected_wallet.blinded_public_shares)?;
    assert_eq_result!(wallet.private_shares, expected_wallet.private_shares)?;

    // Now lookup the wallet from on-chain
    lookup_wallet_and_check_result(&expected_wallet, blinder_seed, share_seed, test_args).await
}
integration_test_async!(test_pay_protocol_fee);
