//! Integration tests for settling matches, both internal and cross-cluster

use crate::{
    helpers::{
        biguint_from_hex_string, increase_erc20_allowance, lookup_wallet_and_check_result,
        new_wallet_in_darkpool,
    },
    IntegrationTestArgs,
};
use circuit_types::{
    balance::Balance,
    fee::Fee,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    r#match::MatchResult,
    traits::{LinkableBaseType, LinkableType},
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use circuits::zk_circuits::valid_match_mpc::ValidMatchMpcWitness;
use common::types::{
    handshake::{mocks::mock_handshake_state, HandshakeResult, HandshakeState},
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle, ValidMatchMpcBundle},
    wallet::Wallet,
};
use eyre::{eyre, Result};
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::BigUint;
use rand::thread_rng;
use renegade_crypto::fields::scalar_to_u64;
use state::RelayerState;
use task_driver::{settle_match::SettleMatchTask, settle_match_internal::SettleMatchInternalTask};
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};
use tokio::sync::{mpsc::unbounded_channel, oneshot::channel};
use uuid::Uuid;

use super::{update_wallet::execute_wallet_update, WETH_ADDR};

/// The price at which the mock trade executes at
const EXECUTION_PRICE: f64 = 9.6;

// -----------
// | Helpers |
// -----------

/// Create a dummy order
fn dummy_order(side: OrderSide, test_args: &IntegrationTestArgs) -> Order {
    let worst_cast_price = match side {
        OrderSide::Buy => 12,
        OrderSide::Sell => 9,
    };

    Order {
        quote_mint: biguint_from_hex_string(&test_args.erc20_addr),
        base_mint: biguint_from_hex_string(WETH_ADDR),
        side,
        amount: 10,
        worst_case_price: FixedPoint::from_integer(worst_cast_price),
        timestamp: 10,
    }
}

/// Create a dummy balance
fn dummy_balance(side: OrderSide, test_args: &IntegrationTestArgs) -> Balance {
    match side {
        OrderSide::Buy => Balance {
            mint: biguint_from_hex_string(&test_args.erc20_addr),
            amount: 500,
        },
        OrderSide::Sell => Balance {
            mint: biguint_from_hex_string(WETH_ADDR),
            amount: 200,
        },
    }
}

/// Setup a wallet with a given order and balance
///
/// Returns the wallet, a blinder seed and a share seed
async fn setup_wallet_with_order_balance(
    order: Order,
    balance: Balance,
    test_args: IntegrationTestArgs,
) -> Result<(Wallet, Scalar, Scalar)> {
    let client = &test_args.starknet_client;
    let (mut wallet, blinder_seed, share_seed) = new_wallet_in_darkpool(client).await?;

    // Deposit the balance into the wallet
    let old_wallet = wallet.clone();
    wallet
        .balances
        .insert(balance.mint.clone(), balance.clone());
    wallet.reblind_wallet();

    // Increase the deposit allowance to transfer the balance
    increase_erc20_allowance(
        balance.amount,
        &balance.mint.to_str_radix(16 /* radix */),
        test_args.clone(),
    )
    .await?;

    execute_wallet_update(
        old_wallet,
        wallet.clone(),
        Some(ExternalTransfer {
            mint: balance.mint,
            amount: balance.amount.into(),
            account_addr: biguint_from_hex_string(&test_args.account_addr),
            direction: ExternalTransferDirection::Deposit,
        }),
        test_args.clone(),
    )
    .await?;

    // Add the order to the wallet
    let old_wallet = wallet.clone();
    wallet.orders.insert(Uuid::new_v4(), order);
    wallet.reblind_wallet();

    execute_wallet_update(
        old_wallet,
        wallet.clone(),
        None, /* transfer */
        test_args.clone(),
    )
    .await?;

    Ok((wallet, blinder_seed, share_seed))
}

/// Setup a buy side wallet
async fn setup_buy_side_wallet(test_args: IntegrationTestArgs) -> Result<(Wallet, Scalar, Scalar)> {
    setup_wallet_with_order_balance(
        dummy_order(OrderSide::Buy, &test_args),
        dummy_balance(OrderSide::Buy, &test_args),
        test_args,
    )
    .await
}

/// Setup a sell side wallet
async fn setup_sell_side_wallet(
    test_args: IntegrationTestArgs,
) -> Result<(Wallet, Scalar, Scalar)> {
    setup_wallet_with_order_balance(
        dummy_order(OrderSide::Sell, &test_args),
        dummy_balance(OrderSide::Sell, &test_args),
        test_args,
    )
    .await
}

/// Setup a `HandshakeResult` by mocking out the process taken by the handshake
/// manager
async fn setup_match_result(
    mut wallet1: Wallet,
    mut wallet2: Wallet,
    test_args: &IntegrationTestArgs,
) -> Result<HandshakeResult> {
    let mut rng = thread_rng();
    let price = FixedPoint::from_f64_round_down(EXECUTION_PRICE);
    let base_amount = 10;
    let quote_amount = price * Scalar::from(base_amount);
    let direction = if wallet1.orders.first().unwrap().1.side == OrderSide::Buy {
        0
    } else {
        1
    };

    let match_ = MatchResult {
        quote_mint: biguint_from_hex_string(&test_args.erc20_addr),
        base_mint: biguint_from_hex_string(WETH_ADDR),
        quote_amount: scalar_to_u64(&quote_amount.floor()),
        base_amount,
        direction,
        max_minus_min_amount: 0,
        min_amount_order_index: 0,
    };

    // Simulate a reblind that would happen before a match
    wallet1.reblind_wallet();
    wallet2.reblind_wallet();

    Ok(HandshakeResult {
        match_: match_.to_linkable(),
        party0_share_nullifier: Scalar::random(&mut rng),
        party1_share_nullifier: Scalar::random(&mut rng),
        party0_reblinded_shares: wallet1.blinded_public_shares.to_linkable(),
        party1_reblinded_shares: wallet2.blinded_public_shares.to_linkable(),
        match_proof: dummy_match_proof(&wallet1, &wallet2, match_, test_args).await?,
        party0_fee: Fee::default().to_linkable(),
        party1_fee: Fee::default().to_linkable(),
    })
}

/// Get the validity proof bundle for the first order in a given wallet
async fn get_first_order_proofs(
    wallet: &Wallet,
    state: &RelayerState,
) -> Result<OrderValidityProofBundle> {
    let order_id = wallet.orders.first().unwrap().0;
    state
        .read_order_book()
        .await
        .get_validity_proofs(order_id)
        .await
        .ok_or_else(|| eyre!("Order validity proof bundle not found"))
}

/// Get the validity proof witness for the first order in a given wallet
async fn get_first_order_witness(
    wallet: &Wallet,
    state: &RelayerState,
) -> Result<OrderValidityWitnessBundle> {
    let order_id = wallet.orders.first().unwrap().0;
    state
        .read_order_book()
        .await
        .get_validity_proof_witnesses(order_id)
        .await
        .ok_or_else(|| eyre!("Order validity witness bundle not found"))
}

/// Generate a dummy match proof on the first order in each wallet
async fn dummy_match_proof(
    wallet1: &Wallet,
    wallet2: &Wallet,
    match_res: MatchResult,
    test_args: &IntegrationTestArgs,
) -> Result<ValidMatchMpcBundle> {
    let order1 = wallet1.orders.first().unwrap().1;
    let balance1 = wallet1.balances.first().unwrap().1;
    let amount1 = Scalar::from(order1.amount);
    let order2 = wallet2.orders.first().unwrap().1;
    let balance2 = wallet2.balances.first().unwrap().1;
    let amount2 = Scalar::from(order2.amount);
    let price = FixedPoint::from_f64_round_down(EXECUTION_PRICE);

    let (send, recv) = channel();
    let job = ProofManagerJob {
        type_: ProofJob::ValidMatchMpcSingleprover {
            witness: ValidMatchMpcWitness {
                order1: order1.to_linkable(),
                order2: order2.to_linkable(),
                balance1: balance1.to_linkable(),
                balance2: balance2.to_linkable(),
                price1: price,
                price2: price,
                amount1,
                amount2,
                match_res: match_res.to_linkable(),
            },
        },
        response_channel: send,
    };
    test_args.proof_job_queue.send(job)?;

    // Await a response
    recv.await
        .map(|bundle| bundle.into())
        .map_err(|_| eyre!("Failed to receive proof bundle"))
}

/// Verify that a match has been correctly applied to a wallet
async fn verify_settlement(
    mut wallet: Wallet,
    blinder_seed: Scalar,
    share_seed: Scalar,
    order_side: OrderSide,
    match_res: MatchResult,
    test_args: IntegrationTestArgs,
) -> Result<()> {
    let state = &test_args.global_state;

    // 1. Apply the match to the wallet
    apply_match(&mut wallet, order_side, &match_res);
    wallet.reblind_wallet();

    // 2. Lookup the wallet in global state, verify that this matches the expected
    let new_wallet = state
        .read_wallet_index()
        .await
        .get_wallet(&wallet.wallet_id)
        .await
        .ok_or_else(|| eyre!("wallet not found in state"))?;

    assert_eq_result!(new_wallet.blinder, wallet.blinder)?;

    assert_eq_result!(
        new_wallet.blinded_public_shares,
        wallet.blinded_public_shares
    )?;
    assert_eq_result!(new_wallet.private_shares, wallet.private_shares)?;

    // 3. Lookup the wallet on-chain, verify that this matches the expected
    lookup_wallet_and_check_result(&wallet, blinder_seed, share_seed, test_args.clone()).await
}

/// Apply a match to the wallet
fn apply_match(wallet: &mut Wallet, order_side: OrderSide, match_res: &MatchResult) {
    let quote_mint = match_res.quote_mint.clone();
    let base_mint = match_res.base_mint.clone();

    let quote_amount = match_res.quote_amount as i64;
    let base_amount = match_res.base_amount as i64;

    match order_side {
        OrderSide::Buy => {
            // Buy the base, sell the quote
            apply_balance_update(wallet, quote_mint, -quote_amount);
            apply_balance_update(wallet, base_mint, base_amount);
        }
        OrderSide::Sell => {
            // Buy the quote, sell the base
            apply_balance_update(wallet, quote_mint, quote_amount);
            apply_balance_update(wallet, base_mint, -base_amount);
        }
    };

    // Update the order volume
    wallet.orders.first_mut().unwrap().1.amount -= match_res.base_amount;
}

/// Add a u64 to an i64 without overflowing
fn apply_balance_update(wallet: &mut Wallet, mint: BigUint, amount: i64) {
    let entry = wallet
        .balances
        .entry(mint.clone())
        .or_insert_with(|| Balance { mint, amount: 0 });

    if amount < 0 {
        entry.amount = entry.amount.saturating_sub(amount.unsigned_abs());
    } else {
        entry.amount = entry.amount.saturating_add(amount as u64);
    }
}

// ---------
// | Tests |
// ---------

/// Tests that settling an internal match succeeds and state is properly updated
async fn test_settle_internal_match(test_args: IntegrationTestArgs) -> Result<()> {
    // Create two new wallets with orders that match
    let state = &test_args.global_state;
    let client = &test_args.starknet_client;
    let (buy_wallet, buy_blinder_seed, buy_share_seed) =
        setup_buy_side_wallet(test_args.clone()).await?;
    let (sell_wallet, sell_blinder_seed, sell_share_seed) =
        setup_sell_side_wallet(test_args.clone()).await?;

    // Setup the match result
    let handshake_res =
        setup_match_result(buy_wallet.clone(), sell_wallet.clone(), &test_args).await?;

    // Create the task
    let (network_sender, _network_recv) = unbounded_channel();
    let task = SettleMatchInternalTask::new(
        FixedPoint::from_f64_round_down(EXECUTION_PRICE),
        *buy_wallet.orders.first().unwrap().0,
        *sell_wallet.orders.first().unwrap().0,
        get_first_order_proofs(&buy_wallet, state).await?,
        get_first_order_witness(&buy_wallet, state).await?,
        get_first_order_proofs(&sell_wallet, state).await?,
        get_first_order_witness(&sell_wallet, state).await?,
        handshake_res.match_.to_base_type(),
        client.clone(),
        network_sender,
        state.clone(),
        test_args.proof_job_queue.clone(),
    )
    .await?;

    let (_id, handle) = test_args.driver.start_task(task).await;
    let res = handle.await?;
    assert_true_result!(res)?;

    // Verify the match on both wallets
    let res = handshake_res.match_.to_base_type();
    verify_settlement(
        buy_wallet,
        buy_blinder_seed,
        buy_share_seed,
        OrderSide::Buy,
        res.clone(),
        test_args.clone(),
    )
    .await?;

    verify_settlement(
        sell_wallet,
        sell_blinder_seed,
        sell_share_seed,
        OrderSide::Sell,
        res,
        test_args.clone(),
    )
    .await
}
integration_test_async!(test_settle_internal_match);

/// Tests settling a match that came from an MPC
async fn test_settle_mpc_match(test_args: IntegrationTestArgs) -> Result<()> {
    // Create two new wallets with orders that match
    let state = &test_args.global_state;
    let client = &test_args.starknet_client;
    let (buy_wallet, buy_blinder_seed, buy_share_seed) =
        setup_buy_side_wallet(test_args.clone()).await?;
    let (mut sell_wallet, sell_blinder_seed, sell_share_seed) =
        setup_sell_side_wallet(test_args.clone()).await?;

    // Setup the match result
    let handshake_res =
        setup_match_result(buy_wallet.clone(), sell_wallet.clone(), &test_args).await?;
    let handshake_state = HandshakeState {
        local_order_id: *buy_wallet.orders.first().unwrap().0,
        peer_order_id: *sell_wallet.orders.first().unwrap().0,
        ..mock_handshake_state()
    };

    let (network_sender, _network_recv) = unbounded_channel();
    let task = SettleMatchTask::new(
        handshake_state,
        Box::new(handshake_res.clone()),
        get_first_order_proofs(&buy_wallet, state).await?,
        get_first_order_proofs(&sell_wallet, state).await?,
        client.clone(),
        network_sender,
        state.clone(),
        test_args.proof_job_queue.clone(),
    )
    .await;

    let (_id, handle) = test_args.driver.start_task(task).await;
    let res = handle.await?;
    assert_true_result!(res)?;

    // Only the first wallet would have been updated in the global state, as the second wallet
    // is assumed to be managed by another cluster
    let match_res = handshake_res.match_.to_base_type();
    verify_settlement(
        buy_wallet,
        buy_blinder_seed,
        buy_share_seed,
        OrderSide::Buy,
        match_res.clone(),
        test_args.clone(),
    )
    .await?;

    // The second wallet we must verify by looking up on-chain
    apply_match(&mut sell_wallet, OrderSide::Sell, &match_res);
    sell_wallet.reblind_wallet();

    lookup_wallet_and_check_result(
        &sell_wallet,
        sell_blinder_seed,
        sell_share_seed,
        test_args.clone(),
    )
    .await
}
integration_test_async!(test_settle_mpc_match);
