//! Integration tests for settling matches, both internal and cross-cluster

use crate::{
    helpers::{
        biguint_from_address, biguint_from_hex_string, increase_erc20_allowance,
        lookup_wallet_and_check_result, new_wallet_in_darkpool,
    },
    IntegrationTestArgs,
};
use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    r#match::{MatchResult, OrderSettlementIndices},
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use circuits::zk_circuits::valid_match_settle::{
    ValidMatchSettleStatement, ValidMatchSettleWitness,
};
use common::types::{
    handshake::{mocks::mock_handshake_state, HandshakeState},
    proof_bundles::{OrderValidityProofBundle, OrderValidityWitnessBundle, ValidMatchSettleBundle},
    wallet::Wallet,
};
use constants::Scalar;
use eyre::{eyre, Result};
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use renegade_crypto::fields::scalar_to_u64;
use state::RelayerState;
use task_driver::{settle_match::SettleMatchTask, settle_match_internal::SettleMatchInternalTask};
use test_helpers::{
    arbitrum::PREDEPLOYED_WETH_ADDR, assert_eq_result, assert_true_result, integration_test_async,
};
use tokio::sync::{mpsc::unbounded_channel, oneshot::channel};
use util::matching_engine::settle_match_into_wallets;
use uuid::Uuid;

use super::update_wallet::execute_wallet_update;

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
        base_mint: biguint_from_hex_string(PREDEPLOYED_WETH_ADDR),
        side,
        amount: 10,
        worst_case_price: FixedPoint::from_integer(worst_cast_price),
        timestamp: 10,
    }
}

/// Create a dummy balance
fn dummy_balance(side: OrderSide, test_args: &IntegrationTestArgs) -> Balance {
    match side {
        OrderSide::Buy => {
            Balance { mint: biguint_from_hex_string(&test_args.erc20_addr), amount: 500 }
        },
        OrderSide::Sell => {
            Balance { mint: biguint_from_hex_string(PREDEPLOYED_WETH_ADDR), amount: 200 }
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
    let client = &test_args.arbitrum_client;
    let account_addr = biguint_from_address(client.wallet_address());
    let (mut wallet, blinder_seed, share_seed) = new_wallet_in_darkpool(client).await?;

    // Deposit the balance into the wallet
    let old_wallet = wallet.clone();
    wallet.balances.insert(balance.mint.clone(), balance.clone());
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
            account_addr,
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
        None, // transfer
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
) -> Result<(MatchResult, ValidMatchSettleBundle)> {
    let price = FixedPoint::from_f64_round_down(EXECUTION_PRICE);
    let base_amount = 10;
    let quote_amount = price * Scalar::from(base_amount);
    let direction = wallet1.orders.first().unwrap().1.side.is_sell();

    let match_ = MatchResult {
        quote_mint: biguint_from_hex_string(&test_args.erc20_addr),
        base_mint: biguint_from_hex_string(PREDEPLOYED_WETH_ADDR),
        quote_amount: scalar_to_u64(&quote_amount.floor()),
        base_amount,
        direction,
        max_minus_min_amount: 0,
        min_amount_order_index: false,
    };

    // Simulate a reblind that would happen before a match
    wallet1.reblind_wallet();
    wallet2.reblind_wallet();

    let proof = dummy_match_proof(&wallet1, &wallet2, match_.clone(), test_args).await?;
    Ok((match_, proof))
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
) -> Result<ValidMatchSettleBundle> {
    let order1 = wallet1.orders.first().unwrap().1.clone();
    let balance1 = wallet1.balances.first().unwrap().1.clone();
    let amount1 = Scalar::from(order1.amount);
    let party0_public_shares = wallet1.blinded_public_shares.clone();

    let order2 = wallet2.orders.first().unwrap().1.clone();
    let balance2 = wallet2.balances.first().unwrap().1.clone();
    let amount2 = Scalar::from(order2.amount);
    let price = FixedPoint::from_f64_round_down(EXECUTION_PRICE);
    let party1_public_shares = wallet2.blinded_public_shares.clone();

    let party0_indices = OrderSettlementIndices { order: 0, balance_send: 0, balance_receive: 1 };
    let party1_indices = party0_indices;

    let mut party0_modified_shares = party0_public_shares.clone();
    let mut party1_modified_shares = party1_public_shares.clone();
    settle_match_into_wallets(
        &mut party0_modified_shares,
        &mut party1_modified_shares,
        party0_indices,
        party1_indices,
        &match_res,
    );

    let (send, recv) = channel();
    let job = ProofManagerJob {
        type_: ProofJob::ValidMatchSettleSingleprover {
            witness: ValidMatchSettleWitness {
                order1,
                order2,
                balance1,
                balance2,
                price1: price,
                price2: price,
                amount1,
                amount2,
                match_res,
                party0_public_shares,
                party1_public_shares,
            },
            statement: ValidMatchSettleStatement {
                party0_indices,
                party1_indices,
                party0_modified_shares,
                party1_modified_shares,
            },
        },
        response_channel: send,
    };
    test_args.proof_job_queue.send(job)?;

    // Await a response
    recv.await.map(|bundle| bundle.into()).map_err(|_| eyre!("Failed to receive proof bundle"))
}

/// Verify that a match has been correctly applied to a wallet
async fn verify_settlement(
    mut wallet: Wallet,
    blinder_seed: Scalar,
    share_seed: Scalar,
    match_res: MatchResult,
    test_args: IntegrationTestArgs,
) -> Result<()> {
    let state = &test_args.global_state;

    // 1. Apply the match to the wallet
    wallet.reblind_wallet();

    let first_order = *wallet.orders.first().unwrap().0;
    wallet.apply_match(&match_res, &first_order);

    // 2. Lookup the wallet in global state, verify that this matches the expected
    let new_wallet = state
        .read_wallet_index()
        .await
        .get_wallet(&wallet.wallet_id)
        .await
        .ok_or_else(|| eyre!("wallet not found in state"))?;

    assert_eq_result!(new_wallet.blinder, wallet.blinder)?;

    assert_eq_result!(new_wallet.blinded_public_shares, wallet.blinded_public_shares)?;
    assert_eq_result!(new_wallet.private_shares, wallet.private_shares)?;

    // 3. Lookup the wallet on-chain, verify that this matches the expected
    lookup_wallet_and_check_result(&wallet, blinder_seed, share_seed, test_args.clone()).await
}

// ---------
// | Tests |
// ---------

/// Tests that settling an internal match succeeds and state is properly updated
async fn test_settle_internal_match(test_args: IntegrationTestArgs) -> Result<()> {
    // Create two new wallets with orders that match
    let state = &test_args.global_state;
    let client = &test_args.arbitrum_client;
    let (buy_wallet, buy_blinder_seed, buy_share_seed) =
        setup_buy_side_wallet(test_args.clone()).await?;
    let (sell_wallet, sell_blinder_seed, sell_share_seed) =
        setup_sell_side_wallet(test_args.clone()).await?;

    // Setup the match result
    let (match_res, _) =
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
        match_res.clone(),
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
    verify_settlement(
        buy_wallet,
        buy_blinder_seed,
        buy_share_seed,
        match_res.clone(),
        test_args.clone(),
    )
    .await?;

    verify_settlement(sell_wallet, sell_blinder_seed, sell_share_seed, match_res, test_args.clone())
        .await
}
integration_test_async!(test_settle_internal_match);

/// Tests settling a match that came from an MPC
async fn test_settle_mpc_match(test_args: IntegrationTestArgs) -> Result<()> {
    // Create two new wallets with orders that match
    let state = &test_args.global_state;
    let client = &test_args.arbitrum_client;
    let (buy_wallet, buy_blinder_seed, buy_share_seed) =
        setup_buy_side_wallet(test_args.clone()).await?;
    let (mut sell_wallet, sell_blinder_seed, sell_share_seed) =
        setup_sell_side_wallet(test_args.clone()).await?;

    // Setup the match result
    let (match_res, match_settle_proof) =
        setup_match_result(buy_wallet.clone(), sell_wallet.clone(), &test_args).await?;
    let handshake_state = HandshakeState {
        local_order_id: *buy_wallet.orders.first().unwrap().0,
        peer_order_id: *sell_wallet.orders.first().unwrap().0,
        ..mock_handshake_state()
    };

    let (network_sender, _network_recv) = unbounded_channel();
    let task = SettleMatchTask::new(
        handshake_state,
        match_settle_proof,
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

    // Only the first wallet would have been updated in the global state, as the
    // second wallet is assumed to be managed by another cluster
    verify_settlement(
        buy_wallet,
        buy_blinder_seed,
        buy_share_seed,
        match_res.clone(),
        test_args.clone(),
    )
    .await?;

    // The second wallet we must verify by looking up on-chain
    let sell_order_id = *sell_wallet.orders.first().unwrap().0;
    sell_wallet.reblind_wallet();
    sell_wallet.apply_match(&match_res, &sell_order_id);

    lookup_wallet_and_check_result(
        &sell_wallet,
        sell_blinder_seed,
        sell_share_seed,
        test_args.clone(),
    )
    .await
}
integration_test_async!(test_settle_mpc_match);
