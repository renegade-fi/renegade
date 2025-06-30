//! Integration tests for settling matches, both internal and cross-cluster

use crate::{
    IntegrationTestArgs,
    helpers::{
        await_immediate_task, await_wallet_task_queue_flush, lookup_wallet_and_check_result,
        setup_initial_wallet, setup_relayer_wallet,
    },
};
use circuit_types::{
    Amount, SizedWallet,
    balance::Balance,
    fixed_point::FixedPoint,
    r#match::{MatchResult, OrderSettlementIndices},
    order::OrderSide,
};
use circuits::zk_circuits::valid_match_settle::{
    ValidMatchSettleStatement, ValidMatchSettleWitness,
};
use common::types::{
    TimestampedPrice,
    handshake::{HandshakeState, mocks::mock_handshake_state},
    proof_bundles::{
        MatchBundle, OrderValidityProofBundle, OrderValidityWitnessBundle, ValidMatchSettleBundle,
        mocks::dummy_link_proof,
    },
    tasks::{SettleMatchInternalTaskDescriptor, SettleMatchTaskDescriptor},
    wallet::{Order, OrderBuilder, Wallet},
    wallet_mocks::mock_empty_wallet,
};
use constants::Scalar;
use eyre::{Result, eyre};
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use rand::thread_rng;
use state::State;
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};
use tokio::sync::oneshot::channel;
use util::{
    hex::biguint_from_hex_string,
    matching_engine::{
        compute_fee_obligation, compute_max_amount, match_orders, settle_match_into_wallets,
    },
    on_chain::get_protocol_fee,
};
use uuid::Uuid;

/// The price at which the mock trade executes at
const EXECUTION_PRICE: f64 = 9.6;
/// The amounts that each order is for
const BUY_ORDER_AMOUNT: u128 = 100_000;
/// The amount of the sell order
const SELL_ORDER_AMOUNT: u128 = 10_000;
/// The relayer fee to use for testing
const RELAYER_FEE: f64 = 0.002; // 20 bps

// -----------
// | Helpers |
// -----------

/// Create a dummy order
fn dummy_order(side: OrderSide, test_args: &IntegrationTestArgs) -> Order {
    let worst_cast_price = match side {
        OrderSide::Buy => 12,
        OrderSide::Sell => 9,
    };

    let order_amount = match side {
        OrderSide::Buy => BUY_ORDER_AMOUNT,
        OrderSide::Sell => SELL_ORDER_AMOUNT,
    };

    OrderBuilder::new()
        .quote_mint(biguint_from_hex_string(&test_args.erc20_addr0).unwrap())
        .base_mint(biguint_from_hex_string(&test_args.erc20_addr1).unwrap())
        .side(side)
        .amount(order_amount)
        .worst_case_price(FixedPoint::from_integer(worst_cast_price))
        .build()
        .unwrap()
}

/// Create a dummy balance
fn dummy_balance(side: OrderSide, test_args: &IntegrationTestArgs) -> Balance {
    let mint = match side {
        OrderSide::Buy => biguint_from_hex_string(&test_args.erc20_addr0).unwrap(),
        OrderSide::Sell => biguint_from_hex_string(&test_args.erc20_addr1).unwrap(),
    };

    Balance::new_from_mint_and_amount(mint, Amount::from(100_000u32))
}

/// Setup a wallet with a given order and balance
///
/// Returns the wallet, a blinder seed and a share seed
async fn setup_wallet_with_order_balance(
    order: Order,
    balance: Balance,
    test_args: IntegrationTestArgs,
) -> Result<(Wallet, Scalar, Scalar)> {
    let mut rng = thread_rng();
    let managing_cluster = test_args.state.get_fee_key().await?.public_key();

    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let mut wallet = mock_empty_wallet();
    wallet.max_match_fee = FixedPoint::from_f64_round_down(RELAYER_FEE);
    wallet.managing_cluster = managing_cluster;

    // Add the balance and order into the wallet
    wallet.balances.insert(balance.mint.clone(), balance.clone());
    wallet.orders.insert(Uuid::new_v4(), order);
    setup_initial_wallet(blinder_seed, share_seed, &mut wallet, &test_args).await?;

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
) -> Result<(MatchResult, MatchBundle)> {
    let price = FixedPoint::from_f64_round_down(EXECUTION_PRICE);

    let o1 = wallet1.orders.first().unwrap().1.clone();
    let o2 = wallet2.orders.first().unwrap().1.clone();
    let b1 = wallet1.balances.first().unwrap().1.clone();
    let b2 = wallet2.balances.first().unwrap().1.clone();
    let match_ = match_orders(&o1.into(), &o2.into(), &b1, &b2, Amount::MIN, price).unwrap();

    // Pull the validity proof witnesses for the wallets so that we may update the
    // public and private shares to the reblinded and augmented shares; as would
    // happen before a real match
    let state = &test_args.state;
    let witness1 = get_first_order_witness(&wallet1, state).await?;
    let witness2 = get_first_order_witness(&wallet2, state).await?;

    wallet1.private_shares = witness1.reblind_witness.reblinded_wallet_private_shares.clone();
    wallet1.blinded_public_shares = witness1.commitment_witness.augmented_public_shares.clone();

    wallet2.private_shares = witness2.reblind_witness.reblinded_wallet_private_shares.clone();
    wallet2.blinded_public_shares = witness2.commitment_witness.augmented_public_shares.clone();

    let proof = dummy_match_bundle(&mut wallet1, &mut wallet2, match_.clone(), test_args).await?;
    Ok((match_, proof))
}

/// Get the validity proof bundle for the first order in a given wallet
async fn get_first_order_proofs(
    wallet: &Wallet,
    state: &State,
) -> Result<OrderValidityProofBundle> {
    let order_id = wallet.orders.first().unwrap().0;
    state
        .get_validity_proofs(&order_id)
        .await?
        .ok_or_else(|| eyre!("Order validity proof bundle not found"))
}

/// Get the validity proof witness for the first order in a given wallet
async fn get_first_order_witness(
    wallet: &Wallet,
    state: &State,
) -> Result<OrderValidityWitnessBundle> {
    let order_id = wallet.orders.first().unwrap().0;
    state
        .get_validity_proof_witness(&order_id)
        .await?
        .ok_or_else(|| eyre!("Order validity witness bundle not found"))
}

/// Generate a dummy match proof on the first order in each wallet
async fn dummy_match_bundle(
    wallet1: &mut Wallet,
    wallet2: &mut Wallet,
    match_res: MatchResult,
    test_args: &IntegrationTestArgs,
) -> Result<MatchBundle> {
    let price = FixedPoint::from_f64_round_down(EXECUTION_PRICE);

    let party0_indices = OrderSettlementIndices { order: 0, balance_send: 0, balance_receive: 1 };
    let party1_indices = party0_indices;

    // Destructure the wallets into their match engine inputs
    let order0 = wallet1.orders.first().unwrap().1.clone();
    let balance0 = wallet1.balances.first().unwrap().1.clone();
    let balance_receive0 = Balance::new_from_mint(order0.receive_mint().clone());
    let relayer_fee0 = wallet1.max_match_fee;
    let amount0 = compute_max_amount(&price, &order0.clone().into(), &balance0);
    let party0_public_shares = wallet1.blinded_public_shares.clone();
    *wallet1.balances.get_index_mut(party0_indices.balance_receive).unwrap() =
        balance_receive0.clone();

    let order1 = wallet2.orders.first().unwrap().1.clone();
    let balance1 = wallet2.balances.first().unwrap().1.clone();
    let balance_receive1 = Balance::new_from_mint(order1.receive_mint().clone());
    let relayer_fee1 = wallet2.max_match_fee;
    let amount1 = compute_max_amount(&price, &order1.clone().into(), &balance1);
    let party1_public_shares = wallet2.blinded_public_shares.clone();
    *wallet2.balances.get_index_mut(party1_indices.balance_receive).unwrap() =
        balance_receive1.clone();

    // Compute the fees owed after the match
    let party0_fees = compute_fee_obligation(relayer_fee0, order0.side, &match_res);
    let party1_fees = compute_fee_obligation(relayer_fee1, order1.side, &match_res);

    let mut party0_modified_shares = party0_public_shares.clone();
    let mut party1_modified_shares = party1_public_shares.clone();
    settle_match_into_wallets(
        &mut party0_modified_shares,
        &mut party1_modified_shares,
        party0_fees,
        party1_fees,
        party0_indices,
        party1_indices,
        &match_res,
    );

    let (send, recv) = channel();
    let job = ProofManagerJob {
        type_: ProofJob::ValidMatchSettleSingleprover {
            witness: ValidMatchSettleWitness {
                order0: order0.into(),
                balance0,
                balance_receive0,
                price0: price,
                amount0: amount0.into(),
                relayer_fee0,
                party0_fees,

                order1: order1.into(),
                balance1,
                balance_receive1,
                price1: price,
                amount1: amount1.into(),
                relayer_fee1,
                party1_fees,

                match_res,
                party0_public_shares,
                party1_public_shares,
            },
            statement: ValidMatchSettleStatement {
                party0_indices,
                party1_indices,
                party0_modified_shares,
                party1_modified_shares,
                protocol_fee: get_protocol_fee(),
            },
        },
        response_channel: send,
    };
    test_args.proof_job_queue.send(job)?;

    // Await a response
    let match_proof: ValidMatchSettleBundle = recv
        .await
        .map(|bundle| bundle.proof.into())
        .map_err(|_| eyre!("Failed to receive proof bundle"))?;

    Ok(MatchBundle {
        match_proof,
        commitments_link0: dummy_link_proof(),
        commitments_link1: dummy_link_proof(),
    })
}

/// Verify that a match has been correctly applied to a wallet
async fn verify_settlement(
    wallet: &Wallet,
    blinder_seed: Scalar,
    share_seed: Scalar,
    match_res: MatchResult,
    test_args: IntegrationTestArgs,
) -> Result<()> {
    // Verify that fees were paid
    verify_fees_paid(wallet, &test_args).await?;

    let mut wallet = wallet.clone();
    let state = &test_args.state;

    // 1. Apply the match to the wallet, remove fees as we waited for them to settle
    let first_order = wallet.orders.first().unwrap().0;
    wallet.apply_match(&match_res, &first_order).unwrap();
    for (_mint, balance) in wallet.balances.iter_mut() {
        balance.relayer_fee_balance = 0;
        balance.protocol_fee_balance = 0;
    }
    wallet.reblind_wallet();

    // 2. Lookup the wallet in global state, verify that this matches the expected
    // Do not check the blinder, it's too clumsy to track the blinder through the
    // multiple updates in our mock
    let new_wallet = state
        .get_wallet(&wallet.wallet_id)
        .await?
        .ok_or_else(|| eyre!("wallet not found in state"))?;
    wallet.blinder = new_wallet.blinder;

    let circuit_wallet1: SizedWallet = wallet.clone().into();
    let circuit_wallet2: SizedWallet = new_wallet.clone().into();
    assert_eq_result!(circuit_wallet1, circuit_wallet2)?;

    // 3. Lookup the wallet on-chain, verify that this matches the expected
    // Use the state wallet to check that the stored wallet stored matches the one
    // on-chain
    lookup_wallet_and_check_result(&new_wallet, blinder_seed, share_seed, &test_args).await
}

/// Verify that fees are paid for a wallet after a match
async fn verify_fees_paid(wallet: &Wallet, test_args: &IntegrationTestArgs) -> Result<()> {
    let id = wallet.wallet_id;
    await_wallet_task_queue_flush(id, test_args).await?;

    // Check the wallet in state, verify that no fees remain
    let state = &test_args.state;
    let wallet = state.get_wallet(&id).await?.ok_or(eyre!("wallet not found in state"))?;
    for balance in wallet.balances.values() {
        assert_true_result!(balance.fees().total() == 0)?;
    }

    Ok(())
}

// ---------
// | Tests |
// ---------

/// Tests that settling an internal match succeeds and state is properly updated
async fn test_settle_internal_match(test_args: IntegrationTestArgs) -> Result<()> {
    // Create two new wallets with orders that match
    let state = &test_args.state;
    setup_relayer_wallet(&test_args).await?;
    let (buy_wallet, buy_blinder_seed, buy_share_seed) =
        setup_buy_side_wallet(test_args.clone()).await?;
    let (sell_wallet, sell_blinder_seed, sell_share_seed) =
        setup_sell_side_wallet(test_args.clone()).await?;

    // Setup the match result
    let (match_res, _) =
        setup_match_result(buy_wallet.clone(), sell_wallet.clone(), &test_args).await?;

    // Create the task
    let order_id1 = *buy_wallet.orders.keys().next().unwrap();
    let order_id2 = *sell_wallet.orders.keys().next().unwrap();
    let task = SettleMatchInternalTaskDescriptor::new(
        TimestampedPrice::new(EXECUTION_PRICE),
        buy_wallet.wallet_id,
        sell_wallet.wallet_id,
        order_id1,
        order_id2,
        get_first_order_proofs(&buy_wallet, state).await?,
        get_first_order_witness(&buy_wallet, state).await?,
        get_first_order_proofs(&sell_wallet, state).await?,
        get_first_order_witness(&sell_wallet, state).await?,
        match_res.clone(),
    )
    .unwrap();

    await_immediate_task(task.into(), &test_args).await?;

    // Verify the match on both wallets
    verify_settlement(
        &buy_wallet,
        buy_blinder_seed,
        buy_share_seed,
        match_res.clone(),
        test_args.clone(),
    )
    .await?;

    verify_settlement(
        &sell_wallet,
        sell_blinder_seed,
        sell_share_seed,
        match_res,
        test_args.clone(),
    )
    .await
}
integration_test_async!(test_settle_internal_match);

/// Tests settling a match that came from an MPC
async fn test_settle_mpc_match(test_args: IntegrationTestArgs) -> Result<()> {
    // Create two new wallets with orders that match
    let state = &test_args.state;
    setup_relayer_wallet(&test_args).await?;
    let (buy_wallet, buy_blinder_seed, buy_share_seed) =
        setup_buy_side_wallet(test_args.clone()).await?;
    let (mut sell_wallet, sell_blinder_seed, sell_share_seed) =
        setup_sell_side_wallet(test_args.clone()).await?;

    // Setup the match result
    let (match_res, match_settle_proof) =
        setup_match_result(buy_wallet.clone(), sell_wallet.clone(), &test_args).await?;
    let handshake_state = HandshakeState {
        local_order_id: buy_wallet.orders.first().unwrap().0,
        peer_order_id: sell_wallet.orders.first().unwrap().0,
        ..mock_handshake_state()
    };

    // Start a task to settle the match
    let task = SettleMatchTaskDescriptor::new(
        buy_wallet.wallet_id,
        handshake_state,
        match_res.clone(),
        match_settle_proof,
        get_first_order_proofs(&buy_wallet, state).await?,
        get_first_order_proofs(&sell_wallet, state).await?,
    )
    .unwrap();

    let res = await_immediate_task(task.into(), &test_args).await;
    assert_true_result!(res.is_ok())?;

    // Only the first wallet would have been updated in the global state, as the
    // second wallet is assumed to be managed by another cluster
    verify_settlement(
        &buy_wallet,
        buy_blinder_seed,
        buy_share_seed,
        match_res.clone(),
        test_args.clone(),
    )
    .await?;

    // The second wallet we must verify by looking up on-chain
    let sell_order_id = sell_wallet.orders.first().unwrap().0;
    sell_wallet.reblind_wallet();
    sell_wallet.apply_match(&match_res, &sell_order_id).unwrap();

    lookup_wallet_and_check_result(&sell_wallet, sell_blinder_seed, sell_share_seed, &test_args)
        .await
}
integration_test_async!(test_settle_mpc_match);
