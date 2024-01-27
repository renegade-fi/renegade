//! Integration tests for settling matches, both internal and cross-cluster

use crate::{
    helpers::{lookup_wallet_and_check_result, setup_initial_wallet},
    IntegrationTestArgs,
};
use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    r#match::{MatchResult, OrderSettlementIndices},
    SizedWallet,
};
use circuits::zk_circuits::valid_match_settle::{
    ValidMatchSettleStatement, ValidMatchSettleWitness,
};
use common::types::{
    handshake::{mocks::mock_handshake_state, HandshakeState},
    proof_bundles::{
        mocks::dummy_link_proof, MatchBundle, OrderValidityProofBundle, OrderValidityWitnessBundle,
        ValidMatchSettleBundle,
    },
    wallet::Wallet,
    wallet_mocks::mock_empty_wallet,
};
use constants::Scalar;
use eyre::{eyre, Result};
use job_types::proof_manager::{ProofJob, ProofManagerJob};
use rand::thread_rng;
use renegade_crypto::fields::scalar_to_u64;
use state::State;
use task_driver::{settle_match::SettleMatchTask, settle_match_internal::SettleMatchInternalTask};
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};
use tokio::sync::{mpsc::unbounded_channel, oneshot::channel};
use util::{hex::biguint_from_hex_string, matching_engine::settle_match_into_wallets};
use uuid::Uuid;

/// The price at which the mock trade executes at
const EXECUTION_PRICE: f64 = 9.6;
/// The amounts that each order is for
const ORDER_AMOUNT: u64 = 5;

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
        quote_mint: biguint_from_hex_string(&test_args.erc20_addr0).unwrap(),
        base_mint: biguint_from_hex_string(&test_args.erc20_addr1).unwrap(),
        side,
        amount: ORDER_AMOUNT,
        worst_case_price: FixedPoint::from_integer(worst_cast_price),
        timestamp: 10,
    }
}

/// Create a dummy balance
fn dummy_balance(side: OrderSide, test_args: &IntegrationTestArgs) -> Balance {
    match side {
        OrderSide::Buy => {
            Balance { mint: biguint_from_hex_string(&test_args.erc20_addr0).unwrap(), amount: 100 }
        },
        OrderSide::Sell => {
            Balance { mint: biguint_from_hex_string(&test_args.erc20_addr1).unwrap(), amount: 100 }
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
    let mut rng = thread_rng();

    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);
    let mut wallet = mock_empty_wallet();

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
    let base_amount = ORDER_AMOUNT;
    let quote_amount = price * Scalar::from(base_amount);
    let direction = wallet1.orders.first().unwrap().1.side.is_sell();

    let match_ = MatchResult {
        quote_mint: biguint_from_hex_string(&test_args.erc20_addr0).unwrap(),
        base_mint: biguint_from_hex_string(&test_args.erc20_addr1).unwrap(),
        quote_amount: scalar_to_u64(&quote_amount.floor()),
        base_amount,
        direction,
        max_minus_min_amount: 0,
        min_amount_order_index: false,
    };

    // Pull the validity proof witnesses for the wallets so that we may update the
    // public and private shares to the reblinded and augmented shares; as would
    // happen before a real match
    let state = &test_args.global_state;
    let witness1 = get_first_order_witness(&wallet1, state).await?;
    let witness2 = get_first_order_witness(&wallet2, state).await?;

    wallet1.private_shares = witness1.reblind_witness.reblinded_wallet_private_shares.clone();
    wallet1.blinded_public_shares = witness1.commitment_witness.augmented_public_shares.clone();

    wallet2.private_shares = witness2.reblind_witness.reblinded_wallet_private_shares.clone();
    wallet2.blinded_public_shares = witness2.commitment_witness.augmented_public_shares.clone();

    let proof = dummy_match_bundle(&wallet1, &wallet2, match_.clone(), test_args).await?;
    Ok((match_, proof))
}

/// Get the validity proof bundle for the first order in a given wallet
async fn get_first_order_proofs(
    wallet: &Wallet,
    state: &State,
) -> Result<OrderValidityProofBundle> {
    let order_id = wallet.orders.first().unwrap().0;
    state
        .get_validity_proofs(&order_id)?
        .ok_or_else(|| eyre!("Order validity proof bundle not found"))
}

/// Get the validity proof witness for the first order in a given wallet
async fn get_first_order_witness(
    wallet: &Wallet,
    state: &State,
) -> Result<OrderValidityWitnessBundle> {
    let order_id = wallet.orders.first().unwrap().0;
    state
        .get_validity_proof_witness(&order_id)?
        .ok_or_else(|| eyre!("Order validity witness bundle not found"))
}

/// Generate a dummy match proof on the first order in each wallet
async fn dummy_match_bundle(
    wallet1: &Wallet,
    wallet2: &Wallet,
    match_res: MatchResult,
    test_args: &IntegrationTestArgs,
) -> Result<MatchBundle> {
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
    mut wallet: Wallet,
    blinder_seed: Scalar,
    share_seed: Scalar,
    match_res: MatchResult,
    test_args: IntegrationTestArgs,
) -> Result<()> {
    let state = &test_args.global_state;

    // 1. Apply the match to the wallet
    wallet.reblind_wallet();

    let first_order = wallet.orders.first().unwrap().0;
    wallet.apply_match(&match_res, &first_order).unwrap();

    // 2. Lookup the wallet in global state, verify that this matches the expected
    let new_wallet =
        state.get_wallet(&wallet.wallet_id)?.ok_or_else(|| eyre!("wallet not found in state"))?;

    let circuit_wallet1: SizedWallet = wallet.clone().into();
    let circuit_wallet2: SizedWallet = new_wallet.clone().into();

    assert_eq_result!(new_wallet.blinder, wallet.blinder)?;
    assert_eq_result!(new_wallet.private_shares, wallet.private_shares)?;

    assert_eq_result!(circuit_wallet1, circuit_wallet2)?;

    assert_eq_result!(new_wallet.blinded_public_shares, wallet.blinded_public_shares)?;

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
        buy_wallet.orders.first().unwrap().0,
        sell_wallet.orders.first().unwrap().0,
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
        local_order_id: buy_wallet.orders.first().unwrap().0,
        peer_order_id: sell_wallet.orders.first().unwrap().0,
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
    .await?;

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
    let sell_order_id = sell_wallet.orders.first().unwrap().0;
    sell_wallet.reblind_wallet();
    sell_wallet.apply_match(&match_res, &sell_order_id).unwrap();

    lookup_wallet_and_check_result(
        &sell_wallet,
        sell_blinder_seed,
        sell_share_seed,
        test_args.clone(),
    )
    .await
}
integration_test_async!(test_settle_mpc_match);
