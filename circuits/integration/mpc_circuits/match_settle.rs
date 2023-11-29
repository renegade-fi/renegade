//! Integration tests for the settlement circuit

use std::cmp;

use ark_mpc::PARTY0;
use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::OrderSide,
    r#match::OrderSettlementIndices,
    traits::{BaseType, MpcBaseType, MpcType, MultiProverCircuit, MultiproverCircuitBaseType},
    Fabric, MpcPlonkCircuit,
};
use circuits::{
    mpc_circuits::{r#match::compute_match, settle::settle_match},
    test_helpers::{random_indices, random_orders_and_match},
    zk_circuits::{
        test_helpers::{SizedWallet, MAX_BALANCES, MAX_FEES, MAX_ORDERS},
        valid_match_settle::{
            AuthenticatedValidMatchSettleStatement, AuthenticatedValidMatchSettleWitness,
            ValidMatchSettle,
        },
    },
};
use constants::Scalar;
use eyre::Result;
use mpc_relation::traits::Circuit;
use rand::{thread_rng, RngCore};
use renegade_crypto::fields::scalar_to_u64;
use test_helpers::{assert_true_result, integration_test_async};

use crate::{types::create_wallet_shares, IntegrationTestArgs};

// -----------
// | Helpers |
// -----------

/// A sized statement type allocated in a fabric
type SizedValidMatchSettleStatement =
    AuthenticatedValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// A sized witness type allocated in a fabric
type SizedValidMatchSettleWitness =
    AuthenticatedValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// Generate two wallets with crossing orders
///
/// Returns the wallets and the indices used in the orders, as well as a
/// randomly sampled price to cross at
fn generate_wallets_for_match() -> (
    SizedWallet,
    SizedWallet,
    OrderSettlementIndices,
    OrderSettlementIndices,
    FixedPoint, // Price
) {
    let mut wallet1 = SizedWallet::default();
    let mut wallet2 = SizedWallet::default();

    // Start with the crossing orders
    let (o1, o2, price, _) = random_orders_and_match();

    // Select random indices for the orders
    let ind1 = random_indices();
    let ind2 = random_indices();

    // Add orders to the wallets
    wallet1.orders[ind1.order as usize] = o1;
    wallet2.orders[ind2.order as usize] = o2;

    // Create balances for the orders
    add_balances_to_wallet(&mut wallet1, ind1, price);
    add_balances_to_wallet(&mut wallet2, ind2, price);

    (wallet1, wallet2, ind1, ind2, price)
}

/// Add mock balances
fn add_balances_to_wallet(
    wallet: &mut SizedWallet,
    ind: OrderSettlementIndices,
    price: FixedPoint,
) {
    let mut rng = thread_rng();

    let order = &wallet.orders[ind.order as usize];
    let base_amt = order.amount;
    let quote_amt = (price * Scalar::from(base_amt)).floor();
    let quote_amt = scalar_to_u64(&quote_amt);

    let base = order.base_mint.clone();
    let quote = order.quote_mint.clone();
    let base_bal = Balance { mint: base.clone(), amount: base_amt + 1 };
    let quote_bal = Balance { mint: quote.clone(), amount: quote_amt + 1 };

    // Begin with a random amount of the receive side mint
    let rand_amt = rng.next_u32() as u64;
    let (send, recv) = match order.side {
        OrderSide::Buy => (quote_bal, Balance { mint: base, amount: rand_amt }),
        OrderSide::Sell => (base_bal, Balance { mint: quote, amount: rand_amt }),
    };

    // Add balances for the order
    wallet.balances[ind.balance_send as usize] = send;
    wallet.balances[ind.balance_receive as usize] = recv;
}

/// Run the match settle process
///
/// Return a witness and statement for `VALID MATCH SETTLE`
fn run_match_settle(
    w1: &SizedWallet,
    w2: &SizedWallet,
    ind1: OrderSettlementIndices,
    ind2: OrderSettlementIndices,
    price: FixedPoint,
    fabric: &Fabric,
) -> (SizedValidMatchSettleStatement, SizedValidMatchSettleWitness) {
    let amt1 = max_amount_at_price(w1, ind1, price);
    let amt2 = max_amount_at_price(w2, ind2, price);

    run_match_settle_with_amounts(w1, w2, ind1, ind2, price, amt1, amt2, fabric)
}

/// Compute the maximum amount that can be matched at a given price
fn max_amount_at_price(
    wallet: &SizedWallet,
    indices: OrderSettlementIndices,
    price: FixedPoint,
) -> u64 {
    // Lookup the amount on the order and the send balance
    let order = &wallet.orders[indices.order as usize];
    let order_amt = order.amount;
    let mut send_bal = wallet.balances[indices.balance_send as usize].amount;

    // Convert the send balance to the base mint amount
    // I.e. convert if the send balance is the quote
    if matches!(order.side, OrderSide::Buy) {
        // Divide the send balance by the price to get the maximum fillable base amount
        let price_f64 = price.to_f64();
        send_bal = (send_bal as f64 / price_f64).floor() as u64;
    }

    cmp::min(order_amt, send_bal)
}

/// Run the match settle process with a given amount for each party
#[allow(clippy::too_many_arguments)]
fn run_match_settle_with_amounts(
    w1: &SizedWallet,
    w2: &SizedWallet,
    ind1: OrderSettlementIndices,
    ind2: OrderSettlementIndices,
    price: FixedPoint,
    amount1: u64,
    amount2: u64,
    fabric: &Fabric,
) -> (SizedValidMatchSettleStatement, SizedValidMatchSettleWitness) {
    // Create shares for the wallets
    let (_, pre_public_shares1) = create_wallet_shares(w1);
    let (_, pre_public_shares2) = create_wallet_shares(w2);

    // Allocate inputs in the fabric
    let order1 = w1.orders[ind1.order as usize].allocate(PARTY0, fabric);
    let order2 = w2.orders[ind2.order as usize].allocate(PARTY0, fabric);
    let amount1 = amount1.allocate(PARTY0, fabric);
    let amount2 = amount2.allocate(PARTY0, fabric);
    let price = price.allocate(PARTY0, fabric);

    let wallet1 = w1.allocate(PARTY0, fabric);
    let wallet2 = w2.allocate(PARTY0, fabric);
    let party0_pre_shares = pre_public_shares1.allocate(PARTY0, fabric);
    let party1_pre_shares = pre_public_shares2.allocate(PARTY0, fabric);

    // Compute the match and settle it
    let match_res = compute_match(&order1, &amount1, &amount2, &price, fabric);
    let (party0_modified_shares, party1_modified_shares) =
        settle_match(ind1, ind2, &party0_pre_shares, &party1_pre_shares, &match_res);

    (
        SizedValidMatchSettleStatement {
            party0_indices: ind1.allocate(PARTY0, fabric),
            party1_indices: ind2.allocate(PARTY0, fabric),
            party0_modified_shares,
            party1_modified_shares,
        },
        SizedValidMatchSettleWitness {
            order1,
            balance1: wallet1.balances[ind1.balance_send as usize].clone(),
            amount1,
            price1: price.clone(),
            order2,
            balance2: wallet2.balances[ind2.balance_send as usize].clone(),
            amount2,
            price2: price,
            party0_public_shares: party0_pre_shares,
            party1_public_shares: party1_pre_shares,
            match_res,
        },
    )
}

/// Checks constraint satisfaction on a generated witness and statement
fn check_constraints(
    statement: SizedValidMatchSettleStatement,
    witness: SizedValidMatchSettleWitness,
    fabric: &Fabric,
) -> bool {
    // Allocate the witness and statement
    let mut cs = MpcPlonkCircuit::new(fabric.clone());
    let witness_var = witness.create_shared_witness(&mut cs);
    let statement_var = statement.create_shared_public_var(&mut cs);

    // Apply constraints and check them against the wire assignments
    ValidMatchSettle::apply_constraints_multiprover(witness_var, statement_var, fabric, &mut cs)
        .unwrap();
    cs.finalize_for_arithmetization().unwrap();

    let statement_scalars = statement.to_authenticated_scalars();
    cs.check_circuit_satisfiability(&statement_scalars).is_ok()
}

// ---------
// | Tests |
// ---------

/// Tests settling a match into a set of wallet shares
///
/// Validates that the resultant shares satisfy the `VALID MATCH SETTLE`
/// circuit's constraints
async fn test_witness_generation(test_args: IntegrationTestArgs) -> Result<()> {
    let fabric = &test_args.mpc_fabric;

    // Samples wallets to test against
    let (w1, w2, ind1, ind2, price) = generate_wallets_for_match();
    let ind1 = ind1.share_public(PARTY0, fabric).await;
    let ind2 = ind2.share_public(PARTY0, fabric).await;

    let (statement, witness) = run_match_settle(&w1, &w2, ind1, ind2, price, fabric);

    assert_true_result!(check_constraints(statement, witness, fabric))
}

/// Tests the MPC when one party in undercapitalized for the match
#[allow(non_snake_case)]
async fn test_witness_generation__undercapitalized(test_args: IntegrationTestArgs) -> Result<()> {
    let fabric = &test_args.mpc_fabric;

    // Samples wallets to test against
    let (mut w1, w2, ind1, ind2, price) = generate_wallets_for_match();
    let ind1 = ind1.share_public(PARTY0, fabric).await;
    let ind2 = ind2.share_public(PARTY0, fabric).await;

    // Set the amount for party 1 to a value that will not cover the amount in its
    // order
    // Balances are initialized to values that marginally cover the order
    w1.balances[ind1.balance_send as usize].amount /= 2;
    let amt1 = max_amount_at_price(&w1, ind1, price);
    let amt2 = max_amount_at_price(&w2, ind2, price);

    let (statement, witness) =
        run_match_settle_with_amounts(&w1, &w2, ind1, ind2, price, amt1, amt2, fabric);

    assert_true_result!(check_constraints(statement, witness, fabric))
}

/// Tests attempting to settle a match with an invalid amount from one party
#[allow(non_snake_case)]
async fn test_witness_generation__invalid_amount(test_args: IntegrationTestArgs) -> Result<()> {
    let fabric = &test_args.mpc_fabric;

    // Samples wallets to test against
    let (w1, w2, ind1, ind2, price) = generate_wallets_for_match();
    let ind1 = ind1.share_public(PARTY0, fabric).await;
    let ind2 = ind2.share_public(PARTY0, fabric).await;

    // Set the amount for party 1 to be invalid
    let amt1 = max_amount_at_price(&w1, ind1, price) + 2;
    let amt2 = max_amount_at_price(&w2, ind2, price);

    let (statement, witness) =
        run_match_settle_with_amounts(&w1, &w2, ind1, ind2, price, amt1, amt2, fabric);

    assert_true_result!(!check_constraints(statement, witness, fabric))
}

integration_test_async!(test_witness_generation);
integration_test_async!(test_witness_generation__undercapitalized);
integration_test_async!(test_witness_generation__invalid_amount);
