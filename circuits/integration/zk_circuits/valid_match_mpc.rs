//! Groups integration tests for the VALID MATCH MPC circuit
#![allow(non_snake_case)]

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{Order, OrderSide},
    r#match::{AuthenticatedLinkableMatchResult, MatchResult},
    traits::{
        BaseType, LinkableBaseType, MpcBaseType, MpcType, MultiProverCircuit,
        MultiproverCircuitBaseType, MultiproverCircuitCommitmentType,
    },
};
use circuits::{
    multiprover_prove, verify_collaborative_proof,
    zk_circuits::valid_match_mpc::{AuthenticatedValidMatchMpcWitness, ValidMatchMpcCircuit},
};
use eyre::{eyre, Result};
use lazy_static::lazy_static;
use merlin::HashChainTranscript as Transcript;
use mpc_bulletproof::{r1cs_mpc::MpcProver, PedersenGens};
use mpc_stark::{algebra::scalar::Scalar, MpcFabric, PARTY0, PARTY1};
use rand::{thread_rng, Rng};
use renegade_crypto::fields::scalar_to_u64;
use std::{cmp, time::SystemTime};
use test_helpers::integration_test_async;

use crate::IntegrationTestArgs;

// -------------
// | Test Data |
// -------------

/// A macro to help select between two values based on `party_id`
macro_rules! sel {
    ($party_id:expr, $a: expr, $b: expr) => {
        if $party_id == 0 {
            $a
        } else {
            $b
        }
    };
}

lazy_static! {
    /// The default price used for testing
    static ref DUMMY_PRICE: FixedPoint = FixedPoint::from_integer(10);
    /// The default worse case buy side price
    static ref DUMMY_BUY_SIDE_WORST_PRICE: FixedPoint = FixedPoint::from_integer(15);
    /// The default worse case sell side price
    static ref DUMMY_SELL_SIDE_WORST_PRICE: FixedPoint = FixedPoint::from_integer(5);
}

/// Construct a test order based on party ID
fn create_test_order(party_id: u64) -> Order {
    let timestamp: u64 = SystemTime::now()
        .elapsed()
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();

    Order {
        quote_mint: 1u8.into(),
        base_mint: 2u8.into(),
        side: sel!(party_id, OrderSide::Buy, OrderSide::Sell),
        amount: sel!(party_id, 20, 30),
        worst_case_price: sel!(
            party_id,
            *DUMMY_BUY_SIDE_WORST_PRICE,
            *DUMMY_SELL_SIDE_WORST_PRICE
        ),
        timestamp,
    }
}

/// Construct a test balance based on party ID
fn create_test_balance(party_id: u64) -> Balance {
    Balance {
        mint: sel!(party_id, 1u8.into(), 2u8.into()),
        amount: 200,
    }
}

// -----------
// | Helpers |
// -----------

/// Compute the maximum matchable amount for an order and balance
fn compute_max_amount(price: FixedPoint, order: &Order, balance: &Balance) -> u64 {
    match order.side {
        // Buy the base, the max amount is possibly limited by the quote
        // balance
        OrderSide::Buy => {
            let price_f64 = price.to_f64();
            let balance_limit = (balance.amount as f64 / price_f64).floor() as u64;
            cmp::min(order.amount, balance_limit)
        },
        // Buy the quote, sell the base, the maximum amount is directly limited
        // by the balance
        OrderSide::Sell => cmp::min(order.amount, balance.amount),
    }
}

/// Creates an authenticated match from an order in each relayer
async fn match_orders(
    amount: u64,
    price: FixedPoint,
    my_order: &Order,
    fabric: MpcFabric,
) -> AuthenticatedLinkableMatchResult {
    // Share orders
    let party0_order = my_order.share_public(PARTY0, fabric.clone()).await;

    // Share amounts
    let party0_max_amount = amount.share_public(PARTY0, fabric.clone()).await;
    let party1_max_amount = amount.share_public(PARTY1, fabric.clone()).await;

    // Match the values
    let min_base_amount = cmp::min(party0_max_amount, party1_max_amount);
    let quote_amount = scalar_to_u64(&(price * Scalar::from(min_base_amount)).floor());

    let match_res = MatchResult {
        base_mint: party0_order.base_mint,
        quote_mint: party0_order.quote_mint,
        base_amount: min_base_amount,
        quote_amount,
        direction: party0_order.side.into(),
        max_minus_min_amount: cmp::max(party0_max_amount, party1_max_amount) - min_base_amount,
        min_amount_order_index: if party0_max_amount == min_base_amount {
            0
        } else {
            1
        },
    }
    .to_linkable();

    match_res.allocate(PARTY0, &fabric)
}

/// Both parties call this value to setup their witness and statement from a
/// given balance, order tuple
async fn setup_witness(
    price: FixedPoint,
    amount: u64,
    order: Order,
    balance: Balance,
    fabric: MpcFabric,
) -> AuthenticatedValidMatchMpcWitness {
    // Generate hashes used for input consistency
    let match_res = match_orders(amount, price, &order, fabric.clone()).await;
    let linkable_order = order.to_linkable();
    let linkable_balance = balance.to_linkable();

    let allocated_price1 = price.allocate(PARTY0, &fabric);
    let allocated_price2 = price.allocate(PARTY1, &fabric);

    let allocated_amount1 = amount.allocate(PARTY0, &fabric);
    let allocated_amount2 = amount.allocate(PARTY1, &fabric);

    let allocated_order1 = linkable_order.allocate(PARTY0, &fabric);
    let allocated_order2 = linkable_order.allocate(PARTY1, &fabric);

    let allocated_balance1 = linkable_balance.allocate(PARTY0, &fabric);
    let allocated_balance2 = linkable_balance.allocate(PARTY1, &fabric);

    AuthenticatedValidMatchMpcWitness {
        order1: allocated_order1,
        balance1: allocated_balance1,
        amount1: allocated_amount1,
        price1: allocated_price1,
        order2: allocated_order2,
        amount2: allocated_amount2,
        balance2: allocated_balance2,
        price2: allocated_price2,
        match_res,
    }
}

/// Prove and verify a valid match MPC circuit, return `true` if verification
/// succeeds
async fn prove_and_verify_match(
    witness: AuthenticatedValidMatchMpcWitness,
    fabric: MpcFabric,
) -> Result<bool> {
    // Prove
    let (witness_comm, proof) = multiprover_prove::<ValidMatchMpcCircuit>(witness, (), fabric)?;

    // Open
    let opened_proof = proof.open().await?;
    let opened_comm = witness_comm.open_and_authenticate().await?;

    // Verify
    Ok(verify_collaborative_proof::<ValidMatchMpcCircuit>((), opened_comm, opened_proof).is_ok())
}

/// Return whether the `VALID MATCH MPC` constraints are satisfied on the given
/// witness
async fn constraints_satisfied(
    witness: AuthenticatedValidMatchMpcWitness,
    fabric: MpcFabric,
) -> Result<bool> {
    let pc_gens = PedersenGens::default();
    let transcript = Transcript::new(b"test");
    let mut prover = MpcProver::new_with_fabric(fabric.clone(), transcript, pc_gens);

    let mut rng = thread_rng();
    let (witness_var, _) = witness.commit_shared(&mut rng, &mut prover)?;

    ValidMatchMpcCircuit::apply_constraints_multiprover(witness_var, (), fabric, &mut prover)?;
    Ok(prover.constraints_satisfied().await)
}

// ---------
// | Tests |
// ---------

/// Tests that the valid match MPC circuit proves and verifies given a correct
/// witness
async fn test_valid_match_mpc_valid(test_args: IntegrationTestArgs) -> Result<()> {
    let party_id = test_args.mpc_fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);

    let witness = setup_witness(
        price,
        compute_max_amount(price, &my_order, &my_balance),
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    )
    .await;

    if !prove_and_verify_match(witness, test_args.mpc_fabric.clone()).await? {
        return Err(eyre!("Failed to prove and verify match"));
    }

    Ok(())
}

/// Test matching an order where the volume is limited by the balance of the
/// sell side party
async fn test_valid_match_undercapitalized__base_side(
    test_args: IntegrationTestArgs,
) -> Result<()> {
    let party_id = test_args.mpc_fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let mut my_balance = create_test_balance(party_id);

    // The party selling the base does not have the balance to cover their full
    // order
    if my_order.side == OrderSide::Sell {
        my_balance.amount = 5;
    }

    // Prove `VALID MATCH MPC`
    let witness = setup_witness(
        price,
        compute_max_amount(price, &my_order, &my_balance),
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    )
    .await;

    if !prove_and_verify_match(witness, test_args.mpc_fabric.clone()).await? {
        return Err(eyre!("Failed to prove and verify match"));
    }

    Ok(())
}

/// Test matching an order where the volume is limited by the balance of the buy
/// side party
async fn test_valid_match_undercapitalized__quote_side(
    test_args: IntegrationTestArgs,
) -> Result<()> {
    let party_id = test_args.mpc_fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let mut my_balance = create_test_balance(party_id);

    // The party selling the base does not have the balance to cover their full
    // order
    if my_order.side == OrderSide::Buy {
        my_balance.amount = 5;
    }

    // Prove `VALID MATCH MPC`
    let witness = setup_witness(
        price,
        compute_max_amount(price, &my_order, &my_balance),
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    )
    .await;

    if !prove_and_verify_match(witness, test_args.mpc_fabric.clone()).await? {
        return Err(eyre!("Failed to prove and verify match"));
    }

    Ok(())
}

/// Test the case in which the price is a non-integral value
async fn test_valid_match__non_integral_price(test_args: IntegrationTestArgs) -> Result<()> {
    let mut rng = thread_rng();
    let party_id = test_args.mpc_fabric.party_id();
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);

    // Party 0 chooses a random price and shares it with party 1
    let price_range = DUMMY_SELL_SIDE_WORST_PRICE.to_f64()..DUMMY_BUY_SIDE_WORST_PRICE.to_f64();
    let price = FixedPoint::from_f64_round_down(rng.gen_range(price_range));
    let price = price
        .share_public(PARTY0, test_args.mpc_fabric.clone())
        .await;

    // Prove `VALID MATCH MPC
    let witness = setup_witness(
        price,
        compute_max_amount(price, &my_order, &my_balance),
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    )
    .await;

    if !prove_and_verify_match(witness, test_args.mpc_fabric.clone()).await? {
        return Err(eyre!("Failed to prove and verify match"));
    }

    Ok(())
}

// Take inventory
integration_test_async!(test_valid_match_mpc_valid);
integration_test_async!(test_valid_match_undercapitalized__base_side);
integration_test_async!(test_valid_match_undercapitalized__quote_side);
integration_test_async!(test_valid_match__non_integral_price);
