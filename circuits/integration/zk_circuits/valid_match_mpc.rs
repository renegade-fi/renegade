//! Groups integration tests for the VALID MATCH MPC circuit
#![allow(non_snake_case)]

use std::{cmp, time::SystemTime};

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
use lazy_static::lazy_static;
use merlin::HashChainTranscript as Transcript;
use mpc_bulletproof::{r1cs_mpc::MpcProver, PedersenGens};
use mpc_stark::{algebra::scalar::Scalar, MpcFabric, PARTY0, PARTY1};
use rand::{thread_rng, Rng};
use renegade_crypto::fields::scalar_to_u64;
use test_helpers::{
    mpc_network::{await_result, await_result_with_error},
    types::IntegrationTest,
};

use crate::{IntegrationTestArgs, TestWrapper};

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
        }
        // Buy the quote, sell the base, the maximum amount is directly limited
        // by the balance
        OrderSide::Sell => cmp::min(order.amount, balance.amount),
    }
}

/// Creates an authenticated match from an order in each relayer
fn match_orders(
    amount: u64,
    price: FixedPoint,
    my_order: &Order,
    fabric: MpcFabric,
) -> AuthenticatedLinkableMatchResult {
    // Share orders
    let party0_order = await_result(my_order.share_public(PARTY0, fabric.clone()));

    // Share amounts
    let party0_max_amount = await_result(amount.share_public(PARTY0, fabric.clone()));
    let party1_max_amount = await_result(amount.share_public(PARTY1, fabric.clone()));

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

/// Both parties call this value to setup their witness and statement from a given
/// balance, order tuple
fn setup_witness(
    price: FixedPoint,
    amount: u64,
    order: Order,
    balance: Balance,
    fabric: MpcFabric,
) -> AuthenticatedValidMatchMpcWitness {
    // Generate hashes used for input consistency
    let match_res = match_orders(amount, price, &order, fabric.clone());
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

/// Prove and verify a valid match MPC circuit, return `true` if verification succeeds
fn prove_and_verify_match(
    witness: AuthenticatedValidMatchMpcWitness,
    fabric: MpcFabric,
) -> Result<bool, String> {
    // Prove
    let (witness_comm, proof) = multiprover_prove::<ValidMatchMpcCircuit>(witness, (), fabric)
        .map_err(|err| format!("Error proving: {:?}", err))?;

    // Open
    let opened_proof = await_result_with_error(proof.open())?;
    let opened_comm = await_result(witness_comm.open_and_authenticate())
        .map_err(|err| format!("Error opening witness commitment: {:?}", err))?;

    // Verify
    Ok(verify_collaborative_proof::<ValidMatchMpcCircuit>((), opened_comm, opened_proof).is_ok())
}

/// Return whether the `VALID MATCH MPC` constraints are satisfied on the given witness
fn constraints_satisfied(
    witness: AuthenticatedValidMatchMpcWitness,
    fabric: MpcFabric,
) -> Result<bool, String> {
    let pc_gens = PedersenGens::default();
    let transcript = Transcript::new(b"test");
    let mut prover = MpcProver::new_with_fabric(fabric.clone(), transcript, pc_gens);

    let mut rng = thread_rng();
    let (witness_var, _) = witness
        .commit_shared(&mut rng, &mut prover)
        .map_err(|err| format!("Error committing witness: {:?}", err))?;

    ValidMatchMpcCircuit::apply_constraints_multiprover(witness_var, (), fabric, &mut prover)
        .map_err(|err| err.to_string())?;

    Ok(await_result(prover.constraints_satisfied()))
}

// ---------
// | Tests |
// ---------

/// Tests that the valid match MPC circuit proves and verifies given a correct witness
fn test_valid_match_mpc_valid(test_args: &IntegrationTestArgs) -> Result<(), String> {
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
    );

    if !prove_and_verify_match(witness, test_args.mpc_fabric.clone())? {
        return Err("Failed to prove and verify match".to_string());
    }

    Ok(())
}

/// Test matching an order where the volume is limited by the balance of the sell side party
fn test_valid_match_undercapitalized__base_side(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let party_id = test_args.mpc_fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let mut my_balance = create_test_balance(party_id);

    // The party selling the base does not have the balance to cover their full order
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
    );

    if !prove_and_verify_match(witness, test_args.mpc_fabric.clone())? {
        return Err("Failed to prove and verify match".to_string());
    }

    Ok(())
}

/// Test matching an order where the volume is limited by the balance of the buy side party
fn test_valid_match_undercapitalized__quote_side(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let party_id = test_args.mpc_fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let mut my_balance = create_test_balance(party_id);

    // The party selling the base does not have the balance to cover their full order
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
    );

    if !prove_and_verify_match(witness, test_args.mpc_fabric.clone())? {
        return Err("Failed to prove and verify match".to_string());
    }

    Ok(())
}

/// Test the case in which the price is a non-integral value
fn test_valid_match__non_integral_price(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let mut rng = thread_rng();
    let party_id = test_args.mpc_fabric.party_id();
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);

    // Party 0 chooses a random price and shares it with party 1
    let price_range = DUMMY_SELL_SIDE_WORST_PRICE.to_f64()..DUMMY_BUY_SIDE_WORST_PRICE.to_f64();
    let price = FixedPoint::from_f64_round_down(rng.gen_range(price_range));
    let price = await_result(price.share_public(PARTY0, test_args.mpc_fabric.clone()));

    // Prove `VALID MATCH MPC
    let witness = setup_witness(
        price,
        compute_max_amount(price, &my_order, &my_balance),
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );

    if !prove_and_verify_match(witness, test_args.mpc_fabric.clone())? {
        return Err("Failed to prove and verify match".to_string());
    }

    Ok(())
}

/// Test the case in which the two parties attempt to match on different mints
fn test_valid_match__different_mints(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let price = *DUMMY_PRICE;
    let mut my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    // One party switches the quote mint of their order
    if fabric.party_id() == PARTY0 {
        my_order.quote_mint = 42u8.into();
    }

    // Validate that the constraints are not satisfied
    let witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance.clone(),
        test_args.mpc_fabric.clone(),
    );
    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    // Now test with base mint switched
    let mut my_order = create_test_order(party_id);
    if fabric.party_id() == PARTY0 {
        my_order.base_mint = 42u8.into();
    }

    // Validate that the constraints are not satisfied
    let witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );
    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the parties sit on the same side of the book
fn test_valid_match__same_side(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let price = *DUMMY_PRICE;
    let mut my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    // Switch the side of the market that the first party sits on
    if fabric.party_id() == PARTY0 {
        my_order.side = my_order.side.opposite();
    }

    // Validate that the constraints are not satisfied
    let witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );
    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the balance provided to the matching engine is not for
/// the correct asset
fn test_valid_match__invalid_balance_mint(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let mut my_balance = create_test_balance(party_id);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    // Switch the mint of the balance to be the wrong asset in the pair
    if party_id == PARTY0 {
        if my_balance.mint == my_order.quote_mint {
            my_balance.mint = my_order.base_mint.clone();
        } else {
            my_balance.mint = my_order.quote_mint.clone();
        }
    }

    // Validate that the constraints are not satisfied
    let witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );
    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the balance provided does not cover the advertised amount
fn test_valid_match__insufficient_balance(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let mut my_balance = create_test_balance(party_id);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    // Reduce the balance to be less than the amount
    if my_balance.mint == my_order.base_mint {
        my_balance.amount = 1;
    }

    // Validate that the constraints are not satisfied
    let witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );
    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the matched amount exceeds the order size for a party
fn test_valid_match__amount_exceeds_order(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);

    // Both parties give an excessive amount so that the minimum amount certainly
    // exceeds the order size
    let amount = my_order.amount + 1;

    // Validate that the constraints are not satisfied
    let witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );
    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the `max_minus_min` field is incorrectly computed
fn test_valid_match__incorrect_max_minus_min(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    // Validate that the constraints are not satisfied
    let mut witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );
    let mut rng = thread_rng();
    witness.match_res.max_minus_min_amount = Scalar::random(&mut rng)
        .to_linkable()
        .allocate(PARTY0, fabric);

    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the `max_minus_min` field is switched to be
/// `min - max` (i.e. negative)
fn test_valid_match__max_minus_min_negative(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    let party0_amount = await_result(amount.share_public(PARTY0, test_args.mpc_fabric.clone()));
    let party1_amount = await_result(amount.share_public(PARTY1, test_args.mpc_fabric.clone()));
    let min_minus_max_amount = Scalar::from(cmp::min(party0_amount, party1_amount))
        - Scalar::from(cmp::max(party0_amount, party1_amount));

    // Validate that the constraints are not satisfied
    let mut witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );
    witness.match_res.max_minus_min_amount =
        min_minus_max_amount.to_linkable().allocate(PARTY0, fabric);

    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the `min_amount_order_index` field is incorrectly computed
fn test_valid_match__incorrect_min_amount_order_index(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let price = *DUMMY_PRICE;
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    // Validate that the constraints are not satisfied
    let mut witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );
    let min_order_index = await_result(witness.match_res.min_amount_order_index.open())
        .map_err(|err| format!("Error opening min_amount_order_index: {:?}", err))?
        .val;

    // Invert the index
    witness.match_res.min_amount_order_index = (Scalar::one() - min_order_index)
        .to_linkable()
        .allocate(PARTY0, fabric);

    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the execution price exceeds the buy side price
/// protection
fn test_valid_match__price_protection_violated_buy_side(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);

    // Execution price exceeds the buy side maximum price
    let price = *DUMMY_BUY_SIDE_WORST_PRICE + FixedPoint::from_integer(1);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    // Validate that the constraints are not satisfied
    let witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );

    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

/// Test the case in which the execution price falls sort of the sell
/// side price protection
fn test_valid_match__price_protection_violated_sell_side(
    test_args: &IntegrationTestArgs,
) -> Result<(), String> {
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();
    let my_order = create_test_order(party_id);
    let my_balance = create_test_balance(party_id);

    // Execution price falls short of the sell side minimum price
    let price = *DUMMY_SELL_SIDE_WORST_PRICE - FixedPoint::from_integer(1);
    let amount = compute_max_amount(price, &my_order, &my_balance);

    // Validate that the constraints are not satisfied
    let witness = setup_witness(
        price,
        amount,
        my_order,
        my_balance,
        test_args.mpc_fabric.clone(),
    );

    if constraints_satisfied(witness, test_args.mpc_fabric.clone())? {
        return Err("Constraints satisfied on invalid witness".to_string());
    }

    Ok(())
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match_mpc_valid",
    test_fn: test_valid_match_mpc_valid
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match_undercapitalized__base_side",
    test_fn: test_valid_match_undercapitalized__base_side
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match_undercapitalized__quote_side",
    test_fn: test_valid_match_undercapitalized__quote_side
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__non_integral_price",
    test_fn: test_valid_match__non_integral_price
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__different_mints",
    test_fn: test_valid_match__different_mints,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__same_side",
    test_fn: test_valid_match__same_side,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__invalid_balance_mint",
    test_fn: test_valid_match__invalid_balance_mint,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__insufficient_balance",
    test_fn: test_valid_match__insufficient_balance,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__amount_exceeds_order",
    test_fn: test_valid_match__amount_exceeds_order,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__incorrect_max_minus_min",
    test_fn: test_valid_match__incorrect_max_minus_min,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__max_minus_min_negative",
    test_fn: test_valid_match__max_minus_min_negative,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__incorrect_min_amount_order_index",
    test_fn: test_valid_match__incorrect_min_amount_order_index,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__price_protection_violated_buy_side",
    test_fn: test_valid_match__price_protection_violated_buy_side,
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match__price_protection_violated_sell_side",
    test_fn: test_valid_match__price_protection_violated_sell_side,
}));
