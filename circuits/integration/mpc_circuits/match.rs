//! Groups integration tests for the match circuitry

use circuits::{
    mpc_circuits::r#match::compute_match,
    traits::{LinkableBaseType, MpcBaseType, MpcType, MultiproverCircuitBaseType},
    types::{
        balance::Balance,
        order::{AuthenticatedOrder, Order, OrderSide},
        r#match::MatchResult,
    },
    zk_circuits::valid_match_mpc::{AuthenticatedValidMatchMpcWitness, ValidMatchMpcCircuit},
    zk_gadgets::fixed_point::FixedPoint,
};
use integration_helpers::types::IntegrationTest;
use merlin::Transcript;
use mpc_bulletproof::{r1cs_mpc::MpcProver, PedersenGens};
use num_bigint::BigUint;
use rand_core::OsRng;

use crate::{IntegrationTestArgs, TestWrapper};

// --------------
// | Test Cases |
// --------------

/// Tests the match function with non overlapping orders for a variety of failure cases
fn test_match_no_match(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Convenience selector for brevity
    let mut rng = OsRng {};
    let party_id = test_args.party_id;
    macro_rules! sel {
        ($a:expr, $b:expr) => {
            if party_id == 0 {
                $a
            } else {
                $b
            }
        };
    }

    // Give a balance to each party and allocate it in the network
    let my_balance = sel!(
        Balance {
            mint: BigUint::from(1u8),
            amount: 200
        },
        Balance {
            mint: BigUint::from(2u8),
            amount: 200
        }
    )
    .to_linkable();

    let balance1 = my_balance
        .allocate(0 /* owning_party */, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error allocating balance1 in the network: {:?}", err))?;
    let balance2 = my_balance
        .allocate(1 /* owning_party */, test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error allocating balance2 in the network: {:?}", err))?;

    // Build the test cases for different invalid match pairs
    let test_cases: Vec<(Order, u64)> = vec![
        // Quote mints different
        (
            Order {
                quote_mint: sel!(0u8, 1u8).into(),
                base_mint: 2u8.into(),
                side: sel!(OrderSide::Buy, OrderSide::Sell),
                worst_case_price: FixedPoint::from_integer(sel!(15, 5)),
                amount: sel!(20, 30),
                timestamp: 0, // unused
            },
            10, /* execution_price */
        ),
        // Base mints different
        (
            Order {
                quote_mint: 1u8.into(),
                base_mint: sel!(0u8, 1u8).into(),
                side: sel!(OrderSide::Buy, OrderSide::Sell),
                worst_case_price: FixedPoint::from_integer(sel!(15, 5)),
                amount: sel!(20, 30),
                timestamp: 0, // unused
            },
            10, /* execution_price */
        ),
        // Orders on the same side (buy side)
        (
            Order {
                quote_mint: 1u8.into(),
                base_mint: 2u8.into(),
                side: OrderSide::Buy,
                worst_case_price: FixedPoint::from_integer(15),
                amount: 20,
                timestamp: 0, // unused
            },
            10, /* execution_price */
        ),
        // Prices differ between orders
        (
            Order {
                quote_mint: 1u8.into(),
                base_mint: 2u8.into(),
                side: sel!(OrderSide::Buy, OrderSide::Sell),
                worst_case_price: FixedPoint::from_integer(sel!(15, 5)),
                amount: 30,
                timestamp: 0, // unused
            },
            sel!(10, 11), /* execution_price */
        ),
    ];

    for (my_order, my_price) in test_cases.into_iter() {
        // Allocate the orders in the network
        let linkable_order1 = my_order
            .to_linkable()
            .allocate(0 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating order1 in the network: {:?}", err))?;
        let linkable_order2 = my_order
            .to_linkable()
            .allocate(1 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating order2 in the network: {:?}", err))?;

        // Allocate the price in the network
        let price1 = FixedPoint::from_integer(my_price)
            .allocate(0 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating price in the network: {:?}", err))?;
        let price2 = FixedPoint::from_integer(my_price)
            .allocate(1 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating price in the network: {:?}", err))?;

        let order1: AuthenticatedOrder<_, _> = AuthenticatedOrder::from_authenticated_scalars(
            &mut linkable_order1
                .clone()
                .to_authenticated_scalars()
                .into_iter(),
        );
        let order2: AuthenticatedOrder<_, _> = AuthenticatedOrder::from_authenticated_scalars(
            &mut linkable_order2
                .clone()
                .to_authenticated_scalars()
                .into_iter(),
        );

        // Compute matches
        let res = compute_match(
            &order1,
            &order2,
            &order1.amount,
            &order2.amount,
            &price1, // Use the first party's price
            test_args.mpc_fabric.clone(),
        )
        .map_err(|err| format!("Error computing order match: {:?}", err))?;

        // Assert that match verification fails
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut dummy_prover =
            MpcProver::new_with_fabric(test_args.mpc_fabric.clone().0, &mut transcript, &pc_gens);

        let witness = AuthenticatedValidMatchMpcWitness {
            order1: linkable_order1,
            amount1: order1.amount,
            price1: price1.clone(),
            order2: linkable_order2,
            amount2: order2.amount,
            price2: price2.clone(),
            balance1: balance1.clone(),
            balance2: balance2.clone(),
            match_res: res.link_commitments(test_args.mpc_fabric.clone()),
        };
        let (witness_var, _) = witness.commit_shared(&mut rng, &mut dummy_prover).unwrap();

        ValidMatchMpcCircuit::matching_engine_check(
            witness_var,
            test_args.mpc_fabric.clone(),
            &mut dummy_prover,
        )
        .unwrap();

        if dummy_prover.constraints_satisfied().unwrap() {
            return Err("Constraints satisfied".to_string());
        }
    }

    Ok(())
}

/// Tests that a valid match is found when one exists
fn test_match_valid_match(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Convenience selector for brevity, simpler to redefine per test than to
    // pass in party_id from the environment
    let party_id = test_args.party_id;
    macro_rules! sel {
        ($a:expr, $b:expr) => {
            if party_id == 0 {
                $a
            } else {
                $b
            }
        };
    }

    let test_cases: Vec<(Order, u64)> = vec![
        // Different amounts
        (
            Order {
                quote_mint: 1u8.into(),
                base_mint: 2u8.into(),
                side: sel!(OrderSide::Buy, OrderSide::Sell),
                worst_case_price: FixedPoint::from_integer(sel!(15, 5)),
                amount: sel!(20, 30),
                timestamp: 0, // unused
            },
            10, /* execution_price */
        ),
        // Same amount
        (
            Order {
                quote_mint: 1u8.into(),
                base_mint: 2u8.into(),
                side: sel!(OrderSide::Sell, OrderSide::Buy),
                worst_case_price: FixedPoint::from_integer(sel!(5, 15)),
                amount: 15,
                timestamp: 0, // unused
            },
            10, /* execution_price */
        ),
    ];

    // Stores the expected result for each test case as a vector
    //      [party1_buy_mint, party1_buy_amount, party2_buy_mint, party2_buy_amount]
    let expected_results = vec![
        MatchResult {
            quote_mint: BigUint::from(1u8),
            base_mint: BigUint::from(2u8),
            quote_amount: 200,
            base_amount: 20,
            direction: 0,
            max_minus_min_amount: 10,
            min_amount_order_index: 0,
        },
        MatchResult {
            quote_mint: BigUint::from(1u8),
            base_mint: BigUint::from(2u8),
            quote_amount: 150,
            base_amount: 15,
            direction: 1,
            max_minus_min_amount: 0,
            min_amount_order_index: 1,
        },
    ];

    for ((my_order, my_price), expected_res) in
        test_cases.into_iter().zip(expected_results.into_iter())
    {
        // Allocate the prices in the network
        let price1 = FixedPoint::from_integer(my_price)
            .allocate(0 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating price1 in the network: {:?}", err))?;

        // Allocate the orders in the network
        let order1 = my_order
            .allocate(0 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating order1 in the network: {:?}", err))?;
        let order2 = my_order
            .allocate(1 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating order2 in the network: {:?}", err))?;

        // Compute matches
        let res = compute_match(
            &order1,
            &order2,
            &order1.amount,
            &order2.amount,
            &price1,
            test_args.mpc_fabric.clone(),
        )
        .map_err(|err| format!("Error computing order match: {:?}", err))?
        .open_and_authenticate(test_args.mpc_fabric.clone())
        .map_err(|err| format!("Error opening match result: {:?}", err))?;

        // Assert that no match occurred
        if res != expected_res.clone() {
            return Err(format!(
                "Match result {:?} does not match expected result {:?}",
                res, expected_res
            ));
        }
    }

    Ok(())
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_circuits::test_match_no_match",
    test_fn: test_match_no_match
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "mpc_circuits::test_match_valid_match",
    test_fn: test_match_valid_match
}));
