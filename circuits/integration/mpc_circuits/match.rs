//! Groups integration tests for the match circuitry

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::{AuthenticatedOrder, Order, OrderSide},
    r#match::MatchResult,
    traits::{LinkableBaseType, MpcBaseType, MpcType, MultiproverCircuitBaseType},
};
use circuits::{
    mpc_circuits::r#match::compute_match,
    zk_circuits::valid_match_mpc::{AuthenticatedValidMatchMpcWitness, ValidMatchMpcCircuit},
};
use eyre::{eyre, Result};
use merlin::HashChainTranscript as Transcript;
use mpc_bulletproof::{r1cs_mpc::MpcProver, PedersenGens};
use mpc_stark::{PARTY0, PARTY1};
use num_bigint::BigUint;
use rand::thread_rng;
use test_helpers::{integration_test_async, types::IntegrationTest};

use crate::IntegrationTestArgs;

// --------------
// | Test Cases |
// --------------

/// Tests the match function with non overlapping orders for a variety of failure cases
async fn test_match_no_match(test_args: IntegrationTestArgs) -> Result<()> {
    // Convenience selector for brevity
    let fabric = &test_args.mpc_fabric;
    let mut rng = thread_rng();
    let party_id = fabric.party_id();

    /// Convenience selector between two party's values
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

    let balance1 = my_balance.allocate(PARTY0, fabric);
    let balance2 = my_balance.allocate(PARTY1, fabric);

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
        let linkable_order1 = my_order.to_linkable().allocate(PARTY0, fabric);
        let linkable_order2 = my_order.to_linkable().allocate(PARTY1, fabric);

        // Allocate the price in the network
        let price1 = FixedPoint::from_integer(my_price).allocate(PARTY0, fabric);
        let price2 = FixedPoint::from_integer(my_price).allocate(PARTY1, fabric);

        let order1: AuthenticatedOrder = AuthenticatedOrder::from_authenticated_scalars(
            &mut linkable_order1
                .clone()
                .to_authenticated_scalars()
                .into_iter(),
        );
        let order2: AuthenticatedOrder = AuthenticatedOrder::from_authenticated_scalars(
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
            fabric,
        );

        // Assert that match verification fails
        let pc_gens = PedersenGens::default();
        let transcript = Transcript::new(b"test");
        let mut dummy_prover =
            MpcProver::new_with_fabric(test_args.mpc_fabric.clone(), transcript, pc_gens);

        let witness = AuthenticatedValidMatchMpcWitness {
            order1: linkable_order1,
            amount1: order1.amount,
            price1: price1.clone(),
            order2: linkable_order2,
            amount2: order2.amount,
            price2: price2.clone(),
            balance1: balance1.clone(),
            balance2: balance2.clone(),
            match_res: res.link_commitments(fabric),
        };
        let (witness_var, _) = witness.commit_shared(&mut rng, &mut dummy_prover).unwrap();

        ValidMatchMpcCircuit::matching_engine_check(
            witness_var,
            test_args.mpc_fabric.clone(),
            &mut dummy_prover,
        )
        .unwrap();

        if dummy_prover.constraints_satisfied().await {
            return Err(eyre!("Constraints satisfied"));
        }
    }

    Ok(())
}

/// Tests that a valid match is found when one exists
async fn test_match_valid_match(test_args: IntegrationTestArgs) -> Result<()> {
    // Convenience selector for brevity, simpler to redefine per test than to
    // pass in party_id from the environment
    let fabric = &test_args.mpc_fabric;
    let party_id = fabric.party_id();

    /// Convenience selector for values that differ between parties
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
        let price1 = FixedPoint::from_integer(my_price).allocate(PARTY0, fabric);

        // Allocate the orders in the network
        let order1 = my_order.allocate(PARTY0, fabric);
        let order2 = my_order.allocate(PARTY1, fabric);

        // Compute matches
        let res = compute_match(
            &order1,
            &order2,
            &order1.amount,
            &order2.amount,
            &price1,
            fabric,
        )
        .open_and_authenticate()
        .await
        .map_err(|e| eyre!("Error computing match: {e:?}"))?;

        // Assert that no match occurred
        if res != expected_res.clone() {
            return Err(eyre!(
                "Match result {res:?} does not match expected result {expected_res:?}",
            ));
        }
    }

    Ok(())
}

// Take inventory
integration_test_async!(test_match_no_match);
integration_test_async!(test_match_valid_match);
