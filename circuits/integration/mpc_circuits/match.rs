//! Groups integration tests for the match circuitry

use circuits::{
    mpc_circuits::r#match::compute_match,
    types::{order::Order, r#match::MatchResult},
    zk_gadgets::fixed_point::FixedPoint,
    Allocate, Open,
};
use integration_helpers::types::IntegrationTest;
use num_bigint::BigInt;

use crate::{IntegrationTestArgs, TestWrapper};

/**
 * Helpers
 */

/// Checks that a given match result is empty (all zeros)
fn check_no_match(res: &MatchResult) -> Result<(), String> {
    // Party 1 buy side
    check_single_match(
        res,
        &MatchResult {
            quote_mint: BigInt::from(0u64),
            base_mint: BigInt::from(0u64),
            quote_amount: 0,
            base_amount: 0,
            direction: 0,
            execution_price: FixedPoint::from(0.),
            max_minus_min_amount: 0,
            min_amount_order_index: 0,
        },
    )?;

    Ok(())
}

/// Checks that a single given match is the expected value
fn check_single_match(res: &MatchResult, expected: &MatchResult) -> Result<(), String> {
    if res.eq(expected) {
        Ok(())
    } else {
        Err(format!("Expected {:?}, got {:?}", expected, res))
    }
}

/**
 * Tests
 */

/// Tests the match function with non overlapping orders for a variety of failure cases
fn test_match_no_match(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Convenience selector for brevity
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

    let mut test_cases: Vec<Vec<u64>> = vec![
        // Quote mints different
        vec![
            sel!(0, 1),   /* quote_mint */
            2,            /* base_mint */
            sel!(0, 1),   /* side */
            sel!(10, 5),  /* price */
            sel!(20, 30), /* amount */
        ],
        // Base mints different
        vec![
            1,            /* quote_mint */
            sel!(1, 2),   /* base_mint */
            sel!(0, 1),   /* side */
            sel!(10, 5),  /* price */
            sel!(20, 30), /* amount */
        ],
        // Both orders on the same side (buy)
        vec![
            1,            /* quote_mint */
            2,            /* base_mint */
            0,            /* side (both buy) */
            sel!(10, 5),  /* price */
            sel!(20, 30), /* amount */
        ],
        // Prices don't overlap between buy and sell side
        vec![
            1,            /* quote_mint */
            2,            /* base_mint */
            sel!(0, 1),   /* side */
            sel!(5, 10),  /* price */
            sel!(20, 30), /* amount */
        ],
    ];

    let timestamp = 0;
    for case in test_cases.iter_mut() {
        // Marshal into an order
        case.push(timestamp);
        let my_order: Order = (case as &[u64]).try_into().unwrap();

        // Allocate the orders in the network
        let order1 = my_order
            .allocate(0 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating order1 in the network: {:?}", err))?;
        let order2 = my_order
            .allocate(1 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating order2 in the network: {:?}", err))?;

        // Compute matches
        let res = compute_match(&order1, &order2, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error computing order match: {:?}", err))?
            .open_and_authenticate()
            .map_err(|err| format!("Error opening match result: {:?}", err))?;

        // Assert that no match occurred
        check_no_match(&res)?;
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

    let mut test_cases: Vec<Vec<u64>> = vec![
        // Different prices and amounts
        vec![
            1,            /* quote_mint */
            2,            /* base_mint */
            sel!(0, 1),   /* side */
            sel!(10, 5),  /* price */
            sel!(20, 30), /* amount */
        ],
        // Same price
        vec![
            1,            /* quote_mint */
            2,            /* base_mint */
            sel!(1, 0),   /* side */
            10,           /* price */
            sel!(10, 20), /* amount */
        ],
        // Same amount
        vec![
            1,          /* quote_mint */
            2,          /* base_mint */
            sel!(1, 0), /* side */
            10,         /* price */
            20,         /* amount */
        ],
    ];

    // Stores the expected result for each test case as a vector
    //      [party1_buy_mint, party1_buy_amount, party2_buy_mint, party2_buy_amount]
    let expected_results = vec![
        MatchResult {
            quote_mint: BigInt::from(1),
            base_mint: BigInt::from(2),
            quote_amount: 150,
            base_amount: 20,
            direction: 0,
            execution_price: FixedPoint::from(7.5),
            max_minus_min_amount: 10,
            min_amount_order_index: 0,
        },
        MatchResult {
            quote_mint: BigInt::from(1),
            base_mint: BigInt::from(2),
            quote_amount: 100,
            base_amount: 10,
            direction: 1,
            execution_price: FixedPoint::from(10.),
            max_minus_min_amount: 10,
            min_amount_order_index: 0,
        },
        MatchResult {
            quote_mint: BigInt::from(1),
            base_mint: BigInt::from(2),
            quote_amount: 200,
            base_amount: 20,
            direction: 1,
            execution_price: FixedPoint::from(10.),
            max_minus_min_amount: 0,
            min_amount_order_index: 1,
        },
    ];

    let timestamp = 0; // dummy value
    for (case, expected_res) in test_cases.iter_mut().zip(expected_results.iter()) {
        // Marshal into an order
        // Explicitly re-represent the price as a fixed point var
        case.push(timestamp);
        let mut my_order: Order = (case as &[u64]).try_into().unwrap();
        my_order.price = FixedPoint::from_integer(case[3].to_owned());

        // Allocate the orders in the network
        let order1 = my_order
            .allocate(0 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating order1 in the network: {:?}", err))?;
        let order2 = my_order
            .allocate(1 /* owning_party */, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error allocating order2 in the network: {:?}", err))?;

        // Compute matches
        let res = compute_match(&order1, &order2, test_args.mpc_fabric.clone())
            .map_err(|err| format!("Error computing order match: {:?}", err))?
            .open_and_authenticate()
            .map_err(|err| format!("Error opening match result: {:?}", err))?;

        // Assert that no match occurred
        assert_eq!(res, expected_res.clone());
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
