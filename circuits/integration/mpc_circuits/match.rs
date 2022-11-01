//! Groups integration tests for the match circuitry

use circuits::{mpc_circuits::r#match::compute_match, types::Order, Allocate};
use integration_helpers::types::IntegrationTest;

use crate::{mpc_gadgets::check_equal, IntegrationTestArgs, TestWrapper};

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

    let test_cases: Vec<Vec<u64>> = vec![
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

    for case in test_cases.iter() {
        // Marshal into an order
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

        // Assert that no match occured
        check_equal(&res, 0)?;
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

    let test_cases: Vec<Vec<u64>> = vec![
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
            1,            /* quote_mint */
            2,            /* base_mint */
            sel!(1, 0),   /* side */
            10,           /* price */
            sel!(20, 20), /* amount */
        ],
    ];

    for case in test_cases.iter() {
        // Marshal into an order
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

        // Assert that no match occured
        check_equal(&res, 1)?;
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
