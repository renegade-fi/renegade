//! Groups integration tests for the VALID MATCH MPC circuit

use std::{cmp, time::SystemTime};

use circuits::{
    mpc::SharedFabric,
    types::{
        balance::Balance,
        order::{Order, OrderSide},
        r#match::AuthenticatedMatchResult,
    },
    zk_circuits::valid_match_mpc::{
        ValidMatchMpcCircuit, ValidMatchMpcStatement, ValidMatchMpcWitness,
    },
    zk_gadgets::fixed_point::{AuthenticatedFixedPoint, FixedPoint},
};
use crypto::fields::biguint_to_scalar;
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{mpc_network::batch_share_plaintext_u64, types::IntegrationTest};
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};

use crate::{zk_gadgets::multiprover_prove_and_verify, IntegrationTestArgs, TestWrapper};

/// Creates an authenticated match from an order in each relayer
fn match_orders<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    my_order: &Order,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedMatchResult<N, S>, String> {
    let my_values = [my_order.side as u64, my_order.price.into(), my_order.amount];
    let party0_values =
        batch_share_plaintext_u64(&my_values, 0 /* owning_party */, fabric.0.clone());
    let party1_values =
        batch_share_plaintext_u64(&my_values, 1 /* owning_party */, fabric.0.clone());

    // Match the values
    let min_amount = cmp::min(party0_values[2], party1_values[2]);

    // The price is represented as a fixed-point variable; convert it to its true value
    // by shifting right by the fixed-point precision (32). Add an additional shift right
    // by 1 to emulate division by 2 for the midpoint
    let price = (party0_values[1] + party1_values[1]) >> 33;
    let private_scalars = vec![
        biguint_to_scalar(&my_order.quote_mint),
        biguint_to_scalar(&my_order.base_mint),
        (price * min_amount).into(),
        min_amount.into(),
        my_order.side.into(),
        price.into(),
        (cmp::max(party0_values[2], party1_values[2]) - min_amount).into(),
        (if party0_values[2] == min_amount {
            0u8
        } else {
            1u8
        })
        .into(),
    ];

    let shared_values = fabric
        .borrow_fabric()
        .batch_allocate_private_scalars(0 /* owning_party */, &private_scalars)
        .map_err(|err| format!("Error sharing authenticated match result: {:?}", err))?;

    Ok(AuthenticatedMatchResult {
        quote_mint: shared_values[0].to_owned(),
        base_mint: shared_values[1].to_owned(),
        quote_amount: shared_values[2].to_owned(),
        base_amount: shared_values[3].to_owned(),
        direction: shared_values[4].to_owned(),
        // Shift the price into its raw fixed point representation
        execution_price: AuthenticatedFixedPoint::from_integer(Scalar::from(price), fabric),
        max_minus_min_amount: shared_values[6].to_owned(),
        min_amount_order_index: shared_values[7].to_owned(),
    })
}

/// Both parties call this value to setup their witness and statement from a given
/// balance, order tuple
fn setup_witness_and_statement<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    order: Order,
    balance: Balance,
    fabric: SharedFabric<N, S>,
) -> Result<(ValidMatchMpcWitness<N, S>, ValidMatchMpcStatement), String> {
    // Generate hashes used for input consistency
    let match_res = match_orders(&order, fabric)?;
    Ok((
        ValidMatchMpcWitness {
            my_order: order.into(),
            my_balance: balance.into(),
            match_res: match_res.into(),
        },
        ValidMatchMpcStatement {},
    ))
}

/// Tests that the valid match MPC circuit proves and verifies given a correct witness
fn test_valid_match_mpc_valid(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // A selector based on party_id
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

    let my_order = vec![
        1,            // quote mint
        2,            // base mint
        sel!(0, 1),   // market side
        sel!(10, 6),  // price
        sel!(20, 30), // amount
    ];
    let my_balance_mint = sel!(1u8.into(), 2u8.into());
    let my_balance_amount = 200;

    let timestamp: u64 = SystemTime::now()
        .elapsed()
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();

    let (witness, statement) = setup_witness_and_statement(
        Order {
            quote_mint: my_order[0].into(),
            base_mint: my_order[1].into(),
            side: if my_order[2] == 0 {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            },
            price: FixedPoint::from_integer(my_order[3]),
            amount: my_order[4],
            timestamp,
        },
        Balance {
            mint: my_balance_mint,
            amount: my_balance_amount,
        },
        test_args.mpc_fabric.clone(),
    )?;

    multiprover_prove_and_verify::<'_, _, _, ValidMatchMpcCircuit<'_, _, _>>(
        witness,
        statement,
        test_args.mpc_fabric.clone(),
    )
    .map_err(|err| format!("Error proving and verifying: {:?}", err))
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match_mpc_valid",
    test_fn: test_valid_match_mpc_valid
}));
