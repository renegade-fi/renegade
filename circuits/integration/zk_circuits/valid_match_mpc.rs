//! Groups integration tests for the VALID MATCH MPC circuit

use std::{cmp, time::SystemTime};

use circuits::{
    mpc::SharedFabric,
    multiprover_prove,
    traits::{BaseType, LinkableBaseType, MpcBaseType, MultiproverCircuitCommitmentType},
    types::{
        balance::Balance,
        order::{Order, OrderSide},
        r#match::{AuthenticatedLinkableMatchResult, LinkableMatchResult, MatchResult},
    },
    verify_collaborative_proof,
    zk_circuits::valid_match_mpc::{AuthenticatedValidMatchMpcWitness, ValidMatchMpcCircuit},
    zk_gadgets::fixed_point::FixedPoint,
};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{mpc_network::mocks::PartyIDBeaverSource, types::IntegrationTest};
use mpc_ristretto::{
    beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64,
    network::{MpcNetwork, QuicTwoPartyNet},
};

use crate::{IntegrationTestArgs, TestWrapper};

/// Creates an authenticated match from an order in each relayer
fn match_orders<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    my_order: &Order,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedLinkableMatchResult<N, S>, String> {
    // Share orders
    let party0_order = my_order
        .share_public(0 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error sharing order: {:?}", err))?;
    let party1_order = my_order
        .share_public(1 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error sharing order: {:?}", err))?;

    // Match the values
    let min_amount = cmp::min(party0_order.amount, party1_order.amount);

    // The price is represented as a fixed-point variable; convert it to its true value
    // by shifting right by the fixed-point precision (32). Add an additional shift right
    // by 1 to emulate division by 2 for the midpoint
    let one_half_fixed_point = FixedPoint::from_f32_round_down(0.5);
    let price = (party0_order.price + party1_order.price).mul_fixed_point(one_half_fixed_point);
    let quote_amount = scalar_to_u64(&(price * Scalar::from(min_amount)).floor());

    let match_res: LinkableMatchResult = MatchResult {
        base_mint: party0_order.base_mint,
        quote_mint: party0_order.quote_mint,
        base_amount: party0_order.amount,
        quote_amount,
        direction: party0_order.side.into(),
        execution_price: price,
        max_minus_min_amount: cmp::max(party0_order.amount, party1_order.amount) - min_amount,
        min_amount_order_index: if party0_order.amount == min_amount {
            0
        } else {
            1
        },
    }
    .to_linkable();

    match_res
        .allocate(0 /* owning_partY */, fabric)
        .map_err(|err| format!("Error allocating match result in the network: {:?}", err))
}

/// Both parties call this value to setup their witness and statement from a given
/// balance, order tuple
fn setup_witness<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    order: Order,
    balance: Balance,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedValidMatchMpcWitness<N, S>, String> {
    // Generate hashes used for input consistency
    let match_res = match_orders(&order, fabric.clone())?;
    let linkable_order = order.to_linkable();
    let linkable_balance = balance.to_linkable();

    let allocated_order1 = linkable_order
        .allocate(0 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error allocating order in the network: {:?}", err))?;
    let allocated_order2 = linkable_order
        .allocate(1 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error allocating order in the network: {:?}", err))?;
    let allocated_balance1 = linkable_balance
        .allocate(0 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error allocating balance in the network: {:?}", err))?;
    let allocated_balance2 = linkable_balance
        .allocate(1 /* owning_party */, fabric)
        .map_err(|err| format!("Error allocating balance in the network: {:?}", err))?;

    Ok(AuthenticatedValidMatchMpcWitness {
        order1: allocated_order1,
        order2: allocated_order2,
        balance1: allocated_balance1,
        balance2: allocated_balance2,
        match_res,
    })
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

    let witness = setup_witness(
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

    // Prove
    let (witness_comm, proof) = multiprover_prove::<
        '_,
        QuicTwoPartyNet,
        PartyIDBeaverSource,
        ValidMatchMpcCircuit<'_, _, _>,
    >(witness, (), test_args.mpc_fabric.clone())
    .map_err(|err| format!("Error proving: {:?}", err))?;

    // Open
    let opened_proof = proof
        .open()
        .map_err(|err| format!("Error opening proof: {:?}", err))?;
    let opened_comm = witness_comm
        .open_and_authenticate()
        .map_err(|err| format!("Error opening witness commitment: {:?}", err))?;

    // Verify
    verify_collaborative_proof::<
        '_,
        QuicTwoPartyNet,
        PartyIDBeaverSource,
        ValidMatchMpcCircuit<'_, _, _>,
    >((), opened_comm, opened_proof)
    .map_err(|err| format!("Error verifying: {:?}", err))
}

// Take inventory
inventory::submit!(TestWrapper(IntegrationTest {
    name: "zk_circuits::valid_match_mpc::test_valid_match_mpc_valid",
    test_fn: test_valid_match_mpc_valid
}));
