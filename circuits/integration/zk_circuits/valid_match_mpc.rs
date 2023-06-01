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
    price: FixedPoint,
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
    let min_base_amount = cmp::min(party0_order.amount, party1_order.amount);
    let quote_amount = scalar_to_u64(&(price * Scalar::from(min_base_amount)).floor());

    let match_res: LinkableMatchResult = MatchResult {
        base_mint: party0_order.base_mint,
        quote_mint: party0_order.quote_mint,
        base_amount: min_base_amount,
        quote_amount,
        direction: party0_order.side.into(),
        max_minus_min_amount: cmp::max(party0_order.amount, party1_order.amount) - min_base_amount,
        min_amount_order_index: if party0_order.amount == min_base_amount {
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
///
/// TODO: Add in variable amounts matched
fn setup_witness<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    price: FixedPoint,
    amount: Scalar,
    order: Order,
    balance: Balance,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedValidMatchMpcWitness<N, S>, String> {
    // Generate hashes used for input consistency
    let match_res = match_orders(&order, price, fabric.clone())?;
    let linkable_order = order.to_linkable();
    let linkable_balance = balance.to_linkable();

    let allocated_price1 = price
        .allocate(0 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error allocating price in the network: {:?}", err))?;
    let allocated_price2 = price
        .allocate(1 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error allocating price in the network: {:?}", err))?;

    let allocated_amount1 = amount
        .allocate(0 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error allocating amount in the network: {:?}", err))?;
    let allocated_amount2 = amount
        .allocate(1 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error allocating amount in the network: {:?}", err))?;

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
        balance1: allocated_balance1,
        amount1: allocated_amount1,
        price1: allocated_price1,
        order2: allocated_order2,
        amount2: allocated_amount2,
        balance2: allocated_balance2,
        price2: allocated_price2,
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

    let price = FixedPoint::from_integer(10);
    let timestamp: u64 = SystemTime::now()
        .elapsed()
        .unwrap()
        .as_millis()
        .try_into()
        .unwrap();
    let my_order = Order {
        quote_mint: 1u8.into(),
        base_mint: 2u8.into(),
        side: if party_id == 0 {
            OrderSide::Buy
        } else {
            OrderSide::Sell
        },
        amount: sel!(20, 30),
        timestamp,
    };
    let my_balance = Balance {
        mint: sel!(1u8.into(), 2u8.into()),
        amount: 200,
    };

    let witness = setup_witness(
        price,
        my_order.amount.into(),
        my_order,
        my_balance,
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
