//! Groups integration tests for the VALID MATCH MPC circuit

use std::cmp;

use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use circuits::{
    mpc::SharedFabric,
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{
        balance::Balance,
        fee::Fee,
        order::{Order, OrderSide},
        r#match::AuthenticatedMatchResult,
    },
    zk_circuits::valid_match_mpc::{
        ValidMatchMpcCircuit, ValidMatchMpcStatement, ValidMatchMpcWitness,
    },
};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{
    mpc_network::{batch_share_plaintext_scalar, batch_share_plaintext_u64},
    types::IntegrationTest,
};
use itertools::Itertools;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use num_bigint::BigInt;
use rand_core::{OsRng, RngCore};

use crate::{
    mpc_gadgets::{poseidon::convert_params, prime_field_to_scalar, scalar_to_prime_field},
    zk_gadgets::multiprover_prove_and_verify,
    IntegrationTestArgs, TestWrapper,
};

/// Hashes the payload of `Scalar`s via the Arkworks Poseidon sponge implementation
/// Returns the result, re-cast into the Dalek Ristretto scalar field
fn hash_values_arkworks(values: &[u64]) -> Scalar {
    let arkworks_input = values
        .iter()
        .map(|val| scalar_to_prime_field(&Scalar::from(*val)))
        .collect_vec();
    let arkworks_params = convert_params(&PoseidonSpongeParameters::default());

    let mut arkworks_hasher = PoseidonSponge::new(&arkworks_params);
    for val in arkworks_input.iter() {
        arkworks_hasher.absorb(val)
    }

    prime_field_to_scalar(&arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0])
}

/// Creates an authenticated match from an order in each relayer
fn match_orders<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    my_order: &Order,
    fabric: SharedFabric<N, S>,
) -> Result<AuthenticatedMatchResult<N, S>, String> {
    let my_values = [my_order.side as u64, my_order.price, my_order.amount];
    let party0_values =
        batch_share_plaintext_u64(&my_values, 0 /* owning_party */, fabric.0.clone());
    let party1_values =
        batch_share_plaintext_u64(&my_values, 1 /* owning_party */, fabric.0.clone());

    // Match the values
    let min_amount = cmp::min(party0_values[2], party1_values[2]);
    // Discritize the price in the same way the circuit does, i.e. with shr
    let price = (party0_values[1] + party1_values[1]) >> 1;

    let shared_values = fabric
        .borrow_fabric()
        .batch_allocate_private_u64s(
            0, /* owning_party */
            &[
                my_order.quote_mint,
                my_order.base_mint,
                price * min_amount, // quote exchanged
                min_amount,         // base exchanged
                my_order.side as u64,
                price,
                cmp::max(party0_values[2], party1_values[2]) - min_amount,
                if party0_values[2] == min_amount { 0 } else { 1 },
            ],
        )
        .map_err(|err| format!("Error sharing authenticated match result: {:?}", err))?;

    Ok(AuthenticatedMatchResult {
        quote_mint: shared_values[0].to_owned(),
        base_mint: shared_values[1].to_owned(),
        quote_amount: shared_values[2].to_owned(),
        base_amount: shared_values[3].to_owned(),
        direction: shared_values[4].to_owned(),
        execution_price: shared_values[5].to_owned(),
        max_minus_min_amount: shared_values[6].to_owned(),
        min_amount_order_index: shared_values[7].to_owned(),
    })
}

/// Both parties call this value to setup their witness and statement from a given
/// balance, order, fee tuple
fn setup_witness_and_statement<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    order: Order,
    balance: Balance,
    fee: Fee,
    fabric: SharedFabric<N, S>,
) -> Result<(ValidMatchMpcWitness<N, S>, ValidMatchMpcStatement), String> {
    // Generate wallet randomness
    let mut rng = OsRng {};
    let wallet_randomness = rng.next_u64();

    // Generate hashes used for input consistency
    let my_order_hash = hash_values_arkworks(&[
        order.quote_mint,
        order.base_mint,
        order.side as u64,
        order.price,
        order.amount,
    ]);
    let my_balance_hash = hash_values_arkworks(&[balance.mint, balance.amount]);
    let my_fee_hash = hash_values_arkworks(&[
        fee.settle_key.clone().try_into().unwrap(),
        fee.gas_addr.clone().try_into().unwrap(),
        fee.gas_token_amount,
        fee.percentage_fee,
    ]);
    let my_randomness_hash = hash_values_arkworks(&[wallet_randomness]);

    // Share random hashes to build a shared statement between the two parties
    let p0_values = batch_share_plaintext_scalar(
        &[
            my_order_hash,
            my_balance_hash,
            my_fee_hash,
            my_randomness_hash,
        ],
        0, /* owning_party */
        fabric.0.clone(),
    );
    let p1_values = batch_share_plaintext_scalar(
        &[
            my_order_hash,
            my_balance_hash,
            my_fee_hash,
            my_randomness_hash,
        ],
        1, /* owning_party */
        fabric.0.clone(),
    );

    let match_res = match_orders(&order, fabric)?;

    Ok((
        ValidMatchMpcWitness {
            my_order: order,
            my_balance: balance,
            my_fee: fee,
            match_res,
        },
        ValidMatchMpcStatement {
            hash_order1: p0_values[0],
            hash_balance1: p0_values[1],
            hash_fee1: p0_values[2],
            hash_randomness1: p0_values[3],
            hash_order2: p1_values[0],
            hash_balance2: p1_values[1],
            hash_fee2: p1_values[2],
            hash_randomness2: p1_values[3],
        },
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
    let my_balance = vec![
        sel!(1, 2), // mint
        200,        // amount
    ];
    let my_fee = vec![
        0, // settle key
        1, // gas token addr
        3, // gas amount
        1, // percentage fee
    ];

    let (witness, statement) = setup_witness_and_statement(
        Order {
            quote_mint: my_order[0],
            base_mint: my_order[1],
            side: if my_order[2] == 0 {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            },
            price: my_order[3],
            amount: my_order[4],
        },
        Balance {
            mint: my_balance[0],
            amount: my_balance[1],
        },
        Fee {
            settle_key: BigInt::from(my_fee[0]),
            gas_addr: BigInt::from(my_fee[1]),
            gas_token_amount: my_fee[2],
            percentage_fee: my_fee[3],
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
