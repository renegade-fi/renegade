//! Groups integration tests for the VALID MATCH MPC circuit

use ark_sponge::{poseidon::PoseidonSponge, CryptographicSponge};
use circuits::{
    mpc::SharedFabric,
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{AuthenticatedMatch, BalanceVar, FeeVar, OrderVar},
    zk_circuits::valid_match_mpc::{
        ValidMatchMpcCircuit, ValidMatchMpcStatement, ValidMatchMpcWitness,
    },
};
use curve25519_dalek::scalar::Scalar;
use integration_helpers::{mpc_network::share_plaintext_scalar, types::IntegrationTest};
use itertools::Itertools;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use rand_core::OsRng;

use crate::{
    mpc_gadgets::{poseidon::convert_params, prime_field_to_scalar, scalar_to_prime_field},
    zk_gadgets::multiprover_prove_and_verify,
    IntegrationTestArgs, TestWrapper,
};

const ORDER_LENGTH_SCALARS: usize = 5; // mint1, mint2, direction, price, amount
const BALANCE_LENGTH_SCALARS: usize = 2; // amount, direction
const FEE_LENGTH_SCALARS: usize = 4; // settle_key, gas_addr, gas_token_amount, percentage_fee

/// Hashes the payload of `Scalar`s via the Arkworks Poseidon sponge implementation
/// Returns the result, re-cast into the Dalek Ristretto scalar field
fn hash_values_arkworks(values: &[Scalar]) -> Scalar {
    let arkworks_input = values.iter().map(scalar_to_prime_field).collect_vec();
    let arkworks_params = convert_params(&PoseidonSpongeParameters::default());

    let mut arkworks_hasher = PoseidonSponge::new(&arkworks_params);
    for val in arkworks_input.iter() {
        arkworks_hasher.absorb(val)
    }

    prime_field_to_scalar(&arkworks_hasher.squeeze_field_elements(1 /* num_elements */)[0])
}

/// Sample a random sequence of scalars
fn random_scalars(n: usize) -> Vec<Scalar> {
    let mut rng = OsRng {};
    (0..n).map(|_| Scalar::random(&mut rng)).collect_vec()
}

/// Generates a random authenticated match with dummy data
/// TODO: Remove this method once the full test is in place
fn random_authenticated_match<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
    fabric: SharedFabric<N, S>,
) -> AuthenticatedMatch<N, S> {
    let borrow = fabric.borrow_fabric();
    AuthenticatedMatch {
        mint: borrow.allocate_public_u64(0),
        amount: borrow.allocate_public_u64(0),
        side: borrow.allocate_public_u64(0),
    }
}

/// Tests that the valid match MPC circuit proves and verifies given a correct witness
fn test_valid_match_mpc_valid(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // TODO: These values should be valid inputs, not random
    let my_random_order = random_scalars(ORDER_LENGTH_SCALARS);
    let my_random_balance = random_scalars(BALANCE_LENGTH_SCALARS);
    let my_random_fee = random_scalars(FEE_LENGTH_SCALARS);

    // Hash the values with Arkworks hasher to get an expected input consistency value
    let my_order_hash = hash_values_arkworks(&my_random_order);
    let my_balance_hash = hash_values_arkworks(&my_random_balance);
    let my_fee_hash = hash_values_arkworks(&my_random_fee);

    // Share random hashes to build the statement
    let p0_order_hash = share_plaintext_scalar(
        my_order_hash,
        0, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );
    let p0_balance_hash = share_plaintext_scalar(
        my_balance_hash,
        0, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );
    let p0_fee_hash = share_plaintext_scalar(
        my_fee_hash,
        0, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );
    let p1_order_hash = share_plaintext_scalar(
        my_order_hash,
        1, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );
    let p1_balance_hash = share_plaintext_scalar(
        my_balance_hash,
        1, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );
    let p1_fee_hash = share_plaintext_scalar(
        my_fee_hash,
        1, /* owning_party */
        test_args.mpc_fabric.0.clone(),
    );

    let witness = ValidMatchMpcWitness {
        my_order: OrderVar {
            quote_mint: my_random_order[0],
            base_mint: my_random_order[1],
            side: my_random_order[2],
            price: my_random_order[3],
            amount: my_random_order[4],
        },
        my_balance: BalanceVar {
            mint: my_random_balance[0],
            amount: my_random_balance[1],
        },
        my_fee: FeeVar {
            settle_key: my_random_fee[0],
            gas_addr: my_random_fee[1],
            gas_token_amount: my_random_fee[2],
            percentage_fee: my_random_fee[3],
        },
        match_res: random_authenticated_match(test_args.mpc_fabric.clone()),
    };

    let statement = ValidMatchMpcStatement {
        hash_order1: p0_order_hash,
        hash_balance1: p0_balance_hash,
        hash_fee1: p0_fee_hash,
        hash_order2: p1_order_hash,
        hash_balance2: p1_balance_hash,
        hash_fee2: p1_fee_hash,
    };

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
