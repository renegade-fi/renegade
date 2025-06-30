//! Groups circuits for MPC and zero knowledge execution

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(inherent_associated_types)]

use circuit_types::{
    CollaborativePlonkProof, Fabric, MpcProofLinkingHint, PlonkProof, ProofLinkingHint,
    errors::{ProverError, VerifierError},
    traits::{MpcType, MultiProverCircuit, SingleProverCircuit},
};
use constants::Scalar;

pub mod mpc_circuits;
pub mod mpc_gadgets;
pub mod zk_circuits;
pub mod zk_gadgets;

// -------------
// | Constants |
// -------------

/// The number of bits in a `Scalar`
pub(crate) const SCALAR_MAX_BITS: usize = 254;
/// The number of bits in a `Scalar` minus two
///
/// Used to truncate values to the range of positive integers in our field
pub(crate) const SCALAR_BITS_MINUS_TWO: usize = SCALAR_MAX_BITS - 2;

// ----------
// | Macros |
// ----------

/// A debug macro used for printing wires in a single-prover circuit during
/// execution
#[allow(unused)]
macro_rules! print_wire {
    ($x:expr, $cs:ident) => {{
        use circuit_types::traits::CircuitVarType;
        let x_eval = $x.eval($cs);
        println!("eval({}): {x_eval}", stringify!($x));
    }};
}

/// A debug macro used for printing wires in a raw MPC circuit during execution
#[allow(unused)]
macro_rules! print_mpc_wire {
    ($x:expr) => {{
        use circuit_types::traits::MpcType;
        use futures::executor::block_on;
        use renegade_crypto::fields::scalar_to_biguint;

        let x_eval = block_on($x.open());
        if $x.fabric().party_id() == 0 {
            info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
        }
    }};
}

/// A debug macro used for printing wires in an MPC-ZK circuit during execution
#[allow(unused)]
macro_rules! print_multiprover_wire {
    ($x:expr, $cs:ident) => {{
        use circuit_types::traits::CircuitVarType;
        use constants::AuthenticatedScalar;
        use futures::executor::block_on;

        let eval: AuthenticatedScalar = $x.eval_multiprover($cs);
        let x_eval = block_on(eval.open());
        println!("eval({}): {x_eval}", stringify!($x));
    }};
}

#[allow(unused)]
pub(crate) use print_mpc_wire;
#[allow(unused)]
pub(crate) use print_multiprover_wire;
#[allow(unused)]
pub(crate) use print_wire;

// -----------
// | Helpers |
// -----------

/// Construct the `Scalar` representation of 2^m
pub fn scalar_2_to_m(m: u64) -> Scalar {
    assert!(m < SCALAR_MAX_BITS as u64, "result would overflow Scalar field");

    Scalar::from(2u8).pow(m)
}

/// Construct a proof of a given circuit
pub fn singleprover_prove<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<PlonkProof, ProverError> {
    C::prove(witness, statement)
}

/// Construct a proof of a given circuit and return a link hint with it
pub fn singleprover_prove_with_hint<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(PlonkProof, ProofLinkingHint), ProverError> {
    C::prove_with_link_hint(witness, statement)
}

/// Verify a proof of a given circuit
pub fn verify_singleprover_proof<C: SingleProverCircuit>(
    statement: C::Statement,
    proof: &PlonkProof,
) -> Result<(), VerifierError> {
    C::verify(statement, proof)
}

/// Generate a proof of a circuit and verify it
pub fn singleprover_prove_and_verify<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(), ProverError> {
    let proof = C::prove(witness, statement.clone())?;
    C::verify(statement, &proof).map_err(ProverError::Verification)
}

/// Construct a multiprover proof of a given circuit
pub fn multiprover_prove<C: MultiProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: Fabric,
) -> Result<CollaborativePlonkProof, ProverError> {
    C::prove(witness, statement, fabric).map_err(ProverError::Plonk)
}

/// Construct a collaborative proof of a given circuit and return a shared link
/// hint with it
pub fn multiprover_prove_with_hint<C: MultiProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: Fabric,
) -> Result<(CollaborativePlonkProof, MpcProofLinkingHint), ProverError> {
    C::prove_with_link_hint(witness, statement, fabric).map_err(ProverError::Plonk)
}

/// Generate a multiprover proof and verify it
pub async fn multiprover_prove_and_verify<C: MultiProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: Fabric,
) -> Result<(), ProverError> {
    let proof = C::prove(witness, statement.clone(), fabric)
        .map_err(ProverError::Plonk)?
        .open_authenticated()
        .await
        .map_err(ProverError::Plonk)?;

    let statement = statement.open().await.map_err(ProverError::Mpc)?;
    C::verify(statement, &proof).map_err(ProverError::Verification)
}

// ----------------
// | Test Helpers |
// ----------------

/// Helpers used in tests throughout the crate and integration tests outside
/// the crate
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {

    use std::iter;

    use ark_mpc::error::MpcError;
    use circuit_types::{
        AMOUNT_BITS, Amount,
        balance::Balance,
        fixed_point::FixedPoint,
        r#match::{MatchResult, OrderSettlementIndices},
        order::{Order, OrderSide},
        traits::BaseType,
        wallet::{Wallet, WalletShare},
    };
    use constants::{AuthenticatedScalar, Scalar};
    use futures::{Future, FutureExt, future::join_all};
    use itertools::Itertools;
    use rand::{Rng, RngCore, thread_rng};
    use renegade_crypto::fields::scalar_to_biguint;
    use util::matching_engine::match_orders_with_max_min_amounts;

    use crate::zk_circuits::test_helpers::{MAX_BALANCES, MAX_ORDERS};

    // -----------
    // | Helpers |
    // -----------

    /// Open a value and unwrap the result
    #[macro_export]
    macro_rules! open_unwrap {
        ($x:expr) => {
            $x.open_authenticated().await.unwrap()
        };
    }

    /// Open a vector of values and unwrap the result
    #[macro_export]
    macro_rules! open_unwrap_vec {
        ($x:expr) => {
            $crate::test_helpers::joint_open($x).await.unwrap()
        };
    }

    /// Create a random sequence of field elements
    #[allow(unused)]
    pub fn random_field_elements(n: usize) -> Vec<Scalar> {
        let mut rng = thread_rng();
        (0..n).map(|_| Scalar::random(&mut rng)).collect_vec()
    }

    /// Generate a random set of settlement indices
    pub fn random_indices() -> OrderSettlementIndices {
        let balance_send = random_index(MAX_BALANCES);
        let mut balance_receive = random_index(MAX_BALANCES);

        while balance_send == balance_receive {
            balance_receive = random_index(MAX_BALANCES);
        }

        OrderSettlementIndices { order: random_index(MAX_ORDERS), balance_send, balance_receive }
    }

    /// Generate a random index bounded by a max
    fn random_index(max: usize) -> usize {
        let mut rng = thread_rng();
        rng.gen_range(0..max)
    }

    /// Generate a random amount valid in a wallet
    pub fn random_wallet_amount() -> Amount {
        let mut rng = thread_rng();
        let amt_unreduced: Amount = rng.r#gen();

        let max_amount = 1u128 << AMOUNT_BITS;
        amt_unreduced % max_amount
    }

    /// Get the maximum amount allowed
    pub fn max_amount() -> Amount {
        (1u128 << AMOUNT_BITS) - 1u128
    }

    /// Get a dummy set of wallet shares
    pub fn dummy_wallet_share<const MAX_BALANCES: usize, const MAX_ORDERS: usize>()
    -> WalletShare<MAX_BALANCES, MAX_ORDERS> {
        let mut iter = iter::from_fn(|| Some(Scalar::zero()));
        WalletShare::from_scalars(&mut iter)
    }

    /// Create a wallet with random zero'd balances
    pub fn wallet_with_random_balances<const MAX_BALANCES: usize, const MAX_FEES: usize>()
    -> Wallet<MAX_BALANCES, MAX_FEES> {
        let mut rng = thread_rng();
        let mut wallet = Wallet::<MAX_BALANCES, MAX_FEES>::default();

        for bal in wallet.balances.iter_mut() {
            let mint = scalar_to_biguint(&Scalar::random(&mut rng));
            *bal = Balance::new_from_mint(mint);
        }

        wallet
    }

    /// Open a batch of values and join into a single future
    #[allow(unused)]
    pub fn joint_open(
        values: Vec<AuthenticatedScalar>,
    ) -> impl Future<Output = Result<Vec<Scalar>, MpcError>> {
        let mut futures = Vec::new();
        for value in values {
            futures.push(value.open_authenticated());
        }

        join_all(futures).map(|res| res.into_iter().collect::<Result<Vec<_>, _>>())
    }

    /// Get two random orders that cross along with their match result
    pub fn random_orders_and_match() -> (Order, Order, FixedPoint, MatchResult) {
        let mut rng = thread_rng();
        let quote_mint = scalar_to_biguint(&Scalar::random(&mut rng));
        let base_mint = scalar_to_biguint(&Scalar::random(&mut rng));

        let price = FixedPoint::from_f64_round_down(rng.gen_range(0.0..100.0));
        let base_amount = rng.next_u32() as u128;

        // Buy side
        let o1 = Order {
            quote_mint: quote_mint.clone(),
            base_mint: base_mint.clone(),
            side: OrderSide::Buy,
            amount: rng.gen_range(1..base_amount),
            worst_case_price: price + Scalar::from(2u8),
        };

        // Sell side
        let o2 = Order {
            quote_mint: quote_mint.clone(),
            base_mint: base_mint.clone(),
            side: OrderSide::Sell,
            amount: rng.gen_range(1..base_amount),
            worst_case_price: price - Scalar::from(2u8),
        };

        // Randomly permute the orders
        let (o1, o2) = if rng.gen_bool(0.5) { (o1, o2) } else { (o2, o1) };

        // Match orders assuming they are fully capitalized
        let match_res = match_orders_with_max_min_amounts(
            &o1,
            &o2,
            o1.amount,
            o2.amount,
            Amount::MIN, // min_quote_amount
            Amount::MIN, // min_base_amount
            price,
        )
        .unwrap();

        (o1, o2, price, match_res)
    }
}
