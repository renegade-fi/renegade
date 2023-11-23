//! Groups circuits for MPC and zero knowledge execution

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(inherent_associated_types)]

use circuit_types::{
    errors::ProverError,
    traits::{MpcType, MultiProverCircuit, SingleProverCircuit},
    Fabric,
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
        use tracing::log;
        let x_eval = $x.eval($cs);
        log::info!("eval({}): {x_eval}", stringify!($x));
    }};
}

/// A debug macro used for printing wires in a raw MPC circuit during execution
#[allow(unused)]
macro_rules! print_mpc_wire {
    ($x:expr) => {{
        use crypto::fields::scalar_to_biguint;
        use futures::executor::block_on;
        use tracing::log;

        let x_eval = block_on($x.open());
        log::info!("eval({}): {:?}", stringify!($x), scalar_to_biguint(&x_eval));
    }};
}

/// A debug macro used for printing wires in an MPC-ZK circuit during execution
#[allow(unused)]
macro_rules! print_multiprover_wire {
    ($x:expr, $cs:ident) => {{
        use circuit_types::traits::CircuitVarType;
        use futures::executor::block_on;
        use mpc_stark::algebra::authenticated_scalar::AuthenticatedScalarResult;
        use tracing::log;

        let eval = $x.eval_multiprover($cs);
        let x_eval = block_on(x.open());
        log::info!("eval({}): {x_eval}", stringify!($x));
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
    assert!(
        m < SCALAR_MAX_BITS as u64,
        "result would overflow Scalar field"
    );

    Scalar::from(2u8).pow(m)
}

/// Generate a proof of a circuit and verify it
pub fn singleprover_prove_and_verify<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(), ProverError> {
    let proof = C::prove(witness, statement.clone())?;
    C::verify(statement, &proof).map_err(ProverError::Verification)
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
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    //! Helpers used in tests throughout the crate and integration tests outside
    //! the crate

    use ark_mpc::error::MpcError;
    use circuit_types::{
        fixed_point::FixedPoint,
        order::{Order, OrderSide},
        r#match::MatchResult,
    };
    use constants::{AuthenticatedScalar, Scalar};
    use env_logger::{Builder, Env, Target};
    use futures::{future::join_all, Future, FutureExt};
    use itertools::Itertools;
    use rand::{thread_rng, Rng, RngCore};
    use renegade_crypto::fields::scalar_to_biguint;
    use tracing::log::LevelFilter;
    use util::matching_engine::match_orders_with_max_amount;

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

    /// Initialize a logger
    pub fn init_logger() {
        let env = Env::default().filter_or("MY_CRATE_LOG", "trace");

        let mut builder = Builder::from_env(env);
        builder.target(Target::Stdout);
        builder.filter_level(LevelFilter::Info);

        builder.init();
    }

    /// Create a random sequence of field elements
    #[allow(unused)]
    pub fn random_field_elements(n: usize) -> Vec<Scalar> {
        let mut rng = thread_rng();
        (0..n).map(|_| Scalar::random(&mut rng)).collect_vec()
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
        let base_amount = rng.next_u32() as u64;

        // Buy side
        let o1 = Order {
            quote_mint: quote_mint.clone(),
            base_mint: base_mint.clone(),
            side: OrderSide::Buy,
            amount: rng.gen_range(1..base_amount),
            worst_case_price: price + Scalar::one(),
            timestamp: 0,
        };

        // Sell side
        let o2 = Order {
            quote_mint: quote_mint.clone(),
            base_mint: base_mint.clone(),
            side: OrderSide::Sell,
            amount: rng.gen_range(1..base_amount),
            worst_case_price: price - Scalar::one(),
            timestamp: 0,
        };

        // Randomly permute the orders
        let (o1, o2) = if rng.gen_bool(0.5) {
            (o1, o2)
        } else {
            (o2, o1)
        };

        // Match orders assuming they are fully capitalized
        let match_res =
            match_orders_with_max_amount(&o1, &o2, o1.amount, o2.amount, price).unwrap();

        (o1, o2, price, match_res)
    }
}
