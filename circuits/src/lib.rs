//! Groups circuits for MPC and zero knowledge execution

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![allow(incomplete_features)]
#![feature(generic_const_exprs)]
#![feature(inherent_associated_types)]

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
        use crypto::fields::scalar_to_biguint;
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

// ----------------
// | Test Helpers |
// ----------------
#[cfg(test)]
pub(crate) mod test_helpers {
    use ark_mpc::error::MpcError;
    use constants::{AuthenticatedScalar, Scalar};
    use env_logger::{Builder, Env, Target};
    use futures::{future::join_all, Future, FutureExt};
    use itertools::Itertools;
    use rand::thread_rng;
    use tracing::log::LevelFilter;

    // -----------
    // | Helpers |
    // -----------

    #[macro_export]
    macro_rules! open_unwrap {
        ($x:expr) => {
            $x.open_authenticated().await.unwrap()
        };
    }

    #[macro_export]
    macro_rules! open_unwrap_vec {
        ($x:expr) => {
            $crate::test_helpers::joint_open($x).await.unwrap()
        };
    }

    /// Constructor to initialize logging in tests
    #[ctor::ctor]
    fn setup() {
        init_logger()
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
    pub fn random_field_elements(n: usize) -> Vec<Scalar> {
        let mut rng = thread_rng();
        (0..n).map(|_| Scalar::random(&mut rng)).collect_vec()
    }

    /// Open a batch of values and join into a single future
    pub fn joint_open(
        values: Vec<AuthenticatedScalar>,
    ) -> impl Future<Output = Result<Vec<Scalar>, MpcError>> {
        let mut futures = Vec::new();
        for value in values {
            futures.push(value.open_authenticated());
        }

        join_all(futures).map(|res| res.into_iter().collect::<Result<Vec<_>, _>>())
    }
}
