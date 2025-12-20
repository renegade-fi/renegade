//! MPC helpers for test utilities

use ark_mpc::error::MpcError;
use constants::{AuthenticatedScalar, Scalar};
use futures::{Future, FutureExt, future::join_all};

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
        $crate::test_helpers::mpc::joint_open($x).await.unwrap()
    };
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
