//! Groups circuits for MPC and zero knowledge execution
#![feature(generic_const_exprs)]
#![allow(incomplete_features)]
#![deny(missing_docs)]

use std::ops::Neg;

use curve25519_dalek::scalar::Scalar;
use errors::MpcError;
use mpc::SharedFabric;
use mpc_ristretto::{beaver::SharedValueSource, network::MpcNetwork};
use num_bigint::{BigInt, Sign};

pub mod constants;
pub mod errors;
pub mod mpc;
pub mod mpc_circuits;
pub mod mpc_gadgets;
pub mod types;
pub mod zk_gadgets;

pub(crate) const SCALAR_MAX_BITS: usize = 252;

/**
 * Helpers
 */

/// Represents 2^m as a scalar
pub fn scalar_2_to_m(m: usize) -> Scalar {
    assert!(
        m < SCALAR_MAX_BITS,
        "Cannot fill scalar with greater than {:?} bits, got {:?}",
        SCALAR_MAX_BITS,
        m,
    );
    if (128..SCALAR_MAX_BITS).contains(&m) {
        Scalar::from(1u128 << 127) * Scalar::from(1u128 << (m - 127))
    } else {
        Scalar::from(1u128 << m)
    }
}

/// Convert a scalar to a BigInt
pub fn scalar_to_bigint(a: &Scalar) -> BigInt {
    BigInt::from_signed_bytes_le(&a.to_bytes())
}

/// Convert a bigint to a scalar
pub fn bigint_to_scalar(a: &BigInt) -> Scalar {
    let (sign, mut bytes) = a.to_bytes_le();
    if bytes.len() < 32 {
        zero_pad_bytes(&mut bytes, 32)
    }

    let scalar = Scalar::from_bytes_mod_order(bytes[..32].try_into().unwrap());

    match sign {
        Sign::Minus => scalar.neg(),
        _ => scalar,
    }
}

/// Pad an array up to the desired length with zeros
fn zero_pad_bytes(unpadded_buf: &mut Vec<u8>, n: usize) {
    unpadded_buf.append(&mut vec![0u8; n - unpadded_buf.len()])
}

/// Convert a bigint to a vector of bits, encoded as scalars
pub fn bigint_to_scalar_bits<const D: usize>(a: &BigInt) -> Vec<Scalar> {
    let mut res = Vec::with_capacity(D);
    // Reverse the iterator; BigInt::bits expects big endian
    for i in 0..D {
        res.push(if a.bit(i as u64) {
            Scalar::one()
        } else {
            Scalar::zero()
        })
    }

    res
}

/**
 * Trait definitions
 */

/// Defines functionality to allocate a value within an MPC network
pub trait Allocate<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The output type that results from allocating the value in the network
    type Output;
    /// Allocates the raw type in the network as a shared value
    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::Output, MpcError>;
}

/// Defines functionality for a shared, allocated type to be opened to another type
///
/// The type this is implemented for is assumed to be a secret sharing of some MPC
/// network allocated value.
pub trait Open {
    /// The output type that results from opening this value
    type Output;
    /// The error type that results if opening fails
    type Error;
    /// Opens the shared type without authenticating
    fn open(&self) -> Result<Self::Output, Self::Error>;
    /// Opens the shared type and authenticates the result
    fn open_and_authenticate(&self) -> Result<Self::Output, Self::Error>;
}

#[cfg(test)]
mod circuits_test {
    use curve25519_dalek::scalar::Scalar;
    use num_bigint::BigInt;
    use rand::{thread_rng, Rng, RngCore};

    use crate::{bigint_to_scalar, bigint_to_scalar_bits, scalar_2_to_m, scalar_to_bigint};

    #[test]
    fn test_scalar_2_to_m() {
        let rand_m: usize = thread_rng().gen_range(0..256);
        let res = scalar_2_to_m(rand_m);

        let expected = bigint_to_scalar(&(BigInt::from(1u64) << rand_m));
        assert_eq!(res, expected);
    }

    #[test]
    fn test_scalar_to_bigint() {
        let rand_val = thread_rng().next_u64();
        let res = scalar_to_bigint(&Scalar::from(rand_val));

        assert_eq!(res, BigInt::from(rand_val));
    }

    #[test]
    fn test_bigint_to_scalar() {
        let rand_val = thread_rng().next_u64();
        let res = bigint_to_scalar(&BigInt::from(rand_val));

        assert_eq!(res, Scalar::from(rand_val));
    }

    #[test]
    fn test_bigint_to_scalar_bits() {
        let mut rng = thread_rng();
        let random_scalar_bits = (0..256)
            .map(|_| rng.gen_bool(0.5 /* p */) as u64)
            .collect::<Vec<_>>();

        let random_bigint = random_scalar_bits
            .iter()
            .rev()
            .cloned()
            .map(BigInt::from)
            .fold(BigInt::from(0u64), |acc, val| acc * 2 + val);
        let scalar_bits = random_scalar_bits
            .into_iter()
            .map(Scalar::from)
            .collect::<Vec<_>>();

        let res = bigint_to_scalar_bits::<256 /* bits */>(&random_bigint);

        assert_eq!(res.len(), scalar_bits.len());
        assert_eq!(res, scalar_bits);
    }
}
