//! Helpers for manipulating values within a field and translating between fields

use std::ops::Neg;

use ark_ff::{Fp256, MontBackend, MontConfig, PrimeField};
use curve25519_dalek::scalar::Scalar;
use num_bigint::{BigInt, BigUint, Sign};

/// Defines a custom Arkworks field with the same modulus as the Dalek Ristretto group
///
/// This is necessary for testing against Arkworks, otherwise the values will not be directly comparable
#[derive(MontConfig)]
#[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
#[generator = "2"]
pub struct DalekRistrettoFieldConfig;
#[allow(missing_docs, clippy::missing_docs_in_private_items)]
pub type DalekRistrettoField = Fp256<MontBackend<DalekRistrettoFieldConfig, 4>>;

/// Convert a scalar to a BigInt
pub fn scalar_to_bigint(a: &Scalar) -> BigInt {
    BigInt::from_signed_bytes_le(&a.to_bytes())
}

/// Convert a scalar to a BigUint
pub fn scalar_to_biguint(a: &Scalar) -> BigUint {
    BigUint::from_bytes_le(&a.to_bytes())
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

/// Convert a BigUint to a scalar
pub fn biguint_to_scalar(a: &BigUint) -> Scalar {
    bigint_to_scalar(&a.clone().into())
}

/// Convert a BigUint to an Arkworks representation of the Ristretto scalar field
pub fn biguint_to_prime_field(a: &BigUint) -> DalekRistrettoField {
    scalar_to_prime_field(&biguint_to_scalar(a))
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

/// Converts a dalek scalar to an arkworks ff element
pub fn scalar_to_prime_field(a: &Scalar) -> DalekRistrettoField {
    Fp256::from(scalar_to_biguint(a))
}

/// Convert an Arkworks field element to a Dalek scalar
pub fn prime_field_to_scalar<F: PrimeField>(a: &F) -> Scalar {
    bigint_to_scalar(&prime_field_to_bigint(a))
}

/// Convert an arkworks prime field element to a bigint
pub fn prime_field_to_bigint<F: PrimeField>(element: &F) -> BigInt {
    let felt_biguint = prime_field_to_biguint(element);
    felt_biguint.into()
}

/// Convert an arkworks prime field element to a BigUint
pub fn prime_field_to_biguint<F: PrimeField>(element: &F) -> BigUint {
    (*element).into()
}

#[cfg(test)]
mod field_helper_test {
    use curve25519_dalek::scalar::Scalar;
    use num_bigint::BigInt;
    use rand::{thread_rng, Rng, RngCore};

    use crate::fields::{bigint_to_scalar, bigint_to_scalar_bits, scalar_to_bigint};

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
