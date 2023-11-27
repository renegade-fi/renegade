//! Helpers for manipulating values within a field and translating between
//! fields

use std::ops::Neg;

use ark_ff::PrimeField;
use bigdecimal::BigDecimal;
use constants::Scalar;
use num_bigint::{BigInt, BigUint, Sign};

// -----------
// | Helpers |
// -----------

/// Return the modulus `p` of the `Scalar` ($Z_p$) field as a `BigUint`
pub fn get_scalar_field_modulus() -> BigUint {
    Scalar::Field::MODULUS.into()
}

// ---------------------------
// | Conversions From Scalar |
// ---------------------------

/// Convert a scalar to a BigInt
pub fn scalar_to_bigint(a: &Scalar) -> BigInt {
    a.to_biguint().into()
}

/// Convert a scalar to a BigUint
pub fn scalar_to_biguint(a: &Scalar) -> BigUint {
    a.to_biguint()
}

/// Convert a scalar to a BigDecimal
pub fn scalar_to_bigdecimal(a: &Scalar) -> BigDecimal {
    let bigint = scalar_to_bigint(a);
    BigDecimal::from(bigint)
}

/// Reduces the scalar to a u64, truncating anything above 2^64 - 1
pub fn scalar_to_u64(a: &Scalar) -> u64 {
    let bytes = a.to_bytes_be();
    let len = bytes.len();

    // Take the last 8 bytes (64 bits)
    let bytes: [u8; 8] = bytes[len - 8..len].try_into().unwrap();
    u64::from_be_bytes(bytes)
}

/// Reduces the scalar to a usize, truncating anything above usize::MAX
pub fn scalar_to_usize(a: &Scalar) -> usize {
    scalar_to_u64(a) as usize
}

// ----------------------------
// | Conversions from Bigints |
// ----------------------------

/// Convert a bigint to a scalar
pub fn bigint_to_scalar(a: &BigInt) -> Scalar {
    match a.sign() {
        Sign::Minus => {
            let biguint = a.neg().to_biguint().unwrap();
            -Scalar::from(biguint)
        },
        _ => Scalar::from(a.to_biguint().unwrap()),
    }
}

/// Convert a BigUint to a scalar
pub fn biguint_to_scalar(a: &BigUint) -> Scalar {
    Scalar::from(a.clone())
}

/// Convert a bigint to a vector of bits, encoded as scalars
pub fn bigint_to_scalar_bits<const D: usize>(a: &BigInt) -> Vec<Scalar> {
    let mut res = Vec::with_capacity(D);
    // Reverse the iterator; BigInt::bits expects big endian
    for i in 0..D {
        res.push(if a.bit(i as u64) { Scalar::one() } else { Scalar::zero() })
    }

    res
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod field_helper_test {
    use constants::Scalar;
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
        let random_scalar_bits =
            (0..256).map(|_| rng.gen_bool(0.5 /* p */) as u64).collect::<Vec<_>>();

        let random_bigint = random_scalar_bits
            .iter()
            .rev()
            .cloned()
            .map(BigInt::from)
            .fold(BigInt::from(0u64), |acc, val| acc * 2 + val);
        let scalar_bits = random_scalar_bits.into_iter().map(Scalar::from).collect::<Vec<_>>();

        let res = bigint_to_scalar_bits::<256 /* bits */>(&random_bigint);

        assert_eq!(res.len(), scalar_bits.len());
        assert_eq!(res, scalar_bits);
    }
}
