//! Helpers for manipulating values within a field and translating between fields

use std::{iter, ops::Neg};

use ark_ff::PrimeField;
use bigdecimal::BigDecimal;
use itertools::Itertools;
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::{BigInt, BigUint, Sign};
use starknet::core::types::FieldElement as StarknetFieldElement;

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

/// Converts a dalek scalar to a StarkNet field element
pub fn scalar_to_starknet_felt(a: &Scalar) -> StarknetFieldElement {
    StarknetFieldElement::from_byte_slice_be(&a.to_bytes_be()).unwrap()
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
        }
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
        res.push(if a.bit(i as u64) {
            Scalar::one()
        } else {
            Scalar::zero()
        })
    }

    res
}

/// Convert a biguint to a Starknet field element
pub fn biguint_to_starknet_felt(a: &BigUint) -> StarknetFieldElement {
    // Simpler than padding bytes
    scalar_to_starknet_felt(&biguint_to_scalar(a))
}

// -----------------------------------
// | Conversions from StarkNet Types |
// -----------------------------------

/// Convert from a Starknet felt to a Dalek scalar
pub fn starknet_felt_to_scalar(element: &StarknetFieldElement) -> Scalar {
    // A dalek scalar stores its bytes in little-endian order and
    // a Starknet felt stores its bytes in big-endian order
    let felt_bytes = element.to_bytes_be();
    Scalar::from_be_bytes_mod_order(&felt_bytes)
}

/// Convert from a Starknet felt to a BigUint
pub fn starknet_felt_to_biguint(element: &StarknetFieldElement) -> BigUint {
    BigUint::from_bytes_be(&element.to_bytes_be())
}

/// Convert from a Starknet felt to a u64; truncating anything about 2^64 -1
pub fn starknet_felt_to_u64(element: &StarknetFieldElement) -> u64 {
    let bytes: [u8; 8] = element.to_bytes_be()[24..].try_into().unwrap();
    u64::from_be_bytes(bytes)
}

/// Convert a u128 to a Starknet felt
pub fn u128_to_starknet_felt(val: u128) -> StarknetFieldElement {
    // Pad to 32 bytes, reverse to big endian and then cast to felt
    let mut u128_bytes_le = val
        .to_le_bytes()
        .into_iter()
        .chain(iter::repeat(0u8))
        .take(32 /* n */)
        .collect_vec();
    u128_bytes_le.reverse();

    let u128_bytes_be: [u8; 32] = u128_bytes_le.try_into().unwrap();

    StarknetFieldElement::from_bytes_be(&u128_bytes_be).unwrap()
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod field_helper_test {
    use mpc_stark::algebra::scalar::Scalar;
    use num_bigint::{BigInt, BigUint};
    use rand::{thread_rng, Rng, RngCore};
    use starknet::core::types::FieldElement as StarknetFieldElement;

    use crate::fields::{bigint_to_scalar, bigint_to_scalar_bits, scalar_to_bigint};

    use super::{starknet_felt_to_biguint, starknet_felt_to_scalar, u128_to_starknet_felt};

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

    #[test]
    fn test_felt_to_scalar() {
        let mut rng = thread_rng();
        let x = rng.next_u64();

        let felt_x = StarknetFieldElement::from(x);
        let scalar_x = Scalar::from(x);
        let converted_x = starknet_felt_to_scalar(&felt_x);

        let bigint_converted_x = BigUint::from_bytes_be(&felt_x.to_bytes_be());
        println!("x: {x}\nbigint_converted_x: {bigint_converted_x}");

        assert_eq!(scalar_x, converted_x);
    }

    #[test]
    fn test_u128_to_starknet_felt() {
        let mut rng = thread_rng();
        let random_u128: u128 = rng.gen();

        let starknet_felt = u128_to_starknet_felt(random_u128);
        let res_biguint = starknet_felt_to_biguint(&starknet_felt);

        assert_eq!(res_biguint, BigUint::from(random_u128));
    }
}
