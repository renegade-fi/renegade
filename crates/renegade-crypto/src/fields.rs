//! Helpers for manipulating values within a field and translating between
//! fields

use std::ops::Neg;

use alloy_primitives::{Address, U160, U256};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use bigdecimal::BigDecimal;
use constants::{EmbeddedScalarField, Scalar, SystemCurveGroup};
use num_bigint::{BigInt, BigUint, Sign};

// -----------
// | Helpers |
// -----------

/// The number of bytes in a U256
pub const U256_BYTES: usize = 256 / 8;

/// Return the modulus `r` of the `Scalar` ($Z_r$) field as a `BigUint`
pub fn get_scalar_field_modulus() -> BigUint {
    Scalar::Field::MODULUS.into()
}

/// Return the modulus `q` of the `Scalar` ($Z_q$) field as a `BigUint`
pub fn get_base_field_modulus() -> BigUint {
    <SystemCurveGroup as CurveGroup>::BaseField::MODULUS.into()
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

/// Convert a scalar to an Address
pub fn scalar_to_address(a: &Scalar) -> Address {
    // Take the lowest 20 bytes of the scalar
    let bytes = a.to_bytes_be();
    let mut address_bytes = [0u8; U160::BYTES];
    address_bytes.copy_from_slice(&bytes[bytes.len() - U160::BYTES..]);

    // Convert to address
    let u160 = U160::from_be_slice(&address_bytes);
    Address::from(u160)
}

/// Convert a scalar to a U256
pub fn scalar_to_u256(a: &Scalar) -> U256 {
    let bytes = a.to_bytes_be();
    let mut u256_bytes = [0u8; U256::BYTES];
    u256_bytes.copy_from_slice(&bytes[bytes.len() - U256::BYTES..]);
    U256::from_be_bytes(u256_bytes)
}

/// Convert a scalar to a BabyJubJub scalar
pub fn scalar_to_jubjub(a: &Scalar) -> EmbeddedScalarField {
    biguint_to_jubjub(&scalar_to_biguint(a))
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

/// Reduces the scalar to a u128, truncating anything above 2^128 - 1
pub fn scalar_to_u128(a: &Scalar) -> u128 {
    let bytes = a.to_bytes_be();
    let len = bytes.len();

    // Take the last 16 bytes (128 bits)
    let bytes: [u8; 16] = bytes[len - 16..len].try_into().unwrap();
    u128::from_be_bytes(bytes)
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

/// Convert a BigUint to a BabyJubJub scalar
pub fn biguint_to_jubjub(a: &BigUint) -> EmbeddedScalarField {
    EmbeddedScalarField::from(a.clone())
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

// --------------------------------
// | Conversions from Alloy Types |
// --------------------------------

/// Convert an Address to a scalar
pub fn address_to_scalar(a: &Address) -> Scalar {
    Scalar::from_be_bytes_mod_order(&a.0.0)
}

/// Convert a U256 to a scalar
pub fn u256_to_scalar(a: &U256) -> Scalar {
    let bytes: [u8; U256::BYTES] = a.to_be_bytes();
    Scalar::from_be_bytes_mod_order(&bytes)
}

// ---------------------------------------
// | Conversions from BabyJubJub Scalars |
// ---------------------------------------

/// Convert a BabyJubJub scalar to a BigUint
pub fn jubjub_to_biguint(a: EmbeddedScalarField) -> BigUint {
    a.into()
}

/// Convert a BabyJubJub scalar to a Scalar
pub fn jubjub_to_scalar(a: EmbeddedScalarField) -> Scalar {
    biguint_to_scalar(&jubjub_to_biguint(a))
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod field_helper_test {
    use alloy_primitives::Address;
    use constants::Scalar;
    use num_bigint::BigInt;
    use rand::{Rng, RngCore, thread_rng};

    use crate::fields::{
        address_to_scalar, bigint_to_scalar, bigint_to_scalar_bits, scalar_to_address,
        scalar_to_bigint,
    };

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

    #[test]
    fn test_scalar_address_round_trip() {
        let mut rng = thread_rng();
        let original_scalar = Scalar::random(&mut rng);

        // Convert scalar to address (only preserves lowest 20 bytes)
        let address = scalar_to_address(&original_scalar);
        let round_trip_scalar = address_to_scalar(&address);

        // Verify that the lowest 20 bytes match (we lose higher-order bytes)
        let original_bytes = original_scalar.to_bytes_be();
        let round_trip_bytes = round_trip_scalar.to_bytes_be();
        assert_eq!(
            &original_bytes[original_bytes.len() - 20..],
            &round_trip_bytes[round_trip_bytes.len() - 20..],
            "Lowest 20 bytes should match after round trip conversion"
        );
    }

    #[test]
    fn test_address_scalar_round_trip() {
        let mut rng = thread_rng();
        // Generate a random address
        let mut address_bytes = [0u8; 20];
        rng.fill(&mut address_bytes);
        let original_address = Address::from(address_bytes);

        // Convert address to scalar
        let scalar = address_to_scalar(&original_address);

        // Convert scalar back to address
        let round_trip_address = scalar_to_address(&scalar);
        assert_eq!(original_address, round_trip_address);
    }
}
