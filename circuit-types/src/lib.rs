//! Groups type definitions and abstractions useful in the circuitry
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![allow(incomplete_features)]
#![feature(future_join)]

// Top-level modules
pub mod elgamal;
#[cfg(feature = "proof-system-types")]
pub mod errors;
pub mod fixed_point;
#[cfg(feature = "proof-system-types")]
pub mod macro_tests;
pub mod merkle;
#[cfg(feature = "proof-system-types")]
pub mod srs;
#[cfg(feature = "proof-system-types")]
pub mod traits;

pub mod v2;
pub use v2::*;

use ark_ff::BigInt;
use bigdecimal::Num;
use constants::{ADDRESS_BYTE_LENGTH, Scalar, ScalarField};
use fixed_point::{DEFAULT_FP_PRECISION, FixedPoint};
use num_bigint::BigUint;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as SerdeErr};

#[cfg(feature = "proof-system-types")]
use {
    ark_mpc::MpcFabric,
    constants::{AuthenticatedScalar, SystemCurve, SystemCurveGroup},
    jf_primitives::pcs::prelude::Commitment as JfCommitment,
    mpc_plonk::{
        multiprover::proof_system::{
            CollaborativeProof, MpcLinkingHint, MpcPlonkCircuit as GenericMpcPlonkCircuit,
            proof_linking::MultiproverLinkingProof,
        },
        proof_system::{
            proof_linking::LinkingProof,
            structs::{LinkingHint, Proof},
        },
    },
    mpc_relation::PlonkCircuit as GenericPlonkCircuit,
};

// -------------
// | Constants |
// -------------

/// The zero value in the Scalar field we work over
pub const SCALAR_ZERO: ScalarField = ScalarField::new(BigInt::new([0, 0, 0, 0]));
/// The one value in the Scalar field we work over
pub const SCALAR_ONE: ScalarField = ScalarField::new(BigInt::new([1, 0, 0, 0]));

/// The type used to track an amount
pub type Amount = u128;
/// The number of bits allowed in a balance or transaction "amount"
pub const AMOUNT_BITS: usize = 100;
/// The number of bits allowed in a price's representation, this included the
/// fixed point precision
///
/// This is the default fixed point precision plus 32 bits for the integral part
pub const PRICE_BITS: usize = DEFAULT_FP_PRECISION + 64;
/// The number of bits allowed in a fee rate representation, including the fixed
/// point precision
///
/// Fees are naturally less than one, so we use the default fixed point
/// precision
pub const FEE_BITS: usize = DEFAULT_FP_PRECISION;

/// An MPC fabric with curve generic attached
#[cfg(feature = "proof-system-types")]
pub type Fabric = MpcFabric<SystemCurveGroup>;
/// A circuit type with curve generic attached
#[cfg(feature = "proof-system-types")]
pub type PlonkCircuit = GenericPlonkCircuit<ScalarField>;
/// A circuit type with curve generic attached in a multiprover context
#[cfg(feature = "proof-system-types")]
pub type MpcPlonkCircuit = GenericMpcPlonkCircuit<SystemCurveGroup>;
/// A Plonk proof represented over the system curve
#[cfg(feature = "proof-system-types")]
pub type PlonkProof = Proof<SystemCurve>;
/// A collaborative plonk proof represented over the system curve
#[cfg(feature = "proof-system-types")]
pub type CollaborativePlonkProof = CollaborativeProof<SystemCurve>;
/// A KZG polynomial commitment over the system curve
#[cfg(feature = "proof-system-types")]
pub type PolynomialCommitment = JfCommitment<SystemCurve>;
/// A proof linking hint defined over the system curve
#[cfg(feature = "proof-system-types")]
pub type ProofLinkingHint = LinkingHint<SystemCurve>;
/// A collaboratively generated proof linking hint defined over the system curve
#[cfg(feature = "proof-system-types")]
pub type MpcProofLinkingHint = MpcLinkingHint<SystemCurve>;
/// A linking proof defined over the system curve
#[cfg(feature = "proof-system-types")]
pub type PlonkLinkProof = LinkingProof<SystemCurve>;
/// A collaboratively generated linking proof defined over the system curve
#[cfg(feature = "proof-system-types")]
pub type MpcPlonkLinkProof = MultiproverLinkingProof<SystemCurve>;

// --------------------
// | Type Definitions |
// --------------------

/// A boolean allocated in an MPC network
#[cfg(feature = "proof-system-types")]
#[derive(Clone, Debug)]
pub struct AuthenticatedBool(AuthenticatedScalar);

/// This implementation does no validation of the underlying value, to do so
/// would require leaking privacy or otherwise complicated circuitry
///
/// The values here are eventually constrained in a collaborative proof, so
/// there is no need to validate them here
#[cfg(feature = "proof-system-types")]
impl From<AuthenticatedScalar> for AuthenticatedBool {
    fn from(value: AuthenticatedScalar) -> Self {
        Self(value)
    }
}

#[cfg(feature = "proof-system-types")]
impl From<AuthenticatedBool> for AuthenticatedScalar {
    fn from(value: AuthenticatedBool) -> Self {
        value.0
    }
}

// -----------
// | Helpers |
// -----------

/// Get the maximum representable price
pub fn max_price() -> FixedPoint {
    let repr_bigint = (BigUint::from(1u8) << PRICE_BITS) - 1u8;
    let repr = biguint_to_scalar(&repr_bigint);
    FixedPoint::from_repr(repr)
}

/// Get the maximum representable amount
pub fn max_amount() -> Amount {
    (1u128 << AMOUNT_BITS) - 1
}

/// Verify that an amount is within the correct bitlength
pub fn validate_amount_bitlength(amount: Amount) -> bool {
    let max_amount = (1u128 << AMOUNT_BITS) - 1;
    amount <= max_amount
}

/// Verify that a price is within the correct bitlength
pub fn validate_price_bitlength(price: FixedPoint) -> bool {
    let max_repr = (1u128 << PRICE_BITS) - 1;
    price.repr <= Scalar::from(max_repr)
}

/// Converts an element of the arkworks `ScalarField` to an `ark-mpc` type
/// `Scalar`
#[macro_export]
macro_rules! scalar {
    ($x:expr) => {
        Scalar::new($x)
    };
}

/// A helper to serialize a Scalar to a hex string
pub fn scalar_to_hex_string<S>(val: &Scalar, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    biguint_to_hex_string(&scalar_to_biguint(val), s)
}

/// A helper to deserialize a Scalar from a hex string
pub fn scalar_from_hex_string<'de, D>(d: D) -> Result<Scalar, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(biguint_to_scalar(&biguint_from_hex_string(d)?))
}

/// A helper to serialize a BigUint to a hex string
pub fn biguint_to_hex_string<S>(val: &BigUint, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    s.serialize_str(&format!("0x{}", val.to_str_radix(16 /* radix */)))
}

/// A helper to serialize a BigUint to a hex address
pub fn biguint_to_hex_addr<S>(val: &BigUint, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut bytes = [0_u8; ADDRESS_BYTE_LENGTH];
    let val_bytes = val.to_bytes_be();

    let len = val_bytes.len();
    debug_assert!(len <= ADDRESS_BYTE_LENGTH, "BigUint too large for an address");

    bytes[ADDRESS_BYTE_LENGTH - val_bytes.len()..].copy_from_slice(&val_bytes);
    let hex_str = hex::encode(bytes);

    s.serialize_str(&format!("0x{hex_str}"))
}

/// A helper to deserialize a BigUint from a hex string
pub fn biguint_from_hex_string<'de, D>(d: D) -> Result<BigUint, D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize as a string and remove "0x" if present
    let hex_string = String::deserialize(d)?;
    let hex_string = hex_string.strip_prefix("0x").unwrap_or(&hex_string);

    BigUint::from_str_radix(hex_string, 16 /* radix */)
        .map_err(|e| SerdeErr::custom(format!("error deserializing BigUint from hex string: {e}")))
}

/// A helper for serializing array types
pub fn serialize_array<const ARR_SIZE: usize, T, S>(
    arr: &[T; ARR_SIZE],
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: Serialize + Clone,
    [(); ARR_SIZE]: Sized,
{
    // Convert the array to a vec
    let arr_vec: Vec<T> = arr.clone().into();
    arr_vec.serialize(s)
}

/// A helper for deserializing array types
pub fn deserialize_array<'de, const ARR_SIZE: usize, T, D>(d: D) -> Result<[T; ARR_SIZE], D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
    [(); ARR_SIZE]: Sized,
{
    // Deserialize a vec and then convert to an array
    let deserialized_vec: Vec<T> = Vec::deserialize(d)?;
    deserialized_vec.try_into().map_err(|_| SerdeErr::custom("incorrect size of serialized array"))
}

/// A helper for serializing an `EmbeddedScalarField` value
#[cfg(feature = "proof-system-types")]
pub mod ser_embedded_scalar_field {
    use ark_mpc::algebra::n_bytes_field;
    use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
    use constants::EmbeddedScalarField;
    use serde::{
        Deserialize, Deserializer, Serializer, de::Error as DeError, ser::Error as SerError,
    };

    /// Serialize an `EmbeddedScalarField` to a byte array
    pub fn serialize<S>(value: &EmbeddedScalarField, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let n_bytes = n_bytes_field::<EmbeddedScalarField>();
        let mut bytes = Vec::with_capacity(n_bytes);
        value.serialize_uncompressed(&mut bytes).map_err(SerError::custom)?;

        serializer.serialize_bytes(&bytes)
    }

    /// Deserialize an `EmbeddedScalarField` from a byte array
    pub fn deserialize<'de, D>(deserializer: D) -> Result<EmbeddedScalarField, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        let value = EmbeddedScalarField::deserialize_uncompressed(bytes.as_slice())
            .map_err(DeError::custom)?;

        Ok(value)
    }
}

/// A set of helpers for working with native types
///
/// A native type is the out-of-circuit representation of a circuit type
#[cfg(feature = "proof-system-types")]
pub mod native_helpers {
    use ark_ff::UniformRand;
    use constants::{EmbeddedScalarField, Scalar};
    use itertools::Itertools;
    use jf_primitives::elgamal::{DecKey, EncKey};
    use rand::thread_rng;

    use crate::{
        elgamal::{DecryptionKey, ElGamalCiphertext, EncryptionKey},
        traits::CircuitBaseType,
    };

    // -------------------------
    // | Cryptographic Helpers |
    // -------------------------

    /// Encrypt a plaintext buffer under the given key, returning both the
    /// ciphertext and the randomness used to encrypt
    pub fn elgamal_encrypt<const N: usize>(
        plaintext: &[Scalar],
        key: &EncryptionKey,
    ) -> (ElGamalCiphertext<N>, EmbeddedScalarField) {
        let mut rng = thread_rng();
        let randomness = EmbeddedScalarField::rand(&mut rng);

        let jf_key = EncKey::from(*key);
        let jf_plaintext = plaintext.iter().map(Scalar::inner).collect_vec();
        let cipher = jf_key.deterministic_encrypt(randomness, &jf_plaintext);

        (cipher.into(), randomness)
    }

    /// Decrypt a ciphertext under the given key
    pub fn elgamal_decrypt<const N: usize, T: CircuitBaseType>(
        ciphertext: &ElGamalCiphertext<N>,
        key: &DecryptionKey,
    ) -> T {
        let jf_key = DecKey::from(*key);
        let jf_cipher = ciphertext.clone().into();
        let mut plaintext_iter = jf_key.decrypt(&jf_cipher).into_iter().map(Scalar::new);

        T::from_scalars(&mut plaintext_iter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_price_validation() {
        // Valid price
        let valid_price = FixedPoint::from_f64_round_down(1234.5678);
        assert!(validate_price_bitlength(valid_price));

        // Maximum representable price
        let repr = Scalar::from(1u8).pow(PRICE_BITS as u64) - Scalar::one();
        let max_price = FixedPoint::from_repr(repr);
        assert!(validate_price_bitlength(max_price));

        // Minimum non-representable price
        let repr = repr + Scalar::one();
        let min_price = FixedPoint::from_repr(repr);
        assert!(validate_price_bitlength(min_price));

        // Invalid price (too large)
        let invalid_price = FixedPoint::from_f64_round_down(1e200); // Assuming this is larger than 2^PRICE_BITS
        assert!(!validate_price_bitlength(invalid_price));
    }

    #[test]
    fn test_amount_validation() {
        // Valid amount
        let valid_amount = 1_000_000;
        assert!(validate_amount_bitlength(valid_amount));

        // Maximum representable amount
        let max_amount = (1u128 << AMOUNT_BITS) - 1;
        assert!(validate_amount_bitlength(max_amount));

        // Minimum non-representable amount
        let min_amount = 1;
        assert!(validate_amount_bitlength(min_amount));

        // Invalid amount (too large)
        let invalid_amount = u128::MAX;
        assert!(!validate_amount_bitlength(invalid_amount));
    }
}
