//! An implementation of ECDSA over the STARK curve, following the IETF RFC 6979 specification: https://datatracker.ietf.org/doc/html/rfc6979

use ark_ff::PrimeField;
use itertools::Itertools;
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::rngs::OsRng;
use tiny_keccak::{Hasher, Keccak};

/// An ECDSA signature
pub struct Signature {
    /// The `r` value of the signature
    pub r: Scalar,
    /// The `s` value of the signature
    pub s: Scalar,
}

/// Computes a Keccak256 hash over a sequence of bytes, returning a 32-byte hash output
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hash_bytes = [0_u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut hash_bytes);
    hash_bytes
}

/// Computes a Keccak256 hash over a message that has been serialized into a sequence of bytes,
/// and returns the result as a big-endian integer reduced modulo the scalar field order
pub fn bytes_message_hash_to_scalar(message: &[u8]) -> Scalar {
    let hash_bytes = keccak256(message);
    Scalar::from_be_bytes_mod_order(&hash_bytes)
}

/// Computes a Keccak256 hash over a message that has been serialized into a sequence of scalars
/// in a manner that is consistent with the Cairo implementation of Keccak256,
/// and returns the result as a big-endian integer reduced modulo the scalar field order
pub fn scalar_message_hash_to_scalar(message: &[Scalar]) -> Scalar {
    let message_bytes = message
        .iter()
        .flat_map(|s| {
            // Cairo Keccak implementation absorbs inputs as little-endian u256s.
            // `to_bytes_be` will already pad to 256 bits, but we need to reverse it
            // in order for the output to be absorbed as a little-endian u256.
            s.to_bytes_be().into_iter().rev()
        })
        .collect_vec();
    bytes_message_hash_to_scalar(&message_bytes)
}

/// Generates an ECDSA signature over a message hash using the provided secret key
#[allow(non_snake_case)]
fn generate_signature(h: &Scalar, secret_key: &Scalar) -> Signature {
    let mut rng = OsRng;

    let mut r = Scalar::zero();
    let mut k = Scalar::zero();
    while r == Scalar::zero() {
        k = Scalar::random(&mut rng);
        while k == Scalar::zero() {
            k = Scalar::random(&mut rng);
        }

        let kG = k * StarkPoint::generator();
        // This reduces the x coordinate of the point kG modulo the scalar field order
        r = Scalar::from_biguint(&kG.to_affine().x.into_bigint().into());
    }

    let s = (h + (secret_key * r)) * k.inverse();

    Signature { r, s }
}

/// Generates an ECDSA signature over a message that has been serialized into a sequence of scalars
/// using the provided secret key
pub fn sign_scalar_message(message: &[Scalar], secret_key: &Scalar) -> Signature {
    generate_signature(&scalar_message_hash_to_scalar(message), secret_key)
}

/// Generates an ECDSA signature over a message that has been serialized into a sequence of bytes
/// using the provided secret key
pub fn sign_bytes_message(message: &[u8], secret_key: &Scalar) -> Signature {
    generate_signature(&bytes_message_hash_to_scalar(message), secret_key)
}

/// Verifies an ECDSA signature over a message hash using the provided public key
fn verify_signature(h: &Scalar, signature: &Signature, public_key: &StarkPoint) -> bool {
    let Signature { r, s } = signature;

    if r == &Scalar::zero() || s == &Scalar::zero() {
        return false;
    }

    let s_inv = s.inverse();
    let u1 = h * s_inv;
    let u2 = r * s_inv;
    let check_point = u1 * StarkPoint::generator() + u2 * public_key;

    if check_point.is_identity() {
        return false;
    }

    // This reduces the x coordinate of the check point modulo the scalar field order
    let check_point_x = Scalar::from_biguint(&check_point.to_affine().x.into_bigint().into());

    r == &check_point_x
}

/// Verifies an ECDSA signature over a message that has been serialized into a sequence of bytes
pub fn verify_signed_bytes_message(
    message: &[u8],
    signature: &Signature,
    public_key: &StarkPoint,
) -> bool {
    let h = bytes_message_hash_to_scalar(message);
    verify_signature(&h, signature, public_key)
}

/// Verifies an ECDSA signature over a message that has been serialized into a sequence of bytes
pub fn verify_signed_scalar_message(
    message: &[Scalar],
    signature: &Signature,
    public_key: &StarkPoint,
) -> bool {
    let h = scalar_message_hash_to_scalar(message);
    verify_signature(&h, signature, public_key)
}

#[cfg(test)]
mod tests {
    use std::iter;

    use super::*;

    #[test]
    fn test_sign_verify_bytes_message() {
        let mut rng = OsRng;

        let secret_key = Scalar::random(&mut rng);
        let public_key = secret_key * StarkPoint::generator();

        let message = b"Hello, world!";
        let signature = sign_bytes_message(message, &secret_key);
        assert!(verify_signed_bytes_message(
            message,
            &signature,
            &public_key
        ));
    }

    #[test]
    fn test_invalid_bytes_message_signature() {
        let mut rng = OsRng;

        let secret_key = Scalar::random(&mut rng);
        let public_key = secret_key * StarkPoint::generator();

        let message = b"Hello, world!";
        let mut signature = sign_bytes_message(message, &secret_key);
        signature.r += Scalar::random(&mut rng);

        assert!(!verify_signed_bytes_message(
            message,
            &signature,
            &public_key
        ));
    }

    #[test]
    fn test_sign_verify_scalar_message() {
        let mut rng = OsRng;

        let secret_key = Scalar::random(&mut rng);
        let public_key = secret_key * StarkPoint::generator();

        let message = iter::repeat(Scalar::random(&mut rng))
            .take(10)
            .collect_vec();
        let signature = sign_scalar_message(&message, &secret_key);
        assert!(verify_signed_scalar_message(
            &message,
            &signature,
            &public_key
        ));
    }

    #[test]
    fn test_invalid_scalar_message_signature() {
        let mut rng = OsRng;

        let secret_key = Scalar::random(&mut rng);
        let public_key = secret_key * StarkPoint::generator();

        let message = iter::repeat(Scalar::random(&mut rng))
            .take(10)
            .collect_vec();
        let mut signature = sign_scalar_message(&message, &secret_key);
        signature.r += Scalar::random(&mut rng);

        assert!(!verify_signed_scalar_message(
            &message,
            &signature,
            &public_key
        ));
    }
}
