//! Helpers for creating encryptions of values

use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use num_bigint::BigUint;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::fields::{biguint_to_scalar, get_ristretto_group_modulus, scalar_to_biguint};

lazy_static! {
    /// We use the generator 2 here as per the same field configured in Arkworks:
    /// https://github.com/arkworks-rs/curves/blob/master/curve25519/src/fields/fr.rs
    ///
    /// This generator is intended to be used with the Ristretto scalar field of prime
    /// order defined here:
    /// https://docs.rs/curve25519-dalek-ng/latest/curve25519_dalek_ng/scalar/index.html
    pub static ref DEFAULT_ELGAMAL_GENERATOR: Scalar = Scalar::from(2u64);
}

/// The result of creating an ElGamal encryption
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    /// The shared secret; the generator raised to the randomness
    pub partial_shared_secret: Scalar,
    /// The encrypted value; the pubkey raised to the randomness, multiplied with the message
    pub encrypted_message: Scalar,
}

/// Create an ElGamal encryption of the given value
///
/// Return both the encryption (used as a public variable) and the randomness
/// used to generate the encryption (used as a witness variable)
pub fn encrypt_scalar(val: Scalar, pubkey: &BigUint) -> (ElGamalCiphertext, Scalar) {
    let mut rng = OsRng {};
    let randomness = scalar_to_biguint(&Scalar::random(&mut rng));

    let field_mod = get_ristretto_group_modulus();
    let ciphertext1 = scalar_to_biguint(&DEFAULT_ELGAMAL_GENERATOR).modpow(&randomness, &field_mod);
    let shared_secret = pubkey.modpow(&randomness, &field_mod);

    let encrypted_message = (shared_secret * scalar_to_biguint(&val)) % &field_mod;

    (
        ElGamalCiphertext {
            partial_shared_secret: biguint_to_scalar(&ciphertext1),
            encrypted_message: biguint_to_scalar(&encrypted_message),
        },
        biguint_to_scalar(&randomness),
    )
}
