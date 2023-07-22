//! Helpers for creating encryptions of values

use lazy_static::lazy_static;
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::BigUint;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::fields::{biguint_to_scalar, get_scalar_field_modulus, scalar_to_biguint};

lazy_static! {
    /// We use the generator 2 here as per the same field configured in Arkworks:
    /// https://github.com/arkworks-rs/curves/blob/master/curve25519/src/fields/fr.rs
    ///
    /// This generator is intended to be used with the Ristretto scalar field of prime
    /// order defined here:
    /// https://docs.rs/curve25519-dalek-ng/latest/curve25519_dalek_ng/scalar/index.html
    pub static ref DEFAULT_ELGAMAL_GENERATOR: Scalar = Scalar::from(2u64);
    /// A bigint version of the above generator
    pub static ref DEFAULT_ELGAMAL_GENERATOR_BIGUINT: BigUint = scalar_to_biguint(&DEFAULT_ELGAMAL_GENERATOR);
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
    let mut rng = thread_rng();
    let randomness = &Scalar::random(&mut rng).to_biguint();

    let field_mod = get_scalar_field_modulus();
    let ciphertext1 = DEFAULT_ELGAMAL_GENERATOR_BIGUINT.modpow(randomness, &field_mod);
    let shared_secret = pubkey.modpow(randomness, &field_mod);

    let encrypted_message = (shared_secret * scalar_to_biguint(&val)) % &field_mod;

    (
        ElGamalCiphertext {
            partial_shared_secret: biguint_to_scalar(&ciphertext1),
            encrypted_message: biguint_to_scalar(&encrypted_message),
        },
        biguint_to_scalar(randomness),
    )
}

/// Decrypt an ElGamal encrypted scalar using the given private key
pub fn decrypt_scalar(cipher: ElGamalCiphertext, secret_key: &BigUint) -> Scalar {
    let field_mod = get_scalar_field_modulus();
    let partial_shared_secret_biguint = scalar_to_biguint(&cipher.partial_shared_secret);
    let shared_secret = partial_shared_secret_biguint.modpow(secret_key, &field_mod);

    let shared_secret_scalar = biguint_to_scalar(&shared_secret);

    shared_secret_scalar.inverse() * cipher.encrypted_message
}

#[cfg(test)]
mod tests {
    use mpc_stark::algebra::scalar::Scalar;
    use rand::thread_rng;

    use crate::fields::{get_scalar_field_modulus, scalar_to_biguint};

    use super::{decrypt_scalar, encrypt_scalar, DEFAULT_ELGAMAL_GENERATOR_BIGUINT};

    /// Generates a random keypair and encrypts a random scalar under this keypair
    /// decrypts the ciphertext and verifies that the decryption succeeded
    #[test]
    fn test_random_keypair_and_ciphertext() {
        let mut rng = thread_rng();
        let modulus = get_scalar_field_modulus();
        let secret_key = scalar_to_biguint(&Scalar::random(&mut rng));
        let public_key = DEFAULT_ELGAMAL_GENERATOR_BIGUINT.modpow(&secret_key, &modulus);

        let plaintext = Scalar::random(&mut rng);
        let (ciphertext, _) = encrypt_scalar(plaintext, &public_key);
        let recovered_plaintext = decrypt_scalar(ciphertext, &secret_key);

        assert_eq!(recovered_plaintext, plaintext);
    }
}
