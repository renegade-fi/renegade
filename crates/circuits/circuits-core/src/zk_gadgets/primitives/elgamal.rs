//! A thin wrapper around the `jf-primitives` ElGamal gadgets
//!
//! We perform EC-ElGamal over the BabyJubJub curve, which has a base field the
//! same size as the BN254 scalar field
#![allow(missing_docs)]

use ark_ec::AffineRepr;
use circuit_types::PlonkCircuit;
use circuit_types::elgamal::{
    BabyJubJubPointVar, DecryptionKeyVar, ElGamalCiphertextVar, EncryptionKeyVar,
};
use constants::EmbeddedCurveConfig;
use constants::EmbeddedCurveGroupAffine;
use jf_primitives::circuit::elgamal::{ElGamalEncryptionGadget, EncKeyVars};
use mpc_relation::{Variable, errors::CircuitError};

use super::comparators::EqGadget;

// -----------
// | Gadgets |
// -----------

/// A gadget for verifying operations in the EC-ElGamal cryptosystem over the
/// BabyJubJub curve
pub struct ElGamalGadget;

impl ElGamalGadget {
    /// Verify that a given decryption key has the given associated encryption
    /// key
    ///
    /// This can be done as a form of authorization, or PoK of decryption key
    /// without actually decrypting a ciphertext.
    ///
    /// Formally this is `k * G == P` where `k` is the decryption key, `G` is
    /// the generator of the curve, and `P` is the encryption key
    #[allow(non_snake_case)]
    pub fn verify_decryption_key(
        decryption_key: &DecryptionKeyVar,
        encryption_key: &EncryptionKeyVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // k * G
        let generator = EmbeddedCurveGroupAffine::generator();
        let kG = cs.fixed_base_scalar_mul(decryption_key.key, &generator)?;
        let kG_point = BabyJubJubPointVar::from(kG);

        EqGadget::constrain_eq(&kG_point, encryption_key, cs)
    }

    /// Encrypt a given plaintext under the key and check that it matches the
    /// given encryption
    pub fn check_ciphertext<const N: usize>(
        plaintext: &[Variable; N],
        key: &EncryptionKeyVar,
        randomness: Variable,
        expected_ciphertext: &ElGamalCiphertextVar<N>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let pk_var = EncKeyVars(key.clone().into());
        let ciphertext =
            <PlonkCircuit as ElGamalEncryptionGadget<_, EmbeddedCurveConfig>>::elgamal_encrypt(
                cs, &pk_var, plaintext, randomness,
            )?;

        let ciphertext_var = ElGamalCiphertextVar::<N>::from(ciphertext);
        EqGadget::constrain_eq(&ciphertext_var, expected_ciphertext, cs)
    }
}

/// Helpers for testing the ElGamal gadgets
#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::elgamal::{DecryptionKey, EncryptionKey};
    use jf_primitives::elgamal::KeyPair;
    use rand::thread_rng;

    /// Create a random keypair
    pub fn random_elgamal_keypair() -> (EncryptionKey, DecryptionKey) {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng);

        let enc = keypair.enc_key().into();
        let dec = keypair.dec_key().into();

        (enc, dec)
    }
}

#[cfg(test)]
mod test {
    use ark_ff::UniformRand;
    use circuit_types::{
        PlonkCircuit, elgamal::DecryptionKey, native_helpers::elgamal_encrypt,
        traits::CircuitBaseType,
    };
    use constants::{EmbeddedScalarField, Scalar};
    use itertools::Itertools;
    use mpc_relation::{Variable, traits::Circuit};
    use rand::{Rng, thread_rng};

    use super::{ElGamalGadget, test_helpers::random_elgamal_keypair};

    /// Tests the `verify_decryption_key` method
    #[test]
    fn test_verify_decryption_key() {
        let mut rng = thread_rng();

        // Correct keypair
        let (enc, dec) = random_elgamal_keypair();

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let enc_var = enc.create_witness(&mut cs);
        let dec_var = dec.create_witness(&mut cs);

        ElGamalGadget::verify_decryption_key(&dec_var, &enc_var, &mut cs).unwrap();
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());

        // Incorrect keypair
        let (enc, _) = random_elgamal_keypair();
        let dec = DecryptionKey { key: EmbeddedScalarField::rand(&mut rng) };

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let enc_var = enc.create_witness(&mut cs);
        let dec_var = dec.create_witness(&mut cs);

        ElGamalGadget::verify_decryption_key(&dec_var, &enc_var, &mut cs).unwrap();
        assert!(cs.check_circuit_satisfiability(&[]).is_err());
    }

    /// Tests the `check_ciphertext` method with a valid ciphertext
    #[test]
    #[allow(non_snake_case)]
    fn test_check_ciphertext__valid_ciphertext() {
        const N: usize = 5;
        let mut rng = thread_rng();
        let data = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        // Generate the ciphertext
        let (enc, _) = random_elgamal_keypair();
        let (cipher, randomness) = elgamal_encrypt(&data, &enc);

        // Check it in circuit
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let enc_var = enc.create_witness(&mut cs);
        let randomness_var = randomness.create_witness(&mut cs);
        let data_vars: [Variable; N] =
            data.iter().map(|d| d.create_witness(&mut cs)).collect_vec().try_into().unwrap();
        let expected_ciphertext_var = cipher.create_witness(&mut cs);

        ElGamalGadget::check_ciphertext(
            &data_vars,
            &enc_var,
            randomness_var,
            &expected_ciphertext_var,
            &mut cs,
        )
        .unwrap();

        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }

    /// Tests the `check_ciphertext` method with an invalid ciphertext
    #[test]
    #[allow(non_snake_case)]
    fn test_check_ciphertext__invalid_ciphertext() {
        const N: usize = 5;
        let mut rng = thread_rng();
        let data = (0..N).map(|_| Scalar::random(&mut rng)).collect_vec();

        // Generate the ciphertext
        let (enc, _) = random_elgamal_keypair();
        let (mut cipher, randomness) = elgamal_encrypt(&data, &enc);

        // Modify the ciphertext at a random index
        let idx = rng.gen_range(0..N);
        cipher.ciphertext[idx] = Scalar::random(&mut rng);

        // Check it in circuit
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let enc_var = enc.create_witness(&mut cs);
        let randomness_var = randomness.create_witness(&mut cs);
        let data_vars: [Variable; N] =
            data.iter().map(|d| d.create_witness(&mut cs)).collect_vec().try_into().unwrap();
        let expected_ciphertext_var = cipher.create_witness(&mut cs);

        ElGamalGadget::check_ciphertext(
            &data_vars,
            &enc_var,
            randomness_var,
            &expected_ciphertext_var,
            &mut cs,
        )
        .unwrap();

        assert!(cs.check_circuit_satisfiability(&[]).is_err());
    }
}
