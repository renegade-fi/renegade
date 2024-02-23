//! A thin wrapper around the `jf-primitives` ElGamal gadgets
//!
//! We perform EC-ElGamal over the BabyJubJub curve, which has a base field the
//! same size as the BN254 scalar field
#![allow(missing_docs)]

use ark_ec::AffineRepr;
use circuit_types::{
    keychain::{BabyJubJubPointVar, DecryptionKeyVar, EncryptionKeyVar},
    PlonkCircuit,
};
use constants::EmbeddedCurveGroupAffine;
use mpc_relation::errors::CircuitError;

use super::comparators::EqGadget;

// ---------
// | Types |
// ---------

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
    /// without actually decrypting the ciphertext.
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
        let gen = EmbeddedCurveGroupAffine::generator();
        let kG = cs.fixed_base_scalar_mul(decryption_key.key, &gen)?;
        let kG_point = BabyJubJubPointVar::from(kG);

        EqGadget::constrain_eq(&kG_point, encryption_key, cs)
    }
}

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    //! Test helpers for the ElGamal gadgets

    use circuit_types::keychain::{DecryptionKey, EncryptionKey};
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
    use circuit_types::{keychain::DecryptionKey, traits::CircuitBaseType, PlonkCircuit};
    use constants::EmbeddedScalarField;
    use mpc_relation::traits::Circuit;
    use rand::thread_rng;

    use super::{test_helpers::random_elgamal_keypair, ElGamalGadget};

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
}
