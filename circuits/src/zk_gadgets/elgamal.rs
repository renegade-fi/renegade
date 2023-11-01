//! Implements the ZK gadgetry for ElGamal encryption
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_macros::circuit_type;
use circuit_types::traits::{
    BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
};
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::R1CSError,
};
use mpc_stark::algebra::scalar::Scalar;
use mpc_stark::algebra::stark_curve::StarkPoint;
use rand::{CryptoRng, RngCore};

use super::arithmetic::PrivateExpGadget;

/// Implements an ElGamal gadget that verifies encryption of some plaintext
/// under a private key
#[derive(Clone, Debug)]
pub struct ElGamalGadget<const SCALAR_BITS: usize> {}

impl<const SCALAR_BITS: usize> ElGamalGadget<SCALAR_BITS> {
    /// Encrypts the given value with the given key and randomness in the
    /// constraint system
    pub fn encrypt<L, CS>(
        generator: Scalar,
        randomness: L,
        plaintext: L,
        pub_key: L,
        cs: &mut CS,
    ) -> Result<ElGamalCiphertextVar<LinearCombination>, R1CSError>
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Take the generator raised to the randomness, so that the secret key holder
        // may reconstruct the shared secret
        let partial_shared_secret = PrivateExpGadget::<SCALAR_BITS>::exp_private_fixed_base(
            generator,
            randomness.clone(),
            cs,
        )?;

        // Raise the public key to the randomness and use this to encrypt the value
        let shared_secret = PrivateExpGadget::<SCALAR_BITS>::exp_private(pub_key, randomness, cs)?;

        // Blind the plaintext using the shared secret
        let (_, _, blinded_plaintext) = cs.multiply(shared_secret, plaintext.into());
        Ok(ElGamalCiphertextVar {
            partial_shared_secret,
            encrypted_message: blinded_plaintext.into(),
        })
    }
}

/// The result of creating an ElGamal encryption
#[circuit_type(singleprover_circuit)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ElGamalCiphertext {
    /// The partial shared secret; the generator raised to the randomness
    pub partial_shared_secret: Scalar,
    /// The encrypted value; the pubkey raised to the randomness, multiplied
    /// with the message
    pub encrypted_message: Scalar,
}

#[cfg(test)]
mod elgamal_tests {
    use circuit_types::traits::CircuitBaseType;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use mpc_stark::algebra::scalar::Scalar;
    use num_bigint::BigUint;
    use rand::{thread_rng, RngCore};
    use renegade_crypto::fields::{biguint_to_scalar, get_scalar_field_modulus, scalar_to_biguint};

    use crate::zk_gadgets::comparators::EqGadget;

    use super::{ElGamalCiphertext, ElGamalGadget};

    /// Test the ElGamal encryption gadget on a valid ciphertext
    #[test]
    fn test_encrypt() {
        // Create a random cipher
        let mut rng = thread_rng();
        let randomness_bitlength = 16;
        let mut randomness_bytes = vec![0u8; randomness_bitlength / 8];
        rng.fill_bytes(&mut randomness_bytes);

        let randomness = biguint_to_scalar(&BigUint::from_bytes_le(&randomness_bytes));
        let plaintext = Scalar::random(&mut rng);

        let pubkey = Scalar::random(&mut rng);
        let generator = Scalar::from(3u64);

        // Generate the expected encryption
        let field_mod = get_scalar_field_modulus();
        let generator_bigint = scalar_to_biguint(&generator);
        let pubkey_bigint = scalar_to_biguint(&pubkey);
        let randomness_bigint = scalar_to_biguint(&randomness);
        let plaintext_bigint = scalar_to_biguint(&plaintext);

        let ciphertext_1 = generator_bigint.modpow(&randomness_bigint, &field_mod);
        let partial_shared_secret = pubkey_bigint.modpow(&randomness_bigint, &field_mod);
        let ciphertext_2 = (&partial_shared_secret * &plaintext_bigint) % &field_mod;

        let expected_ciphertext = ElGamalCiphertext {
            partial_shared_secret: biguint_to_scalar(&ciphertext_1),
            encrypted_message: biguint_to_scalar(&ciphertext_2),
        };

        // Create a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let randomness_var = randomness.commit_public(&mut prover);
        let plaintext_var = plaintext.commit_public(&mut prover);
        let pubkey_var = pubkey.commit_public(&mut prover);

        let res = ElGamalGadget::<16 /* SCALAR_BITS */>::encrypt(
            generator,
            randomness_var,
            plaintext_var,
            pubkey_var,
            &mut prover,
        )
        .unwrap();

        // Check that the result equals the expected
        let expected = expected_ciphertext.commit_public(&mut prover);

        EqGadget::constrain_eq(res, expected, &mut prover);
        assert!(prover.constraints_satisfied());
    }
}
