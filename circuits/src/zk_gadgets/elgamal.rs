//! Implements the ZK gadgetry for ElGamal encryption

use crypto::elgamal::ElGamalCiphertext;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use lazy_static::lazy_static;
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Variable, Verifier,
    },
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit,
};

use super::arithmetic::PrivateExpGadget;

lazy_static! {
    /// We use the generator 2 here as per the same field configured in Arkworks:
    /// https://github.com/arkworks-rs/curves/blob/master/curve25519/src/fields/fr.rs
    ///
    /// This generator is intended to be used with the Ristretto scalar field of prime
    /// order defined here:
    /// https://docs.rs/curve25519-dalek-ng/latest/curve25519_dalek_ng/scalar/index.html
    pub static ref DEFAULT_ELGAMAL_GENERATOR: Scalar = Scalar::from(2u64);
}

/// Implements an ElGamal gadget that verifies encryption of some plaintext under a private key
#[derive(Clone, Debug)]
pub struct ElGamalGadget<const SCALAR_BITS: usize> {}

impl<const SCALAR_BITS: usize> ElGamalGadget<SCALAR_BITS> {
    /// Encrypts the given value with the given key and randomness in the constraint system
    pub fn encrypt<L, CS>(
        generator: Scalar,
        randomness: L,
        plaintext: L,
        pub_key: L,
        cs: &mut CS,
    ) -> Result<(LinearCombination, LinearCombination), R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Take the generator raised to the randomness, so that the secret key holder may
        // reconstruct the shared secret
        let ciphertext1 = PrivateExpGadget::<SCALAR_BITS>::exp_private_fixed_base(
            generator,
            randomness.clone(),
            cs,
        )?;

        // Raise the public key to the randomness and use this to encrypt the value
        let partial_shared_secret =
            PrivateExpGadget::<SCALAR_BITS>::exp_private(pub_key, randomness, cs)?;

        // Blind the plaintext using the shared secret
        let (_, _, blinded_plaintext) = cs.multiply(partial_shared_secret, plaintext.into());

        Ok((ciphertext1, blinded_plaintext.into()))
    }
}

/// An ElGamal ciphertext that has been allocated in a constraint system
#[derive(Copy, Clone, Debug)]
pub struct ElGamalCiphertextVar {
    /// The shared secret; the generator raised to the randomness
    pub partial_shared_secret: Variable,
    /// The encrypted value; the pubkey raised to the randomness, multiplied with the message
    pub encrypted_message: Variable,
}

/// An ElGamal ciphertext that has been committed to by a prover
#[derive(Clone, Debug)]
pub struct ElGamalCiphertextCommitment {
    /// The shared secret; the generator raised to the randomness
    pub partial_shared_secret: CompressedRistretto,
    /// The encrypted value; the pubkey raised to the randomness, multiplied with the message
    pub encrypted_message: CompressedRistretto,
}

impl CommitWitness for ElGamalCiphertext {
    type VarType = ElGamalCiphertextVar;
    type CommitType = ElGamalCiphertextCommitment;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (partial_shared_secret_comm, partial_shared_secret_var) =
            prover.commit(self.partial_shared_secret, Scalar::random(rng));
        let (encrypted_message_comm, encrypted_message_var) =
            prover.commit(self.encrypted_message, Scalar::random(rng));

        Ok((
            ElGamalCiphertextVar {
                partial_shared_secret: partial_shared_secret_var,
                encrypted_message: encrypted_message_var,
            },
            ElGamalCiphertextCommitment {
                partial_shared_secret: partial_shared_secret_comm,
                encrypted_message: encrypted_message_comm,
            },
        ))
    }
}

impl CommitPublic for ElGamalCiphertext {
    type VarType = ElGamalCiphertextVar;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let partial_shared_secret_var = self.partial_shared_secret.commit_public(cs).unwrap();
        let encrypted_message_var = self.encrypted_message.commit_public(cs).unwrap();

        Ok(ElGamalCiphertextVar {
            partial_shared_secret: partial_shared_secret_var,
            encrypted_message: encrypted_message_var,
        })
    }
}

impl CommitVerifier for ElGamalCiphertextCommitment {
    type VarType = ElGamalCiphertextVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let partial_shared_secret_var = verifier.commit(self.partial_shared_secret);
        let encrypted_message_var = verifier.commit(self.encrypted_message);

        Ok(ElGamalCiphertextVar {
            partial_shared_secret: partial_shared_secret_var,
            encrypted_message: encrypted_message_var,
        })
    }
}

/// A witness for the ElGamal encryption circuit; containing the randomness and the plaintext
#[derive(Clone, Debug)]
pub struct ElGamalWitness {
    /// The randomness used to create the shared secret
    pub randomness: Scalar,
    /// The plaintext message encrypted under the key
    pub plaintext: Scalar,
}

/// A statement for the ElGamal encryption circuit; holds the group parameterization and the
/// expected ciphertext
#[derive(Clone, Debug)]
pub struct ElGamalStatement {
    /// The public key that the value is encrypted under
    pub pub_key: Scalar,
    /// The generator of the group that the circuit is defined over
    pub generator: Scalar,
    /// The expected result of encrypting the secret under the pubkey
    pub expected_ciphertext: (Scalar, Scalar),
}

/// An ElGamal witness that has been allocated within a constraint system
#[derive(Clone, Debug)]
pub struct ElGamalWitnessVar {
    /// The randomness used to create the shared secret
    pub randomness: Variable,
    /// The plaintext message encrypted under the key
    pub plaintext: Variable,
}

/// A commitment to an ElGamal witness
#[derive(Clone, Debug)]
pub struct ElGamalWitnessCommitment {
    /// The randomness used to create the shared secret
    pub randomness: CompressedRistretto,
    /// The plaintext message encrypted under the key
    pub plaintext: CompressedRistretto,
}

impl CommitWitness for ElGamalWitness {
    type CommitType = ElGamalWitnessCommitment;
    type VarType = ElGamalWitnessVar;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (randomness_comm, randomness_var) = prover.commit(self.randomness, Scalar::random(rng));
        let (plaintext_comm, plaintext_var) = prover.commit(self.plaintext, Scalar::random(rng));

        Ok((
            ElGamalWitnessVar {
                randomness: randomness_var,
                plaintext: plaintext_var,
            },
            ElGamalWitnessCommitment {
                randomness: randomness_comm,
                plaintext: plaintext_comm,
            },
        ))
    }
}

impl CommitVerifier for ElGamalWitnessCommitment {
    type VarType = ElGamalWitnessVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let randomness_var = verifier.commit(self.randomness);
        let plaintext_var = verifier.commit(self.plaintext);

        Ok(ElGamalWitnessVar {
            randomness: randomness_var,
            plaintext: plaintext_var,
        })
    }
}

impl<const SCALAR_BITS: usize> SingleProverCircuit for ElGamalGadget<SCALAR_BITS> {
    type Witness = ElGamalWitness;
    type WitnessCommitment = ElGamalWitnessCommitment;
    type Statement = ElGamalStatement;

    const BP_GENS_CAPACITY: usize = 1024;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();

        // Commit to the statement
        let pub_key_var = prover.commit_public(statement.pub_key);
        let expected_ciphertext_var = (
            prover.commit_public(statement.expected_ciphertext.0),
            prover.commit_public(statement.expected_ciphertext.1),
        );

        // Apply the constraints
        let res = Self::encrypt(
            statement.generator,
            witness_var.randomness,
            witness_var.plaintext,
            pub_key_var,
            &mut prover,
        )
        .map_err(ProverError::R1CS)?;

        prover.constrain(res.0 - expected_ciphertext_var.0);
        prover.constrain(res.1 - expected_ciphertext_var.1);

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the witness
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

        // Commit to the statement
        let pub_key_var = verifier.commit_public(statement.pub_key);
        let expected_ciphertext_var = (
            verifier.commit_public(statement.expected_ciphertext.0),
            verifier.commit_public(statement.expected_ciphertext.1),
        );

        // Apply the constraints
        let res = Self::encrypt(
            statement.generator,
            witness_var.randomness,
            witness_var.plaintext,
            pub_key_var,
            &mut verifier,
        )
        .map_err(VerifierError::R1CS)?;

        verifier.constrain(res.0 - expected_ciphertext_var.0);
        verifier.constrain(res.1 - expected_ciphertext_var.1);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

#[cfg(test)]
mod elgamal_tests {
    use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
    use curve25519_dalek::scalar::Scalar;
    use integration_helpers::mpc_network::field::get_ristretto_group_modulus;
    use num_bigint::BigUint;
    use rand_core::{OsRng, RngCore};

    use crate::test_helpers::bulletproof_prove_and_verify;

    use super::{ElGamalGadget, ElGamalStatement, ElGamalWitness};

    /// Test the ElGamal encryption gadget on a valid ciphertext
    #[test]
    fn test_valid_ciphertext() {
        // Create a random cipher
        let mut rng = OsRng {};
        let randomness_bitlength = 16;
        let mut randomness_bytes = vec![0u8; randomness_bitlength / 8];
        rng.fill_bytes(&mut randomness_bytes);

        let randomness = biguint_to_scalar(&BigUint::from_bytes_le(&randomness_bytes));
        let plaintext = Scalar::random(&mut rng);

        let pubkey = Scalar::random(&mut rng);
        let generator = Scalar::from(3u64);

        // Generate the expected encryption
        let field_mod = get_ristretto_group_modulus();
        let generator_bigint = scalar_to_biguint(&generator);
        let pubkey_bigint = scalar_to_biguint(&pubkey);
        let randomness_bigint = scalar_to_biguint(&randomness);
        let plaintext_bigint = scalar_to_biguint(&plaintext);

        let ciphertext_1 = generator_bigint.modpow(&randomness_bigint, &field_mod);
        let partial_shared_secret = pubkey_bigint.modpow(&randomness_bigint, &field_mod);
        let ciphertext_2 = (partial_shared_secret * plaintext_bigint) % &field_mod;

        // Prove the statement
        let witness = ElGamalWitness {
            randomness,
            plaintext,
        };
        let statement = ElGamalStatement {
            pub_key: pubkey,
            generator,
            expected_ciphertext: (
                biguint_to_scalar(&ciphertext_1),
                biguint_to_scalar(&ciphertext_2),
            ),
        };

        let res = bulletproof_prove_and_verify::<ElGamalGadget<16>>(witness, statement);
        assert!(res.is_ok());
    }

    /// Tests the ElGamal gadget with an invalid ciphertext
    #[test]
    fn test_invalid_ciphertext() {
        // Create a random cipher
        let mut rng = OsRng {};
        let randomness_bitlength = 16;
        let mut randomness_bytes = vec![0u8; randomness_bitlength / 8];
        rng.fill_bytes(&mut randomness_bytes);

        let randomness = biguint_to_scalar(&BigUint::from_bytes_le(&randomness_bytes));
        let plaintext = Scalar::random(&mut rng);

        let pubkey = Scalar::random(&mut rng);
        let generator = Scalar::from(3u64);

        // Generate the expected encryption
        let expected_ciphertext = (Scalar::random(&mut rng), Scalar::random(&mut rng));

        // Prove the statement
        let witness = ElGamalWitness {
            randomness,
            plaintext,
        };
        let statement = ElGamalStatement {
            pub_key: pubkey,
            generator,
            expected_ciphertext,
        };

        let res = bulletproof_prove_and_verify::<ElGamalGadget<16>>(witness, statement);
        assert!(res.is_err());
    }
}
