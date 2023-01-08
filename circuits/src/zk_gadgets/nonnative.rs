//! Groups gadget definitions for non-native field arithmetic

use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use lazy_static::lazy_static;
use mpc_bulletproof::r1cs::{RandomizableConstraintSystem, Variable};
use num_bigint::BigUint;

/// The number of bits in each word, we use 126 to ensure that
/// multiplications in the base field (dalek `Scalar`s) will not
/// overflow
const WORD_SIZE: usize = 126;

lazy_static! {
    static ref BIGINT_ZERO: BigUint = BigUint::from(0u8);
    static ref BIGINT_2_TO_WORD_SIZE: BigUint = BigUint::from(1u8) << 126;
    static ref BIGINT_WORD_MASK: BigUint = &*BIGINT_2_TO_WORD_SIZE - 1u8;
}

/// Represents an element of a non-native field that has
/// been allocated in a constraint system
///
/// We model the underlying field element as a series of `Scalar`
/// values, denoted "words". The word width here is 126 bits; a
/// Scalar is natively capable of performing arithmetic on elements
/// of F_p where p is slightly larger than 2^252, so using the
/// first 126 bits ensures that arithmetic does not overflow in the
/// base field
#[derive(Clone, Debug)]
pub struct NonNativeElementVar {
    /// The words representing the underlying field
    /// stored in little endian order
    words: Vec<Variable>,
    /// The prime-power modulus of the field
    field_mod: BigUint,
}

impl NonNativeElementVar {
    /// Create a new value from a given bigint
    pub fn new<CS: RandomizableConstraintSystem>(
        mut value: BigUint,
        field_mod: BigUint,
        cs: &mut CS,
    ) -> Self {
        // Ensure that the value is in the field
        value %= &field_mod;

        // Split into words
        let mut words = Vec::with_capacity((value.bits() as usize) / WORD_SIZE + 1);
        while value > BigUint::from(0u8) {
            // Allocate the next 126 bits in the constraint system
            let next_word = biguint_to_scalar(&(&value & &*BIGINT_WORD_MASK));
            let word_var = cs.allocate(Some(next_word)).unwrap();
            words.push(word_var);

            value >>= WORD_SIZE;
        }

        Self { words, field_mod }
    }

    /// Evalute the non-native variable in the given constraint system, and return the
    /// result as a bigint
    pub fn as_bigint<CS: RandomizableConstraintSystem>(&self, cs: &CS) -> BigUint {
        let mut res = BigUint::from(0u8);
        for word in self.words.iter().rev().cloned() {
            // Evaluate the underlying scalar representation of the word
            let word_bigint = scalar_to_biguint(&cs.eval(&word.into()));
            res = (res << WORD_SIZE) + word_bigint
        }

        res
    }
}

#[cfg(test)]
mod nonnative_tests {
    use merlin::Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use num_bigint::BigUint;
    use rand_core::{CryptoRng, OsRng, RngCore};

    use super::NonNativeElementVar;

    // -------------
    // | Constants |
    // -------------

    /// The seed for the prover/verifier transcripts
    const TRANSCRIPT_SEED: &str = "test";

    // -----------
    // | Helpers |
    // -----------

    /// Samples a random 512-bit bigint
    fn random_biguint<R: RngCore + CryptoRng>(rng: &mut R) -> BigUint {
        let bytes = &mut [0u8; 32];
        rng.fill_bytes(bytes);
        BigUint::from_bytes_le(bytes)
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests converting to and from a biguint
    #[test]
    fn test_to_from_biguint() {
        let n_tests = 100;
        let mut rng = OsRng {};

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Sample a random biguint and field modulus, convert to and from
            // non-native, and assert equality
            let random_elem = random_biguint(&mut rng);
            let random_mod = random_biguint(&mut rng);
            let expected_bigint = &random_elem % &random_mod;

            let nonnative_elem = NonNativeElementVar::new(random_elem, random_mod, &mut prover);
            assert_eq!(nonnative_elem.as_bigint(&prover), expected_bigint);
        }
    }
}
