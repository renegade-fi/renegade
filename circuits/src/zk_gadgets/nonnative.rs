//! Groups gadget definitions for non-native field arithmetic

use std::{cmp::max, iter};

use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::scalar::Scalar;
use lazy_static::lazy_static;
use mpc_bulletproof::r1cs::{LinearCombination, RandomizableConstraintSystem, Variable};
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

/// Returns the maximum number of words needed to represent an element from
/// a field of the given modulus
fn words_for_field(modulus: &BigUint) -> usize {
    let word_size_u64 = WORD_SIZE as u64;
    if modulus.bits() % word_size_u64 == 0 {
        (modulus.bits() / word_size_u64) as usize
    } else {
        (modulus.bits() / word_size_u64) as usize + 1
    }
}

/// Reduce the given value to the size of a single word, returning the
/// quotient and remainder
///
/// It is assumed that the value is less than two words in size, so that
/// we can properly constrain the modulus. This check is asserted for
fn div_rem_word<L, CS>(val: L, modulus: &BigUint, cs: &mut CS) -> (Variable, Variable)
where
    L: Into<LinearCombination>,
    CS: RandomizableConstraintSystem,
{
    // Evaluate the underlying linear combination to get a bigint that we can operate on
    let val_lc = val.into();
    let val_bigint = scalar_to_biguint(&cs.eval(&val_lc));

    assert!(
        val_bigint.bits() < (2 * WORD_SIZE) as u64,
        "value too large for div_rem_word"
    );

    let div_bigint = &val_bigint / modulus;
    let rem_bigint = &val_bigint % modulus;

    let div_var = cs.allocate(Some(biguint_to_scalar(&div_bigint))).unwrap();
    let rem_var = cs.allocate(Some(biguint_to_scalar(&rem_bigint))).unwrap();

    let mod_scalar = biguint_to_scalar(modulus);

    // Constrain the modulus to be correct, i.e. dividend = quotient * divisor + remainder
    cs.constrain(val_lc - mod_scalar * div_var + rem_var);

    // Because we are assuming that `val` can fit into at most two words, we constrain the
    // quotient to be either 0 (fits into one word) or 1 (fits into one quotient word and the remainder)
    // We constrain this with the identity x(1-x) which is 0 for binary values only
    let (_, _, mul_var) = cs.multiply(div_var.into(), Variable::One() - div_var);
    cs.constrain(mul_var.into());

    (div_var, rem_var)
}

/// Convert a `BigUint` to a list of scalar words
fn bigint_to_scalar_words(mut val: BigUint) -> Vec<Scalar> {
    let mut words = Vec::new();
    while val.gt(&BIGINT_ZERO) {
        // Compute the next word and shift the input
        let next_word = biguint_to_scalar(&(&val & &*BIGINT_WORD_MASK));
        words.push(next_word);
        val >>= WORD_SIZE;
    }

    words
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
    pub(super) words: Vec<Variable>,
    /// The prime-power modulus of the field
    pub(super) field_mod: BigUint,
}

impl NonNativeElementVar {
    /// Create a new value given a set of pre-allocated words
    pub fn new(mut words: Vec<Variable>, field_mod: BigUint) -> Self {
        let field_words = words_for_field(&field_mod);
        words.append(&mut vec![Variable::Zero(); field_words - words.len()]);
        Self { words, field_mod }
    }

    /// Create a new value from a given bigint
    pub fn from_bigint<CS: RandomizableConstraintSystem>(
        mut value: BigUint,
        field_mod: BigUint,
        cs: &mut CS,
    ) -> Self {
        // Ensure that the value is in the field
        value %= &field_mod;

        // Split into words
        let field_words = words_for_field(&field_mod);
        let mut words = Vec::with_capacity(field_words);
        for _ in 0..field_words {
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

    /// Constrain two non-native field elements to equal one another
    pub fn constrain_equal<CS: RandomizableConstraintSystem>(lhs: &Self, rhs: &Self, cs: &mut CS) {
        assert_eq!(lhs.words.len(), rhs.words.len(), "inequal word widths");

        // Compare each word in the non-native element
        for (lhs_word, rhs_word) in lhs.words.iter().zip(rhs.words.iter()) {
            cs.constrain(*lhs_word - *rhs_word);
        }
    }

    /// Reduce the given element modulo its field
    pub fn reduce<CS: RandomizableConstraintSystem>(&mut self, cs: &mut CS) {
        // Convert to bigint for reduction
        let self_bigint = self.as_bigint(cs);
        let div_bigint = &self_bigint / &self.field_mod;
        let mod_bigint = &self_bigint % &self.field_mod;

        let div_nonnative =
            NonNativeElementVar::from_bigint(div_bigint, self.field_mod.clone(), cs);
        let mod_nonnative =
            NonNativeElementVar::from_bigint(mod_bigint, self.field_mod.clone(), cs);

        // Constrain the values to be a correct modulus
        let div_mod_mul = Self::mul_bigint_unreduced(&div_nonnative, &self.field_mod, cs);
        let reconstructed = Self::add_unreduced(&div_mod_mul, &mod_nonnative, cs);

        Self::constrain_equal(self, &reconstructed, cs);

        // Finally, update self to the correct modulus
        self.words = mod_nonnative.words;
    }

    /// Add together two non-native field elements
    pub fn add<CS: RandomizableConstraintSystem>(lhs: &Self, rhs: &Self, cs: &mut CS) -> Self {
        let mut new_elem = Self::add_unreduced(lhs, rhs, cs);
        new_elem.reduce(cs);

        new_elem
    }

    /// Add together two non-native field elements without reducing the sum
    fn add_unreduced<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: &Self,
        cs: &mut CS,
    ) -> Self {
        // Ensure that both non-native elements are of the same field
        assert_eq!(
            lhs.field_mod, rhs.field_mod,
            "elements from different fields"
        );

        // Add word by word with carry
        let mut carry = Variable::Zero();
        let field_words = words_for_field(&lhs.field_mod);
        let mut new_words = Vec::with_capacity(field_words);
        for i in 0..field_words {
            // Compute the word-wise sum and reduce to fit into a single word
            let word_res = lhs.words[i] + rhs.words[i] + carry;
            let div_rem = div_rem_word(word_res, &BIGINT_2_TO_WORD_SIZE, cs);

            carry = div_rem.0;
            new_words.push(div_rem.1);
        }
        new_words.push(carry);

        // Collect this into a new non-native element and reduce it
        NonNativeElementVar {
            words: new_words,
            field_mod: lhs.field_mod.clone(),
        }
    }

    /// Add together a non-native field element and a bigint
    pub fn add_bigint<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: &BigUint,
        cs: &mut CS,
    ) -> Self {
        let mut res = Self::add_bigint_unreduced(lhs, rhs, cs);
        res.reduce(cs);
        res
    }

    /// Add together a non-native field element and a bigint without reducing the sum
    fn add_bigint_unreduced<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: &BigUint,
        cs: &mut CS,
    ) -> Self {
        // Convert the rhs to a list of words
        let mut rhs_words = bigint_to_scalar_words(rhs.clone());
        if rhs_words.len() < lhs.words.len() {
            rhs_words.append(&mut vec![Scalar::zero(); lhs.words.len() - rhs_words.len()]);
        }

        // Resize the lhs and rhs word iterators to be of equal size
        let lhs_word_iterator =
            lhs.words.iter().cloned().chain(
                iter::repeat(Variable::Zero()).take(max(0, rhs_words.len() - lhs.words.len())),
            );
        let rhs_word_iterator = rhs_words
            .iter()
            .cloned()
            .chain(iter::repeat(Scalar::zero()).take(max(0, lhs.words.len() - rhs_words.len())));

        // Add the two non-native elements word-wise
        let field_words = words_for_field(&lhs.field_mod);
        let mut carry = Variable::Zero();
        let mut new_words = Vec::with_capacity(field_words);
        for (lhs_word, rhs_word) in lhs_word_iterator.zip(rhs_word_iterator) {
            let word_res = lhs_word + rhs_word + carry;
            let div_rem = div_rem_word(word_res, &BIGINT_2_TO_WORD_SIZE, cs);

            new_words.push(div_rem.1);
            carry = div_rem.0;
        }
        new_words.push(carry);

        Self {
            words: new_words,
            field_mod: lhs.field_mod.clone(),
        }
    }

    /// Multiply together two non-native field elements
    pub fn mul<CS: RandomizableConstraintSystem>(lhs: &Self, rhs: &Self, cs: &mut CS) -> Self {
        let mut res = Self::mul_unreduced(lhs, rhs, cs);
        res.reduce(cs);
        res
    }

    /// Multiply together two non-native field elements without reducing the product
    fn mul_unreduced<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: &Self,
        cs: &mut CS,
    ) -> Self {
        assert_eq!(
            lhs.field_mod, rhs.field_mod,
            "elements from different fields"
        );
        let field_words = words_for_field(&lhs.field_mod);

        // Both lhs and rhs are represented as:
        //  x = x_1 + 2^WORD_SIZE * x_2 + ... + 2^(num_words * WORD_SIZE) * x_num_words
        // To multiply the values, we take the direct product of each pair of terms
        // between `lhs` and `rhs`, storing both the term and the carry from reducing
        // each term in one of the buckets below; depending on the shift (2^k) applied
        // to the result
        //
        // The maximum shift is 2^{2 * num_words} as (2^k - 1)(2^k - 1) = 2^2k - 2^{k+1} - 1 < 2^2k
        let mut terms = vec![Vec::new(); 2 * field_words];
        let mut carries = vec![Vec::new(); 2 * field_words];

        for lhs_index in 0..field_words {
            for rhs_index in 0..field_words {
                // Compute the term and reduce it modulo the field
                let (_, _, term_direct_product) =
                    cs.multiply(lhs.words[lhs_index].into(), rhs.words[rhs_index].into());
                let (term_carry, term) = div_rem_word(term_direct_product, &lhs.field_mod, cs);

                // Place the term and the carry in the shift bin corresponding to the value k such that
                // this term is prefixed with 2^k in the expanded representation described above
                let shift_index = lhs_index + rhs_index;
                terms[shift_index].push(term);
                carries[shift_index + 1].push(term_carry);
            }
        }

        // Now reduce each term into a single word
        let mut carry = Variable::Zero();
        let mut res_words = Vec::with_capacity(field_words);
        for word_index in 0..field_words {
            // Sum all the terms and carries at the given word index
            let mut summed_word: LinearCombination = carry.into();
            for word_term in terms[word_index].iter().chain(carries[word_index].iter()) {
                summed_word += *word_term;
            }

            // Reduce this sum and add any carry to the next term's carries
            let div_rem_res = div_rem_word(summed_word, &lhs.field_mod, cs);
            carry = div_rem_res.0;
            res_words.push(div_rem_res.1);
        }

        Self {
            words: res_words,
            field_mod: lhs.field_mod.clone(),
        }
    }

    /// Multiply together a non-native field element and a bigint
    pub fn mul_bigint<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: &BigUint,
        cs: &mut CS,
    ) -> Self {
        let mut res = Self::mul_bigint_unreduced(lhs, rhs, cs);
        res.reduce(cs);
        res
    }

    /// Multiply together a non-native field element and a bigint without reducing to the field modulus
    fn mul_bigint_unreduced<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: &BigUint,
        cs: &mut CS,
    ) -> Self {
        // Split the BigUint into words
        let rhs_words = bigint_to_scalar_words(rhs.clone());
        let n_result_words = rhs_words.len() * lhs.words.len();

        // Both lhs and rhs are represented as:
        //  x = x_1 + 2^WORD_SIZE * x_2 + ... + 2^(num_words * WORD_SIZE) * x_num_words
        // To multiply the values, we take the direct product of each pair of terms
        // between `lhs` and `rhs`, storing both the term and the carry from reducing
        // each term in one of the buckets below; depending on the shift (2^k) applied
        // to the result
        //
        // The maximum shift is 2^{2 * num_words} as (2^k - 1)(2^k - 1) = 2^2k - 2^{k+1} - 1 < 2^2k
        let mut terms = vec![Vec::new(); n_result_words];
        let mut carries = vec![Vec::new(); n_result_words];

        for (lhs_index, lhs_word) in lhs.words.iter().enumerate() {
            for (rhs_index, rhs_word) in rhs_words.iter().enumerate() {
                // Compute the term and reduce it modulo the field
                let term_direct_product = *lhs_word * *rhs_word;
                let (term_carry, term) = div_rem_word(term_direct_product, &lhs.field_mod, cs);

                // Place the term and the carry in the shift bin corresponding to the value k such that
                // this term is prefixed with 2^k in the expanded representation described above
                let shift_index = lhs_index + rhs_index;
                terms[shift_index].push(term);
                carries[shift_index + 1].push(term_carry);
            }
        }

        // Now reduce each term into a single word
        let mut carry = Variable::Zero();
        let mut res_words = Vec::with_capacity(n_result_words);
        for word_index in 0..n_result_words {
            // Sum all the terms and carries at the given word index
            let mut summed_word: LinearCombination = carry.into();
            for word_term in terms[word_index].iter().chain(carries[word_index].iter()) {
                summed_word += *word_term;
            }

            // Reduce this sum and add any carry to the next term's carries
            let div_rem_res = div_rem_word(summed_word, &lhs.field_mod, cs);
            carry = div_rem_res.0;
            res_words.push(div_rem_res.1);
        }

        Self {
            words: res_words,
            field_mod: lhs.field_mod.clone(),
        }
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

            let nonnative_elem =
                NonNativeElementVar::from_bigint(random_elem, random_mod, &mut prover);
            assert_eq!(nonnative_elem.as_bigint(&prover), expected_bigint);
        }
    }
}
