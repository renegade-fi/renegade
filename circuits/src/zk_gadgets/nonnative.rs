//! Groups gadget definitions for non-native field arithmetic

use std::{
    iter::{self, Chain, Cloned, Repeat},
    slice::Iter,
};

use crypto::fields::{bigint_to_scalar_bits, biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use lazy_static::lazy_static;
use miller_rabin::is_prime;
use mpc_bulletproof::r1cs::{LinearCombination, Prover, RandomizableConstraintSystem, Variable};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};

use super::select::CondSelectVectorGadget;

/// The number of bits in each word, we use 126 to ensure that
/// multiplications in the base field (dalek `Scalar`s) will not
/// overflow
const WORD_SIZE: usize = 126;
/// The number of rounds to use when running the Miller-Rabin primality test
const MILLER_RABIN_ROUNDS: usize = 10;

lazy_static! {
    static ref BIGINT_ZERO: BigUint = BigUint::from(0u8);
    static ref BIGINT_2_TO_WORD_SIZE: BigUint = BigUint::from(1u8) << 126;
    static ref BIGINT_WORD_MASK: BigUint = &*BIGINT_2_TO_WORD_SIZE - 1u8;
}

/// Returns the maximum number of words needed to represent an element from
/// a field of the given modulus
fn repr_word_width(val: &BigUint) -> usize {
    let word_size_u64 = WORD_SIZE as u64;
    if val.bits() % word_size_u64 == 0 {
        (val.bits() / word_size_u64) as usize
    } else {
        (val.bits() / word_size_u64) as usize + 1
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
        val_bigint.bits() <= (2 * WORD_SIZE) as u64,
        "value too large for div_rem_word"
    );

    let div_bigint = &val_bigint / modulus;
    let rem_bigint = &val_bigint % modulus;

    let div_var = cs.allocate(Some(biguint_to_scalar(&div_bigint))).unwrap();
    let rem_var = cs.allocate(Some(biguint_to_scalar(&rem_bigint))).unwrap();

    let mod_scalar = biguint_to_scalar(modulus);

    // Constrain the modulus to be correct, i.e. dividend = quotient * divisor + remainder
    cs.constrain(val_lc - (mod_scalar * div_var + rem_var));
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

/// Compute the modular inverse of a value assuming that the field is
/// of prime modulus
///
/// This uses Euler's thm that a^{\phi(m)} (mod m) = 1 (mod m)
/// and for prime m, we have \phi(m) = m - 1
///
/// This implies that a^{\phi(m) - 1} = a^{m - 2} = a^-1 (mod m)
fn mod_inv_prime(val: &BigUint, modulo: &BigUint) -> BigUint {
    val.modpow(&(modulo - 2u8), modulo)
}

/// A representation of a field's modulus that stores an extra primality flag
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FieldMod {
    /// The modulus value that the field is defined over
    pub modulus: BigUint,
    /// Whether or not the value is prime
    pub is_prime: bool,
}

impl FieldMod {
    /// Construct a new field modulus
    pub fn new(modulus: BigUint, is_prime: bool) -> Self {
        Self { modulus, is_prime }
    }

    /// Construct a new field modulus given only the modulus, i.e.
    /// apply a primality test to the value
    pub fn from_modulus(modulus: BigUint) -> Self {
        let is_prime = is_prime(&modulus, MILLER_RABIN_ROUNDS);
        Self { modulus, is_prime }
    }
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
///
/// The generic constant PRIME_FIELD is used to determine whether a given
/// field is prime
#[derive(Clone, Debug)]
pub struct NonNativeElementVar {
    /// The words representing the underlying field
    /// stored in little endian order
    pub(super) words: Vec<LinearCombination>,
    /// The prime-power modulus of the field
    pub(super) field_mod: FieldMod,
}

impl NonNativeElementVar {
    /// Create a new value given a set of pre-allocated words
    pub fn new(mut words: Vec<LinearCombination>, field_mod: FieldMod) -> Self {
        let field_words = repr_word_width(&field_mod.modulus);
        if field_words > words.len() {
            words.append(&mut vec![
                Variable::Zero().into();
                field_words - words.len()
            ]);
        }
        Self { words, field_mod }
    }

    /// Create a new value from a given bigint
    pub fn from_bigint<CS: RandomizableConstraintSystem>(
        mut value: BigUint,
        field_mod: FieldMod,
        cs: &mut CS,
    ) -> Self {
        // Ensure that the value is in the field
        value %= &field_mod.modulus;

        // Split into words
        let field_words = repr_word_width(&field_mod.modulus);
        let mut words = Vec::with_capacity(field_words);
        for _ in 0..field_words {
            // Allocate the next 126 bits in the constraint system
            let next_word = biguint_to_scalar(&(&value & &*BIGINT_WORD_MASK));
            let word_var = cs.allocate(Some(next_word)).unwrap();
            words.push(word_var.into());

            value >>= WORD_SIZE;
        }

        Self { words, field_mod }
    }

    /// Construct a `NonNativeElementVar` from a bigint without reducing modulo the
    /// field modulus
    ///
    /// Here, `word_width` is the number of words that should be used to represent the
    /// resulting allocated non-native field element.
    pub fn from_bigint_unreduced<CS: RandomizableConstraintSystem>(
        value: BigUint,
        word_width: usize,
        field_mod: FieldMod,
        cs: &mut CS,
    ) -> Self {
        // Ensure that the allocated word width is large enough for the underlying value
        assert!(
            repr_word_width(&value) <= word_width,
            "specified word width too narrow {:?} < {:?}",
            word_width,
            repr_word_width(&value)
        );

        let mut words = bigint_to_scalar_words(value);
        words.append(&mut vec![Scalar::zero(); word_width - words.len()]);

        let allocated_words = words
            .iter()
            .map(|word| cs.allocate(Some(*word)).unwrap().into())
            .collect_vec();

        Self {
            words: allocated_words,
            field_mod,
        }
    }

    /// commit to the given bigint in the constraint system and return a reference to the commitments
    /// as well as the result
    pub fn commit_witness<R>(
        mut val: BigUint,
        field_mod: FieldMod,
        rng: &mut R,
        cs: &mut Prover,
    ) -> (Self, Vec<CompressedRistretto>)
    where
        R: RngCore + CryptoRng,
    {
        // Split the bigint into words
        let field_words = repr_word_width(&field_mod.modulus);
        let mut words = Vec::with_capacity(field_words);
        let mut commitments = Vec::with_capacity(field_words);
        for _ in 0..field_words {
            // Allocate the next 126 bits in the constraint system
            let next_word = biguint_to_scalar(&(&val & &*BIGINT_WORD_MASK));
            let (next_word_commit, next_word_var) = cs.commit(next_word, Scalar::random(rng));

            words.push(next_word_var.into());
            commitments.push(next_word_commit);

            val >>= WORD_SIZE;
        }

        (Self { words, field_mod }, commitments)
    }

    /// Commit to the given public bigint in the constraint system and return a
    /// reference to the commitment as well as the result
    pub fn commit_public<CS: RandomizableConstraintSystem>(
        mut val: BigUint,
        field_mod: FieldMod,
        cs: &mut CS,
    ) -> Self {
        // Split the bigint into words
        let field_words = repr_word_width(&field_mod.modulus);
        let mut words = Vec::with_capacity(field_words);
        for _ in 0..field_words {
            // Allocate the next 126 bits in the constraint system
            let next_word = biguint_to_scalar(&(&val & &*BIGINT_WORD_MASK));
            let next_word_var = cs.commit_public(next_word);

            words.push(next_word_var.into());

            val >>= WORD_SIZE;
        }

        Self { words, field_mod }
    }

    /// Generate an iterator over words
    ///
    /// Chains the iterator with an infinitely long repetition of the zero
    /// linear combination
    fn word_iterator(&self) -> Chain<Cloned<Iter<LinearCombination>>, Repeat<LinearCombination>> {
        self.words
            .iter()
            .cloned()
            .chain(iter::repeat(Variable::Zero().into()))
    }

    /// Evaluate the non-native variable in the given constraint system, and return the
    /// result as a bigint
    pub fn as_bigint<CS: RandomizableConstraintSystem>(&self, cs: &CS) -> BigUint {
        let mut res = BigUint::from(0u8);
        for word in self.words.iter().rev() {
            // Evaluate the underlying scalar representation of the word
            let word_bigint = scalar_to_biguint(&cs.eval(word));
            res = (res << WORD_SIZE) + word_bigint
        }

        res
    }

    /// Compute and constrain the little-endian bit decomposition of the input
    ///
    /// The generic constant `D` represents the bitlength of the input
    /// TODO: We should also constrain each output to be binary
    pub fn to_bits<const D: usize, CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Vec<Variable> {
        let self_bigint = Self::as_bigint(self, cs);
        let bits = bigint_to_scalar_bits::<D>(&self_bigint.into());

        // Allocate all the variables in the constraint system
        let mut allocated_bits = Vec::with_capacity(D);
        for bit in bits.iter() {
            allocated_bits.push(cs.allocate(Some(*bit)).unwrap());
        }

        // Reconstruct the words underlying the non-native var and constrain equality
        // Bits are returned in little-endian order
        let mut words = Vec::with_capacity(self.words.len());
        let mut curr_word: LinearCombination = Variable::Zero().into();
        for (index, bit) in bits.iter().enumerate().take(D) {
            // The index of the bit within the current word
            let bit_index = index % WORD_SIZE;

            // Cut a new complete word if we have filled one to bit capacity
            if index > 0 && bit_index == 0 {
                words.push(curr_word);
                curr_word = Variable::Zero().into();
            }

            let shift_scalar = biguint_to_scalar(&(BigUint::from(1u8) << bit_index));
            curr_word += shift_scalar * bit;
        }

        // Add the last word
        words.push(curr_word);

        // Constrain the reconstructed output to equal the input
        #[allow(clippy::needless_range_loop)]
        let zero_lc: LinearCombination = Variable::Zero().into();
        let reconstructed_word_iter = words.into_iter().chain(iter::repeat(zero_lc));
        let self_words_iter = self.word_iterator();
        for (reconstructed_word, self_word) in reconstructed_word_iter
            .zip(self_words_iter)
            .take(repr_word_width(&(BigUint::from(1u8) << D)))
        {
            cs.constrain(reconstructed_word - self_word);
        }

        allocated_bits
    }

    /// Return a variable that is set to 1 if the input is 0, otherwise 0
    ///
    /// Relies on the fact that over a prime field, all elements (except zero) have
    /// a valid multiplicative inverse
    ///
    /// See the circomlib implementation which takes a similar approach:
    /// https://github.com/iden3/circomlib/blob/master/circuits/comparators.circom#L24
    pub fn is_zero<CS: RandomizableConstraintSystem>(&self, cs: &mut CS) -> Variable {
        assert!(
            self.field_mod.is_prime,
            "is_zero can only be tested over a prime field"
        );

        // Compute the multiplicative inverse of the input
        let self_bigint = self.as_bigint(cs);

        let (is_zero, self_inv) = if self_bigint == BigUint::from(0u8) {
            (Variable::One(), BigUint::from(0u8))
        } else {
            (
                Variable::Zero(),
                mod_inv_prime(&self_bigint, &self.field_mod.modulus),
            )
        };

        // Allocate the inverse in the constraint system
        let inv_nonnative = Self::from_bigint(self_inv, self.field_mod.clone(), cs);

        // If the value was non-zero, multiplying by its inverse should give 1, if the value
        // is zero, multiplying by the "inverse" should give zero
        // We can flip these expected outputs via the line f(x) = 1 - x to flip the boolean result
        let val_times_inv = Self::mul(self, &inv_nonnative, cs);
        let one_minus_val = Self::add_bigint(
            &Self::additive_inverse(&val_times_inv, cs),
            &BigUint::from(1u8),
            cs,
        );
        Self::constrain_equal_biguint(&one_minus_val, &BigUint::from(0u8), cs);

        // We then constrain x * is_zero(x) == 0, this ensures that if the value is non-zero, the
        // prover cannot maliciously assign the inverse and the output such that the constraint
        // above is satisfied for is_zero \notin {0, 1}
        let mul_res = Self::mul_var(self, is_zero, cs);
        Self::constrain_zero(&mul_res, cs);

        is_zero
    }

    /// Select between two non-native field elements
    pub fn cond_select<L, CS>(
        selector: L,
        lhs: &Self,
        rhs: &Self,
        cs: &mut CS,
    ) -> NonNativeElementVar
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        // Pad the length of non-native vars such that they have the same length
        let max_len = lhs.words.len().max(rhs.words.len());
        let lhs_words = lhs.word_iterator();
        let rhs_words = rhs.word_iterator();

        let selector_lc: LinearCombination = selector.into();
        let selected_words = CondSelectVectorGadget::select(
            &lhs_words.take(max_len).collect_vec(),
            &rhs_words.take(max_len).collect_vec(),
            selector_lc,
            cs,
        );

        Self::new(selected_words, lhs.field_mod.clone())
    }

    /// Constrain two non-native field elements to equal one another
    pub fn constrain_equal<CS: RandomizableConstraintSystem>(lhs: &Self, rhs: &Self, cs: &mut CS) {
        // Pad the inputs to both be of the length of the longer input
        let max_len = lhs.words.len().max(rhs.words.len());
        let lhs_words = lhs.word_iterator();
        let rhs_words = rhs.word_iterator();

        // Compare each word in the non-native element
        for (lhs_word, rhs_word) in lhs_words.zip(rhs_words).take(max_len) {
            cs.constrain(lhs_word - rhs_word);
        }
    }

    /// Constrain a non-native field element to equal zero
    pub fn constrain_zero<CS: RandomizableConstraintSystem>(val: &Self, cs: &mut CS) {
        Self::constrain_equal_biguint(val, &BigUint::from(0u8), cs);
    }

    /// Constrain a non-native field element to equal the given BigUint
    pub fn constrain_equal_biguint<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: &BigUint,
        cs: &mut CS,
    ) {
        let biguint_words = bigint_to_scalar_words(rhs.clone());

        // Equalize the word width of the two values
        let max_len = biguint_words.len().max(lhs.words.len());
        let lhs_words = lhs.word_iterator();
        let rhs_words = biguint_words
            .into_iter()
            .chain(iter::repeat(Scalar::zero()));

        // Constrain all words to equal one another
        for (lhs_word, rhs_word) in lhs_words.zip(rhs_words).take(max_len) {
            cs.constrain(lhs_word - rhs_word);
        }
    }

    /// Reduce the given element modulo its field
    pub fn reduce<CS: RandomizableConstraintSystem>(&mut self, cs: &mut CS) {
        // Convert to bigint for reduction
        let self_bigint = self.as_bigint(cs);
        let div_bigint = &self_bigint / &self.field_mod.modulus;
        let mod_bigint = &self_bigint % &self.field_mod.modulus;

        // Explicitly compute the representation width of the division result in the constraint system
        // We do this because the value is taken unreduced; so that verifier cannot infer the width
        // from the field modulus, and does not have access to the underlying value to determine its
        // width otherwise
        let field_modulus_word_width = repr_word_width(&self.field_mod.modulus);
        let div_word_width = self.words.len() + 1 - field_modulus_word_width;

        let div_nonnative = NonNativeElementVar::from_bigint_unreduced(
            div_bigint,
            div_word_width,
            self.field_mod.clone(),
            cs,
        );

        let mod_nonnative =
            NonNativeElementVar::from_bigint(mod_bigint, self.field_mod.clone(), cs);

        // Constrain the values to be a correct modulus
        let div_mod_mul = Self::mul_bigint_unreduced(&div_nonnative, &self.field_mod.modulus, cs);
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

        // Pad both left and right hand side to the same length
        let max_word_width = lhs.words.len().max(rhs.words.len());
        let lhs_words = lhs.word_iterator();
        let rhs_words = rhs.word_iterator();

        // Add word by word with carry
        let mut carry = Variable::Zero();
        let mut new_words = Vec::with_capacity(max_word_width + 1);
        for (lhs_word, rhs_word) in lhs_words.zip(rhs_words).take(max_word_width) {
            // Compute the word-wise sum and reduce to fit into a single word
            let word_res = lhs_word + rhs_word + carry;
            let div_rem = div_rem_word(word_res.clone(), &BIGINT_2_TO_WORD_SIZE, cs);

            carry = div_rem.0;
            new_words.push(div_rem.1.into());
        }
        new_words.push(carry.into());

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
        let rhs_words = bigint_to_scalar_words(rhs.clone());

        // Resize the lhs and rhs word iterators to be of equal size
        let max_len = rhs_words.len().max(lhs.words.len());
        let lhs_word_iterator = lhs
            .words
            .iter()
            .cloned()
            .chain(iter::repeat(Variable::Zero().into()));
        let rhs_word_iterator = rhs_words
            .iter()
            .cloned()
            .chain(iter::repeat(Scalar::zero()));

        // Add the two non-native elements word-wise
        let mut carry = Variable::Zero();
        let mut new_words = Vec::with_capacity(max_len + 1);
        for (lhs_word, rhs_word) in lhs_word_iterator.zip(rhs_word_iterator).take(max_len) {
            let word_res = lhs_word + rhs_word + carry;
            let div_rem = div_rem_word(word_res, &BIGINT_2_TO_WORD_SIZE, cs);

            new_words.push(div_rem.1.into());
            carry = div_rem.0;
        }
        new_words.push(carry.into());

        Self {
            words: new_words,
            field_mod: lhs.field_mod.clone(),
        }
    }

    /// Multiply a nonnative variable with a Variable
    pub fn mul_var<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: Variable,
        cs: &mut CS,
    ) -> Self {
        let rhs_nonnative = Self {
            words: vec![rhs.into()],
            field_mod: lhs.field_mod.clone(),
        };
        Self::mul(lhs, &rhs_nonnative, cs)
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
        let n_result_words = lhs.words.len() + rhs.words.len();

        // Both lhs and rhs are represented as:
        //  x = x_1 + 2^WORD_SIZE * x_2 + ... + 2^(num_words * WORD_SIZE) * x_num_words
        // To multiply the values, we take the direct product of each pair of terms
        // between `lhs` and `rhs`, storing both the term and the carry from reducing
        // each term in one of the buckets below; depending on the shift (2^k) applied
        // to the result
        //
        // The maximum shift is 2^{2 * num_words} as (2^k - 1)(2^k - 1) = 2^2k - 2^{k+1} - 1 < 2^2k
        let mut terms = vec![Vec::new(); n_result_words];
        let mut carries = vec![Vec::new(); n_result_words + 1];

        for (lhs_index, lhs_word) in lhs.word_iterator().enumerate().take(lhs.words.len()) {
            for (rhs_index, rhs_word) in rhs.word_iterator().enumerate().take(rhs.words.len()) {
                // Compute the term and reduce it modulo the field
                let (_, _, term_direct_product) =
                    cs.multiply(lhs_word.to_owned(), rhs_word.to_owned());
                let (term_carry, term) =
                    div_rem_word(term_direct_product, &BIGINT_2_TO_WORD_SIZE, cs);

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
            let div_rem_res = div_rem_word(summed_word, &BIGINT_2_TO_WORD_SIZE, cs);
            carry = div_rem_res.0;
            res_words.push(div_rem_res.1.into());
        }
        res_words.push(carry.into());

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
        let n_result_words = rhs_words.len() + lhs.words.len();

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
                let term_direct_product = lhs_word.to_owned() * rhs_word.to_owned();
                let (term_carry, term) =
                    div_rem_word(term_direct_product, &BIGINT_2_TO_WORD_SIZE, cs);

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
            let div_rem_res = div_rem_word(summed_word, &BIGINT_2_TO_WORD_SIZE, cs);
            carry = div_rem_res.0;
            res_words.push(div_rem_res.1.into());
        }

        Self {
            words: res_words,
            field_mod: lhs.field_mod.clone(),
        }
    }

    /// Subtract one nonnative variable from another, i.e. lhs - rhs
    pub fn subtract<CS: RandomizableConstraintSystem>(lhs: &Self, rhs: &Self, cs: &mut CS) -> Self {
        // Compute the additive inverse of the right hand operand, then add the values
        let add_inv = Self::additive_inverse(rhs, cs);
        Self::add(lhs, &add_inv, cs)
    }

    /// Subtract a BigUint from a nonnative variable
    pub fn subtract_bigint<CS: RandomizableConstraintSystem>(
        lhs: &Self,
        rhs: &BigUint,
        cs: &mut CS,
    ) -> Self {
        // Compute the additive inverse of the BigUint
        let additive_inv = &lhs.field_mod.modulus - (rhs % &lhs.field_mod.modulus);
        Self::add_bigint(lhs, &additive_inv, cs)
    }

    /// Computes the additive inverse of the given value in the field
    pub fn additive_inverse<CS: RandomizableConstraintSystem>(val: &Self, cs: &mut CS) -> Self {
        // Evaluate the value in the constraint system
        let mut val_bigint = val.as_bigint(cs);
        val_bigint %= &val.field_mod.modulus;

        // Compute the additive inverse
        let additive_inv = &val.field_mod.modulus - val_bigint;
        let inv_nonnative = Self::from_bigint(additive_inv, val.field_mod.clone(), cs);

        // Constrain the value to be correct
        let val_plus_inv = Self::add(val, &inv_nonnative, cs);
        Self::constrain_equal_biguint(&val_plus_inv, &BigUint::from(0u8), cs);

        inv_nonnative
    }

    /// Computes the multiplicative inverse of the given value modulo the value's field
    pub fn invert<CS: RandomizableConstraintSystem>(val: &Self, cs: &mut CS) -> Self {
        assert!(
            val.field_mod.is_prime,
            "inverse may only be taken in a prime field"
        );

        // Evaluate hte value in the constraint system into a bigint
        let mut val_bigint = val.as_bigint(cs);
        val_bigint %= &val.field_mod.modulus;

        let inverse = mod_inv_prime(&val_bigint, &val.field_mod.modulus);

        // Constrain the inverse to be correctly computed
        let inverse_nonnative = Self::from_bigint(inverse, val.field_mod.clone(), cs);
        let val_times_inverse = Self::mul(val, &inverse_nonnative, cs);

        Self::constrain_equal_biguint(&val_times_inverse, &BigUint::from(1u8), cs);

        inverse_nonnative
    }
}

#[cfg(test)]
mod nonnative_tests {
    use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
    use itertools::Itertools;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, LinearCombination, Prover, R1CSProof, Variable, Verifier},
        BulletproofGens, PedersenGens,
    };
    use mpc_ristretto::mpc_scalar::scalar_to_u64;
    use num_bigint::{BigInt, BigUint, Sign};
    use num_primes::Generator;
    use rand::{thread_rng, Rng};
    use rand_core::{CryptoRng, OsRng, RngCore};

    use crate::{
        errors::{ProverError, VerifierError},
        test_helpers::bulletproof_prove_and_verify,
        CommitProver, CommitVerifier, SingleProverCircuit,
    };

    use super::{bigint_to_scalar_words, FieldMod, NonNativeElementVar};

    // -------------
    // | Constants |
    // -------------

    /// The seed for the prover/verifier transcripts
    const TRANSCRIPT_SEED: &str = "test";

    // -----------
    // | Helpers |
    // -----------

    /// Samples a random 512-bit big unsigned int
    fn random_biguint<R: RngCore + CryptoRng>(rng: &mut R) -> BigUint {
        let bytes = &mut [0u8; 32];
        rng.fill_bytes(bytes);
        BigUint::from_bytes_le(bytes)
    }

    /// Samples a random 512-bit positive signed bigint
    fn random_pos_bigint<R: RngCore + CryptoRng>(rng: &mut R) -> BigInt {
        let bytes = &mut [0u8; 32];
        rng.fill_bytes(bytes);
        BigInt::from_bytes_le(Sign::Plus, bytes)
    }

    /// Samples a random 512-bit prime
    fn random_prime() -> BigUint {
        let prime = Generator::new_prime(512);
        BigUint::from_bytes_le(&prime.to_bytes_le())
    }

    // ------------
    // | Circuits |
    // ------------

    /// A witness type for a fan-in 2, fan-out 1 operator
    #[derive(Clone, Debug)]
    pub struct FanIn2Witness {
        /// The left hand side of the operator
        lhs: BigUint,
        /// The right hand side of the operator
        rhs: BigUint,
        /// The field modulus that these operands are defined over
        field_mod: FieldMod,
    }

    impl CommitProver for FanIn2Witness {
        type VarType = FanIn2WitnessVar;
        type CommitType = FanIn2WitnessCommitment;
        type ErrorType = ();

        fn commit_prover<R: RngCore + CryptoRng>(
            &self,
            rng: &mut R,
            prover: &mut Prover,
        ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
            // Split the bigint into words
            let lhs_words = bigint_to_scalar_words(self.lhs.clone());
            let (lhs_comm, lhs_var): (Vec<CompressedRistretto>, Vec<Variable>) = lhs_words
                .iter()
                .map(|word| prover.commit(*word, Scalar::random(rng)))
                .unzip();

            let lhs_var_lcs: Vec<LinearCombination> =
                lhs_var.into_iter().map(Into::into).collect_vec();
            let lhs_var = NonNativeElementVar::new(lhs_var_lcs, self.field_mod.clone());

            let rhs_words = bigint_to_scalar_words(self.rhs.clone());
            let (rhs_comm, rhs_var): (Vec<CompressedRistretto>, Vec<Variable>) = rhs_words
                .iter()
                .map(|word| prover.commit(*word, Scalar::random(rng)))
                .unzip();

            let rhs_var_lcs: Vec<LinearCombination> =
                rhs_var.into_iter().map(Into::into).collect_vec();
            let rhs_var = NonNativeElementVar::new(rhs_var_lcs, self.field_mod.clone());

            Ok((
                FanIn2WitnessVar {
                    lhs: lhs_var,
                    rhs: rhs_var,
                },
                FanIn2WitnessCommitment {
                    lhs: lhs_comm,
                    rhs: rhs_comm,
                    field_mod: self.field_mod.clone(),
                },
            ))
        }
    }

    /// A constraint-system allocated fan-in 2 witness
    #[derive(Clone, Debug)]
    pub struct FanIn2WitnessVar {
        /// The left hand side of the operator
        lhs: NonNativeElementVar,
        /// The right hand side of the operator
        rhs: NonNativeElementVar,
    }

    /// A commitment to a fan-in 2 witness
    #[derive(Clone, Debug)]
    pub struct FanIn2WitnessCommitment {
        /// The left hand side of the operator
        lhs: Vec<CompressedRistretto>,
        /// The right hand side of the operator
        rhs: Vec<CompressedRistretto>,
        /// The modulus of the field
        field_mod: FieldMod,
    }

    impl CommitVerifier for FanIn2WitnessCommitment {
        type VarType = FanIn2WitnessVar;
        type ErrorType = ();

        fn commit_verifier(
            &self,
            verifier: &mut Verifier,
        ) -> Result<Self::VarType, Self::ErrorType> {
            // Commit to the words in the lhs and rhs vars, then reform them into
            // allocated non-native field elements
            let lhs_vars = self
                .lhs
                .iter()
                .map(|comm| verifier.commit(*comm))
                .collect_vec();

            let lhs_var_lcs: Vec<LinearCombination> =
                lhs_vars.into_iter().map(Into::into).collect_vec();
            let lhs = NonNativeElementVar::new(lhs_var_lcs, self.field_mod.clone());

            let rhs_vars = self
                .rhs
                .iter()
                .map(|comm| verifier.commit(*comm))
                .collect_vec();

            let rhs_var_lcs: Vec<LinearCombination> =
                rhs_vars.into_iter().map(Into::into).collect_vec();
            let rhs = NonNativeElementVar::new(rhs_var_lcs, self.field_mod.clone());

            Ok(FanIn2WitnessVar { lhs, rhs })
        }
    }

    pub struct AdderCircuit {}
    impl SingleProverCircuit for AdderCircuit {
        type Witness = FanIn2Witness;
        type Statement = BigUint;
        type WitnessCommitment = FanIn2WitnessCommitment;

        const BP_GENS_CAPACITY: usize = 64;

        fn prove(
            witness: Self::Witness,
            statement: Self::Statement,
            mut prover: Prover,
        ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
            // Commit to the witness
            let mut rng = OsRng {};
            let (witness_var, wintess_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

            // Commit to the statement variable
            let expected_words = bigint_to_scalar_words(statement);
            let statement_word_vars = expected_words
                .iter()
                .map(|word| prover.commit_public(*word))
                .collect_vec();

            let statement_word_lcs: Vec<LinearCombination> = statement_word_vars
                .into_iter()
                .map(Into::into)
                .collect_vec();
            let expected_nonnative =
                NonNativeElementVar::new(statement_word_lcs, witness.field_mod);

            // Add the two witness values
            let addition_result =
                NonNativeElementVar::add(&witness_var.lhs, &witness_var.rhs, &mut prover);

            NonNativeElementVar::constrain_equal(
                &addition_result,
                &expected_nonnative,
                &mut prover,
            );

            // Prove the statement
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

            Ok((wintess_comm, proof))
        }

        fn verify(
            witness_commitment: Self::WitnessCommitment,
            statement: Self::Statement,
            proof: R1CSProof,
            mut verifier: Verifier,
        ) -> Result<(), VerifierError> {
            // Commit to the witness
            let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

            // Commit to the statement variable
            let expected_words = bigint_to_scalar_words(statement);
            let statement_word_vars = expected_words
                .iter()
                .map(|word| verifier.commit_public(*word))
                .collect_vec();

            let statement_word_lcs: Vec<LinearCombination> = statement_word_vars
                .into_iter()
                .map(Into::into)
                .collect_vec();
            let expected_nonnative =
                NonNativeElementVar::new(statement_word_lcs, witness_commitment.field_mod);

            // Add the two witness values
            let addition_result =
                NonNativeElementVar::add(&witness_var.lhs, &witness_var.rhs, &mut verifier);

            NonNativeElementVar::constrain_equal(
                &addition_result,
                &expected_nonnative,
                &mut verifier,
            );

            // Verify the proof
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            verifier
                .verify(&proof, &bp_gens)
                .map_err(VerifierError::R1CS)
        }
    }

    #[derive(Clone, Debug)]
    pub struct MulCircuit {}
    impl SingleProverCircuit for MulCircuit {
        type Statement = BigUint;
        type Witness = FanIn2Witness;
        type WitnessCommitment = FanIn2WitnessCommitment;

        const BP_GENS_CAPACITY: usize = 128;

        fn prove(
            witness: Self::Witness,
            statement: Self::Statement,
            mut prover: Prover,
        ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
            // Commit to the witness
            let mut rng = OsRng {};
            let (witness_var, wintess_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

            // Commit to the statement variable
            let expected_words = bigint_to_scalar_words(statement);
            let statement_word_vars = expected_words
                .iter()
                .map(|word| prover.commit_public(*word))
                .collect_vec();

            let statement_word_lcs: Vec<LinearCombination> = statement_word_vars
                .into_iter()
                .map(Into::into)
                .collect_vec();
            let expected_nonnative =
                NonNativeElementVar::new(statement_word_lcs, witness.field_mod);

            // Add the two witness values
            let mul_result =
                NonNativeElementVar::mul(&witness_var.lhs, &witness_var.rhs, &mut prover);
            NonNativeElementVar::constrain_equal(&mul_result, &expected_nonnative, &mut prover);

            // Prove the statement
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

            Ok((wintess_comm, proof))
        }

        fn verify(
            witness_commitment: Self::WitnessCommitment,
            statement: Self::Statement,
            proof: R1CSProof,
            mut verifier: Verifier,
        ) -> Result<(), VerifierError> {
            // Commit to the witness
            let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

            // Commit to the statement variable
            let expected_words = bigint_to_scalar_words(statement);
            let statement_word_vars = expected_words
                .iter()
                .map(|word| verifier.commit_public(*word))
                .collect_vec();

            let statement_word_lcs: Vec<LinearCombination> = statement_word_vars
                .into_iter()
                .map(Into::into)
                .collect_vec();
            let expected_nonnative =
                NonNativeElementVar::new(statement_word_lcs, witness_commitment.field_mod);

            // Add the two witness values
            let mul_result =
                NonNativeElementVar::mul(&witness_var.lhs, &witness_var.rhs, &mut verifier);
            NonNativeElementVar::constrain_equal(&mul_result, &expected_nonnative, &mut verifier);

            // Verify the proof
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            verifier
                .verify(&proof, &bp_gens)
                .map_err(VerifierError::R1CS)
        }
    }

    pub struct SubCircuit {}
    impl SingleProverCircuit for SubCircuit {
        type Statement = BigUint;
        type Witness = FanIn2Witness;
        type WitnessCommitment = FanIn2WitnessCommitment;

        const BP_GENS_CAPACITY: usize = 64;

        fn prove(
            witness: Self::Witness,
            statement: Self::Statement,
            mut prover: Prover,
        ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
            // Commit to the witness
            let mut rng = OsRng {};
            let (witness_var, wintess_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

            // Commit to the statement variable
            let expected_words = bigint_to_scalar_words(statement);
            let statement_word_vars = expected_words
                .iter()
                .map(|word| prover.commit_public(*word))
                .collect_vec();

            let statement_word_lcs: Vec<LinearCombination> = statement_word_vars
                .into_iter()
                .map(Into::into)
                .collect_vec();
            let expected_nonnative =
                NonNativeElementVar::new(statement_word_lcs, witness.field_mod);

            // Add the two witness values
            let sub_result =
                NonNativeElementVar::subtract(&witness_var.lhs, &witness_var.rhs, &mut prover);
            NonNativeElementVar::constrain_equal(&sub_result, &expected_nonnative, &mut prover);

            // Prove the statement
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

            Ok((wintess_comm, proof))
        }

        fn verify(
            witness_commitment: Self::WitnessCommitment,
            statement: Self::Statement,
            proof: R1CSProof,
            mut verifier: Verifier,
        ) -> Result<(), VerifierError> {
            // Commit to the witness
            let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

            // Commit to the statement variable
            let expected_words = bigint_to_scalar_words(statement);
            let statement_word_vars = expected_words
                .iter()
                .map(|word| verifier.commit_public(*word))
                .collect_vec();

            let statement_word_lcs: Vec<LinearCombination> = statement_word_vars
                .into_iter()
                .map(Into::into)
                .collect_vec();
            let expected_nonnative =
                NonNativeElementVar::new(statement_word_lcs, witness_commitment.field_mod);

            // Add the two witness values
            let sub_result =
                NonNativeElementVar::subtract(&witness_var.lhs, &witness_var.rhs, &mut verifier);
            NonNativeElementVar::constrain_equal(&sub_result, &expected_nonnative, &mut verifier);

            // Verify the proof
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            verifier
                .verify(&proof, &bp_gens)
                .map_err(VerifierError::R1CS)
        }
    }

    /// This circuit effectively proves that the witness if coprime with the modulus
    pub struct InverseCircuit {}
    impl SingleProverCircuit for InverseCircuit {
        // Don't use one of the operands
        type Witness = FanIn2Witness;
        type WitnessCommitment = FanIn2WitnessCommitment;
        type Statement = ();

        const BP_GENS_CAPACITY: usize = 256;

        fn prove(
            witness: Self::Witness,
            _: Self::Statement,
            mut prover: Prover,
        ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
            // Commit to the witness
            let mut rng = OsRng {};
            let (witness_var, wintess_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

            // Invert the witness, the constraint below is technically already added in the gadget itself,
            // we duplicate it here for completeness
            let inv_result = NonNativeElementVar::invert(&witness_var.lhs, &mut prover);
            let lhs_times_inv =
                NonNativeElementVar::mul(&inv_result, &witness_var.lhs, &mut prover);
            NonNativeElementVar::constrain_equal_biguint(
                &lhs_times_inv,
                &BigUint::from(1u8),
                &mut prover,
            );

            // Prove the statement
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

            Ok((wintess_comm, proof))
        }

        fn verify(
            witness_commitment: Self::WitnessCommitment,
            _: Self::Statement,
            proof: R1CSProof,
            mut verifier: Verifier,
        ) -> Result<(), VerifierError> {
            // Commit to the witness
            let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

            // Invert the witness, the constraint below is technically already added in the gadget itself,
            // we duplicate it here for completeness
            let inv_result = NonNativeElementVar::invert(&witness_var.lhs, &mut verifier);
            let lhs_times_inv =
                NonNativeElementVar::mul(&inv_result, &witness_var.lhs, &mut verifier);
            NonNativeElementVar::constrain_equal_biguint(
                &lhs_times_inv,
                &BigUint::from(1u8),
                &mut verifier,
            );

            // Verify the proof
            let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
            verifier
                .verify(&proof, &bp_gens)
                .map_err(VerifierError::R1CS)
        }
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

            let nonnative_elem = NonNativeElementVar::from_bigint(
                random_elem,
                FieldMod::from_modulus(random_mod),
                &mut prover,
            );
            assert_eq!(nonnative_elem.as_bigint(&prover), expected_bigint);
        }
    }

    /// Test converting to and from a bit representation
    #[test]
    fn test_to_bits() {
        // Generate a series of random bits
        let n_tests = 100;
        let n_bits = 256;
        let mut rng = thread_rng();

        let mut prover_transcript = Transcript::new(&TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Generate a random bitstring
            let rand_bits: Vec<u8> = (0..n_bits).map(|_| rng.gen_bool(0.5).into()).collect_vec();
            // Reconstruct the expected value
            let mut expected_bigint = BigUint::from(0u8);
            for bit in rand_bits.iter().rev() {
                expected_bigint = 2u8 * expected_bigint + bit;
            }

            let field_mod = FieldMod::from_modulus(BigUint::from(1u8) << 256);
            let nonnative_expected =
                NonNativeElementVar::from_bigint(expected_bigint, field_mod, &mut prover);

            // Deconstruct the nonnative into bits
            let nonnative_bits = nonnative_expected.to_bits::<256, _>(&mut prover);

            for i in 0..n_bits {
                let bit = scalar_to_u64(&prover.eval(&nonnative_bits[i].into()));
                assert_eq!(bit, rand_bits[i] as u64, "bits differ at index {:?}", i);
            }
        }
    }

    #[test]
    /// Tests the conditional select implementation
    fn test_cond_select() {
        let n_tests = 100;
        let mut rng = OsRng {};

        // Use the curve25519 field modulus
        let modulus: BigUint = (BigUint::from(1u8) << 255) - 19u8;
        let field_mod = FieldMod::from_modulus(modulus.clone());

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Sample two random non-native field elements and randomly select between
            let random_val1 = random_biguint(&mut rng) % &modulus;
            let random_val2 = random_biguint(&mut rng) % &modulus;

            let nonnative1 = NonNativeElementVar::from_bigint(
                random_val1.clone(),
                field_mod.clone(),
                &mut prover,
            );
            let nonnative2 = NonNativeElementVar::from_bigint(
                random_val2.clone(),
                field_mod.clone(),
                &mut prover,
            );

            // Randomly sample a selector
            let (selector, expected) = if rng.next_u32() % 2 == 0 {
                (Variable::One(), random_val1.clone())
            } else {
                (Variable::Zero(), random_val2.clone())
            };

            let res =
                NonNativeElementVar::cond_select(selector, &nonnative1, &nonnative2, &mut prover);
            assert_eq!(expected, res.as_bigint(&mut prover));
        }
    }

    /// Tests reducing a non-native field element modulo its field
    #[test]
    fn test_reduce() {
        let n_tests = 100;
        let mut rng = OsRng {};

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Sample a random value, and a random modulus
            let random_val = random_biguint(&mut rng);
            let random_mod = random_biguint(&mut rng);

            let expected = &random_val % &random_mod;

            let words = bigint_to_scalar_words(random_val);
            let allocated_words = words
                .iter()
                .map(|word| prover.commit_public(*word).into())
                .collect_vec();

            let mut val =
                NonNativeElementVar::new(allocated_words, FieldMod::from_modulus(random_mod));
            val.reduce(&mut prover);

            // Evaluate the value in the constraint system and ensure it is as expected
            let reduced_val_bigint = val.as_bigint(&prover);
            assert_eq!(reduced_val_bigint, expected);
        }
    }

    /// Tests the addition functionality inside an addition circuit
    #[test]
    fn test_add_circuit() {
        let n_tests = 10;
        let mut rng = OsRng {};

        for _ in 0..n_tests {
            // Sample two random elements, compute their sum, then prover the AdderCircuit
            // statement
            let random_elem1 = random_biguint(&mut rng);
            let random_elem2 = random_biguint(&mut rng);
            let random_mod = random_biguint(&mut rng);
            let expected_bigint = (&random_elem1 + &random_elem2) % &random_mod;

            let witness = FanIn2Witness {
                lhs: random_elem1,
                rhs: random_elem2,
                field_mod: FieldMod::from_modulus(random_mod),
            };

            let statement = expected_bigint;

            // Prove and verify a valid member of the relation
            let res = bulletproof_prove_and_verify::<AdderCircuit>(witness, statement);
            assert!(res.is_ok());
        }
    }

    /// Tests adding a non-native field element with a biguint
    #[test]
    fn test_add_biguint() {
        let n_tests = 100;
        let mut rng = OsRng {};

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Sample two random elements and a modulus, allocate one in the constraint
            // system and add the other directly as a biguint
            let random_elem1 = random_biguint(&mut rng);
            let random_elem2 = random_biguint(&mut rng);
            let random_mod = random_biguint(&mut rng);
            let expected_bigint = (&random_elem1 + &random_elem2) % &random_mod;

            let nonnative = NonNativeElementVar::from_bigint(
                random_elem1,
                FieldMod::from_modulus(random_mod),
                &mut prover,
            );
            let res = NonNativeElementVar::add_bigint(&nonnative, &random_elem2, &mut prover);

            let res_bigint = res.as_bigint(&prover);
            assert_eq!(res_bigint, expected_bigint);
        }
    }

    /// Tests multiplying two non-native field elements together
    #[test]
    fn test_mul_circuit() {
        let n_tests = 10;
        let mut rng = OsRng {};

        for _ in 0..n_tests {
            // Sample two random elements, compute their sum, then prover the AdderCircuit
            // statement
            let random_elem1 = random_biguint(&mut rng);
            let random_elem2 = random_biguint(&mut rng);
            let random_mod = random_biguint(&mut rng);
            let expected_bigint = (&random_elem1 * &random_elem2) % &random_mod;

            let witness = FanIn2Witness {
                lhs: random_elem1,
                rhs: random_elem2,
                field_mod: FieldMod::from_modulus(random_mod),
            };

            let statement = expected_bigint;

            // Prove and verify a valid member of the relation
            let res = bulletproof_prove_and_verify::<MulCircuit>(witness, statement);
            assert!(res.is_ok());
        }
    }

    /// Tests multiplying a non-native field element with a bigint
    #[test]
    fn test_mul_bigint() {
        let n_tests = 100;
        let mut rng = OsRng {};

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Sample two random elements and a modulus, allocate one in the constraint
            // system and add the other directly as a biguint
            let random_elem1 = random_biguint(&mut rng);
            let random_elem2 = random_biguint(&mut rng);
            let random_mod = random_biguint(&mut rng);
            let expected_bigint = (&random_elem1 * &random_elem2) % &random_mod;

            let nonnative = NonNativeElementVar::from_bigint(
                random_elem1,
                FieldMod::from_modulus(random_mod),
                &mut prover,
            );
            let res = NonNativeElementVar::mul_bigint(&nonnative, &random_elem2, &mut prover);

            let res_bigint = res.as_bigint(&prover);
            assert_eq!(res_bigint, expected_bigint);
        }
    }

    /// Tests subtracting one non-native field element from another
    #[test]
    fn test_sub_circuit() {
        let n_tests = 10;
        let mut rng = OsRng {};

        for _ in 0..n_tests {
            // Sample two random elements, compute their sum, then prover the AdderCircuit
            // statement
            let random_elem1 = random_pos_bigint(&mut rng);
            let random_elem2 = random_pos_bigint(&mut rng);
            let random_mod: BigInt = random_biguint(&mut rng).into();
            let mut expected_bigint = if random_elem1.gt(&random_elem2) {
                &random_elem1 - &random_elem2
            } else {
                &random_mod - (&random_elem2 % &random_mod) + (&random_elem1 % &random_mod)
            };
            expected_bigint %= &random_mod;

            let witness = FanIn2Witness {
                lhs: random_elem1.to_biguint().unwrap(),
                rhs: random_elem2.to_biguint().unwrap(),
                field_mod: FieldMod::from_modulus(random_mod.to_biguint().unwrap()),
            };

            let statement = expected_bigint.to_biguint().unwrap();

            // Prove and verify a valid member of the relation
            let res = bulletproof_prove_and_verify::<SubCircuit>(witness, statement);
            assert!(res.is_ok());
        }
    }

    /// Test subtracting a BigUint from a non-native field element
    #[test]
    fn test_sub_bigint() {
        let n_tests = 100;
        let mut rng = OsRng {};

        let mut prover_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        for _ in 0..n_tests {
            // Sample two random elements and a modulus, allocate one in the constraint
            // system and add the other directly as a biguint
            let random_elem1 = random_biguint(&mut rng);
            let random_elem2 = random_biguint(&mut rng);
            let random_mod = random_biguint(&mut rng);
            let mut expected_bigint = if random_elem1.gt(&random_elem2) {
                &random_elem1 - &random_elem2
            } else {
                &random_mod - (&random_elem2 % &random_mod) + (&random_elem1 % &random_mod)
            };
            expected_bigint %= &random_mod;

            let nonnative = NonNativeElementVar::from_bigint(
                random_elem1,
                FieldMod::from_modulus(random_mod),
                &mut prover,
            );
            let res = NonNativeElementVar::subtract_bigint(&nonnative, &random_elem2, &mut prover);

            let res_bigint = res.as_bigint(&prover);
            assert_eq!(res_bigint, expected_bigint);
        }
    }

    /// Test inverting a non-native field element
    #[test]
    fn test_mul_invert() {
        let n_tests = 5;
        let mut rng = OsRng {};

        for _ in 0..n_tests {
            // Sample two random elements, compute their sum, then prover the AdderCircuit
            // statement
            let random_elem1 = random_biguint(&mut rng);
            let random_elem2 = random_biguint(&mut rng);
            let random_prime_mod = random_prime();

            let witness = FanIn2Witness {
                lhs: random_elem1,
                // Ignored
                rhs: random_elem2,
                field_mod: FieldMod::from_modulus(random_prime_mod),
            };

            // Prove and verify a valid member of the relation
            let res = bulletproof_prove_and_verify::<InverseCircuit>(witness, ());
            assert!(res.is_ok());
        }
    }
}
