//! Groups ZK gadgets used as arithmetic primitives in more complicated computations

use std::marker::PhantomData;

use ark_ff::Zero;
use circuit_types::errors::ProverError;
use renegade_crypto::fields::{biguint_to_scalar, scalar_to_biguint};

use circuit_types::traits::{LinearCombinationLike, MpcLinearCombinationLike};
use mpc_bulletproof::r1cs::{LinearCombination, RandomizableConstraintSystem, Variable};
use mpc_bulletproof::r1cs_mpc::{MpcLinearCombination, MpcRandomizableConstraintSystem, R1CSError};
use mpc_stark::algebra::scalar::Scalar;
use mpc_stark::MpcFabric;
use num_bigint::BigUint;
use num_integer::Integer;

use super::bits::ToBitsGadget;
use super::comparators::{EqZeroGadget, LessThanGadget};
use super::select::CondSelectGadget;

// -------------------------
// | Single Prover Gadgets |
// -------------------------

/// A div-rem gadget which for inputs `a`, `b` returns
/// values `q`, `r` such that a = bq + r and r < b
///
/// The generic constant `D` represents the bitlength of the input `b`
#[derive(Clone, Debug)]
pub struct DivRemGadget<const D: usize> {}
impl<const D: usize> DivRemGadget<D> {
    /// Return (q, r) such that a = bq + r and r < b
    pub fn div_rem<L, CS>(a: L, b: L, cs: &mut CS) -> (Variable, Variable)
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        let a_lc: LinearCombination = a.into();
        let b_lc: LinearCombination = b.into();

        // Evaluate to bigint
        let a_bigint = scalar_to_biguint(&cs.eval(&a_lc));
        let b_bigint = scalar_to_biguint(&cs.eval(&b_lc));

        // Compute the divrem outside of the circuit
        // Verifier evals all wires to zero -- it only knows commitments
        // Handle this case explicitly
        let (q, r) = if b_bigint == BigUint::zero() {
            (BigUint::zero(), b_bigint)
        } else {
            a_bigint.div_rem(&b_bigint)
        };

        let q_var = cs.allocate(Some(biguint_to_scalar(&q))).unwrap();
        let r_var = cs.allocate(Some(biguint_to_scalar(&r))).unwrap();

        // Constrain a == bq + r
        let (_, _, bq) = cs.multiply(b_lc.clone(), q_var.into());
        cs.constrain(a_lc - bq - r_var);

        // Constraint r < b
        LessThanGadget::<D>::constrain_less_than(r_var.into(), b_lc, cs);
        (q_var, r_var)
    }
}

/// The inputs to the exp gadget
/// A gadget to compute exponentiation: x^\alpha
pub struct ExpGadget {}
impl ExpGadget {
    /// Computes a linear combination representing the result of taking x^\alpha
    ///
    /// Provides a functional interface for composing this gadget into a larger
    /// circuit.
    pub fn exp<L, CS>(x: L, alpha: u64, cs: &mut CS) -> LinearCombination
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        if alpha == 0 {
            LinearCombination::from(Scalar::one())
        } else if alpha == 1 {
            x.into()
        } else if alpha % 2 == 0 {
            let recursive_result = ExpGadget::exp(x, alpha / 2, cs);
            let (_, _, out_var) = cs.multiply(recursive_result.clone(), recursive_result);
            out_var.into()
        } else {
            let x_lc = x.into();
            let recursive_result = ExpGadget::exp(x_lc.clone(), (alpha - 1) / 2, cs);
            let (_, _, out_var1) = cs.multiply(recursive_result.clone(), recursive_result);
            let (_, _, out_var2) = cs.multiply(out_var1.into(), x_lc);
            out_var2.into()
        }
    }
}

/// An exponentiation gadget on a private exponent; compute x^\alpha
#[derive(Clone, Debug)]
pub struct PrivateExpGadget<const ALPHA_BITS: usize> {}
impl<const ALPHA_BITS: usize> PrivateExpGadget<ALPHA_BITS> {
    /// Compute x^\alpha where `x` is public and alpha is private
    pub fn exp_private_fixed_base<L, CS>(
        x: Scalar,
        alpha: L,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Bit decompose the exponent, this removes the need to check `is_odd` at every
        // iteration
        let alpha_bits = ToBitsGadget::<ALPHA_BITS>::to_bits(alpha, cs)?;
        Self::exp_private_fixed_base_impl::<L, CS>(x, &alpha_bits, cs)
    }

    /// Compute x^\alpha where both x and alpha are private values
    pub fn exp_private<L, CS>(x: L, alpha: L, cs: &mut CS) -> Result<LinearCombination, R1CSError>
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Bit decompose the exponent, this removes the need to check `is_odd` at every
        // iteration
        let alpha_bits = ToBitsGadget::<ALPHA_BITS>::to_bits(alpha, cs)?;

        let x_lc: LinearCombination = x.into();
        Self::exp_private_impl(x_lc, &alpha_bits, cs)
    }

    /// An implementation helper for fixed base exponentiation that assumes a bit decomposition of
    /// the exponent is passed in
    fn exp_private_fixed_base_impl<L, CS>(
        x: Scalar,
        alpha_bits: &[Variable],
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        if alpha_bits.is_empty() {
            return Ok(LinearCombination::from(Scalar::one()));
        }

        // Check whether all bits are zero
        let alpha_zero = Self::all_bits_zero(alpha_bits, cs);
        let is_odd = alpha_bits[0];

        // Recursive call
        let recursive_result = Self::exp_private_fixed_base_impl::<L, CS>(x, &alpha_bits[1..], cs)?;
        let (_, _, recursive_doubled) = cs.multiply(recursive_result.clone(), recursive_result);

        // If the value is odd multiply by an extra copy of `x`
        let recursive_plus_one = x * recursive_doubled;

        // Mux between the two results depending on whether the current exponent is odd or even
        let odd_bit_selection: LinearCombination =
            CondSelectGadget::select(recursive_plus_one, recursive_doubled.into(), is_odd, cs);

        // Mask the value of the output if alpha is already zero
        let zero_mask =
            CondSelectGadget::select(Variable::One().into(), odd_bit_selection, alpha_zero, cs);

        Ok(zero_mask)
    }

    /// An implementation helper that assumes a bit decomposition of the exponent
    fn exp_private_impl<L, CS>(
        x: L,
        alpha_bits: &[Variable],
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        if alpha_bits.is_empty() {
            return Ok(LinearCombination::from(Scalar::one()));
        }

        let x_lc: LinearCombination = x.into();

        // Check whether all bits are zero
        let alpha_zero = Self::all_bits_zero(alpha_bits, cs);
        let is_odd = alpha_bits[0];

        // Recursive call
        let recursive_result = Self::exp_private_impl(x_lc.clone(), &alpha_bits[1..], cs)?;
        let (_, _, recursive_doubled) = cs.multiply(recursive_result.clone(), recursive_result);

        // If the value is odd multiply by an extra copy of `x`
        let (_, _, recursive_plus_one) = cs.multiply(x_lc, recursive_doubled.into());

        // Mux between the two results depending on whether the current exponent is odd or even
        let odd_bit_selection: LinearCombination =
            CondSelectGadget::select(recursive_plus_one, recursive_doubled, is_odd, cs);

        // Mask the value of the output if alpha is already zero
        let zero_mask =
            CondSelectGadget::select(Variable::One().into(), odd_bit_selection, alpha_zero, cs);

        Ok(zero_mask)
    }

    /// Returns whether all the given bits are zero, it is assumed that these values
    /// are constrained to be binary elsewhere in the circuit
    fn all_bits_zero<L, CS>(bits: &[L], cs: &mut CS) -> Variable
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Add all the bits
        let mut bit_sum: LinearCombination = Variable::Zero().into();
        for bit in bits
            .iter()
            .map(|bit| Into::<LinearCombination>::into(bit.clone()))
        {
            bit_sum += bit;
        }

        EqZeroGadget::eq_zero(bit_sum, cs)
    }
}

// -----------------------
// | Multiprover Gadgets |
// -----------------------

/// A multiprover implementation of the exp gadget
pub struct MultiproverExpGadget<'a> {
    /// Phantom
    _phantom: &'a PhantomData<()>,
}

impl<'a> MultiproverExpGadget<'a> {
    /// Apply the gadget to the input
    pub fn exp<L, CS>(
        x: L,
        alpha: u64,
        fabric: MpcFabric,
        cs: &mut CS,
    ) -> Result<MpcLinearCombination, ProverError>
    where
        L: MpcLinearCombinationLike,
        CS: MpcRandomizableConstraintSystem,
    {
        if alpha == 0 {
            Ok(MpcLinearCombination::from_scalar(Scalar::one(), fabric))
        } else if alpha == 1 {
            Ok(x.into())
        } else if alpha % 2 == 0 {
            let recursive_result = MultiproverExpGadget::exp(x, alpha / 2, fabric, cs)?;
            let (_, _, out_var) = cs
                .multiply(&recursive_result, &recursive_result)
                .map_err(ProverError::Collaborative)?;
            Ok(out_var.into())
        } else {
            let x_lc = x.into();
            let recursive_result =
                MultiproverExpGadget::exp(x_lc.clone(), (alpha - 1) / 2, fabric, cs)?;
            let (_, _, out_var1) = cs
                .multiply(&recursive_result, &recursive_result)
                .map_err(ProverError::Collaborative)?;
            let (_, _, out_var2) = cs
                .multiply(&out_var1.into(), &x_lc)
                .map_err(ProverError::Collaborative)?;
            Ok(out_var2.into())
        }
    }
}

#[cfg(test)]
mod arithmetic_tests {
    use circuit_types::traits::CircuitBaseType;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, Prover, Variable},
        PedersenGens,
    };
    use mpc_stark::algebra::scalar::Scalar;
    use num_bigint::BigUint;
    use num_integer::Integer;
    use rand::{thread_rng, RngCore};
    use renegade_crypto::fields::{
        bigint_to_scalar, biguint_to_scalar, get_scalar_field_modulus, scalar_to_biguint,
    };

    use super::{DivRemGadget, ExpGadget, PrivateExpGadget};

    /// Tests the single prover exponentiation gadget
    #[test]
    fn test_single_prover_exp() {
        // Generate a random input
        let mut rng = thread_rng();
        let alpha = rng.next_u32(); // Compute x^\alpha
        let random_value = Scalar::random(&mut rng);

        let random_bigint = scalar_to_biguint(&random_value);
        let expected_res = random_bigint.modpow(&BigUint::from(alpha), &get_scalar_field_modulus());
        let expected_scalar = bigint_to_scalar(&expected_res.into());

        // Build a constraint system
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        // Create the circuit
        let base_var = random_bigint.commit_public(&mut prover);
        let res = ExpGadget::exp(base_var, alpha as u64, &mut prover);

        // Check the result
        assert_eq!(expected_scalar, prover.eval(&res));
    }

    /// Tests the single prover exponent gadget on a private exponent
    #[test]
    fn test_private_exp_gadget() {
        let mut rng = thread_rng();
        let alpha_bytes = 8;
        let mut random_bytes = vec![0u8; alpha_bytes];
        rng.fill_bytes(&mut random_bytes);

        let alpha = biguint_to_scalar(&BigUint::from_bytes_le(&random_bytes));
        let x = Scalar::random(&mut rng);

        // Compute the expected exponentiation result
        let x_bigint = scalar_to_biguint(&x);
        let alpha_bigint = scalar_to_biguint(&alpha);
        let expected = x_bigint.modpow(&alpha_bigint, &get_scalar_field_modulus());

        // Build a constraint system
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        let x_var = x_bigint.commit_public(&mut prover);
        let alpha_var = alpha_bigint.commit_public(&mut prover);
        let res =
            PrivateExpGadget::<64 /* ALPHA_BITS */>::exp_private(x_var, alpha_var, &mut prover)
                .unwrap();

        // Check the result
        assert_eq!(biguint_to_scalar(&expected), prover.eval(&res));
    }

    /// Tests the div_rem gadget
    #[test]
    fn test_div_rem() {
        // Sample random inputs
        let mut rng = thread_rng();
        let random_dividend = BigUint::from(rng.next_u32());
        let random_divisor = BigUint::from(rng.next_u32());

        let (expected_q, expected_r) = random_dividend.div_rem(&random_divisor);

        // Build a constraint system
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        // Allocate the inputs in the constraint system
        let dividend_var = prover.commit_public(biguint_to_scalar(&random_dividend));
        let divisor_var = prover.commit_public(biguint_to_scalar(&random_divisor));

        let (q_res, r_res) =
            DivRemGadget::<32 /* bitlength */>::div_rem(dividend_var, divisor_var, &mut prover);
        prover.constrain(q_res - biguint_to_scalar(&expected_q) * Variable::One());
        prover.constrain(r_res - biguint_to_scalar(&expected_r) * Variable::One());

        assert!(prover.constraints_satisfied());
    }
}
