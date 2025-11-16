//! Groups gadgets for going from scalar -> bits and from bits -> scalar
//!
//! We do not reuse gadgets between single and multi-prover circuits, because
//! bit operations require particular care in the multiprover context to be done
//! efficiently

use std::iter;

use ark_ff::One;
use bitvec::{order::Lsb0, slice::BitSlice};
use circuit_types::{Fabric, MpcPlonkCircuit, PlonkCircuit, traits::CircuitVarType};
use constants::{Scalar, ScalarField};
use itertools::Itertools;
use mpc_relation::{BoolVar, Variable, errors::CircuitError, traits::Circuit};

use crate::{SCALAR_BITS_MINUS_TWO, mpc_gadgets::bits::to_bits_le};

/// Convert a scalar to its little endian bit representation where each bit
/// is itself a `Scalar`
pub fn scalar_to_bits_le(a: &Scalar, n: usize) -> Vec<Scalar> {
    let a_biguint = a.to_biguint();
    BitSlice::<_, Lsb0>::from_slice(&a_biguint.to_bytes_le())
        .iter()
        .by_vals()
        .map(|bit| if bit { Scalar::one() } else { Scalar::zero() })
        .chain(iter::repeat(Scalar::zero()))
        .take(n)
        .collect_vec()
}

/// Singleprover implementation of the `ToBits` gadget
pub struct ToBitsGadget {}
impl ToBitsGadget {
    /// Decompose and reconstruct a value to and from its bitwise representation
    /// with a fixed bitlength
    ///
    /// This is useful as a range check for a power of two, wherein the value
    /// may only be represented in 2^D bits
    pub fn decompose_and_reconstruct(
        a: Variable,
        num_bits: usize,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let bits = Self::to_bits_unconstrained(a, num_bits, cs)?;
        Self::bit_reconstruct(&bits, cs)
    }

    /// Converts a value to its bitwise representation in a single-prover
    /// constraint system
    pub fn to_bits(
        a: Variable,
        num_bits: usize,
        cs: &mut PlonkCircuit,
    ) -> Result<Vec<BoolVar>, CircuitError> {
        let bits = Self::to_bits_unconstrained(a, num_bits, cs)?;
        let reconstructed = Self::bit_reconstruct(&bits, cs)?;
        cs.enforce_equal(reconstructed, a)?;

        Ok(bits)
    }

    /// Converts a value to its bitwise representation without constraining the
    /// value to be correct
    fn to_bits_unconstrained(
        a: Variable,
        num_bits: usize,
        cs: &mut PlonkCircuit,
    ) -> Result<Vec<BoolVar>, CircuitError> {
        // Convert the scalar to bits
        let a_scalar = a.eval(cs);
        let bits = scalar_to_bits_le(&a_scalar, num_bits);

        // Allocate the bits in the constraint system
        bits.iter()
            .map(Scalar::inner)
            .map(|bit| cs.create_boolean_variable(bit))
            .collect::<Result<Vec<_>, _>>()
    }

    /// Reconstruct a value from its bitwise representation
    ///
    /// Assumes a little-endian representation
    pub fn bit_reconstruct(
        bits: &[BoolVar],
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let n = bits.len();
        let two = ScalarField::from(2u64);
        let coeffs = (0..n)
            .scan(ScalarField::one(), |state, _| {
                let res = *state;
                *state *= two;
                Some(res)
            })
            .collect_vec();

        let bits_vars = bits.iter().map(|&b| Variable::from(b)).collect_vec();
        cs.lc_sum(&bits_vars, &coeffs)
    }
}

/// A gadget to constrain a value to be representable in a given bitlength
pub struct BitRangeGadget;
impl BitRangeGadget {
    /// Constrain the given value to be representable in `D` bits
    pub fn constrain_bit_range(
        a: Variable,
        num_bits: usize,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Decompose into `n` bits, this checks that the reconstruction is
        // correct, so this will also force the value to be within the range [0,
        // 2^n-1]
        ToBitsGadget::to_bits(a, num_bits, cs).map(|_| ())
    }
}

/// Takes a scalar and returns its bit representation, constrained to be correct
pub struct MultiproverToBitsGadget;
impl MultiproverToBitsGadget {
    /// Converts a value into its bitwise representation
    ///
    /// `num_bits` is the number of bits to convert the value to
    pub fn to_bits(
        a: Variable,
        num_bits: usize,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<Vec<Variable>, CircuitError> {
        assert!(
            num_bits <= SCALAR_BITS_MINUS_TWO,
            "a positive value may only have {:?} bits",
            SCALAR_BITS_MINUS_TWO
        );

        // Evaluate the linear combination so that we can use a raw MPC to get the bits
        let a_scalar = a.eval_multiprover(cs);

        // Convert the scalar to bits in a raw MPC gadget
        let bits = to_bits_le(&a_scalar, num_bits, fabric);

        // Allocate the bits in the constraint system, and constrain their inner product
        // with 1, 2, 4, ..., 2^{n-1} to be equal to the input value
        let bit_vars = bits
            .into_iter()
            .map(|bit| cs.create_boolean_variable(bit).map(Into::into))
            .collect::<Result<Vec<_>, _>>()?;

        let coeffs = (0..num_bits)
            .scan(ScalarField::one(), |state, _| {
                let res = *state;
                *state *= ScalarField::from(2u64);
                Some(res)
            })
            .collect_vec();

        let reconstructed = cs.lc_sum(&bit_vars, &coeffs)?;
        cs.enforce_equal(reconstructed, a)?;

        Ok(bit_vars)
    }
}

/// Constrain a value to be within a specific bit range in a multiprover context
pub struct MultiproverBitRangeGadget;
impl MultiproverBitRangeGadget {
    /// Constrain a value to be within a specific bit range
    pub fn constrain_bit_range(
        value: Variable,
        num_bits: usize,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Decompose into `n` bits, this checks that the reconstruction is correct, so
        // this will also force the value to be within the range [0, 2^n-1]
        MultiproverToBitsGadget::to_bits(value, num_bits, fabric, cs).map(|_| ())
    }
}

#[cfg(test)]
mod bits_test {
    use ark_mpc::PARTY0;
    use circuit_types::{
        MpcPlonkCircuit, PlonkCircuit,
        traits::{CircuitBaseType, MpcBaseType, MultiproverCircuitBaseType},
    };
    use constants::Scalar;
    use itertools::Itertools;
    use mpc_relation::traits::Circuit;
    use rand::{Rng, RngCore, thread_rng};
    use renegade_crypto::fields::{bigint_to_scalar_bits, scalar_to_bigint};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        SCALAR_MAX_BITS,
        zk_gadgets::{
            bits::{BitRangeGadget, MultiproverBitRangeGadget, MultiproverToBitsGadget},
            comparators::NotEqualGadget,
        },
    };

    use super::ToBitsGadget;

    // -----------
    // | Helpers |
    // -----------

    /// Generate a random scalar under the specified bit amount
    fn random_bitlength_scalar(bit_length: usize) -> Scalar {
        let mut rng = thread_rng();

        let bits = (0..bit_length).map(|_| rng.gen_bool(0.5)).collect_vec();
        let mut res = Scalar::zero();

        for bit in bits.into_iter() {
            res *= Scalar::from(2u8);
            if bit {
                res += Scalar::one();
            }
        }

        res
    }

    /// Test that the to_bits single-prover gadget functions correctly
    #[test]
    fn test_to_bits() {
        // Create a random input to bitify
        let mut rng = thread_rng();
        let random_value = rng.next_u64();

        // Create the statement by bitifying the input
        let witness = Scalar::from(random_value);
        let bits = bigint_to_scalar_bits::<64 /* bits */>(&scalar_to_bigint(&witness));

        // Create a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();

        // Bitify the input
        let input_var = witness.create_witness(&mut cs);
        let res = ToBitsGadget::to_bits(input_var, 64 /* bits */, &mut cs).unwrap();

        for (bit, expected) in res.into_iter().zip(bits.into_iter()) {
            cs.enforce_constant(bit.into(), expected.inner()).unwrap();
        }

        // Check that the constraint system is satisfied
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }

    /// Test decomposing and reconstructing a value
    #[test]
    fn test_decompose_reconstruct() {
        const BIT_LENGTH: usize = 64;
        let mut rng = thread_rng();
        let value = rng.next_u64();
        let big_value: u128 = rng.r#gen();

        // Create a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let small_var = value.create_witness(&mut cs);
        let big_var = big_value.create_witness(&mut cs);

        // Decompose and reconstruct the successful value
        let small_res =
            ToBitsGadget::decompose_and_reconstruct(small_var, BIT_LENGTH, &mut cs).unwrap();
        cs.enforce_equal(small_var, small_res).unwrap();

        // Attempt to decompose and reconstruct a value that is too large
        let big_res =
            ToBitsGadget::decompose_and_reconstruct(big_var, BIT_LENGTH, &mut cs).unwrap();
        let ne = NotEqualGadget::not_equal(big_res, big_var, &mut cs).unwrap();

        cs.enforce_true(ne).unwrap();

        // Check that the constraint system is satisfied
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
    }

    #[tokio::test]
    async fn test_bit_range_gadget() {
        const BIT_LEN: usize = 120; // Placeholder for the constant value

        let two_to_bitlength = Scalar::from(2u8).pow(BIT_LEN as u64);
        let rem_bitlength = SCALAR_MAX_BITS - BIT_LEN;
        let random_high_scalar = random_bitlength_scalar(rem_bitlength) + two_to_bitlength;
        let cases = [
            (random_bitlength_scalar(BIT_LEN), true), // Random value below bitlength
            (two_to_bitlength - Scalar::one(), true), // Maximum value for bitlength
            (Scalar::zero(), true),                   // Minimum value for bitlength
            (two_to_bitlength, false),                // Minimum invalid value
            (two_to_bitlength + Scalar::one(), false), // Bitlength plus one
            (random_high_scalar, false),              // Random value above bitlength
        ];

        // Test each case in a singleprover context
        for (i, (value, is_valid)) in cases.into_iter().enumerate() {
            let mut cs = PlonkCircuit::new_turbo_plonk();
            let value_var = value.create_witness(&mut cs);
            BitRangeGadget::constrain_bit_range(value_var, BIT_LEN, &mut cs).unwrap();

            let res = cs.check_circuit_satisfiability(&[]).is_ok();
            assert_eq!(res, is_valid, "test case {i} failed")
        }

        // Test each case in a multiprover context
        for (i, (value, is_valid)) in cases.into_iter().enumerate() {
            let (res, _) = execute_mock_mpc(move |fabric| async move {
                let mut cs = MpcPlonkCircuit::new(fabric.clone());
                let val = value.allocate(PARTY0, &fabric);
                let value_var = val.create_shared_witness(&mut cs);

                MultiproverBitRangeGadget::constrain_bit_range(
                    value_var, BIT_LEN, &fabric, &mut cs,
                )
                .unwrap();

                cs.check_circuit_satisfiability(&[]).is_ok()
            })
            .await;

            assert_eq!(res, is_valid, "test case {i} failed")
        }
    }

    /// Tests the multiprover to_bits gadget
    #[tokio::test]
    async fn test_to_bits_multiprover() {
        // Create a random input to bitify
        let mut rng = thread_rng();
        let random_value = rng.next_u64();

        // Create the statement by bitifying the input
        let witness = Scalar::from(random_value);
        let bits = bigint_to_scalar_bits::<64 /* bits */>(&scalar_to_bigint(&witness));

        // Create a constraint system
        let (res, _) = execute_mock_mpc(move |fabric| {
            let bits = bits.clone();
            async move {
                let mut cs = MpcPlonkCircuit::new(fabric.clone());
                let val = witness.allocate(PARTY0, &fabric);
                let input_var = val.create_shared_witness(&mut cs);

                let res = MultiproverToBitsGadget::to_bits(
                    input_var, 64, // bits
                    &fabric, &mut cs,
                )
                .unwrap();
                for (bit, expected) in res.into_iter().zip(bits.into_iter()) {
                    cs.enforce_constant(bit, expected.inner()).unwrap();
                }

                cs.check_circuit_satisfiability(&[])
            }
        })
        .await;

        assert!(res.is_ok());
    }
}
