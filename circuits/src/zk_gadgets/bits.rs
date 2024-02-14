//! Groups gadgets for going from scalar -> bits and from bits -> scalar
//!
//! We do not reuse gadgets between single and multi-prover circuits, because
//! bit operations require particular care in the multiprover context to be done
//! efficiently

use std::iter;

use ark_ff::One;
use bitvec::{order::Lsb0, slice::BitSlice};
use circuit_types::{traits::CircuitVarType, Fabric, MpcPlonkCircuit, PlonkCircuit};
use constants::{Scalar, ScalarField};
use itertools::Itertools;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar, Variable};

use crate::{mpc_gadgets::bits::to_bits_le, SCALAR_BITS_MINUS_TWO};

/// Convert a scalar to its little endian bit representation where each bit
/// is itself a `Scalar`
pub fn scalar_to_bits_le<const N: usize>(a: &Scalar) -> Vec<Scalar> {
    let a_biguint = a.to_biguint();
    BitSlice::<_, Lsb0>::from_slice(&a_biguint.to_bytes_le())
        .iter()
        .by_vals()
        .map(|bit| if bit { Scalar::one() } else { Scalar::zero() })
        .chain(iter::repeat(Scalar::zero()))
        .take(N)
        .collect_vec()
}

/// Singleprover implementation of the `ToBits` gadget
pub struct ToBitsGadget<const D: usize> {}
impl<const D: usize> ToBitsGadget<D> {
    /// Decompose and reconstruct a value to and from its bitwise representation
    /// with a fixed bitlength
    ///
    /// This is useful as a range check for a power of two, wherein the value
    /// may only be represented in 2^D bits
    pub fn decompose_and_reconstruct(
        a: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        let bits = Self::to_bits(a, cs)?;
        Self::bit_reconstruct(&bits, cs)
    }

    /// Converts a value to its bitwise representation in a single-prover
    /// constraint system
    pub fn to_bits(a: Variable, cs: &mut PlonkCircuit) -> Result<Vec<BoolVar>, CircuitError> {
        // Convert the scalar to bits
        let a_scalar = a.eval(cs);
        let bits = scalar_to_bits_le::<D>(&a_scalar);

        // Allocate the bits in the constraint system
        let bit_vars = bits
            .iter()
            .map(Scalar::inner)
            .map(|bit| cs.create_boolean_variable(bit))
            .collect::<Result<Vec<_>, _>>()?;

        // Ensure that the decomposition is correctly done
        let two = ScalarField::from(2u64);
        let coeffs = (0..D)
            .scan(ScalarField::one(), |state, _| {
                let res = *state;
                *state *= two;
                Some(res)
            })
            .collect_vec();

        let bits_vars = bit_vars.iter().map(|&b| Variable::from(b)).collect_vec();
        cs.lc_sum(&bits_vars, &coeffs)?;

        Ok(bit_vars)
    }

    /// Reconstruct a value from its bitwise representation
    ///
    /// Assumes a little-endian representation
    pub fn bit_reconstruct(
        bits: &[BoolVar],
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        // Constrain the bit decomposition to be correct
        // This implicitly constrains the value to be greater than zero, i.e. if it can
        // be represented without the highest bit set, then it is greater than
        // zero. This assumes a two's complement representation
        let two = ScalarField::from(2u64);
        let coeffs = (0..D)
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

/// Takes a scalar and returns its bit representation, constrained to be correct
///
/// D is the bitlength of the input vector to bitify
pub struct MultiproverToBitsGadget<const D: usize>;
impl<const D: usize> MultiproverToBitsGadget<D> {
    /// Converts a value into its bitwise representation
    pub fn to_bits(
        a: Variable,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<Vec<Variable>, CircuitError> {
        assert!(
            D <= SCALAR_BITS_MINUS_TWO,
            "a positive value may only have {:?} bits",
            SCALAR_BITS_MINUS_TWO
        );

        // Evaluate the linear combination so that we can use a raw MPC to get the bits
        let a_scalar = a.eval_multiprover(cs);

        // Convert the scalar to bits in a raw MPC gadget
        let bits = to_bits_le::<D /* bits */>(&a_scalar, fabric);

        // Allocate the bits in the constraint system, and constrain their inner product
        // with 1, 2, 4, ..., 2^{D-1} to be equal to the input value
        let bit_vars = bits
            .into_iter()
            .map(|bit| cs.create_boolean_variable(bit).map(Into::into))
            .collect::<Result<Vec<_>, _>>()?;

        let coeffs = (0..D)
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

#[cfg(test)]
mod bits_test {
    use ark_mpc::PARTY0;
    use circuit_types::{
        traits::{CircuitBaseType, MpcBaseType, MultiproverCircuitBaseType},
        MpcPlonkCircuit, PlonkCircuit,
    };
    use constants::Scalar;
    use mpc_relation::traits::Circuit;
    use rand::{thread_rng, Rng, RngCore};
    use renegade_crypto::fields::{bigint_to_scalar_bits, scalar_to_bigint};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::zk_gadgets::{bits::MultiproverToBitsGadget, comparators::NotEqualGadget};

    use super::ToBitsGadget;

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
        let res = ToBitsGadget::<64 /* bits */>::to_bits(input_var, &mut cs).unwrap();

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
        let big_value: u128 = rng.gen();

        // Create a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let small_var = value.create_witness(&mut cs);
        let big_var = big_value.create_witness(&mut cs);

        // Decompose and reconstruct the successful value
        let small_res =
            ToBitsGadget::<BIT_LENGTH>::decompose_and_reconstruct(small_var, &mut cs).unwrap();
        cs.enforce_equal(small_var, small_res).unwrap();

        // Attempt to decompose and reconstruct a value that is too large
        let big_res =
            ToBitsGadget::<BIT_LENGTH>::decompose_and_reconstruct(big_var, &mut cs).unwrap();
        let ne = NotEqualGadget::not_equal(big_res, big_var, &mut cs).unwrap();

        cs.enforce_true(ne).unwrap();

        // Check that the constraint system is satisfied
        assert!(cs.check_circuit_satisfiability(&[]).is_ok());
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

                let res =
                    MultiproverToBitsGadget::<64 /* bits */>::to_bits(input_var, &fabric, &mut cs)
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
