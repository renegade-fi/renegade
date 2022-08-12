use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::{Boolean, EqGadget}, ToBytesGadget, uint8::UInt8};
use ark_relations::r1cs::SynthesisError;

/**
 * Generic helper circuits for comparisons
 */

// Returns a boolean value x >= y
pub struct GreaterThanEqGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl <F: PrimeField> GreaterThanEqGadget<F> {
    pub fn greater_than(
        a: FpVar<F>,
        b: FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let diff = a - b;
        let diff_bytes = diff.to_bytes()?;

        diff_bytes[diff_bytes.len() - 1].is_eq(&UInt8::<F>::constant(0))
    }
}