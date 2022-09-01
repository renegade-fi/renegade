use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::{Boolean, EqGadget}, ToBytesGadget, uint8::UInt8, uint64::UInt64, select::CondSelectGadget, ToBitsGadget};
use ark_relations::r1cs::SynthesisError;

/**
 * Generic helper circuits for comparisons
 */

// Returns a boolean value a >= b
pub struct GreaterThanEqGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl <F: PrimeField> GreaterThanEqGadget<F> {
    pub fn greater_than(
        a: &FpVar<F>,
        b: &FpVar<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let diff = a - b;
        let diff_bytes = diff.to_bytes()?;

        diff_bytes[diff_bytes.len() - 1].is_eq(&UInt8::<F>::constant(0))
    }

    pub fn greater_than_u64(
        a: &UInt64<F>,
        b: &UInt64<F>,
    ) -> Result<Boolean<F>, SynthesisError> {
        let a_fp = &Boolean::le_bits_to_fp_var(&a.to_bits_le())?;
        let b_fp = &Boolean::le_bits_to_fp_var(&b.to_bits_le())?;

        Self::greater_than(a_fp, b_fp)
    }
}

// Returns min(a, b)
pub struct MinGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl <F: PrimeField> MinGadget<F> {
    pub fn min(
        a: FpVar<F>,
        b: FpVar<F>
    ) -> Result<FpVar<F>, SynthesisError> {
        let a_greater_than = GreaterThanEqGadget::greater_than(&a, &b)?;

        FpVar::<F>::conditionally_select(
            &a_greater_than /* cond */, 
            &b /* true_value */, 
            &a /* false_value */
        )
    }

    // Computes the min of two UInt64; casting to and from FpVar
    pub fn min_uint64(
        a: UInt64<F>,
        b: UInt64<F>
    ) -> Result<UInt64<F>, SynthesisError> {
        let a_fp = Boolean::le_bits_to_fp_var(&a.to_bits_le())?;
        let b_fp = Boolean::le_bits_to_fp_var(&b.to_bits_le())?;

        let min_fp = Self::min(a_fp, b_fp)?;
        Ok(UInt64::from_bits_le(&min_fp.to_bits_le()?[..64]))
    }
}

// Returns: a if cond else 0
pub struct MaskGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl <F: PrimeField> MaskGadget<F> {
    pub fn mask_uint64(
        a: &UInt64<F>,
        cond: &Boolean<F>
    ) -> Result<UInt64<F>, SynthesisError> {
        UInt64::conditionally_select(
            cond, 
            a /* true_value */, 
            &UInt64::constant(0) /* false_value */
        )
    }

    pub fn mask_uint8(
        a: &UInt8<F>,
        cond: &Boolean<F>
    ) -> Result<UInt8<F>, SynthesisError> {
        UInt8::conditionally_select(
            cond,
            a /* true_value */,
            &UInt8::constant(0) /* false_value */
        )
    }
}