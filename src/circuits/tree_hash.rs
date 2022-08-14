use std::{marker::PhantomData, borrow::Borrow};

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::{AllocVar, Boolean}, uint64::UInt64, uint8::UInt8, ToBitsGadget};
use ark_relations::r1cs::SynthesisError;
use ark_sponge::poseidon::PoseidonParameters;

use crate::state::Wallet;

use super::{types::{OrderVar, WalletVar}, wallet_match::SystemField, constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3}};


/**
 * Groups logic for the implementation of a Merkle hash
 */

/**
 * Helpers
*/

// Converts a UInt64 constraint variable into a field element
fn u64_to_field_element<F: PrimeField>(a: &UInt64<F>) -> Result<FpVar<F>, SynthesisError> {
    Boolean::le_bits_to_fp_var(&a.to_bits_le())
}

fn u8_to_field_element<F: PrimeField>(a: &UInt8<F>) -> Result<FpVar<F>, SynthesisError> {
   Boolean::le_bits_to_fp_var(&a.to_bits_le()?)
}

/**
 * Constraint system types
 */

// Poseidon hash parameters for a 2-1 hash
#[derive(Debug)]
pub struct Poseidon2To1Params<F: PrimeField>(PoseidonParameters<F>);

impl<F: PrimeField> Default for Poseidon2To1Params<F> {
    fn default() -> Self {
        Self(
            // Poseidon parameters taken from the paper (tables 2 and 8): https://eprint.iacr.org/2019/458.pdf
            // t = 3 here for a 2 to 1 hash (to be composed into a Merkle tree)
            PoseidonParameters::new(
                8 /* full_rounds */,				// Number of full S box rounds to apply before and after partial rounds
                33 /* partial_rounds */,			// Number of partial S box rounds, applying the S-box to only one element
                5 /* alpha */,					// \alpha from the paper; used to parameterize the permutation y = x^\alpha (mod p)
                POSEIDON_MDS_MATRIX_T_3::<F>() /* mds */,	// The MDS matrix used as a linear layer after the S-box
                POSEIDON_ROUND_CONSTANTS_T_3::<F>() /* ark */,	// The round constants for each round, xor'd with the input to each round
            )
        )
    }
}

pub struct PoseidonTreeHashInput<F: PrimeField> {
    leaves: Vec<FpVar<F>>
}

// Alloc a tree hash input from a wallet
impl<F: PrimeField> AllocVar<WalletVar<F>, F> for PoseidonTreeHashInput<F> {
    fn new_variable<T: Borrow<WalletVar<F>>>(
        cs: impl Into<ark_relations::r1cs::Namespace<F>>,
        f: impl FnOnce() -> Result<T, SynthesisError>,
        mode: ark_r1cs_std::prelude::AllocationMode,
    ) -> Result<Self, SynthesisError> {
        // Turn every order variable into a field element and concat
        let mut leaves = Vec::<FpVar<F>>::new();
        f().and_then(|wallet: T| {
            wallet.borrow()
                .orders
                .iter()
                .map(|order| {
                    leaves.push(u64_to_field_element(&order.base_mint)?);
                    leaves.push(u64_to_field_element(&order.quote_mint)?);
                    leaves.push(u8_to_field_element(&order.side)?);
                    leaves.push(u64_to_field_element(&order.price)?);
                    leaves.push(u64_to_field_element(&order.amount)?);
                    Ok(())
                })
                .collect::<Result<Vec<()>, SynthesisError>>()?;
        
            Ok(PoseidonTreeHashInput { leaves })
        })
    }
}


/**
 * Gadgets
 */
pub struct PoseidonTreeHashGadget<F: PrimeField> {
    _phantom: PhantomData<F>
}

impl<F: PrimeField> PoseidonTreeHashGadget<F> {
    fn evaluate(
        input: PoseidonTreeHashInput<F>,
        params: Poseidon2To1Params<F>
    ) -> Result<FpVar<F>, SynthesisError> {
        // Assume the input to be of length 2^n for some n 
    
        Err(SynthesisError::AssignmentMissing)
    }
}
