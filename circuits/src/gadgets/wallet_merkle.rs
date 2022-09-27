use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{
    fields::fp::FpVar,
    prelude::{Boolean, EqGadget},
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use arkworks_native_gadgets::poseidon::{sbox::PoseidonSbox, Poseidon, PoseidonParameters};
use arkworks_r1cs_gadgets::{
    merkle_tree::PathVar,
    poseidon::{FieldHasherGadget, PoseidonGadget},
};

use crate::constants::{POSEIDON_MDS_MATRIX_T_3, POSEIDON_ROUND_CONSTANTS_T_3};

use super::poseidon::{PoseidonHashInput, PoseidonSpongeWrapperVar, PoseidonVectorHashGadget};

/**
 * Groups gadgets that verify Merkle proofs for wallet balances and orders
 */

pub struct MerklePoseidonGadget<const DEPTH: usize, F: PrimeField> {
    _phantom: PhantomData<F>,
}

impl<const DEPTH: usize, F: PrimeField> MerklePoseidonGadget<DEPTH, F> {
    pub fn check_opening(
        cs: &mut ConstraintSystemRef<F>,
        leaf: &impl PoseidonHashInput<F>,
        tree_hasher: Poseidon<F>,
        path: &PathVar<F, PoseidonGadget<F>, DEPTH>,
        root: &FpVar<F>,
    ) -> Result<(), SynthesisError> {
        let mut hasher = PoseidonSpongeWrapperVar::new(cs.clone());
        let hash_digest = PoseidonVectorHashGadget::evaluate(leaf, &mut hasher)?;

        let tree_hasher_var = PoseidonGadget::from_native(cs, tree_hasher)?;
        path.check_membership(root, &hash_digest, &tree_hasher_var)?
            .enforce_equal(&Boolean::TRUE)?;

        Ok(())
    }
}

pub fn get_merkle_hash_params<F: PrimeField>() -> PoseidonParameters<F> {
    PoseidonParameters {
        round_keys: POSEIDON_ROUND_CONSTANTS_T_3()
            .into_iter()
            .flatten()
            .collect(),
        mds_matrix: POSEIDON_MDS_MATRIX_T_3(),
        full_rounds: 56,
        partial_rounds: 8,
        width: 3,              /* t from the paper */
        sbox: PoseidonSbox(5), /* \alpha */
    }
}
