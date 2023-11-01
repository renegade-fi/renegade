//! Groups gadgets around computing Merkle entries and proving Merkle openings
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_types::{merkle::MerkleOpeningVar, traits::LinearCombinationLike};
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem},
    r1cs_mpc::R1CSError,
};
use mpc_stark::algebra::scalar::Scalar;
use renegade_crypto::hash::default_poseidon_params;
use std::ops::Neg;

use super::poseidon::PoseidonHashGadget;

/// The single-prover hash gadget, computes the Merkle root of a leaf given a
/// path of sister nodes
pub struct PoseidonMerkleHashGadget<const HEIGHT: usize> {}
impl<const HEIGHT: usize> PoseidonMerkleHashGadget<HEIGHT> {
    /// Compute the root of the tree given the leaf node and the path of
    /// sister nodes leading to the root
    pub fn compute_root<L1, L2, CS>(
        leaf_node: Vec<L1>,
        opening: MerkleOpeningVar<L2, HEIGHT>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Hash the leaf_node into a field element
        let leaf_hash: LinearCombination = Self::leaf_hash(&leaf_node, cs)?;
        Self::compute_root_prehashed(leaf_hash, opening, cs)
    }

    /// Compute the root given an already hashed leaf, i.e. do not hash a leaf
    /// buffer first
    pub fn compute_root_prehashed<L1, L2, CS>(
        leaf_node: L1,
        opening: MerkleOpeningVar<L2, HEIGHT>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Hash the leaf_node into a field element
        let mut current_hash: LinearCombination = leaf_node.into();
        for (path_elem, lr_select) in opening.elems.into_iter().zip(opening.indices.into_iter()) {
            // Select the left and right hand sides based on whether this node in the
            // opening represents the left or right hand child of its parent
            let (lhs, rhs) = Self::select_left_right(
                current_hash.clone(),
                path_elem.into(),
                lr_select.into(),
                cs,
            );
            current_hash = Self::hash_internal_nodes(&lhs, &rhs, cs)?;
        }

        Ok(current_hash)
    }

    /// Compute the root and constrain it to an expected value
    pub fn compute_and_constrain_root<L1, L2, CS>(
        leaf_node: Vec<L1>,
        opening: MerkleOpeningVar<L2, HEIGHT>,
        expected_root: L1,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        let root = Self::compute_root(leaf_node, opening, cs)?;
        cs.constrain(expected_root.into() - root);

        Ok(())
    }

    /// Compute the root from a prehashed leaf and constrain it to an expected
    /// value
    pub fn compute_and_constrain_root_prehashed<L1, L2, CS>(
        leaf_node: L1,
        opening: MerkleOpeningVar<L2, HEIGHT>,
        expected_root: L1,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        L1: LinearCombinationLike,
        L2: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        let root = Self::compute_root_prehashed(leaf_node, opening, cs)?;
        cs.constrain(expected_root.into() - root);

        Ok(())
    }

    /// Selects whether to place the current hash on the left or right hand
    /// side of the 2-1 hash.
    ///
    /// This is based on whether the current hash represents the left or right
    /// child of its parent to be computed
    fn select_left_right<L, CS>(
        current_hash: L,
        sister_node: L,
        lr_select: L,
        cs: &mut CS,
    ) -> (LinearCombination, LinearCombination)
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        let current_hash_lc = current_hash.into();
        let sister_node_lc = sister_node.into();
        let lr_select_lc = lr_select.into();

        // If lr_select == 0 { current_hash } else { sister_node }
        //      ==> current_hash * (1 - lr_select) + sister_node * lr_select
        let (_, _, left_child_term1) = cs.multiply(
            current_hash_lc.clone(),
            lr_select_lc.clone().neg() + Scalar::one(),
        );
        let (_, _, left_child_term2) = cs.multiply(sister_node_lc.clone(), lr_select_lc);

        let left_child = left_child_term1 + left_child_term2;

        // If lr_select == 0 { sister_node } else { current_hash }
        // We can avoid an extra multiplication here, because we know the lhs term, the
        // rhs term is equal to the other term, which can be computed by
        // addition alone      rhs = a + b - lhs
        let right_child = current_hash_lc + sister_node_lc - left_child.clone();
        (left_child, right_child)
    }

    /// Hash the value at the leaf into a bulletproof constraint value
    fn leaf_hash<L, CS>(values: &[L], cs: &mut CS) -> Result<LinearCombination, R1CSError>
    where
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    {
        // Build a sponge hasher
        let hasher_params = default_poseidon_params();
        let mut hasher = PoseidonHashGadget::new(hasher_params);
        hasher.batch_absorb(values, cs)?;

        hasher.squeeze(cs)
    }

    /// Hash two internal nodes in the (binary) Merkle tree, giving the tree
    /// value at the parent node
    fn hash_internal_nodes<CS: RandomizableConstraintSystem>(
        left: &LinearCombination,
        right: &LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        let hasher_params = default_poseidon_params();
        let mut hasher = PoseidonHashGadget::new(hasher_params);
        hasher.batch_absorb(&[left.clone(), right.clone()], cs)?;

        hasher.squeeze(cs)
    }
}

#[cfg(test)]
pub(crate) mod merkle_test {
    use ark_crypto_primitives::{
        crh::{
            poseidon::{TwoToOneCRH, CRH},
            CRHScheme,
        },
        merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    };
    use circuit_types::{merkle::MerkleOpening, traits::CircuitBaseType};
    use itertools::Itertools;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use mpc_stark::algebra::scalar::Scalar;
    use rand::{thread_rng, Rng};
    use renegade_crypto::hash::default_poseidon_params;

    use crate::zk_gadgets::merkle::PoseidonMerkleHashGadget;

    struct MerkleConfig {}
    impl Config for MerkleConfig {
        type Leaf = [Scalar::Field];
        type LeafDigest = Scalar::Field;
        type InnerDigest = Scalar::Field;

        type LeafHash = CRH<Scalar::Field>;
        type TwoToOneHash = TwoToOneCRH<Scalar::Field>;
        type LeafInnerDigestConverter = IdentityDigestConverter<Scalar::Field>;
    }

    /// Create a random sequence of field elements
    fn random_field_elements(n: usize) -> Vec<Scalar> {
        let mut rng = thread_rng();
        (0..n).map(|_| Scalar::random(&mut rng)).collect_vec()
    }

    /// Get the opening indices from the index, this can be done by
    /// bit-decomposing the input to determine incrementally which subtree a
    /// given index should be a part of.
    ///
    /// The tree indices from leaf to root are exactly the LSB decomposition of
    /// the scalar
    pub(crate) fn get_opening_indices<const HEIGHT: usize>(
        mut leaf_index: usize,
    ) -> [Scalar; HEIGHT]
    where
        [(); HEIGHT]: Sized,
    {
        let mut res = Vec::with_capacity(HEIGHT);
        for _ in 0..HEIGHT {
            res.push(match leaf_index % 2 {
                val @ 0..=1 => Scalar::from(val as u64),
                _ => unreachable!("impossible evaluation mod 2"),
            });

            leaf_index >>= 1;
        }

        res.try_into().unwrap()
    }

    #[test]
    #[allow(non_upper_case_globals)]
    fn test_against_arkworks() {
        // A random input at the leaf
        const leaf_size: usize = 6;
        let num_leaves = 32;
        const TREE_HEIGHT: usize = 10;

        // Build a random Merkle tree via arkworks
        let arkworks_params = default_poseidon_params();

        let mut merkle_tree =
            MerkleTree::<MerkleConfig>::blank(&arkworks_params, &arkworks_params, TREE_HEIGHT)
                .unwrap();

        let mut ark_leaf_data = Vec::with_capacity(num_leaves);
        for i in 0..num_leaves {
            let leaf_data: [Scalar::Field; leaf_size] = (*random_field_elements(leaf_size))
                .iter()
                .map(|s| s.inner())
                .collect_vec()
                .try_into()
                .unwrap();

            merkle_tree.update(i, &leaf_data).unwrap();
            ark_leaf_data.push(leaf_data);
        }

        // Generate a proof for a random index and prove it in the native gadget
        let random_index = thread_rng().gen_range(0..num_leaves);
        let expected_root = merkle_tree.root();
        let opening = merkle_tree.generate_proof(random_index).unwrap();
        let mut opening_scalars: Vec<Scalar::Field> = opening
            .auth_path
            .into_iter()
            .rev() // Path comes in reverse
            .collect_vec();

        // Hash the sister leaf of the given scalar
        let sister_leaf_data = if random_index % 2 == 0 {
            ark_leaf_data[random_index + 1]
        } else {
            ark_leaf_data[random_index - 1]
        };
        let sister_leaf_hash: Scalar::Field =
            CRH::evaluate(&arkworks_params, sister_leaf_data).unwrap();

        opening_scalars.insert(0, sister_leaf_hash);

        // Convert the leaf data for the given leaf to scalars
        let leaf_data = ark_leaf_data[random_index];

        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let leaf_vars = leaf_data
            .into_iter()
            .map(Scalar::from)
            .map(|x| x.commit_public(&mut prover))
            .collect_vec();

        let opening_var = MerkleOpening {
            elems: opening_scalars
                .into_iter()
                .map(Scalar::from)
                .collect_vec()
                .try_into()
                .unwrap(),
            indices: get_opening_indices::<{ TREE_HEIGHT - 1 }>(random_index),
        }
        .commit_public(&mut prover);
        let expected_root_var = Scalar::from(expected_root).commit_public(&mut prover);

        // Apply the constraints
        PoseidonMerkleHashGadget::compute_and_constrain_root(
            leaf_vars,
            opening_var,
            expected_root_var,
            &mut prover,
        )
        .unwrap();
        assert!(prover.constraints_satisfied());
    }

    #[test]
    #[allow(non_upper_case_globals)]
    fn test_invalid_witness() {
        // A random input at the leaf
        let mut rng = thread_rng();
        const leaf_size: usize = 6;
        const TREE_HEIGHT: usize = 10;

        let leaf_data: [Scalar::Field; leaf_size] = (0..leaf_size)
            .map(|_| Scalar::random(&mut rng))
            .map(|s| s.inner())
            .collect_vec()
            .try_into()
            .unwrap();

        // Compute the correct root via Arkworks
        let arkworks_params = default_poseidon_params();
        let mut merkle_tree =
            MerkleTree::<MerkleConfig>::blank(&arkworks_params, &arkworks_params, TREE_HEIGHT)
                .unwrap();
        merkle_tree.update(0 /* index */, &leaf_data).unwrap();

        // Random (incorrect) root
        let expected_root = Scalar::random(&mut rng);
        let opening = merkle_tree.generate_proof(0 /* index */).unwrap();
        let mut opening_scalars: Vec<Scalar::Field> =
            opening.auth_path.into_iter().rev().collect_vec();

        // Add a zero to the opening scalar for the next leaf
        opening_scalars.insert(0, Scalar::zero().inner());

        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Apply the constraints
        let leaf_vars = leaf_data
            .into_iter()
            .map(Scalar::from)
            .map(|x| x.commit_public(&mut prover))
            .collect_vec();
        let opening_scalars = opening_scalars.into_iter().map(Scalar::from).collect_vec();

        let opening_var = MerkleOpening {
            elems: opening_scalars.try_into().unwrap(),
            indices: get_opening_indices::<{ TREE_HEIGHT - 1 }>(0 /* leaf_index */),
        }
        .commit_public(&mut prover);
        let expected_root_var = expected_root.commit_public(&mut prover);

        PoseidonMerkleHashGadget::compute_and_constrain_root(
            leaf_vars,
            opening_var,
            expected_root_var,
            &mut prover,
        )
        .unwrap();
        assert!(!prover.constraints_satisfied());
    }
}
