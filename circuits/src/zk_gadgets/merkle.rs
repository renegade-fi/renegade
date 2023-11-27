//! Groups gadgets around computing Merkle entries and proving Merkle openings
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use ark_ff::One;
use circuit_types::merkle::MerkleOpeningVar;
use constants::ScalarField;
use mpc_relation::{errors::CircuitError, traits::Circuit, BoolVar, Variable};

use super::poseidon::PoseidonHashGadget;

/// The single-prover hash gadget, computes the Merkle root of a leaf given a
/// path of sister nodes
pub struct PoseidonMerkleHashGadget<const HEIGHT: usize> {}
impl<const HEIGHT: usize> PoseidonMerkleHashGadget<HEIGHT> {
    /// Compute the root of the tree given the leaf node and the path of
    /// sister nodes leading to the root
    pub fn compute_root<C: Circuit<ScalarField>>(
        leaf_node: &[Variable],
        opening: &MerkleOpeningVar<HEIGHT>,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // Hash the leaf_node into a field element
        let leaf_hash = Self::leaf_hash(leaf_node, cs)?;
        Self::compute_root_prehashed(leaf_hash, opening, cs)
    }

    /// Compute the root given an already hashed leaf, i.e. do not hash a leaf
    /// buffer first
    pub fn compute_root_prehashed<C: Circuit<ScalarField>>(
        leaf_node: Variable,
        opening: &MerkleOpeningVar<HEIGHT>,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // Hash the leaf_node into a field element
        let mut current_hash = leaf_node;
        for (path_elem, lr_select) in opening.elems.into_iter().zip(opening.indices.into_iter()) {
            // Select the left and right hand sides based on whether this node in the
            // opening represents the left or right hand child of its parent
            let (lhs, rhs) = Self::select_left_right(current_hash, path_elem, lr_select, cs)?;
            current_hash = Self::hash_internal_nodes(lhs, rhs, cs)?;
        }

        Ok(current_hash)
    }

    /// Compute the root and constrain it to an expected value
    pub fn compute_and_constrain_root<C: Circuit<ScalarField>>(
        leaf_node: &[Variable],
        opening: &MerkleOpeningVar<HEIGHT>,
        expected_root: Variable,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let root = Self::compute_root(leaf_node, opening, cs)?;
        cs.enforce_equal(expected_root, root)
    }

    /// Compute the root from a prehashed leaf and constrain it to an expected
    /// value
    pub fn compute_and_constrain_root_prehashed<C: Circuit<ScalarField>>(
        leaf_node: Variable,
        opening: &MerkleOpeningVar<HEIGHT>,
        expected_root: Variable,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        let root = Self::compute_root_prehashed(leaf_node, opening, cs)?;
        cs.enforce_equal(expected_root, root)
    }

    /// Selects whether to place the current hash on the left or right hand
    /// side of the 2-1 hash.
    ///
    /// This is based on whether the current hash represents the left or right
    /// child of its parent to be computed
    fn select_left_right<C: Circuit<ScalarField>>(
        current_hash: Variable,
        sister_node: Variable,
        lr_select: BoolVar,
        cs: &mut C,
    ) -> Result<(Variable, Variable), CircuitError> {
        // lr_select is `true` if the current hash is the right child of its parent
        let left_child = cs.mux(lr_select, sister_node, current_hash)?;

        // right_child = current_hash + sister_node - left_child
        let one = ScalarField::one();
        let neg_one = -one;
        let zero_var = cs.zero();

        let right_child =
            cs.lc(&[current_hash, sister_node, left_child, zero_var], &[one, one, neg_one, one])?;

        Ok((left_child, right_child))
    }

    /// Hash the value at the leaf into a bulletproof constraint value
    fn leaf_hash<C: Circuit<ScalarField>>(
        values: &[Variable],
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // Build a sponge hasher
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(values, cs)?;

        hasher.squeeze(cs)
    }

    /// Hash two internal nodes in the (binary) Merkle tree, giving the tree
    /// value at the parent node
    fn hash_internal_nodes<C: Circuit<ScalarField>>(
        left: Variable,
        right: Variable,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&[left, right], cs)?;

        hasher.squeeze(cs)
    }
}

#[cfg(test)]
pub(crate) mod merkle_test {
    use std::{borrow::Borrow, iter};

    use ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    };
    use circuit_types::{merkle::MerkleOpening, scalar, traits::CircuitBaseType, PlonkCircuit};
    use constants::{Scalar, ScalarField};
    use itertools::Itertools;
    use mpc_relation::traits::Circuit;
    use rand::{distributions::uniform::SampleRange, thread_rng, Rng};
    use renegade_crypto::hash::compute_poseidon_hash;

    use crate::{
        test_helpers::random_field_elements, zk_gadgets::merkle::PoseidonMerkleHashGadget,
    };

    // -----------
    // | Helpers |
    // -----------

    /// The height of the tree to test against
    const TREE_HEIGHT: usize = 10;
    /// The number of scalars in a leaf value
    const LEAF_SIZE: usize = 6;

    /// A dummy hasher to build an arkworks Merkle tree on top of
    struct Poseidon2Hasher;
    impl CRHScheme for Poseidon2Hasher {
        type Input = Vec<ScalarField>;
        type Output = ScalarField;
        type Parameters = ();

        fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
            Ok(())
        }

        fn evaluate<T: Borrow<Self::Input>>(
            _parameters: &Self::Parameters,
            input: T,
        ) -> Result<Self::Output, ark_crypto_primitives::Error> {
            let scalars = input.borrow().iter().map(|s| scalar!(*s)).collect_vec();
            let res = compute_poseidon_hash(&scalars);

            Ok(res.inner())
        }
    }

    impl TwoToOneCRHScheme for Poseidon2Hasher {
        type Input = ScalarField;
        type Output = ScalarField;
        type Parameters = ();

        fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
            Ok(())
        }

        fn evaluate<T: Borrow<Self::Input>>(
            _parameters: &Self::Parameters,
            left_input: T,
            right_input: T,
        ) -> Result<Self::Output, ark_crypto_primitives::Error> {
            let res = compute_poseidon_hash(&[
                scalar!(*left_input.borrow()),
                scalar!(*right_input.borrow()),
            ]);

            Ok(res.inner())
        }

        fn compress<T: Borrow<Self::Output>>(
            parameters: &Self::Parameters,
            left_input: T,
            right_input: T,
        ) -> Result<Self::Output, ark_crypto_primitives::Error> {
            <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input, right_input)
        }
    }

    struct MerkleConfig {}
    impl Config for MerkleConfig {
        type Leaf = Vec<ScalarField>;
        type LeafDigest = ScalarField;
        type InnerDigest = ScalarField;

        type LeafHash = Poseidon2Hasher;
        type TwoToOneHash = Poseidon2Hasher;
        type LeafInnerDigestConverter = IdentityDigestConverter<Scalar::Field>;
    }

    /// Generate random leaf data
    fn random_leaf_data() -> Vec<ScalarField> {
        random_field_elements(LEAF_SIZE).iter().map(Scalar::inner).collect_vec()
    }

    /// Get the opening indices from the index, this can be done by
    /// bit-decomposing the input to determine incrementally which subtree a
    /// given index should be a part of.
    ///
    /// The tree indices from leaf to root are exactly the LSB decomposition of
    /// the scalar
    pub(crate) fn get_opening_indices<const HEIGHT: usize>(mut leaf_index: usize) -> [bool; HEIGHT]
    where
        [(); HEIGHT]: Sized,
    {
        let mut res = Vec::with_capacity(HEIGHT);
        for _ in 0..HEIGHT {
            res.push(leaf_index % 2 == 1);
            leaf_index >>= 1;
        }

        res.try_into().unwrap()
    }

    /// Fill an arkworks tree, sample a random index, and generate a proof of
    /// opening for the given index
    ///
    /// Returns:
    ///     - The leaf data hashed into the tree
    ///     - The expected root of the tree
    ///     - The opening for the sampled index
    #[allow(non_upper_case_globals)]
    fn build_random_opening() -> (Vec<Scalar>, Scalar, MerkleOpening<TREE_HEIGHT>) {
        // Fill the tree with a random number of leaves
        let mut rng = thread_rng();
        let num_leaves = (0..2usize.pow(TREE_HEIGHT as u32)).sample_single(&mut rng);

        let mut ark_tree = MerkleTree::<MerkleConfig>::blank(&(), &(), TREE_HEIGHT + 1).unwrap();
        for i in 0..num_leaves {
            let leaf_data = random_leaf_data();
            ark_tree.update(i, &leaf_data).unwrap();
        }

        // Select an index at which to modify the opening, and generate fresh leaf data
        let random_index = thread_rng().gen_range(0..num_leaves);
        let new_leaf = random_leaf_data();
        ark_tree.update(random_index, &new_leaf).unwrap();

        // Generate a proof for a random index and prove it in the native
        let expected_root = scalar!(ark_tree.root());
        let opening = ark_tree.generate_proof(random_index).unwrap();

        // Reverse the opening (bottom to top) and prepend the leaf sibling's hash
        let opening_scalars = opening
            .auth_path
            .into_iter()
            .chain(iter::once(opening.leaf_sibling_hash))
            .map(Scalar::new)
            .rev()
            .collect_vec()
            .try_into()
            .unwrap();

        (
            new_leaf.into_iter().map(Scalar::new).collect(),
            expected_root,
            MerkleOpening {
                elems: opening_scalars,
                indices: get_opening_indices::<{ TREE_HEIGHT }>(random_index),
            },
        )
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests our Merkle tree's constraint satisfaction against an Arkworks
    /// generated opening
    #[test]
    fn test_against_arkworks() {
        // Build a random opening
        let (leaf_data, expected_root, opening) = build_random_opening();

        // Allocate the leaf data and opening in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let leaf_vars = leaf_data.into_iter().map(|x| x.create_witness(&mut cs)).collect_vec();
        let opening_var = opening.create_witness(&mut cs);
        let root = expected_root.create_public_var(&mut cs);

        // Apply the merkle constraints
        PoseidonMerkleHashGadget::compute_and_constrain_root(
            &leaf_vars,
            &opening_var,
            root,
            &mut cs,
        )
        .unwrap();

        assert!(cs.check_circuit_satisfiability(&[expected_root.inner()]).is_ok())
    }

    #[test]
    fn test_invalid_witness() {
        // Build a random opening
        let (leaf_data, expected_root, opening) = build_random_opening();

        // Allocate the leaf data and opening in a constraint system
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let leaf_vars = leaf_data.into_iter().map(|x| x.create_witness(&mut cs)).collect_vec();
        let opening_var = opening.create_witness(&mut cs);
        let root = expected_root.create_public_var(&mut cs);

        // Apply the merkle constraints
        PoseidonMerkleHashGadget::compute_and_constrain_root(
            &leaf_vars,
            &opening_var,
            root,
            &mut cs,
        )
        .unwrap();

        // Check constraint satisfaction with a different root
        let rand_root = Scalar::random(&mut thread_rng()).inner();
        assert!(cs.check_circuit_satisfiability(&[rand_root]).is_err())
    }
}
