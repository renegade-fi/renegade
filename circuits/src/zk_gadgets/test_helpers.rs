//! Test helpers for ZK gadgets

use circuit_types::{
    merkle::MerkleOpening,
    traits::{BaseType, SecretShareType},
};
use constants::Scalar;
use itertools::Itertools;
use renegade_crypto::hash::compute_poseidon_hash;

use crate::test_helpers::random_scalars_vec;

// ----------------
// | Secret Share |
// ----------------

/// Create a random sharing of the given type
///
/// Returns a tuple of the private and public shares
pub fn create_random_shares<V: SecretShareType>(v: &V::Base) -> (V, V) {
    let values = v.to_scalars();
    let private_shares = random_scalars_vec(values.len());
    let public_shares = values.iter().zip(private_shares.iter()).map(|(v, s)| v - s).collect_vec();

    // Deserialize
    let private = V::from_scalars(&mut private_shares.into_iter());
    let public = V::from_scalars(&mut public_shares.into_iter());
    (private, public)
}

// ----------
// | Merkle |
// ----------

/// Create a Merkle opening for a single leaf
///
/// Returns the root and the opening
pub fn create_merkle_opening<const HEIGHT: usize>(leaf: Scalar) -> (Scalar, MerkleOpening<HEIGHT>) {
    let (root, mut openings) = create_multi_opening(&[leaf]);
    (root, openings.pop().unwrap())
}

/// Create a multi-item opening in a Merkle tree, do so by constructing the
/// Merkle tree from the given items, padded with zeros
///
/// The return type is structured as a tuple with the following elements in
/// order:
///     - root: The root of the Merkle tree
///     - openings: A vector of opening vectors; the sister nodes hashed with
///       the Merkle path
///     - opening_indices: A vector of opening index vectors; the left/right
///       booleans for the path
pub fn create_multi_opening<const HEIGHT: usize>(
    items: &[Scalar],
) -> (Scalar, Vec<MerkleOpening<HEIGHT>>) {
    create_multi_opening_with_default_leaf(items, Scalar::zero() /* default_value */)
}

/// Create a multi opening with a non-zero default (empty) leaf value
pub fn create_multi_opening_with_default_leaf<const HEIGHT: usize>(
    items: &[Scalar],
    default_leaf: Scalar,
) -> (Scalar, Vec<MerkleOpening<HEIGHT>>) {
    let tree_capacity = 2usize.pow(HEIGHT as u32);
    assert!(items.len() <= tree_capacity, "tree capacity exceeded by seed items");
    assert!(!items.is_empty(), "cannot create a multi-opening for an empty tree");

    let (root, mut opening_paths) =
        create_multi_opening_helper(items.to_vec(), default_leaf, HEIGHT);
    opening_paths.truncate(items.len());

    // Create Merkle opening paths from each of the results
    let merkle_paths = opening_paths
        .into_iter()
        .enumerate()
        .map(|(i, path)| (get_opening_indices(i, HEIGHT), path))
        .map(|(indices, path)| MerkleOpening {
            indices: indices.try_into().unwrap(),
            elems: path.try_into().unwrap(),
        })
        .collect_vec();

    (root, merkle_paths)
}

/// A recursive helper to compute a multi-opening for a set of leaves
///
/// Returns the root and a set of paths, where path[i] is hte path for
/// leaves[i]
fn create_multi_opening_helper(
    mut leaves: Vec<Scalar>,
    zero_value: Scalar,
    height: usize,
) -> (Scalar, Vec<Vec<Scalar>>) {
    // If the height is zero we are at the root of the tree, return
    if height == 0 {
        return (leaves[0], vec![Vec::new()]);
    }

    // Otherwise, pad the leaves with zeros to an even number and fold into the next
    // recursive level
    let pad_length = leaves.len() % 2;
    leaves.append(&mut vec![zero_value; pad_length]);
    let next_level_leaves = leaves.chunks_exact(2).map(compute_poseidon_hash).collect_vec();

    // Recurse up the tree
    let zero_value = compute_poseidon_hash(&[zero_value, zero_value]);
    let (root, parent_openings) =
        create_multi_opening_helper(next_level_leaves, zero_value, height - 1);

    // Append sister nodes to each recursive result
    let mut openings: Vec<Vec<Scalar>> = Vec::with_capacity(leaves.len());
    for (leaf_chunk, recursive_opening) in leaves.chunks_exact(2).zip(parent_openings) {
        // Add the leaves to each other's paths
        let (left, right) = (leaf_chunk[0], leaf_chunk[1]);
        openings.push([vec![right], recursive_opening.clone()].concat());
        openings.push([vec![left], recursive_opening].concat());
    }

    (root, openings)
}

/// Get the opening indices for a given insertion index into a Merkle tree
///
/// Here, the indices are represented as `Scalar` values where `0`
/// represents a left child and `1` represents a right child
fn get_opening_indices(leaf_index: usize, height: usize) -> Vec<bool> {
    let mut leaf_index = leaf_index as u64;
    let mut indices = Vec::with_capacity(height);

    for _ in 0..height {
        indices.push(leaf_index % 2 == 1);
        leaf_index >>= 1;
    }
    indices
}
