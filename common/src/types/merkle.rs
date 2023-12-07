//! Defines types related to Merkle trees within the system

use circuit_types::{merkle::MerkleOpening, SizedMerkleOpening};
use constants::Scalar;
use constants::MERKLE_HEIGHT;
use itertools::Itertools;
use num_bigint::BigUint;
use renegade_crypto::hash::compute_poseidon_hash;
use serde::{Deserialize, Serialize};

/// A wrapper representing the coordinates of a value in a Merkle tree
///
/// Used largely for readability
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MerkleTreeCoords {
    /// The height (0 is root) of the coordinate in the tree
    pub height: usize,
    /// The leaf index of the coordinate
    ///
    /// I.e. if we look at the nodes at a given height left to right in a list
    /// the index of the coordinate in that list
    pub index: BigUint,
}

impl MerkleTreeCoords {
    /// Constructor
    pub fn new(height: usize, index: BigUint) -> Self {
        Self { height, index }
    }
}

/// Represents a Merkle authentication path for a wallet
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleAuthenticationPath {
    /// A list of sibling node values that are hashed with
    /// the wallet commitment in the root computation
    ///
    /// The first value in this list is a leaf, the last value is
    /// one of the root's children
    pub path_siblings: [Scalar; MERKLE_HEIGHT],
    /// The leaf index that this node sits at
    pub leaf_index: BigUint,
    /// The value being authenticated
    pub value: Scalar,
}

impl MerkleAuthenticationPath {
    /// Constructor
    pub fn new(path_siblings: [Scalar; MERKLE_HEIGHT], leaf_index: BigUint, value: Scalar) -> Self {
        Self { path_siblings, leaf_index, value }
    }

    /// Static helper method to get the coordinates of a Merkle authentication
    /// path from the leaf value
    pub fn construct_path_coords(leaf_index: BigUint, height: usize) -> Vec<MerkleTreeCoords> {
        let mut coords = Vec::with_capacity(height);
        let mut curr_height_index = leaf_index;
        for height in (1..height + 1).rev() {
            // If the LSB of the node index at the current height is zero, the node
            // is a left hand child. If the LSB is one, it is a right hand child.
            // Choose the index of its sibling
            let sibling_index = if &curr_height_index % 2u8 == BigUint::from(0u8) {
                &curr_height_index + 1u8
            } else {
                &curr_height_index - 1u8
            };

            coords.push(MerkleTreeCoords::new(height, sibling_index));
            curr_height_index >>= 1;
        }

        coords
    }

    /// Compute the coordinates of the wallet's authentication path in the tree
    ///
    /// The result is sorted from leaf level to depth 1
    pub fn compute_authentication_path_coords(&self) -> Vec<MerkleTreeCoords> {
        let mut current_index = self.leaf_index.clone();

        let mut coords = Vec::with_capacity(MERKLE_HEIGHT);
        for height in (1..MERKLE_HEIGHT + 1).rev() {
            let sibling_index = if &current_index % 2u8 == BigUint::from(0u8) {
                // Left hand node
                &current_index + 1u8
            } else {
                // Right hand node
                &current_index - 1u8
            };

            coords.push(MerkleTreeCoords::new(height, sibling_index));
            current_index >>= 1u8;
        }

        coords
    }

    /// Compute the root implied by the path
    pub fn compute_root(&self) -> Scalar {
        let mut current_index = self.leaf_index.clone();
        let mut current_value = self.value;

        for sibling in self.path_siblings.iter() {
            current_value = if &current_index % 2u8 == BigUint::from(0u8) {
                compute_poseidon_hash(&[current_value, *sibling])
            } else {
                compute_poseidon_hash(&[*sibling, current_value])
            };

            current_index >>= 1;
        }

        current_value
    }
}

/// Conversion to circuit type
impl From<MerkleAuthenticationPath> for SizedMerkleOpening {
    fn from(native_path: MerkleAuthenticationPath) -> Self {
        // The path conversion is simply the first `MERKLE_HEIGHT` bits of
        // the leaf index
        let path_indices =
            (0..MERKLE_HEIGHT).map(|bit| native_path.leaf_index.bit(bit as u64)).collect_vec();

        MerkleOpening {
            elems: native_path.path_siblings.to_vec().try_into().unwrap(),
            indices: path_indices.try_into().unwrap(),
        }
    }
}
