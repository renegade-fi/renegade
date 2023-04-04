//! Groups state object definitions and handles logic for serializing access to shared
//! global state elements
mod orderbook;
pub mod peers;
mod priority;
#[allow(clippy::module_inception)]
mod state;
pub mod tui;
pub mod wallet;

use num_bigint::BigUint;

pub use self::orderbook::{NetworkOrder, NetworkOrderBook, NetworkOrderState, OrderIdentifier};
pub use self::state::*;

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
