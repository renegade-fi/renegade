//! Constant values referenced by the Arbitrum client.

use std::marker::PhantomData;

use ark_ff::BigInt;
use constants::{Scalar, MERKLE_HEIGHT};
use lazy_static::lazy_static;
use num_bigint::BigUint;
use renegade_crypto::hash::compute_poseidon_hash;

/// The chain environment
#[derive(Clone, Copy)]
pub enum Chain {
    /// Mainnet chain
    Mainnet,
    /// Testnet chain
    Testnet,
    /// Devnet chain
    Devnet,
}

/// The value of an empty leaf in the Merkle tree,
/// computed as the Keccak-256 hash of the string "renegade",
/// reduced modulo the scalar field order when interpreted as a
/// big-endian unsigned integer
pub const EMPTY_LEAF_VALUE: Scalar = Scalar(Fp(
    BigInt([
        14542100412480080699,
        1005430062575839833,
        8810205500711505764,
        2121377557688093532,
    ]),
    PhantomData,
));

/// The number of bytes in a Solidity function selector
pub const SELECTOR_LEN: usize = 4;

lazy_static! {
    // ------------------------
    // | Merkle Tree Metadata |
    // ------------------------

    /// The default values of an authentication path; i.e. the values in the path before any
    /// path elements are changed by insertions
    ///
    /// These values are simply recursive hashes of the empty leaf value, as this builds the
    /// empty tree
    pub static ref DEFAULT_AUTHENTICATION_PATH: [Scalar; MERKLE_HEIGHT] = {
        let mut values = Vec::with_capacity(MERKLE_HEIGHT);

        let mut curr_val = *EMPTY_LEAF_VALUE;
        for _ in 0..MERKLE_HEIGHT {
            values.push(curr_val);
            curr_val = compute_poseidon_hash(&[curr_val, curr_val]);
        }

        values.try_into().unwrap()
    };
}
