//! Constant values referenced by the Arbitrum client.

use std::{fmt::Display, marker::PhantomData, str::FromStr};

use ark_ff::{BigInt, Fp};
use constants::{Scalar, MERKLE_HEIGHT};
use lazy_static::lazy_static;
use renegade_crypto::hash::compute_poseidon_hash;
use serde::{Deserialize, Serialize};

/// The chain environment
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum Chain {
    /// Mainnet chain
    Mainnet,
    /// Testnet chain
    Testnet,
    /// Devnet chain
    Devnet,
}

impl Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Mainnet => write!(f, "mainnet"),
            Chain::Testnet => write!(f, "testnet"),
            Chain::Devnet => write!(f, "devnet"),
        }
    }
}

impl FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Chain::Mainnet),
            "testnet" => Ok(Chain::Testnet),
            "devnet" => Ok(Chain::Devnet),
            _ => Err(format!("Invalid chain: {s}")),
        }
    }
}

/// The number of bytes in a Solidity function selector
pub const SELECTOR_LEN: usize = 4;

// The following are used for cases in which runtime type-based event filtering
// is not possible. In these cases, we must construct filters manually using ABI
// signatures

/// The abi signature for the `WalletUpdated` event
pub const WALLET_UPDATED_EVENT_NAME: &str = "WalletUpdated";
/// The abi signature for the `NodeChanged` event
pub const MERKLE_NODE_CHANGED_EVENT_NAME: &str = "NodeChanged";
/// The abi signature for the `NullifierSpent` event
pub const NULLIFIER_SPENT_EVENT_NAME: &str = "NullifierSpent";

lazy_static! {
    // ------------------------
    // | Merkle Tree Metadata |
    // ------------------------

    /// The value of an empty leaf in the Merkle tree,
    /// computed as the Keccak-256 hash of the string "renegade",
    /// reduced modulo the scalar field order when interpreted as a
    /// big-endian unsigned integer
    pub static ref EMPTY_LEAF_VALUE: Scalar = Scalar::new(Fp(
        BigInt([
            14542100412480080699,
            1005430062575839833,
            8810205500711505764,
            2121377557688093532,
        ]),
        PhantomData,
    ));

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
