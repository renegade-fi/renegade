//! Provides a wrapper around the starknet_core clients that holds node
//! specific information (keys, api credentials, etc) and provides a cleaner
//! interface for interacting with on-chain state in Renegade specific patterns

#![allow(incomplete_features)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(missing_docs)]
#![deny(unsafe_code)]
#![feature(generic_const_exprs)]

use std::{convert::TryInto, str::FromStr};

use constants::MERKLE_HEIGHT;
use lazy_static::lazy_static;
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::BigUint;
use renegade_crypto::hash::compute_poseidon_hash;
use starknet::core::{types::FieldElement as StarknetFieldElement, utils::get_selector_from_name};

pub mod client;
pub mod error;
mod helpers;
pub mod types;

lazy_static! {
    // -------------
    // | Selectors |
    // -------------

    // -- Getters --

    /// Contract view function selector to fetch the current Merkle root
    static ref MERKLE_ROOT_SELECTOR: StarknetFieldElement = get_selector_from_name("get_root")
        .unwrap();
    /// Contract view function selector to test whether the given Merkle root is valid
    static ref MERKLE_ROOT_IN_HISTORY_SELECTOR: StarknetFieldElement = get_selector_from_name("root_in_history")
        .unwrap();
    /// Contract view function selector to test whether the given nullifier is used
    static ref NULLIFIER_USED_SELECTOR: StarknetFieldElement = get_selector_from_name("is_nullifier_used")
        .unwrap();
    /// Contract view function selector to fetch the hash of the transaction that indexed a given public blinder share
    static ref GET_PUBLIC_BLINDER_TRANSACTION: StarknetFieldElement = get_selector_from_name("get_wallet_blinder_transaction")
        .unwrap();

    // -- Setters --

    /// Contract function selector to create a new wallet
    static ref NEW_WALLET_SELECTOR: StarknetFieldElement = get_selector_from_name("new_wallet")
        .unwrap();
    /// Contract function selector to update an existing wallet, nullifying the previous version
    static ref UPDATE_WALLET_SELECTOR: StarknetFieldElement = get_selector_from_name("update_wallet")
        .unwrap();
    /// Contract function selector to submit a match, encumbering two wallets
    static ref MATCH_SELECTOR: StarknetFieldElement = get_selector_from_name("process_match")
        .unwrap();

    /// The event selector for internal node changes
    pub static ref INTERNAL_NODE_CHANGED_EVENT_SELECTOR: StarknetFieldElement =
        get_selector_from_name("MerkleInternalNodeChanged").unwrap();
    /// The event selector for Merkle value insertion
    pub static ref VALUE_INSERTED_EVENT_SELECTOR: StarknetFieldElement =
        get_selector_from_name("MerkleValueInserted").unwrap();

    // ------------------------
    // | Merkle Tree Metadata |
    // ------------------------

    /// The value of an empty leaf in the Merkle tree
    pub static ref EMPTY_LEAF_VALUE: Scalar = {
        BigUint::from_str(
            "306932273398430716639340090025251550554329269971178413658580639401611971225"
        )
        .unwrap()
        .into()
    };
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
