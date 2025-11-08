//! Groups the validity proofs for the V2 darkpool
//!
//! Validity proofs verify the state elements input to a match.
//!
//! At a high level, validity proofs verify that:
//! 1. The owner of all *new* state elements has authorized their creation
//! 2. *Existing* state elements are present in the Merkle tree
//! 3. Nullifiers have been computed correctly for pre-update state elements
//! 4. New shares have been allocated for updated elements
//!
//! The files in this module represent different configurations of private vs
//! public intents and balances input to a match; as well as first fill vs
//! subsequent fills for private intents.
//!
//! The state elements which witness these validity proofs are proof-linked into
//! the match settlement proofs in `settlement/`

pub mod intent_only;
pub mod intent_only_first_fill;
