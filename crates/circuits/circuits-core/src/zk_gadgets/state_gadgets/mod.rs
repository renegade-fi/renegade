//! State gadgets for zero knowledge circuits
//!
//! This module contains gadgets that operate on state types like balances,
//! intents, fees, deposits, withdrawals, etc.

pub mod fee;
pub mod note;

// Re-export state-related gadgets from state_primitives
pub use crate::zk_gadgets::state_primitives::{
    CommitmentGadget, NullifierGadget, RecoveryIdGadget,
};

// Re-export merkle gadget (used for state verification)
pub use crate::zk_gadgets::primitives::merkle::PoseidonMerkleHashGadget;

// Re-export note gadget
pub use note::NoteGadget;
