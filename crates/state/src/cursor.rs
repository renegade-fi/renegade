//! Event cursor type for tracking chain event positions
//!
//! Used to prevent stale writes by rejecting proposals that arrive out of
//! order. The cursor uniquely identifies a log event's position in the chain.

use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

/// Uniquely identifies a log event's position in the chain.
///
/// Derived Ord gives lexicographic comparison: (block_number, tx_index,
/// log_index) This provides total ordering of all events across the chain.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    Archive,
    RkyvDeserialize,
    RkyvSerialize,
)]
#[rkyv(derive(Debug))]
pub struct EventCursor {
    /// The block number where the event occurred
    pub block_number: u64,
    /// The transaction index within the block
    pub tx_index: u64,
    /// The log index within the transaction
    pub log_index: u64,
}

impl EventCursor {
    /// Create a new event cursor
    pub fn new(block_number: u64, tx_index: u64, log_index: u64) -> Self {
        Self { block_number, tx_index, log_index }
    }
}

impl std::fmt::Display for EventCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {}, {})", self.block_number, self.tx_index, self.log_index)
    }
}
