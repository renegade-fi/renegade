//! Defines replication primitives for the relayer state on top of a
//! base raft implementation. Raft provides a consistent, distributed log
//! with serializable access. We describe state transitions and persist these
//! to the raft log

pub mod error;
mod log_store;

use openraft::{EmptyNode, RaftTypeConfig};
use std::io::Cursor;

use crate::StateTransition;

// Declare the types config for the raft
openraft::declare_raft_types! (
    /// The type config for the raft
    pub TypeConfig:
        D = StateTransition,
        R = (), // Response
        Node = EmptyNode,
);

/// A type alias for entries in the raft log
pub type Entry = <TypeConfig as RaftTypeConfig>::Entry;
/// A type alias for the node id type
pub type NodeId = <TypeConfig as RaftTypeConfig>::NodeId;
