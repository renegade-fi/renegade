//! Defines replication primitives for the relayer state on top of a
//! base raft implementation. Raft provides a consistent, distributed log
//! with serializable access. We describe state transitions and persist these
//! to the raft log

pub mod error;
pub mod log_store;
pub mod network;
pub mod raft_node;
