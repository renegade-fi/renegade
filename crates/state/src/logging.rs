//! Closed `Task` vocabulary for structured logging in the `state` crate.
//!
//! Each variant names an operation this crate performs around raft replication,
//! log application, snapshots, and the durable state store. See
//! [`util::logging`] for the shared envelope and the [`util::log_task`] macro.

use util::logging::LogTask;

/// Closed vocabulary of operations the `state` crate performs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Task {
    /// Raft core lifecycle (startup, panic detection, shutdown).
    RaftLifecycle,
    /// Leader election and leadership handoff.
    LeaderElection,
    /// Raft membership changes (adding learners, promoting voters, expiring
    /// peers).
    MembershipChange,
    /// Proposing a state transition through raft and watching its result.
    Proposal,
    /// Recovering the state machine from a persisted snapshot.
    SnapshotRecovery,
    /// One-time node metadata setup at startup.
    NodeSetup,
    /// Indexing gossip peers into the durable store.
    PeerIndex,
    /// Applying task-queue state transitions.
    TaskQueue,
    /// Applying network order book state transitions.
    OrderBookUpdate,
    /// Applying account index state transitions.
    AccountIndexUpdate,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::RaftLifecycle => "raft-lifecycle",
            Task::LeaderElection => "leader-election",
            Task::MembershipChange => "membership-change",
            Task::Proposal => "proposal",
            Task::SnapshotRecovery => "snapshot-recovery",
            Task::NodeSetup => "node-setup",
            Task::PeerIndex => "peer-index",
            Task::TaskQueue => "task-queue",
            Task::OrderBookUpdate => "order-book-update",
            Task::AccountIndexUpdate => "account-index-update",
        }
    }
}
