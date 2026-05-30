//! Structured logging tasks for the network manager

use util::logging::LogTask;

/// The set of operations the network manager performs, used as the task
/// dimension of structured log records
#[derive(Copy, Clone, Debug)]
pub enum Task {
    /// The network manager's main executor loop lifecycle
    ExecutorLoop,
    /// Processing a behavior job issued from inside the worker
    HandleBehaviorJob,
    /// Sending an outbound message to the network
    HandleOutbound,
    /// Handling an inbound message received from the network
    HandleInbound,
    /// Binding a new listen address on the swarm
    Listen,
    /// Discovering the local peer's public identity via the identify protocol
    Identify,
    /// Forwarding a heartbeat to the gossip server
    ForwardHeartbeat,
    /// Adding a peer address to the Kademlia DHT routing table
    AddRoutingTableEntry,
    /// Indexing a newly discovered peer address
    IndexAddr,
    /// Sending a response notification to a waiting requester
    SendResponseNotification,
    /// Handling a raft request routed through the network manager
    HandleRaftRequest,
}

impl LogTask for Task {
    fn as_str(&self) -> &'static str {
        match self {
            Task::ExecutorLoop => "executor-loop",
            Task::HandleBehaviorJob => "handle-behavior-job",
            Task::HandleOutbound => "handle-outbound",
            Task::HandleInbound => "handle-inbound",
            Task::Listen => "listen",
            Task::Identify => "identify",
            Task::ForwardHeartbeat => "forward-heartbeat",
            Task::AddRoutingTableEntry => "add-routing-table-entry",
            Task::IndexAddr => "index-addr",
            Task::SendResponseNotification => "send-response-notification",
            Task::HandleRaftRequest => "handle-raft-request",
        }
    }
}
