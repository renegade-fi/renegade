//! State transition types for the state machine

use serde::{Deserialize, Serialize};
use types_gossip::WrappedPeerId;
use types_runtime::MatchingPoolName;
use types_tasks::{QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey};
use uuid::Uuid;

// ---------------------
// | State Transitions |
// ---------------------

/// A type alias for the proposal ID
pub type ProposalId = Uuid;
/// The proposal submitted to the state machine
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    /// The ID of the proposal
    id: ProposalId,
    /// The state transition to apply
    transition: Box<StateTransition>,
}

/// The `StateTransitionType` encapsulates all possible state transitions,
/// allowing transitions to be handled generically before they are applied
#[derive(Clone, Debug, Serialize, Deserialize)]
#[allow(missing_docs)]
#[rustfmt::skip]
pub enum StateTransition {
    // --- Matching Pools --- //
    /// Create a matching pool
    CreateMatchingPool { pool_name: MatchingPoolName },
    /// Destroy a matching pool
    DestroyMatchingPool { pool_name: MatchingPoolName },

    // --- Task Queue --- //
    /// Add a task to the task queue
    AppendTask { task: QueuedTask, executor: WrappedPeerId },
    /// Pop the top task from the task queue
    PopTask { task_id: TaskIdentifier, success: bool },
    /// Transition the state of the top task in the task queue
    TransitionTask { task_id: TaskIdentifier, state: QueuedTaskState },
    /// Clear all tasks in the queue, marking them as failed
    ClearTaskQueue { queue: TaskQueueKey },
    /// Enqueue a preemptive task for the given task queues
    /// 
    /// Transitions any running tasks to `Queued` state and enqueues the given task
    /// at the front of each queue
    /// 
    /// If `serial` is true, the task is enqueued as a serial task and requires
    /// exclusive access to the task queue. If false, the task is enqueued as a
    /// concurrent task and may share the queue with other concurrent, preemptive
    /// tasks.
    EnqueuePreemptiveTask { keys: Vec<TaskQueueKey>, task: QueuedTask, executor: WrappedPeerId, serial: bool },
    /// Reassign all tasks from one peer to another peer
    ReassignTasks { from: WrappedPeerId, to: WrappedPeerId },

    // --- Raft --- //
    // /// Add a raft learner to the cluster
    // AddRaftLearners { learners: Vec<(NodeId, RaftNode)> },
    // /// Add a raft peer to the local consensus cluster
    // AddRaftVoters { peer_ids: Vec<NodeId> },
    // /// Remove a raft peer from the local consensus cluster
    // RemoveRaftPeers { peer_ids: Vec<NodeId> },
}

impl From<StateTransition> for Proposal {
    fn from(transition: StateTransition) -> Self {
        let transition = Box::new(transition);
        Self { id: Uuid::new_v4(), transition }
    }
}
