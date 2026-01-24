//! State transition types for the state machine
//!
//! Note: missing_docs is allowed in this module because the rkyv derive macro
//! generates archived types with undocumented fields.
#![allow(missing_docs)]

use circuit_types::Nullifier;
use darkpool_types::rkyv_remotes::ScalarDef;
use serde::{Deserialize, Serialize};
use types_account::{
    Account, MatchingPoolName, MerkleAuthenticationPath, account::OrderId, balance::Balance,
    order::Order, order_auth::OrderAuth,
};
use types_core::AccountId;
use types_gossip::WrappedPeerId;
use types_tasks::{QueuedTask, QueuedTaskState, TaskIdentifier, TaskQueueKey};
use uuid::Uuid;

use crate::{
    replication::{NodeId, RaftNode},
    storage::tx::merkle_proofs::MerkleProofType,
};

// ---------------------
// | State Transitions |
// ---------------------

/// A type alias for the proposal ID
pub type ProposalId = Uuid;
/// The proposal submitted to the state machine
#[derive(
    Clone, Debug, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct Proposal {
    /// The ID of the proposal
    pub id: ProposalId,
    /// The state transition to apply
    pub transition: Box<StateTransition>,
}

/// The `StateTransitionType` encapsulates all possible state transitions,
/// allowing transitions to be handled generically before they are applied
#[derive(Clone, Debug, Serialize, Deserialize, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(derive(Debug))]
#[rustfmt::skip]
pub enum StateTransition {
    // --- Accounts --- //
    /// Create a new account
    CreateAccount { account: Account },
    /// Update an account by adding an order, marking it as local, and storing its auth
    AddOrderToAccount { account_id: AccountId, order: Order, auth: OrderAuth },
    /// Remove an order from an account
    RemoveOrderFromAccount { account_id: AccountId, order_id: OrderId },
    /// Update an existing order in an account
    UpdateOrder { order: Order },
    /// Update a balance in an account
    UpdateAccountBalance { account_id: AccountId, balance: Balance },

    // --- Orders --- //
    /// Add a validity proof to an order
    AddOrderValidityProof { 
        /// The ID of the order
        order_id: OrderId, 
        /// The nullifier proof
        #[rkyv(with = ScalarDef)]
        proof: Nullifier },

    // --- Merkle Proofs --- //
    /// Add a Merkle authentication path (proof) for an intent or balance
    AddMerkleProof {
        /// The type of proof (contains the ID information)
        proof_type: MerkleProofType,
        /// The proof
        proof: MerkleAuthenticationPath,
    },

    // --- Matching Pools --- //
    /// Create a matching pool
    CreateMatchingPool { pool_name: MatchingPoolName },
    /// Destroy a matching pool
    DestroyMatchingPool { pool_name: MatchingPoolName },
    /// Assign an order to a matching pool
    AssignOrderToMatchingPool { order_id: OrderId, pool_name: MatchingPoolName },

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
    /// Add a raft learner to the cluster
    AddRaftLearners { learners: Vec<(NodeId, RaftNode)> },
    /// Add a raft peer to the local consensus cluster
    AddRaftVoters { peer_ids: Vec<NodeId> },
    /// Remove a raft peer from the local consensus cluster
    RemoveRaftPeers { peer_ids: Vec<NodeId> },
}

impl From<StateTransition> for Proposal {
    fn from(transition: StateTransition) -> Self {
        let transition = Box::new(transition);
        Self { id: Uuid::new_v4(), transition }
    }
}
