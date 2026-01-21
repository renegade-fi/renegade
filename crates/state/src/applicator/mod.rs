//! The state applicator applies updates that have been committed to by the raft
//! group to the global state, persisting them to local storage

use std::sync::Arc;

use job_types::{
    event_manager::EventManagerQueue, matching_engine::MatchingEngineWorkerQueue,
    task_driver::TaskDriverQueue,
};
use system_bus::SystemBus;
use types_account::OrderId;
use types_gossip::ClusterId;

use crate::state_transition::StateTransition;
use crate::storage::db::DB;
use matching_engine_core::MatchingEngine;

use self::{error::StateApplicatorError, return_type::ApplicatorReturnType};

pub mod account_index;
pub mod error;
pub mod matching_pools;
pub mod merkle_proofs;
pub mod order_book;
pub mod return_type;
pub mod task_queue;

// -------------
// | Constants |
// -------------

/// A type alias for the result type given by the applicator
pub(crate) type Result<T> = std::result::Result<T, StateApplicatorError>;

// ----------
// | Errors |
// ----------

/// Create an order missing rejection error
fn reject_order_missing(order_id: OrderId) -> StateApplicatorError {
    StateApplicatorError::reject(format!("order {order_id} not found in state"))
}

// --------------
// | Applicator |
// --------------

/// The config for the state applicator
#[derive(Clone)]
pub struct StateApplicatorConfig {
    /// Whether or not to allow peers on the localhost
    pub allow_local: bool,
    /// The local peer's cluster ID
    pub cluster_id: ClusterId,
    /// A sender to the task driver's work queue
    pub task_queue: TaskDriverQueue,
    /// The handshake manager's work queue
    pub handshake_manager_queue: MatchingEngineWorkerQueue,
    /// The event manager's work queue
    pub event_queue: EventManagerQueue,
    /// The matching engine
    pub matching_engine: MatchingEngine,
    /// A handle to the database underlying the storage layer
    pub db: Arc<DB>,
    /// A handle to the system bus used for internal pubsub
    pub system_bus: SystemBus,
}

/// The applicator applies state updates to the global state and persists them
/// to local storage after consensus has been formed on the updates
///
/// If we view our state implementation as a distributed log forming consensus
/// over the ordering of RPC executions, then the `StateApplicator` can be
/// thought of as the RPC server that executes the RPCs after their consensus
/// has been formed
#[derive(Clone)]
pub struct StateApplicator {
    /// The config for the applicator
    pub(crate) config: StateApplicatorConfig,
}

impl StateApplicator {
    /// Create a new state applicator
    pub fn new(config: StateApplicatorConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Handle a state transition
    pub fn handle_state_transition(
        &self,
        transition: Box<StateTransition>,
    ) -> Result<ApplicatorReturnType> {
        match *transition {
            StateTransition::CreateAccount { account } => self.create_account(&account),
            StateTransition::AddOrderToAccount { account_id, order, auth } => {
                self.add_order_to_account(account_id, &order, &auth)
            },
            StateTransition::RemoveOrderFromAccount { account_id, order_id } => {
                self.remove_order_from_account(account_id, order_id)
            },
            StateTransition::AddOrderValidityProof { order_id, proof } => {
                self.add_order_validity_proof(order_id, proof)
            },
            StateTransition::CreateMatchingPool { pool_name } => {
                self.create_matching_pool(&pool_name)
            },
            StateTransition::DestroyMatchingPool { pool_name } => {
                self.destroy_matching_pool(&pool_name)
            },
            StateTransition::AssignOrderToMatchingPool { order_id, pool_name } => {
                self.assign_order_to_matching_pool(order_id, &pool_name)
            },
            StateTransition::AppendTask { task, executor } => self.append_task(&task, &executor),
            StateTransition::PopTask { task_id, success } => self.pop_task(task_id, success),
            StateTransition::TransitionTask { task_id, state } => {
                self.transition_task_state(task_id, state)
            },
            StateTransition::ClearTaskQueue { queue } => self.clear_queue(queue),
            StateTransition::EnqueuePreemptiveTask { keys, task, executor, serial } => {
                self.enqueue_preemptive_task(&keys, &task, &executor, serial)
            },
            StateTransition::ReassignTasks { from, to } => self.reassign_tasks(&from, &to),
            StateTransition::AddMerkleProof { proof_type, proof } => {
                self.add_merkle_proof(proof_type, proof)
            },
            _ => unimplemented!("Unsupported state transition forwarded to applicator"),
        }
    }

    /// Get a reference to the db
    pub fn db(&self) -> &DB {
        &self.config.db
    }

    /// Get a reference to the system bus
    fn system_bus(&self) -> &SystemBus {
        &self.config.system_bus
    }

    /// Get a reference to the matching engine
    pub(crate) fn matching_engine(&self) -> MatchingEngine {
        self.config.matching_engine.clone()
    }
}

/// Test helpers for mock state applicator
#[cfg(any(test, feature = "mocks"))]
pub mod test_helpers {
    use std::{mem, str::FromStr, sync::Arc};

    use job_types::{
        event_manager::new_event_manager_queue,
        matching_engine::new_matching_engine_worker_queue,
        task_driver::{TaskDriverQueue, new_task_driver_queue},
    };
    use matching_engine_core::MatchingEngine;
    use system_bus::SystemBus;
    use types_gossip::ClusterId;

    use crate::test_helpers::mock_db;

    use super::{StateApplicator, StateApplicatorConfig};

    /// Create a mock `StateApplicator`
    pub fn mock_applicator() -> StateApplicator {
        let (task_queue, recv) = new_task_driver_queue();
        mem::forget(recv);

        mock_applicator_with_task_queue(task_queue)
    }

    /// Create a mock `StateApplicator` with the given task queue
    pub(crate) fn mock_applicator_with_task_queue(task_queue: TaskDriverQueue) -> StateApplicator {
        let (handshake_manager_queue, _recv) = new_matching_engine_worker_queue();
        mem::forget(_recv);

        let (event_queue, _recv) = new_event_manager_queue();
        mem::forget(_recv);

        let config = StateApplicatorConfig {
            allow_local: true,
            task_queue,
            matching_engine: MatchingEngine::new(),
            db: Arc::new(mock_db()),
            handshake_manager_queue,
            event_queue,
            system_bus: SystemBus::new(),
            cluster_id: ClusterId::from_str("test-cluster").unwrap(),
        };

        StateApplicator::new(config).unwrap()
    }
}
