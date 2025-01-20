//! The state applicator applies updates that have been committed to by the raft
//! group to the global state, persisting them to local storage

use std::sync::Arc;

use common::types::gossip::ClusterId;
use external_api::bus_message::SystemBusMessage;
use job_types::{
    event_manager::EventManagerQueue, handshake_manager::HandshakeManagerQueue,
    task_driver::TaskDriverQueue,
};
use system_bus::SystemBus;

use crate::{caching::order_cache::OrderBookCache, storage::db::DB, StateTransition};

use self::{error::StateApplicatorError, return_type::ApplicatorReturnType};

pub mod error;
pub mod matching_pools;
pub mod order_book;
pub mod order_history;
pub mod return_type;
pub mod task_queue;
pub mod wallet_index;

// -------------
// | Constants |
// -------------

/// A type alias for the result type given by the applicator
pub(crate) type Result<T> = std::result::Result<T, StateApplicatorError>;

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
    pub handshake_manager_queue: HandshakeManagerQueue,
    /// The event manager's work queue
    pub event_queue: EventManagerQueue,
    /// The order book cache
    pub order_cache: Arc<OrderBookCache>,
    /// A handle to the database underlying the storage layer
    pub db: Arc<DB>,
    /// A handle to the system bus used for internal pubsub
    pub system_bus: SystemBus<SystemBusMessage>,
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
            StateTransition::AddWallet { wallet } => self.add_wallet(&wallet),
            StateTransition::UpdateWallet { wallet } => self.update_wallet(&wallet),
            StateTransition::AddOrderValidityBundle { order_id, proof, witness } => {
                self.add_order_validity_proof(order_id, proof, witness)
            },
            StateTransition::UpdateOrderMetadata { meta } => self.update_order_metadata(meta),
            StateTransition::CreateMatchingPool { pool_name } => {
                self.create_matching_pool(&pool_name)
            },
            StateTransition::DestroyMatchingPool { pool_name } => {
                self.destroy_matching_pool(&pool_name)
            },
            StateTransition::AssignOrderToMatchingPool { order_id, pool_name } => {
                self.assign_order_to_matching_pool(&order_id, &pool_name)
            },
            StateTransition::AppendTask { task, executor } => self.append_task(&task, &executor),
            StateTransition::PopTask { task_id, success } => self.pop_task(task_id, success),
            StateTransition::TransitionTask { task_id, state } => {
                self.transition_task_state(task_id, state)
            },
            StateTransition::ClearTaskQueue { queue } => self.clear_queue(queue),
            StateTransition::PreemptTaskQueues { keys, task, executor } => {
                self.preempt_task_queues(&keys, &task, &executor)
            },
            StateTransition::ResumeTaskQueues { keys, success } => {
                self.resume_task_queues(&keys, success)
            },
            StateTransition::ReassignTasks { from, to } => self.reassign_tasks(&from, &to),
            _ => unimplemented!("Unsupported state transition forwarded to applicator"),
        }
    }

    /// Get a reference to the db
    pub fn db(&self) -> &DB {
        &self.config.db
    }

    /// Get a reference to the system bus
    fn system_bus(&self) -> &SystemBus<SystemBusMessage> {
        &self.config.system_bus
    }

    /// Get a reference to the order cache
    pub(crate) fn order_cache(&self) -> &OrderBookCache {
        &self.config.order_cache
    }
}

/// Test helpers for mock state applicator
#[cfg(any(test, feature = "mocks"))]
pub mod test_helpers {
    use std::{mem, str::FromStr, sync::Arc};

    use common::types::gossip::ClusterId;
    use job_types::{
        event_manager::new_event_manager_queue,
        handshake_manager::new_handshake_manager_queue,
        task_driver::{new_task_driver_queue, TaskDriverQueue},
    };
    use system_bus::SystemBus;

    use crate::{caching::order_cache::OrderBookCache, test_helpers::mock_db};

    use super::{StateApplicator, StateApplicatorConfig};

    /// Create a mock `StateApplicator`
    pub fn mock_applicator() -> StateApplicator {
        let (task_queue, recv) = new_task_driver_queue();
        mem::forget(recv);

        mock_applicator_with_task_queue(task_queue)
    }

    /// Create a mock `StateApplicator` with the given task queue
    pub(crate) fn mock_applicator_with_task_queue(task_queue: TaskDriverQueue) -> StateApplicator {
        let (handshake_manager_queue, _recv) = new_handshake_manager_queue();
        mem::forget(_recv);

        let (event_queue, _recv) = new_event_manager_queue();
        mem::forget(_recv);

        let config = StateApplicatorConfig {
            allow_local: true,
            task_queue,
            order_cache: Arc::new(OrderBookCache::new()),
            db: Arc::new(mock_db()),
            handshake_manager_queue,
            event_queue,
            system_bus: SystemBus::new(),
            cluster_id: ClusterId::from_str("test-cluster").unwrap(),
        };

        StateApplicator::new(config).unwrap()
    }
}
