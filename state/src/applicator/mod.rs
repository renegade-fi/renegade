//! The state applicator applies updates that have been committed to by the raft
//! group to the global state, persisting them to local storage

use std::sync::Arc;

use common::types::gossip::ClusterId;
use external_api::bus_message::SystemBusMessage;
use job_types::task_driver::TaskDriverQueue;
use system_bus::SystemBus;

use crate::{storage::db::DB, StateTransition};

use self::error::StateApplicatorError;

pub mod error;
pub mod order_book;
pub mod task_queue;
pub mod wallet_index;

// -------------
// | Constants |
// -------------

/// A type alias for the result type given by the applicator
pub(crate) type Result<T> = std::result::Result<T, StateApplicatorError>;

/// The config for the state applicator
#[derive(Clone)]
pub struct StateApplicatorConfig {
    /// Whether or not to allow peers on the localhost
    pub allow_local: bool,
    /// The local peer's cluster ID
    pub cluster_id: ClusterId,
    /// A sender to the task driver's work queue
    pub task_queue: TaskDriverQueue,
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
    config: StateApplicatorConfig,
}

impl StateApplicator {
    /// Create a new state applicator
    pub fn new(config: StateApplicatorConfig) -> Result<Self> {
        Ok(Self { config })
    }

    /// Handle a state transition
    pub fn handle_state_transition(&self, transition: StateTransition) -> Result<()> {
        match transition {
            StateTransition::AddWallet { wallet } => self.add_wallet(&wallet),
            StateTransition::UpdateWallet { wallet } => self.update_wallet(&wallet),
            StateTransition::AddOrderValidityBundle { order_id, proof, witness } => {
                self.add_order_validity_proof(order_id, proof, witness)
            },
            StateTransition::AppendWalletTask { wallet_id, task } => {
                self.append_wallet_task(wallet_id, task)
            },
            StateTransition::PopWalletTask { wallet_id } => self.pop_wallet_task(wallet_id),
            _ => unimplemented!("Unsupported state transition forwarded to applicator"),
        }
    }

    /// Get a reference to the db
    fn db(&self) -> &DB {
        &self.config.db
    }

    /// Get a reference to the system bus
    fn system_bus(&self) -> &SystemBus<SystemBusMessage> {
        &self.config.system_bus
    }
}

#[cfg(test)]
mod test_helpers {
    use std::{mem, str::FromStr, sync::Arc};

    use common::types::gossip::ClusterId;
    use job_types::task_driver::{new_task_driver_queue, TaskDriverQueue};
    use system_bus::SystemBus;

    use crate::test_helpers::mock_db;

    use super::{StateApplicator, StateApplicatorConfig};

    /// Create a mock `StateApplicator`
    pub(crate) fn mock_applicator() -> StateApplicator {
        let (task_queue, recv) = new_task_driver_queue();
        mem::forget(recv);

        mock_applicator_with_task_queue(task_queue)
    }

    /// Create a mock `StateApplicator` with the given task queue
    pub(crate) fn mock_applicator_with_task_queue(task_queue: TaskDriverQueue) -> StateApplicator {
        let config = StateApplicatorConfig {
            allow_local: true,
            task_queue,
            db: Arc::new(mock_db()),
            system_bus: SystemBus::new(),
            cluster_id: ClusterId::from_str("test-cluster").unwrap(),
        };

        StateApplicator::new(config).unwrap()
    }
}
