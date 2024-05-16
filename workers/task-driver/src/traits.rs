//! Defines traits that tasks must implement to be driven by the task driver and
//! queued by the consensus engine
use std::fmt::{Debug, Display};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use external_api::bus_message::SystemBusMessage;
use job_types::{network_manager::NetworkManagerQueue, proof_manager::ProofManagerQueue};
use serde::{Deserialize, Serialize};
use state::State;
use system_bus::SystemBus;

use crate::driver::StateWrapper;

// ------------------
// | Task and State |
// ------------------

/// The task trait defines a sequence of largely async flows, each of which is
/// possibly unreliable and may need to be retried until completion or to some
/// retry threshold
///
/// The task must be constructable from a descriptor, which is a serializable
/// description of the task's state transition, and a set of dependency
/// injections from the task driver that may include: network manager queue,
/// arbitrum client, etc.
#[async_trait]
pub trait Task: Send + Sized {
    /// The descriptor of a task, this may be used to construct the task
    ///
    /// The descriptor must be serializable so that it can be placed into the
    /// task queue and managed by the consensus engine
    type Descriptor: Debug + Serialize + for<'de> Deserialize<'de>;
    /// The state type of the task, used for task introspection
    ///
    /// The state must be orderable so that a commit point can be defined and
    /// measured against
    type State: TaskState;
    /// The error type that the task may give
    type Error: TaskError;

    /// A constructor for the task that takes a descriptor and a set of
    /// dependency injections
    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error>;
    /// Get the current state of the task
    fn state(&self) -> Self::State;
    /// Whether or not the task is completed
    fn completed(&self) -> bool {
        self.state().completed()
    }
    /// Get a displayable name for the task
    fn name(&self) -> String;
    /// Whether or not updates to this task should bypass the task queue
    ///
    /// Defined on this trait to allow maximally granular control over which
    /// tasks bypass the task queue in the future
    fn bypass_task_queue(&self) -> bool {
        false
    }
    /// Take a step in the task, steps should represent largely async behavior
    async fn step(&mut self) -> Result<(), Self::Error>;
    /// A cleanup step that is run in the event of a task failure
    async fn cleanup(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// The state of a task
///
/// Must implement methods determining whether a task has completed or committed
pub trait TaskState: Debug + Display + Ord + Send + Serialize + Into<StateWrapper> {
    /// Whether or not the task is completed
    fn completed(&self) -> bool;
    /// The state in which the task may be considered (at least partially)
    /// committed
    ///
    /// Beyond this point the task may not be preempted
    fn commit_point() -> Self;
    /// Whether or not the task is committed
    fn committed(&self) -> bool {
        *self >= Self::commit_point()
    }
}

/// The error type of a task
/// Must implement a method to determine if an error is retryable or permanent
pub trait TaskError: Debug + Display + Send {
    /// Whether or not the error is retryable
    fn retryable(&self) -> bool;
}

// ------------------------------
// | Dependency Injection Types |
// ------------------------------

/// The context given to a task by the driver in its constructor
///
/// This allows the task to be serializable into the consensus-maintained queue
/// by injecting non-serializable dependencies into the task's constructor via
/// the driver
#[derive(Clone)]
pub struct TaskContext {
    /// An arbitrum client
    pub arbitrum_client: ArbitrumClient,
    /// A handle on the global state
    pub state: State,
    /// A sender to the network manager's queue
    pub network_queue: NetworkManagerQueue,
    /// A sender to the proof manager's queue
    pub proof_queue: ProofManagerQueue,
    /// A handle on the system bus
    pub bus: SystemBus<SystemBusMessage>,
}
