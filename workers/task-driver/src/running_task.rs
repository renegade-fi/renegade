//! Encapsulates the running task's bookkeeping structure to simplify the driver
//! logic

use common::types::tasks::TaskIdentifier;
use state::{error::StateError, State};
use tracing::{error, info};

use crate::{
    driver::StateWrapper,
    error::TaskDriverError,
    traits::{Task, TaskContext, TaskError},
};

// ----------------
// | Running Task |
// ----------------

/// The container type for a task running in the driver
///
/// Used to simplify driver logic
pub struct RunnableTask<T: Task> {
    /// Whether or not the task is a preemptive task
    preemptive: bool,
    /// The id of the underlying task
    task_id: TaskIdentifier,
    /// The underlying task
    task: T,
    /// A handle to the relayer-global state
    state: State,
}

impl<T: Task> RunnableTask<T> {
    /// Creates a new running task from the given task and state
    pub fn new(preemptive: bool, task_id: TaskIdentifier, task: T, state: State) -> Self {
        Self { preemptive, task_id, task, state }
    }

    /// Create a runnable from the given descriptor and context
    pub async fn from_descriptor(
        preemptive: bool,
        id: TaskIdentifier,
        descriptor: T::Descriptor,
        ctx: TaskContext,
    ) -> Result<Self, TaskDriverError> {
        let state = ctx.state.clone();
        let task = T::new(descriptor, ctx).await?;

        Ok(Self::new(preemptive, id, task, state))
    }

    /// The ID of the underlying task
    pub fn id(&self) -> TaskIdentifier {
        self.task_id
    }

    /// Whether the underlying task completed
    pub fn completed(&self) -> bool {
        self.task.completed()
    }

    /// Returns the state of the underlying task
    pub fn state(&self) -> StateWrapper {
        self.task.state().into()
    }

    /// Step the underlying task, returns whether the driver should continue or
    /// abort. `Ok(true)` means successful step, `Ok(false)` means that the task
    /// step failed and should be retried, an error should be aborted
    ///
    /// This includes a state transition in the consensus engine, if this method
    /// returns an error the driver should abort the task
    pub async fn step(&mut self) -> Result<bool, TaskDriverError> {
        // Handle a failed step
        if let Err(e) = self.task.step().await {
            error!("error executing task step: {e}");
            return if e.retryable() { Ok(false) } else { Err(e.into()) };
        };

        // Successful step, attempt to transition the state
        self.transition_state().await?;
        Ok(true)
    }

    /// Attempts to transition the state of the underlying task in the consensus
    /// engine. If this method fails the driver should abort the task
    pub async fn transition_state(&mut self) -> Result<(), StateError> {
        let task_id = self.task_id;
        let name = self.task.name();
        let new_state = self.state();
        info!("task {name}({task_id:?}) transitioning to state {new_state}");

        // Preemptive tasks need not update state in the consensus engine
        if self.preemptive {
            return Ok(());
        }

        // If this state commits the task (first state past the commit point) then await
        // consensus before continuing
        let is_commit = new_state.is_committing();
        let waiter = self.state.transition_task(task_id, new_state.into())?;
        if is_commit {
            waiter.await?;
        }

        Ok(())
    }

    /// Cleanup the underlying task
    pub async fn cleanup(&mut self) -> Result<(), TaskDriverError> {
        // Do not propagate errors from cleanup, continue to cleanup
        if let Err(e) = self.task.cleanup().await {
            error!("error cleaning up task: {e:?}");
        }

        // Pop the task from the state
        // Preemptive tasks are not indexed, so no work needs to be done
        if !self.preemptive {
            self.state.pop_task(self.task_id)?.await?;
        }

        Ok(())
    }
}
