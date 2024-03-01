//! The interface for interacting with the task queue

use common::types::tasks::{
    QueuedTask, QueuedTaskState, TaskDescriptor, TaskIdentifier, TaskQueueKey,
};

use crate::{error::StateError, notifications::ProposalWaiter, State, StateTransition};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Whether or not the task queue contains a specific task
    pub fn contains_task(&self, task_id: &TaskIdentifier) -> Result<bool, StateError> {
        let tx = self.db.new_read_tx()?;
        let key = self.get_task_queue_key(task_id)?;
        tx.commit()?;

        Ok(key.is_some())
    }

    /// Get the length of the task queue
    pub fn get_task_queue_len(&self, key: &TaskQueueKey) -> Result<usize, StateError> {
        self.get_queued_tasks(key).map(|tasks| tasks.len())
    }

    /// Get the list of tasks
    pub fn get_queued_tasks(&self, key: &TaskQueueKey) -> Result<Vec<QueuedTask>, StateError> {
        let tx = self.db.new_read_tx()?;
        let tasks = tx.get_queued_tasks(key)?;
        tx.commit()?;

        Ok(tasks)
    }

    /// Get the task queue key that a task modifies
    pub fn get_task_queue_key(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<TaskQueueKey>, StateError> {
        let tx = self.db.new_read_tx()?;
        let key = tx.get_queue_key_for_task(task_id)?;
        tx.commit()?;

        Ok(key)
    }

    /// Get a task by ID
    pub fn get_task(&self, task_id: &TaskIdentifier) -> Result<Option<QueuedTask>, StateError> {
        let tx = self.db.new_read_tx()?;
        let task = tx.get_task(task_id)?;
        tx.commit()?;

        Ok(task)
    }

    /// Get the status of a task
    pub fn get_task_status(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<QueuedTaskState>, StateError> {
        let tx = self.db.new_read_tx()?;
        let status = tx.get_task(task_id)?;
        tx.commit()?;

        Ok(status.map(|x| x.state))
    }

    /// Returns the current running task for a queue if it exists and has
    /// already committed
    pub fn current_committed_task(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<TaskIdentifier>, StateError> {
        let tx = self.db.new_read_tx()?;
        let running = tx.get_current_running_task(key)?;
        tx.commit()?;

        Ok(running.filter(|x| x.state.is_committed()).map(|x| x.id))
    }

    // -----------
    // | Setters |
    // -----------

    /// Append a task to the queue
    pub fn append_task(
        &self,
        task: TaskDescriptor,
    ) -> Result<(TaskIdentifier, ProposalWaiter), StateError> {
        // Pick a task ID and create a task from the description
        let id = TaskIdentifier::new_v4();
        let self_id = self.get_peer_id()?;
        let task =
            QueuedTask { id, state: QueuedTaskState::Queued, executor: self_id, descriptor: task };

        // Propose the task to the task queue
        let waiter = self.send_proposal(StateTransition::AppendTask { task })?;
        Ok((id, waiter))
    }

    /// Pop a task from the queue
    pub fn pop_task(&self, task_id: TaskIdentifier) -> Result<ProposalWaiter, StateError> {
        // Propose the task to the task queue
        self.send_proposal(StateTransition::PopTask { task_id })
    }

    /// Transition the state of the top task in a queue
    pub fn transition_task(
        &self,
        task_id: TaskIdentifier,
        state: QueuedTaskState,
    ) -> Result<ProposalWaiter, StateError> {
        // Propose the task to the task queue
        self.send_proposal(StateTransition::TransitionTask { task_id, state })
    }

    /// Pause a task queue
    pub fn pause_task_queue(&self, key: &TaskQueueKey) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::PreemptTaskQueue { key: *key })
    }

    /// Resume a task queue
    pub fn resume_task_queue(&self, key: &TaskQueueKey) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::ResumeTaskQueue { key: *key })
    }
}

#[cfg(test)]
mod test {
    use common::types::{
        tasks::{mocks::mock_queued_task, QueuedTaskState, TaskQueueKey},
        wallet_mocks::mock_empty_wallet,
    };

    use crate::test_helpers::mock_state;

    /// Tests getter methods on an empty queue
    #[test]
    fn test_empty_queue() {
        let state = mock_state();

        let key = TaskQueueKey::new_v4();
        assert_eq!(state.get_task_queue_len(&key).unwrap(), 0);
        assert!(state.get_queued_tasks(&key).unwrap().is_empty());
    }

    /// Tests appending to an empty queue
    #[tokio::test]
    async fn test_append() {
        let state = mock_state();

        // Propose a task to the queue
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key).descriptor;

        let (task_id, waiter) = state.append_task(task).unwrap();
        waiter.await.unwrap();

        // Check that the task was added
        assert_eq!(state.get_task_queue_len(&key).unwrap(), 1);

        let tasks = state.get_queued_tasks(&key).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task_id);
        assert!(matches!(tasks[0].state, QueuedTaskState::Running { .. })); // Should be started

        assert!(state.get_task(&task_id).unwrap().is_some());
    }

    /// Tests popping from a queue
    #[tokio::test]
    async fn test_pop() {
        let state = mock_state();

        // Add a wallet that the task may reference
        let wallet = mock_empty_wallet();
        let wallet_id = wallet.wallet_id;
        state.new_wallet(wallet).unwrap().await.unwrap();

        // Propose a task to the queue
        let task = mock_queued_task(wallet_id).descriptor;
        let (task_id, waiter) = state.append_task(task).unwrap();
        waiter.await.unwrap();

        // Pop the task from the queue
        let waiter = state.pop_task(task_id).unwrap();
        waiter.await.unwrap();

        // Check that the task was removed
        assert_eq!(state.get_task_queue_len(&wallet_id).unwrap(), 0);
    }

    /// Tests transitioning the state of a task
    #[tokio::test]
    async fn test_transition() {
        let state = mock_state();

        // Propose a new task to the queue
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key).descriptor;

        let (task_id, waiter) = state.append_task(task).unwrap();
        waiter.await.unwrap();

        // Transition the task to a new state
        let waiter = state
            .transition_task(
                task_id,
                QueuedTaskState::Running { state: "Test".to_string(), committed: false },
            )
            .unwrap();
        waiter.await.unwrap();

        // Check that the task was transitioned
        let task = state.get_task(&task_id).unwrap().unwrap();
        assert_eq!(
            task.state,
            QueuedTaskState::Running { state: "Test".to_string(), committed: false }
        );
    }

    /// Tests the `has_committed_task` method
    #[tokio::test]
    async fn test_has_committed_task() {
        let state = mock_state();

        // Add a task
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key).descriptor;

        let (task_id, waiter) = state.append_task(task).unwrap();
        waiter.await.unwrap();

        // Check that the queue has no committed task
        assert!(state.current_committed_task(&key).unwrap().is_none());

        // Transition the task to running and check again
        let waiter = state
            .transition_task(
                task_id,
                QueuedTaskState::Running { state: "Running".to_string(), committed: false },
            )
            .unwrap();
        waiter.await.unwrap();
        assert!(state.current_committed_task(&key).unwrap().is_none());

        // Transition the task to committed and check again
        let waiter = state
            .transition_task(
                task_id,
                QueuedTaskState::Running { state: "Running".to_string(), committed: true },
            )
            .unwrap();
        waiter.await.unwrap();
        assert_eq!(state.current_committed_task(&key).unwrap(), Some(task_id));
    }
}
