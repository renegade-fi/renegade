//! The interface for interacting with the task queue

use common::types::tasks::{
    HistoricalTask, QueuedTask, QueuedTaskState, TaskDescriptor, TaskIdentifier, TaskQueueKey,
};
use tracing::instrument;
use util::{get_current_time_millis, telemetry::helpers::backfill_trace_field};

use crate::{
    error::StateError, notifications::ProposalWaiter, replicationv2::raft::NetworkEssential, State,
    StateHandle, StateTransition,
};

impl<N: NetworkEssential> StateHandle<N> {
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

    /// Get the list of all tasks (running an historical) up to a truncation
    /// length
    pub fn get_task_history(
        &self,
        len: usize,
        key: &TaskQueueKey,
    ) -> Result<Vec<HistoricalTask>, StateError> {
        // Fetch running and historical tasks
        let tx = self.db.new_read_tx()?;
        let running = tx.get_queued_tasks(key)?;
        let remaining = len.saturating_sub(running.len());
        let historical = tx.get_truncated_task_history(remaining, key)?;
        tx.commit()?;

        // Convert running tasks and concatenate the lists
        let converted = running
            .into_iter()
            .filter_map(|t| HistoricalTask::from_queued_task(*key, t))
            .chain(historical)
            .take(len)
            .collect();

        Ok(converted)
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
    #[instrument(name = "propose_append_task", skip_all, err, fields(task_id, task = %task.display_description()))]
    pub async fn append_task(
        &self,
        task: TaskDescriptor,
    ) -> Result<(TaskIdentifier, ProposalWaiter), StateError> {
        // Pick a task ID and create a task from the description
        let id = TaskIdentifier::new_v4();
        backfill_trace_field("task_id", id.to_string());

        let self_id = self.get_peer_id()?;
        let task = QueuedTask {
            id,
            state: QueuedTaskState::Queued,
            executor: self_id,
            descriptor: task,
            created_at: get_current_time_millis(),
        };

        // Propose the task to the task queue
        let waiter = self.send_proposal(StateTransition::AppendTask { task }).await?;
        Ok((id, waiter))
    }

    /// Pop a task from the queue
    #[instrument(name = "propose_pop_task", skip_all, err, fields(task_id = %task_id, success = %success))]
    pub async fn pop_task(
        &self,
        task_id: TaskIdentifier,
        success: bool,
    ) -> Result<ProposalWaiter, StateError> {
        // Propose the task to the task queue
        self.send_proposal(StateTransition::PopTask { task_id, success }).await
    }

    /// Transition the state of the top task in a queue
    pub async fn transition_task(
        &self,
        task_id: TaskIdentifier,
        state: QueuedTaskState,
    ) -> Result<ProposalWaiter, StateError> {
        // Propose the task to the task queue
        self.send_proposal(StateTransition::TransitionTask { task_id, state }).await
    }

    /// Pause a task queue placing the given task at the front of the queue
    #[instrument(name = "propose_preempt_task_queue", skip_all, err, fields(task_id, task = %task.display_description()))]
    pub async fn pause_task_queue(
        &self,
        key: &TaskQueueKey,
        task_id: TaskIdentifier,
        task: TaskDescriptor,
    ) -> Result<ProposalWaiter, StateError> {
        // Pick a task ID and create a task from the description
        backfill_trace_field("task_id", task_id.to_string());
        let self_id = self.get_peer_id()?;
        let task = QueuedTask {
            id: task_id,
            state: QueuedTaskState::Preemptive,
            executor: self_id,
            descriptor: task,
            created_at: get_current_time_millis(),
        };

        self.send_proposal(StateTransition::PreemptTaskQueue { key: *key, task }).await
    }

    /// Resume a task queue
    #[instrument(name = "propose_resume_task_queue", skip_all, err, fields(queue_key = %key))]
    pub async fn resume_task_queue(
        &self,
        key: &TaskQueueKey,
        success: bool,
    ) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::ResumeTaskQueue { key: *key, success }).await
    }
}

#[cfg(test)]
mod test {
    use common::types::{
        tasks::{
            mocks::{mock_queued_task, mock_task_descriptor},
            QueuedTaskState, TaskQueueKey,
        },
        wallet::WalletIdentifier,
        wallet_mocks::mock_empty_wallet,
    };

    use crate::test_helpers::mock_state;

    /// Tests getter methods on an empty queue
    #[tokio::test]
    async fn test_empty_queue() {
        let state = mock_state().await;

        let key = TaskQueueKey::new_v4();
        assert_eq!(state.get_task_queue_len(&key).unwrap(), 0);
        assert!(state.get_queued_tasks(&key).unwrap().is_empty());
    }

    /// Tests appending to an empty queue
    #[tokio::test]
    async fn test_append() {
        let state = mock_state().await;

        // Propose a task to the queue
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key).descriptor;

        let (task_id, waiter) = state.append_task(task).await.unwrap();
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
        let state = mock_state().await;

        // Add a wallet that the task may reference
        let wallet = mock_empty_wallet();
        let wallet_id = wallet.wallet_id;
        let waiter = state.new_wallet(wallet).await.unwrap();
        waiter.await.unwrap();

        // Propose a task to the queue
        let task = mock_queued_task(wallet_id).descriptor;
        let (task_id, waiter) = state.append_task(task).await.unwrap();
        waiter.await.unwrap();

        // Pop the task from the queue
        let waiter = state.pop_task(task_id, true /* success */).await.unwrap();
        waiter.await.unwrap();

        // Check that the task was removed
        assert_eq!(state.get_task_queue_len(&wallet_id).unwrap(), 0);
    }

    /// Tests transitioning the state of a task
    #[tokio::test]
    async fn test_transition() {
        let state = mock_state().await;

        // Propose a new task to the queue
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key).descriptor;

        let (task_id, waiter) = state.append_task(task).await.unwrap();
        waiter.await.unwrap();

        // Transition the task to a new state
        let waiter = state
            .transition_task(
                task_id,
                QueuedTaskState::Running { state: "Test".to_string(), committed: false },
            )
            .await
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
        let state = mock_state().await;

        // Add a task
        let key = TaskQueueKey::new_v4();
        let task = mock_queued_task(key).descriptor;

        let (task_id, waiter) = state.append_task(task).await.unwrap();
        waiter.await.unwrap();

        // Check that the queue has no committed task
        assert!(state.current_committed_task(&key).unwrap().is_none());

        // Transition the task to running and check again
        let waiter = state
            .transition_task(
                task_id,
                QueuedTaskState::Running { state: "Running".to_string(), committed: false },
            )
            .await
            .unwrap();
        waiter.await.unwrap();
        assert!(state.current_committed_task(&key).unwrap().is_none());

        // Transition the task to committed and check again
        let waiter = state
            .transition_task(
                task_id,
                QueuedTaskState::Running { state: "Running".to_string(), committed: true },
            )
            .await
            .unwrap();
        waiter.await.unwrap();
        assert_eq!(state.current_committed_task(&key).unwrap(), Some(task_id));
    }

    /// Tests fetching task history
    #[tokio::test]
    async fn test_task_history() {
        const N: usize = 10;
        let state = mock_state().await;
        let wallet_id = WalletIdentifier::new_v4();

        // Add historical tasks
        for _ in 0..N {
            // First push to the queue then pop
            let task = mock_task_descriptor(wallet_id);
            let (task_id, waiter) = state.append_task(task).await.unwrap();
            waiter.await.unwrap();

            let waiter = state.pop_task(task_id, true /* success */).await.unwrap();
            waiter.await.unwrap();
        }

        // Add a few running tasks
        for _ in 0..N / 2 {
            let task = mock_task_descriptor(wallet_id);
            let (_, waiter) = state.append_task(task).await.unwrap();
            waiter.await.unwrap();
        }

        // Fetch the task history
        let history = state.get_task_history(N, &wallet_id).unwrap();
        assert_eq!(history.len(), N);
        assert!(matches!(history[0].state, QueuedTaskState::Running { .. }));
        for task in history.iter().take(N / 2).skip(1) {
            assert_eq!(task.state, QueuedTaskState::Queued);
        }

        for task in history.iter().skip(N / 2) {
            assert!(matches!(task.state, QueuedTaskState::Completed));
        }
    }
}
