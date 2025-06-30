//! The interface for interacting with the task queue

use common::types::{
    gossip::WrappedPeerId,
    tasks::{
        HistoricalTask, QueuedTask, QueuedTaskState, RefreshWalletTaskDescriptor, TaskDescriptor,
        TaskIdentifier, TaskQueueKey,
    },
    wallet::WalletIdentifier,
};
use tracing::instrument;
use util::telemetry::helpers::backfill_trace_field;

use crate::{
    StateInner, StateTransition, error::StateError, notifications::ProposalWaiter,
    storage::tx::task_queue::TaskQueuePreemptionState,
};

impl StateInner {
    // -----------
    // | Getters |
    // -----------

    /// Whether or not the task queue contains a specific task
    pub async fn contains_task(&self, task_id: &TaskIdentifier) -> Result<bool, StateError> {
        let tid = *task_id;
        self.with_read_tx(move |tx| Ok(tx.get_task(&tid)?.is_some())).await
    }

    /// Whether the queue is paused by a serial task
    pub async fn is_queue_paused_serial(&self, key: &TaskQueueKey) -> Result<bool, StateError> {
        let key = *key;
        self.with_read_tx(move |tx| {
            let queue = tx.get_task_queue(&key)?;
            let paused_serial =
                queue.preemption_state == TaskQueuePreemptionState::SerialPreemptionQueued;
            Ok(paused_serial)
        })
        .await
    }

    /// Whether there are any serial tasks enqueued for the given queue
    pub async fn has_active_serial_tasks(&self, key: &TaskQueueKey) -> Result<bool, StateError> {
        let serial_task_len = self.serial_tasks_queue_len(key).await?;
        Ok(serial_task_len > 0)
    }

    /// Get the length of the serial task queue
    pub async fn serial_tasks_queue_len(&self, key: &TaskQueueKey) -> Result<usize, StateError> {
        let key = *key;
        self.with_read_tx(move |tx| {
            let queue = tx.get_task_queue(&key)?;
            Ok(queue.serial_tasks.len())
        })
        .await
    }

    /// Get the list of tasks enqueued for the given queue
    pub async fn get_queued_tasks(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Vec<QueuedTask>, StateError> {
        let key = *key;
        self.with_read_tx(move |tx| {
            let queue = tx.get_queued_tasks(&key)?;
            Ok(queue)
        })
        .await
    }

    /// Get the list of all tasks (running an historical) up to a truncation
    /// length
    pub async fn get_task_history(
        &self,
        len: usize,
        key: &TaskQueueKey,
    ) -> Result<Vec<HistoricalTask>, StateError> {
        let key = *key;
        self.with_read_tx(move |tx| {
            let running = tx.get_queued_tasks(&key)?;
            let remaining = len.saturating_sub(running.len());
            let historical = tx.get_truncated_task_history(remaining, &key)?;
            Ok(running
                .into_iter()
                .filter_map(|t| HistoricalTask::from_queued_task(key, t))
                .chain(historical)
                .take(len)
                .collect())
        })
        .await
    }

    /// Get a task by ID
    pub async fn get_task(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<QueuedTask>, StateError> {
        let tid = *task_id;
        self.with_read_tx(move |tx| {
            let task = tx.get_task(&tid)?;
            Ok(task)
        })
        .await
    }

    /// Get the status of a task
    pub async fn get_task_status(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<QueuedTaskState>, StateError> {
        let tid = *task_id;
        self.with_read_tx(move |tx| {
            let status = tx.get_task(&tid)?;
            Ok(status.map(|x| x.state))
        })
        .await
    }

    // -----------
    // | Setters |
    // -----------

    /// A shorthand to append a wallet refresh task to the queue and await the
    /// state transition
    ///
    /// Returns the task ID for the refresh
    pub async fn append_wallet_refresh_task(
        &self,
        wallet_id: WalletIdentifier,
    ) -> Result<TaskIdentifier, StateError> {
        let task = RefreshWalletTaskDescriptor::new(wallet_id);
        let (task_id, waiter) = self.append_task(task.into()).await?;
        waiter.await?;

        Ok(task_id)
    }

    /// Append a task to the queue
    #[instrument(name = "propose_append_task", skip_all, err, fields(task_id, task = %task.display_description()))]
    pub async fn append_task(
        &self,
        task: TaskDescriptor,
    ) -> Result<(TaskIdentifier, ProposalWaiter), StateError> {
        // Build the task
        let task = QueuedTask::new(task);
        let tid = task.id;
        backfill_trace_field("task_id", tid.to_string());

        // Propose the task to the task queue
        let executor = self.get_peer_id().await?;
        let proposal = StateTransition::AppendTask { task, executor };
        let waiter = self.send_proposal(proposal).await?;
        Ok((tid, waiter))
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

    /// Clear a task queue
    pub async fn clear_task_queue(&self, key: &TaskQueueKey) -> Result<ProposalWaiter, StateError> {
        self.send_proposal(StateTransition::ClearTaskQueue { queue: *key }).await
    }

    /// Enqueue a preemptive task
    ///
    /// A task marked `serial` (i.e. `serial = true`) requires exclusive access
    /// to the task queues specified by `keys`. A task marked `!serial` is a
    /// concurrent task, and is allowed to run concurrently with other
    /// concurrent tasks on the same queues.
    #[instrument(
        name = "propose_enqueue_preemptive_task", 
        skip_all, err, fields(
            queue_keys = ?keys, task_id, task = %task.display_description(), serial = %serial
        )
    )]
    pub async fn enqueue_preemptive_task(
        &self,
        keys: Vec<TaskQueueKey>,
        task: TaskDescriptor,
        serial: bool,
    ) -> Result<(TaskIdentifier, ProposalWaiter), StateError> {
        // Build the task
        let task = QueuedTask::new(task);
        let tid = task.id;
        backfill_trace_field("task_id", tid.to_string());

        // Propose the task to the task queue, with the local peer as the executor
        let executor = self.get_peer_id().await?;
        let transition = StateTransition::EnqueuePreemptiveTask { keys, task, executor, serial };
        let waiter = self.send_proposal(transition).await?;
        Ok((tid, waiter))
    }

    /// Reassign the tasks from a failed peer to the local peer
    pub async fn reassign_tasks(
        &self,
        failed_peer: &WrappedPeerId,
    ) -> Result<ProposalWaiter, StateError> {
        let local_peer = self.get_peer_id().await?;
        let proposal = StateTransition::ReassignTasks { from: *failed_peer, to: local_peer };
        self.send_proposal(proposal).await
    }
}

#[cfg(test)]
mod test {
    use common::types::{
        tasks::{
            QueuedTaskState, TaskQueueKey,
            mocks::{mock_queued_task, mock_task_descriptor},
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
        assert_eq!(state.serial_tasks_queue_len(&key).await.unwrap(), 0);
        assert!(state.get_queued_tasks(&key).await.unwrap().is_empty());
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
        assert_eq!(state.serial_tasks_queue_len(&key).await.unwrap(), 1);

        let tasks = state.get_queued_tasks(&key).await.unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task_id);
        assert!(matches!(tasks[0].state, QueuedTaskState::Running { .. })); // Should be started

        assert!(state.get_task(&task_id).await.unwrap().is_some());
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
        assert_eq!(state.serial_tasks_queue_len(&wallet_id).await.unwrap(), 0);
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
        let task = state.get_task(&task_id).await.unwrap().unwrap();
        assert_eq!(
            task.state,
            QueuedTaskState::Running { state: "Test".to_string(), committed: false }
        );
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
        let history = state.get_task_history(N, &wallet_id).await.unwrap();
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
