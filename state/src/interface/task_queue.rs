//! The interface for interacting with the task queue

use common::types::{
    task_descriptors::{QueuedTask, QueuedTaskState, TaskDescriptor},
    tasks::TaskIdentifier,
    wallet::WalletIdentifier,
};

use crate::{error::StateError, notifications::ProposalWaiter, State, StateTransition};

impl State {
    // -----------
    // | Getters |
    // -----------

    /// Get the length of the task queue for a wallet
    pub fn get_wallet_task_queue_len(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<usize, StateError> {
        self.get_wallet_tasks(wallet_id).map(|tasks| tasks.len())
    }

    /// Get the list of tasks for a wallet
    pub fn get_wallet_tasks(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<Vec<QueuedTask>, StateError> {
        let tx = self.db.new_read_tx()?;
        let tasks = tx.get_wallet_tasks(wallet_id)?;
        tx.commit()?;

        Ok(tasks)
    }

    /// Get the ID of the wallet that a task modified
    pub fn get_task_wallet(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<WalletIdentifier>, StateError> {
        let tx = self.db.new_read_tx()?;
        let wallet = tx.get_task_wallet(task_id)?;
        tx.commit()?;

        Ok(wallet)
    }

    /// Get a task by ID and wallet
    pub fn get_wallet_task_by_id(
        &self,
        wallet_id: &WalletIdentifier,
        task_id: &TaskIdentifier,
    ) -> Result<Option<QueuedTask>, StateError> {
        let tx = self.db.new_read_tx()?;
        let task = tx.get_wallet_task_by_id(wallet_id, task_id)?;
        tx.commit()?;

        Ok(task)
    }

    // -----------
    // | Setters |
    // -----------

    /// Append a wallet task to the queue
    pub fn append_wallet_task(
        &self,
        wallet_id: &WalletIdentifier,
        task: TaskDescriptor,
    ) -> Result<(TaskIdentifier, ProposalWaiter), StateError> {
        // Pick a task ID and create a task from the description
        let id = TaskIdentifier::new_v4();
        let self_id = self.get_peer_id()?;
        let task =
            QueuedTask { id, state: QueuedTaskState::Queued, executor: self_id, descriptor: task };

        // Propose the task to the task queue
        let waiter =
            self.send_proposal(StateTransition::AppendWalletTask { wallet_id: *wallet_id, task })?;
        Ok((id, waiter))
    }

    /// Pop a wallet task from the queue
    pub fn pop_wallet_task(
        &self,
        wallet_id: &WalletIdentifier,
    ) -> Result<ProposalWaiter, StateError> {
        // Propose the task to the task queue
        self.send_proposal(StateTransition::PopWalletTask { wallet_id: *wallet_id })
    }

    /// Transition the state of the top task in a wallet's queue
    pub fn transition_wallet_task(
        &self,
        wallet_id: &WalletIdentifier,
        state: QueuedTaskState,
    ) -> Result<ProposalWaiter, StateError> {
        // Propose the task to the task queue
        self.send_proposal(StateTransition::TransitionWalletTask { wallet_id: *wallet_id, state })
    }
}

#[cfg(test)]
mod test {
    use common::types::{
        task_descriptors::{mocks::mock_queued_task, QueuedTaskState},
        wallet::WalletIdentifier,
    };

    use crate::test_helpers::mock_state;

    /// Tests getter methods on an empty queue
    #[test]
    fn test_empty_queue() {
        let state = mock_state();

        let wallet_id = WalletIdentifier::new_v4();
        assert_eq!(state.get_wallet_task_queue_len(&wallet_id).unwrap(), 0);
        assert!(state.get_wallet_tasks(&wallet_id).unwrap().is_empty());
    }

    /// Tests appending to an empty queue
    #[tokio::test]
    async fn test_append() {
        let state = mock_state();

        // Propose a task to the queue
        let wallet_id = WalletIdentifier::new_v4();
        let task = mock_queued_task().descriptor;

        let (task_id, waiter) = state.append_wallet_task(&wallet_id, task).unwrap();
        waiter.await.unwrap();

        // Check that the task was added
        assert_eq!(state.get_wallet_task_queue_len(&wallet_id).unwrap(), 1);

        let tasks = state.get_wallet_tasks(&wallet_id).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, task_id);
        assert!(matches!(tasks[0].state, QueuedTaskState::Running { .. })); // Should be started

        assert!(state.get_wallet_task_by_id(&wallet_id, &task_id).unwrap().is_some());
    }

    /// Tests popping from a queue
    #[tokio::test]
    async fn test_pop() {
        let state = mock_state();

        // Propose a task to the queue
        let wallet_id = WalletIdentifier::new_v4();
        let task = mock_queued_task().descriptor;

        let (_task_id, waiter) = state.append_wallet_task(&wallet_id, task).unwrap();
        waiter.await.unwrap();

        // Pop the task from the queue
        let waiter = state.pop_wallet_task(&wallet_id).unwrap();
        waiter.await.unwrap();

        // Check that the task was removed
        assert_eq!(state.get_wallet_task_queue_len(&wallet_id).unwrap(), 0);
    }

    /// Tests transitioning the state of a task
    #[tokio::test]
    async fn test_transition() {
        let state = mock_state();

        // Propose a task to the queue
        let wallet_id = WalletIdentifier::new_v4();
        let task = mock_queued_task().descriptor;

        let (task_id, waiter) = state.append_wallet_task(&wallet_id, task).unwrap();
        waiter.await.unwrap();

        // Transition the task to a new state
        let waiter = state
            .transition_wallet_task(
                &wallet_id,
                QueuedTaskState::Running { state: "Test".to_string() },
            )
            .unwrap();
        waiter.await.unwrap();

        // Check that the task was transitioned
        let task = state.get_wallet_task_by_id(&wallet_id, &task_id).unwrap().unwrap();
        assert_eq!(task.state, QueuedTaskState::Running { state: "Test".to_string() });
    }
}
