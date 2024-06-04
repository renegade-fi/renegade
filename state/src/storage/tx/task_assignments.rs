//! Handles storage operations on the table that tracks the assignment of tasks
//! to nodes

// -----------
// | Getters |
// -----------

use common::types::{gossip::WrappedPeerId, tasks::TaskIdentifier};
use libmdbx::{TransactionKind, RW};

use crate::{storage::error::StorageError, TASK_ASSIGNMENT_TABLE};

use super::StateTxn;

/// Get the key for the list of tasks assigned to a node
fn node_tasks_key(id: &WrappedPeerId) -> String {
    format!("assigned-tasks-{id}")
}

/// Get the key for a task's assignment
fn task_assignment_key(task_id: &TaskIdentifier) -> String {
    format!("task-assignment-{task_id}")
}

/// Create a key not found error for a task assignment
fn task_not_found_err(task_id: &TaskIdentifier) -> StorageError {
    StorageError::NotFound(format!("Task {task_id} not found"))
}

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Get the tasks assigned to a node
    pub fn get_assigned_tasks(
        &self,
        peer_id: &WrappedPeerId,
    ) -> Result<Vec<TaskIdentifier>, StorageError> {
        let key = node_tasks_key(peer_id);
        self.read_set(TASK_ASSIGNMENT_TABLE, &key)
    }

    /// Get the node assigned to a given task
    pub fn get_task_assignment(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<WrappedPeerId, StorageError> {
        let key = task_assignment_key(task_id);
        let value = self
            .inner()
            .read(TASK_ASSIGNMENT_TABLE, &key)?
            .ok_or_else(|| task_not_found_err(task_id))?;

        Ok(value)
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Push a task to the list of assigned tasks for a node
    pub fn add_assigned_tasks(
        &self,
        peer_id: &WrappedPeerId,
        task_id: &TaskIdentifier,
    ) -> Result<(), StorageError> {
        let key = node_tasks_key(peer_id);
        self.add_to_set(TASK_ASSIGNMENT_TABLE, &key, task_id)?;

        // Set the inverse assignment
        self.assign_task_to_node(task_id, peer_id)
    }

    /// Remove a task from the list of assigned tasks for a node
    pub fn remove_assigned_task(
        &self,
        peer_id: &WrappedPeerId,
        task_id: &TaskIdentifier,
    ) -> Result<(), StorageError> {
        let key = node_tasks_key(peer_id);
        self.remove_from_set(TASK_ASSIGNMENT_TABLE, &key, task_id)?;

        // Delete the assignment
        let key = task_assignment_key(task_id);
        self.inner().delete(TASK_ASSIGNMENT_TABLE, &key)?;
        Ok(())
    }

    /// Add an assignment from a task id to a node
    fn assign_task_to_node(
        &self,
        task_id: &TaskIdentifier,
        peer_id: &WrappedPeerId,
    ) -> Result<(), StorageError> {
        let key = task_assignment_key(task_id);
        self.inner().write(TASK_ASSIGNMENT_TABLE, &key, peer_id)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use common::types::{gossip::mocks::mock_peer, tasks::TaskIdentifier};

    use crate::test_helpers::mock_db;

    /// Tests the basic flow of adding and removing task assignments
    #[test]
    fn test_assignments() {
        let db = mock_db();
        let peer_id = mock_peer().get_peer_id();
        let task_id = TaskIdentifier::new_v4();
        let tx = db.new_write_tx().unwrap();

        // First check the assigned tasks => should be empty
        let assigned_tasks = tx.get_assigned_tasks(&peer_id).unwrap();
        assert_eq!(assigned_tasks, vec![]);

        // Add the task to the assigned tasks
        tx.add_assigned_tasks(&peer_id, &task_id).unwrap();

        // Check the assigned tasks => should be empty
        let assigned_tasks = tx.get_assigned_tasks(&peer_id).unwrap();
        let task_assignment = tx.get_task_assignment(&task_id).unwrap();
        assert_eq!(assigned_tasks, vec![task_id]);
        assert_eq!(task_assignment, peer_id);

        // Remove the task from the assigned tasks
        tx.remove_assigned_task(&peer_id, &task_id).unwrap();

        // Check the assigned tasks => should be empty
        let assigned_tasks = tx.get_assigned_tasks(&peer_id).unwrap();
        let task_assignment = tx.get_task_assignment(&task_id);
        assert_eq!(assigned_tasks, vec![]);
        assert!(task_assignment.is_err());
    }
}
