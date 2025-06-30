//! Handles storage operations on the table that tracks the assignment of tasks
//! to nodes

// -----------
// | Getters |
// -----------

use common::types::{gossip::WrappedPeerId, tasks::TaskIdentifier};
use libmdbx::{RW, TransactionKind};

use crate::{TASK_ASSIGNMENT_TABLE, storage::error::StorageError};

use super::StateTxn;

/// Get the key for the list of tasks assigned to a node
fn node_tasks_key(id: &WrappedPeerId) -> String {
    format!("assigned-tasks-{id}")
}

/// Get the key for a task's assignment
fn task_assignment_key(task_id: &TaskIdentifier) -> String {
    format!("task-assignment-{task_id}")
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
    ) -> Result<Option<WrappedPeerId>, StorageError> {
        let key = task_assignment_key(task_id);
        let value = self.inner().read(TASK_ASSIGNMENT_TABLE, &key)?;

        Ok(value)
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Push a task to the list of assigned tasks for a node
    pub fn add_assigned_task(
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

    /// Reassign the tasks from one peer to another
    ///
    /// Returns the ids of the tasks that were reassigned
    pub fn reassign_tasks(
        &self,
        from: &WrappedPeerId,
        to: &WrappedPeerId,
    ) -> Result<Vec<TaskIdentifier>, StorageError> {
        // Reassign the tasks
        let new_tasks = self.get_assigned_tasks(from)?;
        let mut curr_tasks = self.get_assigned_tasks(to)?;

        curr_tasks.extend(new_tasks.clone());
        self.write_assigned_tasks(to, &curr_tasks)?;
        self.write_assigned_tasks(from, &vec![])?;

        // Update the inverse mapping
        for task_id in new_tasks.iter() {
            self.assign_task_to_node(task_id, to)?;
        }

        Ok(new_tasks)
    }

    // --- Helpers --- //

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

    /// Write the set of assigned tasks for a node
    fn write_assigned_tasks(
        &self,
        peer_id: &WrappedPeerId,
        value: &Vec<TaskIdentifier>,
    ) -> Result<(), StorageError> {
        let key = node_tasks_key(peer_id);
        // Delete the key if empty
        if value.is_empty() {
            self.inner().delete(TASK_ASSIGNMENT_TABLE, &key)?;
        } else {
            self.write_set(TASK_ASSIGNMENT_TABLE, &key, value)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use common::types::{gossip::mocks::mock_peer, tasks::TaskIdentifier};
    use itertools::Itertools;

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
        assert!(assigned_tasks.is_empty());

        // Add the task to the assigned tasks
        tx.add_assigned_task(&peer_id, &task_id).unwrap();

        // Check the assigned tasks => should be empty
        let assigned_tasks = tx.get_assigned_tasks(&peer_id).unwrap();
        let task_assignment = tx.get_task_assignment(&task_id).unwrap();
        assert_eq!(assigned_tasks, vec![task_id]);
        assert_eq!(task_assignment, Some(peer_id));

        // Remove the task from the assigned tasks
        tx.remove_assigned_task(&peer_id, &task_id).unwrap();

        // Check the assigned tasks => should be empty
        let assigned_tasks = tx.get_assigned_tasks(&peer_id).unwrap();
        let task_assignment = tx.get_task_assignment(&task_id).unwrap();
        assert!(assigned_tasks.is_empty());
        assert_eq!(task_assignment, None);
    }

    /// Tests reassigning an empty set of tasks
    #[test]
    fn test_reassign_empty() {
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();

        let from = mock_peer().get_peer_id();
        let to = mock_peer().get_peer_id();
        let task_id = TaskIdentifier::new_v4();

        // Add a task to the receiver
        tx.add_assigned_task(&to, &task_id).unwrap();
        tx.reassign_tasks(&from, &to).unwrap();

        // Check that the already existing task is the only task assigned to the
        // receiver
        let assigned_tasks = tx.get_assigned_tasks(&to).unwrap();
        let task_assignment = tx.get_task_assignment(&task_id).unwrap();
        assert_eq!(assigned_tasks, vec![task_id]);
        assert_eq!(task_assignment, Some(to));
    }

    /// Tests reassigning tasks from a non-empty set
    #[test]
    fn test_reassign_non_empty() {
        const N: usize = 10;
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();

        let from = mock_peer().get_peer_id();
        let to = mock_peer().get_peer_id();
        let from_tasks = (0..N).map(|_| TaskIdentifier::new_v4()).collect_vec();
        let to_tasks = (0..N).map(|_| TaskIdentifier::new_v4()).collect_vec();

        // Setup the to and from tasks
        for i in 0..N {
            tx.add_assigned_task(&to, &to_tasks[i]).unwrap();
            tx.add_assigned_task(&from, &from_tasks[i]).unwrap();
        }

        // Reassign the tasks
        tx.reassign_tasks(&from, &to).unwrap();

        let expected_tasks = to_tasks.iter().chain(from_tasks.iter()).cloned().collect_vec();
        let assigned_tasks = tx.get_assigned_tasks(&to).unwrap();
        assert_eq!(assigned_tasks, expected_tasks);

        // Check that the tasks are reassigned
        for i in 0..N {
            let from_task_assignment = tx.get_task_assignment(&from_tasks[i]).unwrap();
            let to_task_assignment = tx.get_task_assignment(&to_tasks[i]).unwrap();
            assert_eq!(from_task_assignment, Some(to));
            assert_eq!(to_task_assignment, Some(to));
        }
    }
}
