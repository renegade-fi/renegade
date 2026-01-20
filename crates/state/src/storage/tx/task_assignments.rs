//! Handles storage operations on the table that tracks the assignment of tasks
//! to nodes
//!
//! Task assignments use a per-task key scheme for efficient O(1) writes:
//! - `assigned-task/{peer_id}/{task_id}` -> `()` for peer-to-task index
//! - `task-assignment/{task_id}` -> `peer_id` for task-to-peer lookup

// -----------
// | Getters |
// -----------

use libmdbx::{RW, TransactionKind};
use types_gossip::WrappedPeerId;
use types_tasks::TaskIdentifier;

use crate::{
    TASK_ASSIGNMENT_TABLE,
    storage::{ArchivedValue, error::StorageError},
};

use super::StateTxn;

/// A type alias for an archived peer ID value
pub type PeerIdValue<'a> = ArchivedValue<'a, WrappedPeerId>;

// ------------------
// | Key Formatting |
// ------------------

/// The prefix for the peer-to-task index keys
const ASSIGNED_TASK_PREFIX: &str = "assigned-task/";

/// Get the key for a single task assignment (peer -> task mapping)
fn assigned_task_key(peer_id: &WrappedPeerId, task_id: &TaskIdentifier) -> String {
    format!("{ASSIGNED_TASK_PREFIX}{peer_id}/{task_id}")
}

/// Get the prefix for all tasks assigned to a peer
fn assigned_task_prefix(peer_id: &WrappedPeerId) -> String {
    format!("{ASSIGNED_TASK_PREFIX}{peer_id}/")
}

/// Get the key for a task's assignment (task -> peer lookup)
fn task_assignment_key(task_id: &TaskIdentifier) -> String {
    format!("task-assignment/{task_id}")
}

/// Parse a task identifier from an assigned task key
///
/// Key format: `assigned-task/{peer_id}/{task_id}`
fn parse_task_id_from_key(key: &str) -> Option<TaskIdentifier> {
    // Find the last '/' and parse everything after it as a TaskIdentifier
    let suffix = key.rsplit('/').next()?;
    suffix.parse().ok()
}

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Get the tasks assigned to a node
    ///
    /// This uses a cursor scan over the `assigned-task/{peer_id}/` prefix.
    /// This operation is O(n) in the number of tasks assigned to the peer,
    /// but is only used during peer failure recovery (rare).
    pub fn get_assigned_tasks(
        &self,
        peer_id: &WrappedPeerId,
    ) -> Result<Vec<TaskIdentifier>, StorageError> {
        let prefix = assigned_task_prefix(peer_id);
        let cursor = self
            .inner()
            .cursor::<String, ()>(TASK_ASSIGNMENT_TABLE)?
            .with_key_prefix(&prefix);

        let mut tasks = Vec::new();
        for entry in cursor.into_iter() {
            let (key, _) = entry?;
            if let Some(task_id) = parse_task_id_from_key(&key) {
                tasks.push(task_id);
            }
        }

        Ok(tasks)
    }

    /// Get the node assigned to a given task
    pub fn get_task_assignment(
        &self,
        task_id: &TaskIdentifier,
    ) -> Result<Option<PeerIdValue>, StorageError> {
        let key = task_assignment_key(task_id);
        self.inner().read::<_, WrappedPeerId>(TASK_ASSIGNMENT_TABLE, &key)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Add a task to the list of assigned tasks for a node
    ///
    /// This is an O(1) operation - just writes a single key for the
    /// peer-to-task index plus the task-to-peer lookup key.
    pub fn add_assigned_task(
        &self,
        peer_id: &WrappedPeerId,
        task_id: &TaskIdentifier,
    ) -> Result<(), StorageError> {
        // Write the peer-to-task index key
        let key = assigned_task_key(peer_id, task_id);
        self.inner().write(TASK_ASSIGNMENT_TABLE, &key, &())?;

        // Write the task-to-peer lookup key
        self.write_task_assignment(task_id, peer_id)
    }

    /// Remove a task from the list of assigned tasks for a node
    ///
    /// This is an O(1) operation - just deletes a single key for the
    /// peer-to-task index plus the task-to-peer lookup key.
    pub fn remove_assigned_task(
        &self,
        peer_id: &WrappedPeerId,
        task_id: &TaskIdentifier,
    ) -> Result<(), StorageError> {
        // Delete the peer-to-task index key
        let key = assigned_task_key(peer_id, task_id);
        self.inner().delete(TASK_ASSIGNMENT_TABLE, &key)?;

        // Delete the task-to-peer lookup key
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
        // Get all tasks from the source peer
        let tasks_to_reassign = self.get_assigned_tasks(from)?;

        // For each task, update both index keys
        for task_id in tasks_to_reassign.iter() {
            // Delete old peer-to-task key
            let old_key = assigned_task_key(from, task_id);
            self.inner().delete(TASK_ASSIGNMENT_TABLE, &old_key)?;

            // Write new peer-to-task key
            let new_key = assigned_task_key(to, task_id);
            self.inner().write(TASK_ASSIGNMENT_TABLE, &new_key, &())?;

            // Update the task-to-peer lookup
            self.write_task_assignment(task_id, to)?;
        }

        Ok(tasks_to_reassign)
    }

    // --- Helpers --- //

    /// Write the task-to-peer assignment lookup key
    fn write_task_assignment(
        &self,
        task_id: &TaskIdentifier,
        peer_id: &WrappedPeerId,
    ) -> Result<(), StorageError> {
        let key = task_assignment_key(task_id);
        self.inner().write(TASK_ASSIGNMENT_TABLE, &key, peer_id)
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use types_gossip::mocks::mock_peer;
    use types_tasks::TaskIdentifier;

    use crate::test_helpers::mock_db;

    /// Tests the basic flow of adding and removing task assignments
    #[test]
    fn test_assignments() {
        let db = mock_db();
        let peer_id = mock_peer().peer_id;
        let task_id = TaskIdentifier::new_v4();
        let tx = db.new_write_tx().unwrap();

        // First check the assigned tasks => should be empty
        let assigned_tasks = tx.get_assigned_tasks(&peer_id).unwrap();
        assert!(assigned_tasks.is_empty());

        // Add the task to the assigned tasks
        tx.add_assigned_task(&peer_id, &task_id).unwrap();

        // Check the assigned tasks => should be empty
        let assigned_tasks = tx.get_assigned_tasks(&peer_id).unwrap();
        let task_assignment = tx.get_task_assignment(&task_id).unwrap().unwrap();
        assert_eq!(assigned_tasks, vec![task_id]);
        assert_eq!(*task_assignment, peer_id);

        // Remove the task from the assigned tasks
        tx.remove_assigned_task(&peer_id, &task_id).unwrap();

        // Check the assigned tasks => should be empty
        let assigned_tasks = tx.get_assigned_tasks(&peer_id).unwrap();
        let task_assignment = tx.get_task_assignment(&task_id).unwrap();
        assert!(assigned_tasks.is_empty());
        assert!(task_assignment.is_none());
    }

    /// Tests reassigning an empty set of tasks
    #[test]
    fn test_reassign_empty() {
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();

        let from = mock_peer().peer_id;
        let to = mock_peer().peer_id;
        let task_id = TaskIdentifier::new_v4();

        // Add a task to the receiver
        tx.add_assigned_task(&to, &task_id).unwrap();
        tx.reassign_tasks(&from, &to).unwrap();

        // Check that the already existing task is the only task assigned to the
        // receiver
        let assigned_tasks = tx.get_assigned_tasks(&to).unwrap();
        let task_assignment = tx.get_task_assignment(&task_id).unwrap().unwrap();
        assert_eq!(assigned_tasks, vec![task_id]);
        assert_eq!(*task_assignment, to);
    }

    /// Tests reassigning tasks from a non-empty set
    #[test]
    fn test_reassign_non_empty() {
        use std::collections::HashSet;

        const N: usize = 10;
        let db = mock_db();
        let tx = db.new_write_tx().unwrap();

        let from = mock_peer().peer_id;
        let to = mock_peer().peer_id;
        let from_tasks = (0..N).map(|_| TaskIdentifier::new_v4()).collect_vec();
        let to_tasks = (0..N).map(|_| TaskIdentifier::new_v4()).collect_vec();

        // Setup the to and from tasks
        for i in 0..N {
            tx.add_assigned_task(&to, &to_tasks[i]).unwrap();
            tx.add_assigned_task(&from, &from_tasks[i]).unwrap();
        }

        // Reassign the tasks
        tx.reassign_tasks(&from, &to).unwrap();

        // Compare as sets since cursor returns in key order, not insertion order
        let expected_tasks: HashSet<_> =
            to_tasks.iter().chain(from_tasks.iter()).cloned().collect();
        let assigned_tasks: HashSet<_> = tx.get_assigned_tasks(&to).unwrap().into_iter().collect();
        assert_eq!(assigned_tasks, expected_tasks);

        // Check that the tasks are reassigned
        for i in 0..N {
            let from_task_assignment = tx.get_task_assignment(&from_tasks[i]).unwrap().unwrap();
            let to_task_assignment = tx.get_task_assignment(&to_tasks[i]).unwrap().unwrap();
            assert_eq!(*from_task_assignment, to);
            assert_eq!(*to_task_assignment, to);
        }
    }
}
