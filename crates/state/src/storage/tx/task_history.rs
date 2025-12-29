//! Storage methods for task history

use std::cmp::Reverse;

use libmdbx::{RW, TransactionKind};
use types_tasks::{HistoricalTask, TaskIdentifier, TaskQueueKey};

use crate::{
    NODE_METADATA_TABLE, TASK_HISTORY_TABLE,
    storage::{ArchivedValue, error::StorageError},
};

use super::StateTxn;

/// The key for the local relayer's historical state enabled flag in the node
/// metadata table
const HISTORICAL_STATE_ENABLED_KEY: &str = "historical-state-enabled";

/// A type alias for an archived task history entry
type HistoricalTaskValue<'a> = ArchivedValue<'a, HistoricalTask>;
/// A type alias for an archived task ID list
type TaskIdListValue<'a> = ArchivedValue<'a, Vec<TaskIdentifier>>;

/// Get the key for a given queue's history
fn task_history_key(key: &TaskQueueKey) -> String {
    format!("{key}-history")
}

/// Get the key for a specific task in the history
fn task_history_item_key(key: &TaskQueueKey, task_id: &TaskIdentifier) -> String {
    format!("{key}-history-task-{task_id}")
}

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    /// Get the task history for a given task queue
    pub fn get_task_history(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Vec<HistoricalTaskValue<'_>>, StorageError> {
        // Fetch the list of task IDs
        let ids_value = self.get_task_ids_in_history(key)?;
        if ids_value.is_none() {
            return Ok(Vec::new());
        }
        let ids = &*ids_value.unwrap();

        // Fetch each task individually
        let mut tasks = Vec::new();
        for task_id in ids.iter() {
            let item_key = task_history_item_key(key, task_id);
            let task_value = self.inner.read::<_, HistoricalTask>(TASK_HISTORY_TABLE, &item_key)?;

            if let Some(v) = task_value {
                tasks.push(v);
            }
        }

        // Sort by created_at in reverse order (most recent first)
        tasks.sort_by_key(|t| Reverse(t.created_at));
        Ok(tasks)
    }

    /// Get up to `n` most recent tasks from the task history
    pub fn get_truncated_task_history(
        &self,
        n: usize,
        key: &TaskQueueKey,
    ) -> Result<Vec<HistoricalTaskValue<'_>>, StorageError> {
        let mut tasks = self.get_task_history(key)?;
        tasks.truncate(n);
        Ok(tasks)
    }

    /// Check that the task history table is enabled, throwing an error if not
    fn check_task_history_enabled(&self) -> Result<(), StorageError> {
        // If the flag doesn't exist, treat it as disabled
        let enabled_value = self
            .inner
            .read::<_, bool>(NODE_METADATA_TABLE, &HISTORICAL_STATE_ENABLED_KEY.to_string())?;

        if enabled_value.is_none() || !*enabled_value.unwrap() {
            return Err(StorageError::TableDisabled(TASK_HISTORY_TABLE.to_string()));
        }

        Ok(())
    }

    /// Get the task IDs in a history
    fn get_task_ids_in_history(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Option<TaskIdListValue<'_>>, StorageError> {
        self.check_task_history_enabled()?;

        // Fetch a list of the tasks in history
        let history_key = task_history_key(key);
        let ids_value =
            self.inner.read::<_, Vec<TaskIdentifier>>(TASK_HISTORY_TABLE, &history_key)?;

        Ok(ids_value)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    /// Append a task to the task history
    pub fn append_task_to_history(
        &self,
        key: &TaskQueueKey,
        task: &HistoricalTask,
    ) -> Result<(), StorageError> {
        self.check_task_history_enabled()?;

        // Write the task individually
        let item_key = task_history_item_key(key, &task.id);
        self.inner.write(TASK_HISTORY_TABLE, &item_key, task)?;

        // Update the history list (just IDs)
        let ids_value = self.get_task_ids_in_history(key)?;
        let mut task_ids = ids_value.map(|a| a.deserialize()).transpose()?.unwrap_or_default();

        // Insert at the front to keep the most recent tasks first
        task_ids.insert(0, task.id);
        self.inner.write(TASK_HISTORY_TABLE, &task_history_key(key), &task_ids)?;

        Ok(())
    }

    /// Purge the task history for a given task queue
    pub fn purge_task_history(&self, key: &TaskQueueKey) -> Result<(), StorageError> {
        let history_key = task_history_key(key);

        // Read the list of task IDs
        let ids_value = self.get_task_ids_in_history(key)?;
        let task_ids = ids_value.map(|a| a.deserialize()).transpose()?.unwrap_or_default();

        // Delete each individual task
        for task_id in task_ids {
            let item_key = task_history_item_key(key, &task_id);
            self.inner.delete(TASK_HISTORY_TABLE, &item_key)?;
        }

        // Delete the history list
        self.inner.delete(TASK_HISTORY_TABLE, &history_key).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Reverse;

    use itertools::Itertools;
    use types_tasks::{HistoricalTask, TaskQueueKey};

    use crate::test_helpers::mock_db;

    /// Tests getting the task history
    #[test]
    fn test_get_history() {
        let db = mock_db();
        let wallet_id = TaskQueueKey::new_v4();

        // Fetch an empty history
        let tx = db.new_read_tx().unwrap();
        let history = tx.get_task_history(&wallet_id).unwrap();
        assert!(history.is_empty());
        drop(history);
        tx.commit().unwrap();

        // Add a task to the history
        let task = HistoricalTask::mock();
        let tx = db.new_write_tx().unwrap();
        tx.append_task_to_history(&wallet_id, &task).unwrap();
        tx.commit().unwrap();

        // Fetch the history
        let tx = db.new_read_tx().unwrap();
        let history = tx.get_task_history(&wallet_id).unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id.as_bytes(), task.id.as_bytes());
        drop(history);
        tx.commit().unwrap();
    }

    /// Tests getting a truncated task history
    #[test]
    fn test_truncated_history() {
        const N: usize = 100;
        let db = mock_db();
        let wallet_id = TaskQueueKey::new_v4();

        let mut tasks = (0..N).map(|_| HistoricalTask::mock()).collect_vec();
        let tx = db.new_write_tx().unwrap();
        for task in tasks.iter() {
            tx.append_task_to_history(&wallet_id, task).unwrap();
        }
        tx.commit().unwrap();

        // Sort tasks by reverse creation
        tasks.sort_by_key(|t| Reverse(t.created_at));

        // Fetch the first half of the history
        let tx = db.new_read_tx().unwrap();
        let history = tx.get_truncated_task_history(N / 2, &wallet_id).unwrap();
        assert_eq!(history.len(), N / 2);
        for (a, b) in history.iter().zip(tasks.iter()) {
            assert_eq!(a.id.as_bytes(), b.id.as_bytes());
        }
        drop(history);
        tx.commit().unwrap();
    }

    /// Tests purging task history
    #[test]
    fn test_purge_history() {
        const N: usize = 100;
        let db = mock_db();
        let wallet_id = TaskQueueKey::new_v4();

        let tasks = (0..N).map(|_| HistoricalTask::mock()).collect_vec();
        let tx = db.new_write_tx().unwrap();
        for task in tasks.iter() {
            tx.append_task_to_history(&wallet_id, task).unwrap();
        }
        tx.commit().unwrap();

        // Assert current length of task history
        let tx = db.new_read_tx().unwrap();
        let history = tx.get_task_history(&wallet_id).unwrap();
        assert_eq!(history.len(), N);
        drop(history);
        tx.commit().unwrap();

        // Purge the history
        let tx = db.new_write_tx().unwrap();
        tx.purge_task_history(&wallet_id).unwrap();
        tx.commit().unwrap();

        // Assert that the history is now empty
        let tx = db.new_read_tx().unwrap();
        let history = tx.get_task_history(&wallet_id).unwrap();
        assert!(history.is_empty());
        drop(history);
        tx.commit().unwrap();
    }
}
