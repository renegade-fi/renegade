//! Storage methods for task history

use std::cmp::Reverse;

use common::types::tasks::{HistoricalTask, TaskQueueKey};
use libmdbx::{TransactionKind, RW};

use crate::{storage::error::StorageError, TASK_HISTORY_TABLE};

use super::StateTxn;

/// Get the key for a given queue's history
fn task_history_key(key: &TaskQueueKey) -> String {
    format!("{key}-history")
}

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Get the task history for a given task queue
    pub fn get_task_history(
        &self,
        key: &TaskQueueKey,
    ) -> Result<Vec<HistoricalTask>, StorageError> {
        self.check_task_history_enabled()?;

        let key = task_history_key(key);
        let mut tasks: Vec<HistoricalTask> =
            self.inner.read(TASK_HISTORY_TABLE, &key)?.unwrap_or_default();
        tasks.sort_by_key(|t| Reverse(t.created_at));

        Ok(tasks)
    }

    /// Get up to `n` most recent tasks from the task history
    pub fn get_truncated_task_history(
        &self,
        n: usize,
        key: &TaskQueueKey,
    ) -> Result<Vec<HistoricalTask>, StorageError> {
        let mut tasks = self.get_task_history(key)?;
        tasks.truncate(n);
        Ok(tasks)
    }

    /// Check that the task history table is enabled, throwing an error if not
    fn check_task_history_enabled(&self) -> Result<(), StorageError> {
        if !self.get_historical_state_enabled()? {
            return Err(StorageError::TableDisabled(String::from(TASK_HISTORY_TABLE)));
        }

        Ok(())
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Append a task to the task history
    pub fn append_task_to_history(
        &self,
        key: &TaskQueueKey,
        task: HistoricalTask,
    ) -> Result<(), StorageError> {
        self.check_task_history_enabled()?;

        let mut tasks = self.get_task_history(key)?;

        // Push to the front to keep the most recent tasks first
        tasks.insert(0, task);
        let key = task_history_key(key);
        self.inner.write(TASK_HISTORY_TABLE, &key, &tasks)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Reverse;

    use common::types::tasks::historical_mocks::mock_historical_task;
    use common::types::wallet::WalletIdentifier;
    use itertools::Itertools;

    use crate::test_helpers::mock_db;

    /// Tests getting the task history
    #[test]
    fn test_get_history() {
        let db = mock_db();
        let wallet_id = WalletIdentifier::new_v4();

        // Fetch an empty history
        let tx = db.new_read_tx().unwrap();
        let history = tx.get_task_history(&wallet_id).unwrap();
        tx.commit().unwrap();
        assert!(history.is_empty());

        // Add a task to the history
        let task = mock_historical_task();
        let tx = db.new_write_tx().unwrap();
        tx.append_task_to_history(&wallet_id, task.clone()).unwrap();
        tx.commit().unwrap();

        // Fetch the history
        let tx = db.new_read_tx().unwrap();
        let history = tx.get_task_history(&wallet_id).unwrap();
        tx.commit().unwrap();

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].id, task.id);
    }

    /// Tests getting a truncated task history
    #[test]
    fn test_truncated_history() {
        const N: usize = 100;
        let db = mock_db();
        let wallet_id = WalletIdentifier::new_v4();

        let mut tasks = (0..N).map(|_| mock_historical_task()).collect_vec();
        let tx = db.new_write_tx().unwrap();
        for task in tasks.iter() {
            tx.append_task_to_history(&wallet_id, task.clone()).unwrap();
        }
        tx.commit().unwrap();

        // Sort tasks by reverse creation
        tasks.sort_by_key(|t| Reverse(t.created_at));

        // Fetch the first half of the history
        let tx = db.new_read_tx().unwrap();
        let history = tx.get_truncated_task_history(N / 2, &wallet_id).unwrap();
        tx.commit().unwrap();
        assert_eq!(history.len(), N / 2);
        for (a, b) in history.iter().zip(tasks.iter()) {
            assert_eq!(a.id, b.id);
        }
    }
}
