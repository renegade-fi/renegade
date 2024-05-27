//! Recover the state machine from a snapshot

use common::types::tasks::{QueuedTask, TaskQueueKey};
use openraft::SnapshotMeta;
use tracing::info;
use uuid::Uuid;

use crate::{replication::error::ReplicationV2Error, TASK_QUEUE_TABLE};

use super::StateMachine;

impl StateMachine {
    /// Check for a snapshot to recover from
    pub(crate) async fn maybe_recover_snapshot(&mut self) -> Result<(), ReplicationV2Error> {
        if !self.snapshot_archive_path().exists() {
            return Ok(());
        }

        // Open the snap DB and apply a dummy snapshot
        info!("snapshot found, recovering...");
        let snap_db = self.open_snap_db().await?;
        let dummy_meta = SnapshotMeta {
            last_log_id: None,
            last_membership: Default::default(),
            snapshot_id: "recovery".to_string(),
        };

        self.update_from_snapshot(&dummy_meta, snap_db).await?;
        self.clear_task_queues()
    }

    /// Clear all task queues
    ///
    /// We do this when recovering to prevent wallets from being blocked on a
    /// task queue that failed
    fn clear_task_queues(&self) -> Result<(), ReplicationV2Error> {
        let tx = self.db().new_write_tx().unwrap();
        let cur = tx.inner().cursor::<TaskQueueKey, Vec<QueuedTask>>(TASK_QUEUE_TABLE)?;
        for kv in cur.into_iter().keys() {
            let queue_key: Uuid = kv?;
            tx.clear_task_queue(&queue_key)?;
        }
        tx.commit()?;

        Ok(())
    }
}
