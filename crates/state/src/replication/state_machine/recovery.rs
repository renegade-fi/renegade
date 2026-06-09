//! Recover the state machine from a snapshot

use openraft::SnapshotMeta;
use tokio::fs;
use util::err_str;
use util::log_task;
use util::logging::Outcome;

use crate::logging::Task;
use crate::replication::error::ReplicationError;
use crate::replication::{Node, NodeId};

use super::StateMachine;

impl StateMachine {
    /// Check for a snapshot to recover from
    pub(crate) async fn maybe_recover_snapshot(&mut self) -> Result<(), ReplicationError> {
        let path = self.snapshot_archive_path();
        if !path.exists() {
            return Ok(());
        }

        // Check if the file is empty, this may happen if a dummy snapshot was created
        let metadata = fs::metadata(path).await.map_err(err_str!(ReplicationError::Snapshot))?;
        if metadata.len() == 0 {
            log_task!(
                Task::SnapshotRecovery,
                Outcome::Skipped,
                "empty snapshot found, skipping..."
            );
            return Ok(());
        }

        // Open the snap DB and recover from it, restoring the REAL applied log-id
        // and membership from the persisted snapshot metadata.
        //
        // `update_from_snapshot` overwrites the live DB with the snapshot's
        // contents (state as of the snapshot's applied log-id), so
        // `applied_state()` MUST report that same log-id. The previous code passed
        // a dummy meta (`last_log_id: None`, `last_membership: Default`), telling
        // openraft that nothing had been applied. On boot openraft would then try
        // to replay logs from an index that snapshot compaction had already purged,
        // panicking with `'LogIndex(0)' violates ... try to get log at index 0` and
        // crash-looping the node. Restoring the real metadata anchors
        // `last_membership` at its true log-id and makes openraft replay only the
        // retained post-snapshot logs.
        log_task!(Task::SnapshotRecovery, Outcome::Started, "snapshot found, recovering...");
        self.recovered_from_snapshot = true;
        let snap_db = self.open_snap_db().await?;
        let meta = self.recover_snapshot_meta()?;

        self.update_from_snapshot(&meta, snap_db).await?;
        self.clear_account_task_queues()?;
        self.delete_snapshot_data().await
    }

    /// Read the persisted snapshot metadata used to anchor the recovered state
    /// machine's applied log-id and membership.
    ///
    /// Falls back to an empty meta only if no metadata is stored, which should
    /// not happen once any snapshot has been built (`build_snapshot` and
    /// `update_from_snapshot` both persist it).
    fn recover_snapshot_meta(&self) -> Result<SnapshotMeta<NodeId, Node>, ReplicationError> {
        let tx = self.db().new_read_tx()?;
        match tx.get_snapshot_metadata()? {
            Some(archived) => Ok(archived.deserialize_with()?),
            None => {
                log_task!(
                    Task::SnapshotRecovery,
                    Outcome::Failed,
                    "snapshot data present but metadata missing; recovering without an \
                     applied-log anchor"
                );
                Ok(SnapshotMeta {
                    last_log_id: None,
                    last_membership: Default::default(),
                    snapshot_id: "recovery".to_string(),
                })
            },
        }
    }

    /// Clear all account task queues
    ///
    /// We do this when recovering to prevent accounts from being blocked on a
    /// task queue that failed
    fn clear_account_task_queues(&self) -> Result<(), ReplicationError> {
        let tx = self.db().new_write_tx_with_retry()?;
        let account_ids = tx.get_all_account_ids()?;
        for account_id in account_ids {
            tx.clear_task_queue(&account_id)?;
        }

        tx.commit()?;
        Ok(())
    }
}
