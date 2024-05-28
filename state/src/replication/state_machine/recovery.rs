//! Recover the state machine from a snapshot

use openraft::SnapshotMeta;
use tokio::fs;
use tracing::info;
use util::err_str;

use crate::replication::error::ReplicationV2Error;

use super::StateMachine;

impl StateMachine {
    /// Check for a snapshot to recover from
    pub(crate) async fn maybe_recover_snapshot(&mut self) -> Result<(), ReplicationV2Error> {
        let path = self.snapshot_archive_path();
        if !path.exists() {
            return Ok(());
        }

        // Check if the file is empty, this may happen if a dummy snapshot was created
        let metadata = fs::metadata(path).await.map_err(err_str!(ReplicationV2Error::Snapshot))?;
        if metadata.len() == 0 {
            info!("empty snapshot found, skipping...");
            return Ok(());
        }

        // Open the snap DB and apply a dummy snapshot
        info!("snapshot found, recovering...");
        self.recovered_from_snapshot = true;
        let snap_db = self.open_snap_db().await?;
        let dummy_meta = SnapshotMeta {
            last_log_id: None,
            last_membership: Default::default(),
            snapshot_id: "recovery".to_string(),
        };

        self.update_from_snapshot(&dummy_meta, snap_db).await?;
        self.clear_wallet_task_queues()
    }

    /// Clear all wallet task queues
    ///
    /// We do this when recovering to prevent wallets from being blocked on a
    /// task queue that failed
    fn clear_wallet_task_queues(&self) -> Result<(), ReplicationV2Error> {
        let tx = self.db().new_write_tx().unwrap();
        let wallets = tx.get_all_wallets()?;
        for wallet in wallets.into_iter() {
            let queue_key = wallet.wallet_id;
            tx.clear_task_queue(&queue_key)?;
        }

        tx.commit()?;

        Ok(())
    }
}
