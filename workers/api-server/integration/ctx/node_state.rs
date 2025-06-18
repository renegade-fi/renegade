//! Helpers for working with the integration node's state

use eyre::Result;
use state::State;

use crate::ctx::IntegrationTestCtx;

/// The tables that are cleared when the state is cleared
///
/// We'd rather keep the constants in the state private, so we copy them here
const TABLES_TO_CLEAR: [&str; 6] = [
    "orders",
    "order-history",
    "matching-pools",
    "order-to-wallet",
    "nullifier-to-wallet",
    "wallet-info",
];

impl IntegrationTestCtx {
    /// Get the state of the integration node
    pub fn state(&self) -> State {
        self.mock_node.state()
    }

    /// Setup the state of the mock node
    pub async fn setup_state(&mut self) -> Result<()> {
        let state = self.state();
        let this_peer = state.get_peer_id().await?;
        state.initialize_raft(vec![this_peer] /* this_peer */).await?;
        Ok(())
    }

    /// Clear the state of the mock node
    pub async fn clear_state(&mut self) -> Result<()> {
        self.clear_raft_snapshots().await?;
        for table in TABLES_TO_CLEAR {
            self.clear_table(table).await?;
        }

        Ok(())
    }

    /// Clear a table on the state's database
    async fn clear_table(&self, name: &str) -> Result<()> {
        let db = &self.state().db;
        let tx = db.new_write_tx()?;

        tx.clear_table(name)?;
        tx.commit()?;
        Ok(())
    }

    /// Delete any snapshots the raft has taken
    async fn clear_raft_snapshots(&self) -> Result<()> {
        let snapshot_path = self.mock_node.config().raft_snapshot_path;
        clear_dir_contents(&snapshot_path).await
    }
}

// -----------
// | Helpers |
// -----------

/// Clear all files and directories within a directory, keeping the directory
/// itself
async fn clear_dir_contents(path: &str) -> Result<()> {
    // If the directory doesn't exist, do nothing
    if !std::path::Path::new(path).exists() {
        return Ok(());
    }

    let mut entries = tokio::fs::read_dir(path).await?;
    while let Some(entry) = entries.next_entry().await? {
        let entry_path = entry.path();
        if entry_path.is_dir() {
            tokio::fs::remove_dir_all(entry_path).await?;
        } else {
            tokio::fs::remove_file(entry_path).await?;
        }
    }

    Ok(())
}
