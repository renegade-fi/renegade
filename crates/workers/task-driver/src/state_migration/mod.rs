//! Defines state migrations to initialize the node's global state
//!
//! A state migration may, for example, fixup missing data, backfill a
//! denormalized table, or prune stale state entries
//!
//! These migrations should be idempotent, and defined as need be

use state::State;
use tokio::task::JoinHandle;

/// Apply all state migrations
pub(crate) fn run_state_migrations(_state: &State) -> Vec<JoinHandle<()>> {
    #[allow(unused_mut)]
    let mut handles = Vec::new();

    // Add state migrations here

    handles
}

// -----------
// | Testbed |
// -----------

/// The tests below load a snapshot from a static location and test the
/// migrations against it
///
/// To use: place a snapshot at:
///     {workspace_root}/test-snapshot/snapshot.gz
///
/// Then run:
///     cargo test -p task-driver test_state_migrations
///
/// Note: The test will output verbose logs from openraft. To reduce noise,
/// temporarily comment out the `setup_system_logger` line in the test
#[cfg(test)]
mod test {
    use std::{
        fs::File,
        path::{Path, PathBuf},
    };

    use config::RelayerConfig;
    use eyre::{Result, eyre};
    use flate2::read::GzDecoder;
    use state::{State, test_helpers::mock_state_with_config};
    use tracing::warn;
    use util::telemetry::{LevelFilter, setup_system_logger};

    use super::run_state_migrations;

    /// The directory at which a snapshot should be placed to test
    const SNAPSHOT_DIR: &str = "test-snapshot";
    /// The snapshot file name
    const SNAPSHOT_FILE: &str = "snapshot.gz";
    /// The unzipped data file name
    const DATA_FILE: &str = "snapshot.dat";

    /// Test state migrations
    #[tokio::test]
    async fn test_state_migrations() {
        setup_system_logger(LevelFilter::INFO);

        // Create state from the snapshot
        let state = match create_state_from_snapshot().await {
            Ok(state) => state,
            Err(e) => {
                warn!("Skipping test: {e}");
                return;
            },
        };

        // Run the migrations
        let handles = run_state_migrations(&state);

        // Wait for migrations to complete
        for handle in handles {
            handle.await.expect("migration task panicked");
        }
        println!("State migrations completed successfully");
    }

    /// Create a State instance from the snapshot
    async fn create_state_from_snapshot() -> Result<State> {
        // Get the workspace root (cargo test runs from various directories)
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .ok_or_else(|| eyre!("Failed to get workspace root"))?
            .parent()
            .ok_or_else(|| eyre!("Failed to get workspace root"))?
            .to_path_buf();
        let snapshot_path = workspace_root.join(SNAPSHOT_DIR).join(SNAPSHOT_FILE);
        if !snapshot_path.exists() {
            eyre::bail!("Snapshot file not found. Place snapshot at: {snapshot_path:?}");
        }
        let data_path = workspace_root.join(SNAPSHOT_DIR).join(DATA_FILE);

        // Unzip the snapshot to get the data file
        unzip_snapshot(&snapshot_path, &data_path)?;

        // Build a State instance with the DB
        let config = RelayerConfig {
            db_path: data_path.to_str().unwrap().to_string(),
            allow_local: true,
            record_historical_state: true,
            ..Default::default()
        };
        Ok(mock_state_with_config(&config).await)
    }

    /// Unzip the snapshot file to the given destination
    fn unzip_snapshot(snapshot_path: &Path, dest_path: &Path) -> Result<()> {
        // Remove preexisting data file if it exists
        if dest_path.exists() {
            std::fs::remove_file(dest_path)
                .map_err(|e| eyre!("failed to remove existing data file: {e}"))?;
        }

        let snapshot_file =
            File::open(snapshot_path).map_err(|e| eyre!("failed to open snapshot file: {e}"))?;
        let mut dest_writer =
            File::create(dest_path).map_err(|e| eyre!("failed to create destination file: {e}"))?;

        // Unzip the data file
        let mut decoder = GzDecoder::new(snapshot_file);
        std::io::copy(&mut decoder, &mut dest_writer)
            .map_err(|e| eyre!("failed to unzip snapshot: {e}"))?;

        Ok(())
    }
}
