//! Raft snapshots implementation
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;
use util::err_str;

use crate::storage::{db::DB, tx::raft_log::RAFT_LOGS_TABLE};
use crate::{CLUSTER_MEMBERSHIP_TABLE, NODE_METADATA_TABLE, PEER_INFO_TABLE};

use super::error::ReplicationV2Error;

/// The MDBX data file
const MDBX_DATA_FILE: &str = "mdbx.dat";
/// The snapshot file name
const SNAPSHOT_FILE: &str = "snapshot.dat";
/// Tables that should be excluded from the snapshot
///
/// These are tables whose values are not set through consensus, are node
/// specific, or otherwise contain volatile state not worth snapshotting
const EXCLUDED_TABLES: &[&str] =
    &[RAFT_LOGS_TABLE, PEER_INFO_TABLE, CLUSTER_MEMBERSHIP_TABLE, NODE_METADATA_TABLE];

/// An error awaiting a blocking zip task
const ERR_AWAIT_ZIP: &str = "error awaiting zip task";

/// Take a snapshot of the DB
pub(crate) async fn take_db_snapshot(out_dir: &str, db: &DB) -> Result<(), ReplicationV2Error> {
    // Start a tx to prevent writers from modifying the DB while copying
    let tx = db.new_read_tx().map_err(ReplicationV2Error::Storage)?;
    let snapshot_path = make_data_copy(db.path(), out_dir).await?;
    tx.commit().map_err(ReplicationV2Error::Storage)?;

    // TODO: Remove unneeded tables

    // Zip the snapshot
    let zip_task = tokio::task::spawn_blocking(move || zip_file(&snapshot_path));
    zip_task.await.map_err(|_| ReplicationV2Error::Snapshot(ERR_AWAIT_ZIP.to_string()))?
}

/// Copy the data file of the DB
///
/// Returns the location at which the data was copied
async fn make_data_copy(path: &str, out_dir: &str) -> Result<PathBuf, ReplicationV2Error> {
    let path = PathBuf::from(path);
    let data_path = path.join(MDBX_DATA_FILE);
    let snapshot_path = PathBuf::from(out_dir).join(SNAPSHOT_FILE);

    // Make a copy of the data
    tokio::fs::copy(data_path, snapshot_path.clone())
        .await
        .map_err(err_str!(ReplicationV2Error::Snapshot))?;
    Ok(snapshot_path)
}

/// Zip a file and delete the original
fn zip_file(path: &PathBuf) -> Result<(), ReplicationV2Error> {
    let source_file = File::open(path).map_err(err_str!(ReplicationV2Error::Snapshot))?;
    let mut source_reader = BufReader::new(source_file);
    let zip_path = path.with_extension("gz");
    let zip_file = File::create(zip_path).map_err(err_str!(ReplicationV2Error::Snapshot))?;

    // gzip the file
    let mut encoder = GzEncoder::new(zip_file, Compression::best());
    std::io::copy(&mut source_reader, &mut encoder)
        .map_err(err_str!(ReplicationV2Error::Snapshot))?;
    encoder.finish().map_err(err_str!(ReplicationV2Error::Snapshot))?;

    // Delete the file
    fs::remove_file(path).map_err(err_str!(ReplicationV2Error::Snapshot))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::env::temp_dir;

    use flate2::bufread::GzDecoder;

    use crate::{storage::db::DbConfig, test_helpers::tmp_db_path};

    use super::*;

    /// Recover a data file from a snapshot archive
    ///
    /// Returns the location of the recovered data file
    async fn recover_data_from_snapshot(snapshot_path: &str) -> String {
        let snapshot_path = PathBuf::from(snapshot_path);
        let snapshot_path = snapshot_path.join(SNAPSHOT_FILE).with_extension("gz");

        let tmp_dir = temp_dir();
        let out_path = tmp_dir.join(MDBX_DATA_FILE);
        let mut out_file = File::create(out_path.clone()).unwrap();

        // Load the snapshot and unzip it
        let snapshot_file = File::open(snapshot_path).unwrap();
        let snapshot_reader = BufReader::new(snapshot_file);
        let mut snapshot_decoder = GzDecoder::new(snapshot_reader);
        std::io::copy(&mut snapshot_decoder, &mut out_file).unwrap();

        out_path.to_str().unwrap().to_string()
    }

    /// Tests snapshotting and recovering a DB from a snapshot
    #[tokio::test]
    async fn test_snapshot() {
        const TABLE: &str = "test-table";
        let (k, v) = ("key".to_string(), "value".to_string());

        let db_path = tmp_db_path();
        let snap_path = db_path.clone();

        // Create a DB and write to it
        let db = DB::new(&DbConfig { path: db_path }).unwrap();
        db.create_table(TABLE).unwrap();
        db.write(TABLE, &k, &v).unwrap();

        // Take a snapshot then recover from it
        take_db_snapshot(&snap_path, &db).await.unwrap();
        let new_data_file = recover_data_from_snapshot(&snap_path).await;

        // Check that the recovered DB contains the same data
        let new_db = DB::new(&DbConfig { path: new_data_file }).unwrap();
        let value: String = new_db.read(TABLE, &k).unwrap().unwrap();

        assert_eq!(value, v);
    }
}
