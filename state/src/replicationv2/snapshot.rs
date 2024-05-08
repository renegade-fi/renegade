//! Raft snapshots implementation
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;
use util::err_str;

use crate::storage::db::DbConfig;
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
const ERR_AWAIT_BUILD: &str = "error awaiting build task";

/// Take a snapshot of the DB
pub(crate) async fn take_db_snapshot(out_dir: &str, db: &DB) -> Result<(), ReplicationV2Error> {
    // Start a tx to prevent writers from modifying the DB while copying
    let tx = db.new_read_tx().map_err(ReplicationV2Error::Storage)?;
    let snapshot_path = make_data_copy(db.path(), out_dir).await?;
    tx.commit().map_err(ReplicationV2Error::Storage)?;

    // Build the snapshot
    let build_task = tokio::task::spawn_blocking(move || build_snapshot(&snapshot_path));
    build_task.await.map_err(|_| ReplicationV2Error::Snapshot(ERR_AWAIT_BUILD.to_string()))?
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

/// Build the snapshot from a copy of the data file
///
/// This involves removing excluded tables and zipping the data file
fn build_snapshot(copy_path: &PathBuf) -> Result<(), ReplicationV2Error> {
    remove_excluded_tables(copy_path.to_str().unwrap())?;
    zip_file(copy_path)
}

/// Removes excluded tables from the snapshot
///
/// These tables are those that need not show up in a snapshot, or for which it
/// would cause errors to snapshot on the consumer side
fn remove_excluded_tables(copy_path: &str) -> Result<(), ReplicationV2Error> {
    let path_str = copy_path.to_string();
    let db_config = DbConfig { path: path_str };
    let snapshot_db = DB::new(&db_config).map_err(ReplicationV2Error::Storage)?;

    for table in EXCLUDED_TABLES {
        #[allow(unsafe_code)]
        unsafe { snapshot_db.drop_table(table) }.map_err(ReplicationV2Error::Storage)?;
    }

    Ok(())
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
    use libmdbx::Error as MdbxError;

    use crate::{storage::error::StorageError, test_helpers::tmp_db_path};

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

    /// Tests taking a snapshot with a key in an excluded table
    #[tokio::test]
    async fn test_snapshot_excluded_table() {
        const DUMMY_TABLE: &str = "dummy-table";
        const EXCLUDED_TABLE: &str = EXCLUDED_TABLES[0];
        let (k1, v1) = ("key1".to_string(), "value1".to_string());
        let (k2, v2) = ("key2".to_string(), "value2".to_string());

        let db_path = tmp_db_path();
        let snap_path = db_path.clone();

        // Create a DB and write to it
        let db = DB::new(&DbConfig { path: db_path }).unwrap();
        db.create_table(DUMMY_TABLE).unwrap();
        db.create_table(EXCLUDED_TABLE).unwrap();
        db.write(DUMMY_TABLE, &k1, &v1).unwrap();
        db.write(EXCLUDED_TABLE, &k2, &v2).unwrap();

        // Take a snapshot then recover from it
        take_db_snapshot(&snap_path, &db).await.unwrap();
        let new_data_file = recover_data_from_snapshot(&snap_path).await;

        // Check that the original table still contains the excluded value
        let value: String = db.read(EXCLUDED_TABLE, &k2).unwrap().unwrap();
        assert_eq!(value, v2);

        // Check that the recovered DB contains the same data minus the excluded table
        let new_db = DB::new(&DbConfig { path: new_data_file }).unwrap();
        let value1: String = new_db.read(DUMMY_TABLE, &k1).unwrap().unwrap();
        let v2_err: StorageError = new_db.read::<_, String>(EXCLUDED_TABLE, &k2).err().unwrap();

        assert_eq!(value1, v1);
        assert!(matches!(v2_err, StorageError::OpenTable(MdbxError::NotFound)));
    }

    /// Test taking multiple snapshots after successive updates, ensuring that
    /// snapshots overwrite one another
    #[tokio::test]
    async fn test_snapshot_overwrite() {
        const TABLE: &str = "test-table";
        let db_path = tmp_db_path();
        let snap_path = db_path.clone();

        let (k, v1) = ("key".to_string(), "value".to_string());
        let v2 = "value2".to_string();

        // Create a DB and write to it
        let db = DB::new(&DbConfig { path: db_path }).unwrap();
        db.create_table(TABLE).unwrap();
        db.write(TABLE, &k, &v1).unwrap();

        // Take a snapshot, write the value, then take another snapshot
        take_db_snapshot(&snap_path, &db).await.unwrap();
        db.write(TABLE, &k, &v2).unwrap();
        take_db_snapshot(&snap_path, &db).await.unwrap();

        // Recover the DB and verify that only the second value remains
        let new_data_file = recover_data_from_snapshot(&snap_path).await;
        let new_db = DB::new(&DbConfig { path: new_data_file }).unwrap();
        let value: String = new_db.read(TABLE, &k).unwrap().unwrap();

        assert_eq!(value, v2);
    }
}
