//! Raft snapshots implementation
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use flate2::write::GzEncoder;
use flate2::Compression;
use openraft::{
    ErrorSubject, ErrorVerb, LogId, RaftSnapshotBuilder, Snapshot, SnapshotMeta,
    StorageError as RaftStorageError, StoredMembership,
};
use util::{err_str, get_current_time_millis};

use crate::storage::db::DbConfig;
use crate::storage::{db::DB, tx::raft_log::RAFT_LOGS_TABLE};
use crate::{CLUSTER_MEMBERSHIP_TABLE, NODE_METADATA_TABLE, PEER_INFO_TABLE};

use super::error::{new_snapshot_error, ReplicationV2Error};
use super::state_machine::StateMachine;
use super::{Node, NodeId, TypeConfig};

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

/// The completed snapshot
#[derive(Clone, Debug)]
pub struct SnapshotInfo {
    /// The location at which the snapshot zip was created
    location: PathBuf,
    /// The last log entry that was included in the snapshot
    last_log: Option<LogId<NodeId>>,
    /// The membership at the time the snapshot was created
    membership: StoredMembership<NodeId, Node>,
    /// The timestamp at which the snapshot was created
    timestamp: u64,
}

impl SnapshotInfo {
    /// Create snapshot metadata from the info
    pub fn get_snapshot_meta(&self) -> SnapshotMeta<NodeId, Node> {
        let id = format!("raft-snapshot-{}", self.timestamp);
        SnapshotMeta {
            last_log_id: self.last_log,
            last_membership: self.membership.clone(),
            snapshot_id: id,
        }
    }

    /// Get the location at which the snapshot was created
    pub fn location(&self) -> &PathBuf {
        &self.location
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, RaftStorageError<NodeId>> {
        let info = self.take_db_snapshot().await.map_err(new_snapshot_error)?;
        let meta = info.get_snapshot_meta();
        let snapshot_file = tokio::fs::File::open(info.location()).await.map_err(|err| {
            RaftStorageError::from_io_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, err)
        })?;

        Ok(Snapshot { meta, snapshot: Box::new(snapshot_file) })
    }
}

impl StateMachine {
    /// Take a snapshot of the DB
    pub(crate) async fn take_db_snapshot(&self) -> Result<SnapshotInfo, ReplicationV2Error> {
        let out_dir = &self.config.snapshot_out;

        // Start a tx to prevent writers from modifying the DB while copying
        let tx = self.db().new_read_tx().map_err(ReplicationV2Error::Storage)?;
        let snapshot_path = self.make_data_copy(out_dir).await?;
        tx.commit().map_err(ReplicationV2Error::Storage)?;

        // Build the snapshot
        let location = snapshot_path.clone();
        let build_task = tokio::task::spawn_blocking(move || Self::build_snapshot(&snapshot_path));
        build_task
            .await
            .map_err(|_| ReplicationV2Error::Snapshot(ERR_AWAIT_BUILD.to_string()))??;

        // Create the snapshot info
        let last_log = self.last_applied_log;
        let membership = self.last_membership.clone();
        let timestamp = get_current_time_millis();
        Ok(SnapshotInfo { location, last_log, membership, timestamp })
    }

    /// Copy the data file of the DB
    ///
    /// Returns the location at which the data was copied
    async fn make_data_copy(&self, out_dir: &str) -> Result<PathBuf, ReplicationV2Error> {
        let path = PathBuf::from(self.db().path());
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
        Self::remove_excluded_tables(copy_path.to_str().unwrap())?;
        Self::zip_file(copy_path)
    }

    /// Removes excluded tables from the snapshot
    ///
    /// These tables are those that need not show up in a snapshot, or for which
    /// it would cause errors to snapshot on the consumer side
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
}

#[cfg(test)]
mod tests {

    use flate2::bufread::GzDecoder;
    use libmdbx::Error as MdbxError;

    use crate::{
        replicationv2::test_helpers::mock_state_machine, storage::error::StorageError,
        test_helpers::tmp_db_path,
    };

    use super::*;

    /// Recover a data file from a snapshot archive
    ///
    /// Returns the location of the recovered data file
    async fn recover_data_from_snapshot(snapshot_path: &str) -> String {
        let snapshot_path = PathBuf::from(snapshot_path);
        let snapshot_path = snapshot_path.join(SNAPSHOT_FILE).with_extension("gz");

        let tmp_dir = PathBuf::from(tmp_db_path());
        if !tmp_dir.exists() {
            fs::create_dir_all(&tmp_dir).unwrap();
        }

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

        let state_machine = mock_state_machine();
        let snap_path = state_machine.snapshot_path();

        // Write to the DB
        let db = state_machine.db();
        db.create_table(TABLE).unwrap();
        db.write(TABLE, &k, &v).unwrap();

        // Take a snapshot then recover from it
        state_machine.take_db_snapshot().await.unwrap();
        let new_data_file = recover_data_from_snapshot(snap_path).await;

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

        let state_machine = mock_state_machine();
        let snap_path = state_machine.snapshot_path();
        let db = state_machine.db();

        // Write to the DB
        db.create_table(DUMMY_TABLE).unwrap();
        db.create_table(EXCLUDED_TABLE).unwrap();
        db.write(DUMMY_TABLE, &k1, &v1).unwrap();
        db.write(EXCLUDED_TABLE, &k2, &v2).unwrap();

        // Take a snapshot then recover from it
        state_machine.take_db_snapshot().await.unwrap();
        let new_data_file = recover_data_from_snapshot(snap_path).await;

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
        let state_machine = mock_state_machine();
        let snap_path = state_machine.snapshot_path();
        let db = state_machine.db();

        let (k, v1) = ("key".to_string(), "value".to_string());
        let v2 = "value2".to_string();

        // Write to the DB
        db.create_table(TABLE).unwrap();
        db.write(TABLE, &k, &v1).unwrap();

        // Take a snapshot, write the value, then take another snapshot
        state_machine.take_db_snapshot().await.unwrap();
        db.write(TABLE, &k, &v2).unwrap();
        state_machine.take_db_snapshot().await.unwrap();

        // Recover the DB and verify that only the second value remains
        let new_data_file = recover_data_from_snapshot(snap_path).await;
        let new_db = DB::new(&DbConfig { path: new_data_file }).unwrap();
        let value: String = new_db.read(TABLE, &k).unwrap().unwrap();

        assert_eq!(value, v2);
    }
}
