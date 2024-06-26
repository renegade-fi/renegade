//! Raft snapshots implementation
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use openraft::{
    ErrorSubject, ErrorVerb, LogId, RaftSnapshotBuilder, Snapshot, SnapshotMeta,
    StorageError as RaftStorageError, StoredMembership,
};
use util::{err_str, get_current_time_millis};

use crate::replication::error::{new_snapshot_error, ReplicationV2Error};
use crate::storage::db::{DbConfig, DB};
use crate::{
    ALL_TABLES, CLUSTER_MEMBERSHIP_TABLE, NODE_METADATA_TABLE, PEER_INFO_TABLE, RAFT_LOGS_TABLE,
    RAFT_METADATA_TABLE, RELAYER_FEES_TABLE,
};

use super::{Node, NodeId, StateMachine, TypeConfig};

/// The MDBX data file
const MDBX_DATA_FILE: &str = "mdbx.dat";
/// Tables that should be excluded from the snapshot
///
/// These are tables whose values are not set through consensus, are node
/// specific, or otherwise contain volatile state not worth snapshotting
const EXCLUDED_TABLES: &[&str] = &[
    RAFT_LOGS_TABLE,
    RAFT_METADATA_TABLE,
    PEER_INFO_TABLE,
    CLUSTER_MEMBERSHIP_TABLE,
    NODE_METADATA_TABLE,
    RELAYER_FEES_TABLE,
];

/// An error awaiting a blocking zip task
const ERR_AWAIT_BUILD: &str = "error awaiting build task";
/// An error occurred while awaiting the snapshot installation task
const ERR_AWAIT_INSTALL: &str = "error awaiting snapshot installation task";
/// Error converting an async file into a sync file
const ERR_CONVERT_FILE: &str = "error converting file from async to sync";

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
        // Create the lock file
        self.create_snapshot_lock().await.map_err(new_snapshot_error)?;

        let info = self.take_db_snapshot().await.map_err(new_snapshot_error)?;
        let meta = info.get_snapshot_meta();
        let snapshot_file = tokio::fs::File::open(info.location()).await.map_err(|err| {
            RaftStorageError::from_io_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, err)
        })?;

        // Remove the lock file, store the metadata and return
        self.delete_snapshot_lock().await.map_err(new_snapshot_error)?;
        self.write_snapshot_metadata(&meta).map_err(new_snapshot_error)?;
        Ok(Snapshot { meta, snapshot: Box::new(snapshot_file) })
    }
}

impl StateMachine {
    // ----------------
    // | Snapshotting |
    // ----------------

    /// Write the metadata for a snapshot
    fn write_snapshot_metadata(
        &self,
        meta: &SnapshotMeta<NodeId, Node>,
    ) -> Result<(), ReplicationV2Error> {
        let tx = self.db().new_write_tx().map_err(ReplicationV2Error::Storage)?;
        tx.set_snapshot_metadata(meta)?;
        tx.commit().map_err(ReplicationV2Error::Storage)?;

        Ok(())
    }

    /// Take a snapshot of the DB
    pub(crate) async fn take_db_snapshot(&self) -> Result<SnapshotInfo, ReplicationV2Error> {
        // Start a tx to prevent writers from modifying the DB while copying
        let tx = self.db().new_read_tx().map_err(ReplicationV2Error::Storage)?;
        let snapshot_path = self.make_data_copy().await?;
        tx.commit().map_err(ReplicationV2Error::Storage)?;

        // Build the snapshot
        let build_task = tokio::task::spawn_blocking(move || Self::build_snapshot(&snapshot_path));
        build_task
            .await
            .map_err(|_| ReplicationV2Error::Snapshot(ERR_AWAIT_BUILD.to_string()))??;

        // Create the snapshot info
        let location = self.snapshot_archive_path();
        let last_log = self.last_applied_log;
        let membership = self.last_membership.clone();
        let timestamp = get_current_time_millis();
        Ok(SnapshotInfo { location, last_log, membership, timestamp })
    }

    /// Copy the data file of the DB
    ///
    /// Returns the location at which the data was copied
    async fn make_data_copy(&self) -> Result<PathBuf, ReplicationV2Error> {
        // Create the directory if it doesn't exist
        self.create_snapshot_dir().await?;

        let path = PathBuf::from(self.db().path());
        let data_path = path.join(MDBX_DATA_FILE);
        let snapshot_path = self.snapshot_data_path();

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
        let db_config = DbConfig::new_with_path(&path_str);
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

        // Create a temporary archive file to write the snapshot to while compression is
        // underway. This is to avoid overwriting an existing snapshot which may
        // currently be in the process of streaming to a peer.
        let tmp_zip_path = path.with_extension("tmp.gz");
        let zip_file =
            File::create(tmp_zip_path.clone()).map_err(err_str!(ReplicationV2Error::Snapshot))?;

        // gzip the file
        let mut encoder = GzEncoder::new(zip_file, Compression::best());
        std::io::copy(&mut source_reader, &mut encoder)
            .map_err(err_str!(ReplicationV2Error::Snapshot))?;
        encoder.finish().map_err(err_str!(ReplicationV2Error::Snapshot))?;

        // Delete the file
        fs::remove_file(path).map_err(err_str!(ReplicationV2Error::Snapshot))?;

        // Delete the old snapshot file if it exists & rename the temp file
        let zip_path = path.with_extension("gz");
        if zip_path.exists() {
            fs::remove_file(zip_path.clone()).map_err(err_str!(ReplicationV2Error::Snapshot))?;
        }
        fs::rename(tmp_zip_path, zip_path).map_err(err_str!(ReplicationV2Error::Snapshot))?;

        Ok(())
    }

    // ----------------
    // | Installation |
    // ----------------

    /// Unzip a snapshot and open a DB from the data
    #[allow(unused)]
    pub(crate) async fn open_snap_db(&self) -> Result<DB, ReplicationV2Error> {
        // Open the file
        let zip_path = self.snapshot_archive_path();
        let file = tokio::fs::File::open(zip_path)
            .await
            .map_err(err_str!(ReplicationV2Error::Snapshot))?;
        self.open_snap_db_with_file(file).await
    }

    /// Open a snapshot DB from a given file
    pub(crate) async fn open_snap_db_with_file(
        &self,
        file: tokio::fs::File,
    ) -> Result<DB, ReplicationV2Error> {
        // Unzip the snapshot
        let dest_path = self.snapshot_data_path();
        let db_path = dest_path.clone();
        let std_file = file
            .try_into_std()
            .map_err(|_| ReplicationV2Error::Snapshot(ERR_CONVERT_FILE.to_string()))?;
        let job = tokio::task::spawn_blocking(move || Self::unzip_data_file(&std_file, &dest_path));
        job.await.map_err(|_| ReplicationV2Error::Snapshot(ERR_AWAIT_BUILD.to_string()))??;

        // Open the DB
        let path = db_path.to_str().unwrap().to_string();
        let db_config = DbConfig::new_with_path(&path);
        let db = DB::new(&db_config).map_err(ReplicationV2Error::Storage)?;

        Ok(db)
    }

    /// Update the local DB using a snapshot DB
    pub async fn update_from_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, Node>,
        snapshot_db: DB,
    ) -> Result<(), ReplicationV2Error> {
        self.last_applied_log = meta.last_log_id;
        self.last_membership = meta.last_membership.clone();
        self.write_snapshot_metadata(meta)?;

        let db_clone = self.db_owned();
        let jh = tokio::task::spawn_blocking(move || Self::copy_db_data(&snapshot_db, &db_clone));
        jh.await.map_err(|_| ReplicationV2Error::Snapshot(ERR_AWAIT_INSTALL.to_string()))?
    }

    /// Copy all data from one DB to another
    pub(crate) fn copy_db_data(src: &DB, dest: &DB) -> Result<(), ReplicationV2Error> {
        let src_tx = src.new_read_tx()?;
        let dest_tx = dest.new_write_tx()?;
        for table in ALL_TABLES.iter() {
            if EXCLUDED_TABLES.contains(table) {
                continue;
            }

            // Clear the table on the destination
            dest_tx.clear_table(table)?;

            // Copy all keys and values
            let src_cursor = src_tx.inner().cursor(table)?;
            dest_tx.inner().copy_cursor_to_table(table, src_cursor)?;
        }

        dest_tx.commit()?;
        src_tx.commit()?;
        Ok(())
    }

    /// Unzip the given file to the given location
    fn unzip_data_file(
        data_file: &std::fs::File,
        dest: &PathBuf,
    ) -> Result<(), ReplicationV2Error> {
        // Remove a preexisting data temp file if it exists
        if dest.exists() {
            fs::remove_file(dest).map_err(err_str!(ReplicationV2Error::Snapshot))?;
        }
        let mut dest_writer = File::create(dest).map_err(err_str!(ReplicationV2Error::Snapshot))?;

        // Unzip the data file into the dest file
        let mut decoder = GzDecoder::new(data_file);
        std::io::copy(&mut decoder, &mut dest_writer)
            .map_err(err_str!(ReplicationV2Error::Snapshot))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use common::types::{wallet::Wallet, wallet_mocks::mock_empty_wallet};
    use libmdbx::Error as MdbxError;

    use crate::{
        replication::test_helpers::mock_state_machine, storage::error::StorageError,
        test_helpers::mock_db, WALLETS_TABLE,
    };

    use super::*;

    /// Tests snapshotting and recovering a DB from a snapshot
    #[tokio::test]
    async fn test_snapshot() {
        const TABLE: &str = "test-table";
        let (k, v) = ("key".to_string(), "value".to_string());

        let state_machine = mock_state_machine().await;

        // Write to the DB
        let db = state_machine.db();
        db.create_table(TABLE).unwrap();
        db.write(TABLE, &k, &v).unwrap();

        // Take a snapshot then recover from it
        state_machine.take_db_snapshot().await.unwrap();
        let new_db = state_machine.open_snap_db().await.unwrap();
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

        let state_machine = mock_state_machine().await;
        let db = state_machine.db();

        // Write to the DB
        db.create_table(DUMMY_TABLE).unwrap();
        db.create_table(EXCLUDED_TABLE).unwrap();
        db.write(DUMMY_TABLE, &k1, &v1).unwrap();
        db.write(EXCLUDED_TABLE, &k2, &v2).unwrap();

        // Take a snapshot then recover from it
        state_machine.take_db_snapshot().await.unwrap();

        // Check that the original table still contains the excluded value
        let value: String = db.read(EXCLUDED_TABLE, &k2).unwrap().unwrap();
        assert_eq!(value, v2);

        // Check that the recovered DB contains the same data minus the excluded table
        let new_db = state_machine.open_snap_db().await.unwrap();
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
        let state_machine = mock_state_machine().await;
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
        let new_db = state_machine.open_snap_db().await.unwrap();
        let value: String = new_db.read(TABLE, &k).unwrap().unwrap();

        assert_eq!(value, v2);
    }

    /// Tests the helper that directly copies a DB to another
    #[tokio::test]
    async fn test_copy_db() {
        // One table is included in a snapshot copy operation, one is excluded
        const INCLUDED_TABLE: &str = WALLETS_TABLE;
        const EXCLUDED_TABLE: &str = EXCLUDED_TABLES[0];
        let (k1, v1) = ("key1".to_string(), "value1".to_string());
        let (k2, v2) = ("key2".to_string(), "value2".to_string());
        let (k3, v3) = ("key3".to_string(), "value3".to_string());
        // Test a more complicated value
        let wallet = mock_empty_wallet();
        let (k4, v4) = ("key4".to_string(), wallet.clone());

        let src_db = mock_db();
        let dest_db = mock_db();

        // Write (k1, v1) to the excluded table of src_db, (k2, v2) to the excluded
        // table of dest_db, and (k3, v3) to the included table of src_db
        src_db.write(EXCLUDED_TABLE, &k1, &v1).unwrap();
        dest_db.write(EXCLUDED_TABLE, &k2, &v2).unwrap();
        src_db.write(INCLUDED_TABLE, &k3, &v3).unwrap();
        dest_db.write(INCLUDED_TABLE, &k3, &"overwritten".to_string()).unwrap();
        src_db.write(INCLUDED_TABLE, &k4, &v4).unwrap();

        // Copy the contents of one db to another
        StateMachine::copy_db_data(&src_db, &dest_db).unwrap();

        // The destination should have (k3, v3) overwritten and (k2, v2) should remain.
        // k1 should not be present
        let dest_k1: Option<String> = dest_db.read(EXCLUDED_TABLE, &k1).unwrap();
        let dest_k2: String = dest_db.read(EXCLUDED_TABLE, &k2).unwrap().unwrap();
        let dest_k3: String = dest_db.read(INCLUDED_TABLE, &k3).unwrap().unwrap();
        let dest_k4: Wallet = dest_db.read(INCLUDED_TABLE, &k4).unwrap().unwrap();

        assert_eq!(dest_k1, None);
        assert_eq!(dest_k2, v2);
        assert_eq!(dest_k3, v3);
        assert_eq!(dest_k4, v4);
    }

    /// Tests applying a snapshot to the DB
    #[tokio::test]
    async fn test_apply_snapshot() {
        const INCLUDED_TABLE: &str = WALLETS_TABLE;
        const EXCLUDED_TABLE: &str = EXCLUDED_TABLES[0];
        let (k1, v1) = ("key1".to_string(), "value1".to_string());
        let (k2, v2) = ("key2".to_string(), "value2".to_string());

        let mut state_machine = mock_state_machine().await;
        let snapshot_db = mock_db();
        let meta = SnapshotMeta::default();

        // Write to the DB
        snapshot_db.write(INCLUDED_TABLE, &k1, &v1).unwrap();
        snapshot_db.write(EXCLUDED_TABLE, &k2, &v2).unwrap();

        // Apply the snapshot
        state_machine.update_from_snapshot(&meta, snapshot_db).await.unwrap();

        // Check that the snapshot was applied correctly; only k1 should be present
        let sm_db = state_machine.db();
        let value1: String = sm_db.read(INCLUDED_TABLE, &k1).unwrap().unwrap();
        let value2: Option<String> = sm_db.read(EXCLUDED_TABLE, &k2).unwrap();

        assert_eq!(value1, v1);
        assert_eq!(value2, None);
    }
}
