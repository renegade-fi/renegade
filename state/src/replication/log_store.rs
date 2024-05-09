//! Defines the storage layer for the `raft` implementation. We store logs,
//! snapshots, metadata, etc in the storage layer -- concretely an embedded KV
//! store

use std::sync::Arc;

use raft::{
    eraftpb::{ConfState, HardState},
    prelude::{Entry as RaftEntry, Snapshot as RaftSnapshot},
    Error as RaftError, GetEntriesContext, RaftState, Result as RaftResult, Storage,
};

use crate::{
    storage::{db::DB, tx::raft_log::parse_lsn},
    RAFT_LOGS_TABLE, RAFT_METADATA_TABLE,
};

use super::error::ReplicationError;

// -------------
// | Constants |
// -------------

/// A marker for a placeholder in an unused variable
///
/// Currently used to indicate that a peer ID is not used in a snapshot
/// as the snapshot logic does not branch on peer ID
pub const UNUSED: u64 = 0;

// -------------
// | Log Store |
// -------------

/// The central storage abstraction, wraps a KV database
pub struct LogStore {
    /// The underlying database reference
    db: Arc<DB>,
}

impl LogStore {
    /// Constructor
    pub fn new(db: Arc<DB>) -> Result<Self, ReplicationError> {
        // Create the logs table in the db
        db.create_table(RAFT_METADATA_TABLE).map_err(ReplicationError::Storage)?;
        db.create_table(RAFT_LOGS_TABLE).map_err(ReplicationError::Storage)?;

        // Write a default snapshot to the metadata table
        let tx = db.new_write_tx()?;
        tx.apply_snapshot(&RaftSnapshot::new())?;
        tx.commit()?;

        Ok(Self { db })
    }

    // -----------
    // | Setters |
    // -----------

    /// Apply a hard state to the log store
    pub fn apply_hard_state(&self, hard_state: HardState) -> Result<(), ReplicationError> {
        let tx = self.db.new_write_tx()?;
        tx.apply_hard_state(hard_state)?;

        Ok(tx.commit()?)
    }

    /// Apply a config state to the log store
    pub fn apply_config_state(&self, conf_state: ConfState) -> Result<(), ReplicationError> {
        let tx = self.db.new_write_tx()?;
        tx.apply_config_state(conf_state)?;

        Ok(tx.commit()?)
    }

    /// Append entries to the log
    #[allow(clippy::needless_pass_by_value)]
    pub fn append_log_entries(&self, entries: Vec<RaftEntry>) -> Result<(), ReplicationError> {
        todo!()
    }

    /// Apply a snapshot to the log store
    pub fn apply_snapshot(&self, snapshot: &RaftSnapshot) -> Result<(), ReplicationError> {
        let tx = self.db.new_write_tx()?;
        tx.apply_snapshot(snapshot)?;

        Ok(tx.commit()?)
    }
}

impl Storage for LogStore {
    /// Returns the initial raft state
    fn initial_state(&self) -> RaftResult<RaftState> {
        todo!()
    }

    /// Returns the log entries between two indices, capped at a max size
    /// in bytes
    ///
    /// Entries are in the range [low, high) and are returned in ascending order
    fn entries(
        &self,
        low: u64,
        high: u64,
        max_size: impl Into<Option<u64>>,
        _context: GetEntriesContext,
    ) -> RaftResult<Vec<RaftEntry>> {
        todo!()
    }

    /// Returns the term for a given index in the log
    fn term(&self, idx: u64) -> RaftResult<u64> {
        todo!()
    }

    /// Returns the index of the first available entry in the log
    fn first_index(&self) -> RaftResult<u64> {
        let tx = self.db.new_read_tx()?;
        let mut cursor = tx.logs_cursor()?;
        cursor.seek_first().map_err(RaftError::from)?;

        match cursor.get_current().map_err(RaftError::from)? {
            Some((key, _)) => parse_lsn(&key).map_err(RaftError::from),
            None => {
                let snapshot_idx =
                    self.snapshot(0 /* request_idx */, UNUSED)?.get_metadata().get_index();

                Ok(snapshot_idx + 1)
            },
        }
    }

    /// Returns the index of the last available entry in the log
    fn last_index(&self) -> RaftResult<u64> {
        let tx = self.db.new_read_tx()?;
        let mut cursor = tx.logs_cursor()?;
        cursor.seek_last().map_err(RaftError::from)?;

        match cursor.get_current().map_err(RaftError::from)? {
            Some((key, _)) => parse_lsn(&key).map_err(RaftError::from),
            None => {
                let snapshot_idx =
                    self.snapshot(0 /* request_idx */, UNUSED)?.get_metadata().get_index();

                Ok(snapshot_idx)
            },
        }
    }

    /// Returns the most recent snapshot of the consensus state
    ///
    /// A snapshot index mustn't be less than `request_index`
    ///
    /// The `to` field indicates the peer this will be sent to, unused here
    fn snapshot(&self, request_index: u64, _to: u64) -> RaftResult<RaftSnapshot> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use protobuf::Message;
    use raft::{
        prelude::{ConfState, Entry as RaftEntry, HardState, Snapshot, SnapshotMetadata},
        GetEntriesContext, Storage,
    };
    use rand::{seq::IteratorRandom, thread_rng};

    use crate::test_helpers::mock_db;

    use super::LogStore;

    // -----------
    // | Helpers |
    // -----------

    /// Add a batch of entries to the log store
    fn add_entry_batch(store: &LogStore, entries: &[RaftEntry]) {
        store.append_log_entries(entries.to_vec()).unwrap();
    }

    /// Create a series of empty entries for the log
    fn empty_entries(n: usize) -> Vec<RaftEntry> {
        let mut res = Vec::with_capacity(n);
        for i in 0..n {
            let mut entry = RaftEntry::new();
            entry.index = i as u64;

            res.push(entry);
        }

        res
    }

    /// Create a mock `LogStore`
    fn mock_log_store() -> LogStore {
        let db = Arc::new(mock_db());
        LogStore::new(db).unwrap()
    }

    /// Create a mock snapshot
    fn mock_snapshot() -> Snapshot {
        // Create a mock snapshot
        let mut snap = Snapshot::new();
        let mut metadata = SnapshotMetadata::new();

        // Hard state
        metadata.set_term(15);
        metadata.set_index(5);

        // Conf state
        let mut conf_state = ConfState::new();
        conf_state.set_voters(vec![1, 2, 3]);
        metadata.set_conf_state(conf_state.clone());

        snap.set_metadata(metadata.clone());
        snap
    }

    // ------------------
    // | Metadata Tests |
    // ------------------

    /// Test the initial state without having initialized the `LogStore`
    /// i.e. upon raft initial startup
    #[test]
    fn test_startup_state() {
        let store = mock_log_store();
        let state = store.initial_state().unwrap();

        assert_eq!(state.hard_state, HardState::new());
        assert_eq!(state.conf_state, ConfState::new());
    }

    /// Tests applying a snapshot then fetching initial state, simulating a
    /// crash recovery
    #[test]
    fn test_recover_snapshot_state() {
        let store = mock_log_store();
        let snap = mock_snapshot();
        store.apply_snapshot(&snap).unwrap();

        // Now fetch the initial state
        let state = store.initial_state().unwrap();

        assert_eq!(state.hard_state.term, snap.get_metadata().get_term());
        assert_eq!(state.hard_state.commit, snap.get_metadata().get_index());
        assert_eq!(&state.conf_state, snap.get_metadata().get_conf_state());
    }

    /// Tests fetching an up-to-date snapshot
    #[test]
    fn test_up_to_date_snapshot() {
        let store = mock_log_store();
        let snap = mock_snapshot();
        store.apply_snapshot(&snap).unwrap();

        // Attempt to fetch a snapshot at a lower index than the one stored
        let index = snap.get_metadata().get_index() - 1;
        let res = store.snapshot(index, 0 /* peer_id */);

        assert!(res.is_ok());
        let snap_res = res.unwrap();

        assert_eq!(snap_res.get_metadata(), snap.get_metadata());
    }
}
