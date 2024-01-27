//! Defines the storage layer for the `raft` implementation. We store logs,
//! snapshots, metadata, etc in the storage layer -- concretely an embedded KV
//! store

use std::{cmp::Ordering, sync::Arc};

use protobuf::Message;
use raft::{
    eraftpb::{ConfState, HardState},
    prelude::{Entry as RaftEntry, Snapshot as RaftSnapshot},
    Error as RaftError, GetEntriesContext, RaftState, Result as RaftResult, Storage,
    StorageError as RaftStorageError,
};

use crate::storage::{
    db::DB,
    error::StorageError,
    tx::raft_log::{lsn_to_key, parse_lsn, RAFT_LOGS_TABLE, RAFT_METADATA_TABLE},
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
    pub fn append_log_entries(&self, entries: Vec<RaftEntry>) -> Result<(), ReplicationError> {
        let tx = self.db.new_write_tx()?;
        tx.append_log_entries(entries)?;

        Ok(tx.commit()?)
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
        // Read the hard state
        let tx = self.db.new_read_tx()?;
        let hard_state = tx.read_hard_state()?;
        let conf_state = tx.read_conf_state()?;
        tx.commit()?;

        Ok(RaftState { hard_state, conf_state })
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
        let tx = self.db.new_read_tx()?;
        let mut cursor = tx.logs_cursor()?;

        // Seek the cursor to the first entry in the range
        cursor.seek_geq(&lsn_to_key(low)).map_err(RaftError::from)?;

        let mut entries = Vec::new();
        let mut remaining_space = max_size.into().map(|v| v as u32).unwrap_or(u32::MAX);

        for record in cursor.map(|entry| {
            entry.map_err(RaftError::from).map(|(key, value)| (key, value.into_inner()))
        }) {
            let (key, entry) = record?;
            let lsn = parse_lsn(&key).map_err(RaftError::from)?;

            // If we've reached the end of the range, break
            if lsn >= high {
                break;
            }

            // If we've reached the max size, break
            // Do not limit the size to zero entries
            let size = entry.compute_size();
            if !entries.is_empty() && size > remaining_space {
                break;
            }

            // Otherwise, add the entry to the list and update the remaining space
            entries.push(entry);
            remaining_space = remaining_space.saturating_sub(size);
        }

        Ok(entries)
    }

    /// Returns the term for a given index in the log
    fn term(&self, idx: u64) -> RaftResult<u64> {
        let tx = self.db.new_read_tx()?;
        match tx.read_log_entry(idx).map(|entry| entry.term) {
            // Check the snapshot if not found
            Err(StorageError::NotFound(_)) => {
                if let Ok(snap) = self.snapshot(idx, UNUSED)
                    && snap.get_metadata().get_index() == idx
                {
                    Ok(snap.get_metadata().get_term())
                } else {
                    Err(RaftError::Store(RaftStorageError::Unavailable))
                }
            },
            res => res.map_err(RaftError::from),
        }
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
        let tx = self.db.new_read_tx()?;
        let mut snap = RaftSnapshot::default();
        let md = snap.mut_metadata();

        // Read the snapshot metadata from the metadata table
        let hard_state = tx.read_hard_state()?;
        md.index = hard_state.commit;

        let stored_metadata = tx.read_snapshot_metadata()?;
        md.term = match md.index.cmp(&stored_metadata.index) {
            Ordering::Equal => stored_metadata.term,
            Ordering::Greater => tx.read_log_entry(md.index).map(|entry| entry.term)?,
            Ordering::Less => {
                return Err(RaftError::Store(RaftStorageError::SnapshotOutOfDate));
            },
        };

        if md.index < request_index {
            md.index = request_index;
        }

        let conf_state = tx.read_conf_state()?;
        md.set_conf_state(conf_state);

        Ok(snap)
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

    // -------------------
    // | Log Entry Tests |
    // -------------------

    /// Tests fetching the first and last entries from an empty log
    #[test]
    fn test_empty_log() {
        let store = mock_log_store();

        let first = store.first_index().unwrap();
        let last = store.last_index().unwrap();
        let entry_term = store.term(1 /* index */);

        assert_eq!(first, 1);
        assert_eq!(last, 0);
        assert!(matches!(entry_term, Ok(0)))
    }

    /// Tests fetching the entries from a basic log with a handful of entries
    #[test]
    fn test_log_access_basic() {
        const N: usize = 1_000;
        let store = mock_log_store();

        // Add a few entries to the log
        let entries = empty_entries(N);
        add_entry_batch(&store, &entries);

        // Fetch the first and last indices
        let first = store.first_index().unwrap();
        let last = store.last_index().unwrap();

        assert_eq!(first, 0);
        assert_eq!(last, (N - 1) as u64);

        // Fetch the entries
        let entries = store
            .entries(first, last + 1, None, GetEntriesContext::empty(false /* can_async */))
            .unwrap();

        assert_eq!(entries.len(), N);
        assert_eq!(entries, entries);
    }

    /// Tests fetching a subset of entries from a log
    #[test]
    fn test_log_access_subset() {
        const N: usize = 1_000;
        let store = mock_log_store();

        // Add a few entries to the log
        let entries = empty_entries(N);
        add_entry_batch(&store, &entries);

        let mut rng = thread_rng();
        let low = (0..(N - 1)).choose(&mut rng).unwrap();
        let high = (low..N).choose(&mut rng).unwrap();

        // Fetch the entries
        let entries_res = store
            .entries(low as u64, high as u64, None, GetEntriesContext::empty(false /* can_async */))
            .unwrap();

        assert_eq!(entries_res.len(), high - low);
        assert_eq!(entries_res, &entries[low..high]);
    }

    /// Tests log access with a cap on the result's memory footprint
    #[test]
    fn test_log_access_with_size_bound() {
        const N: usize = 1_000;
        let store = mock_log_store();

        // Add a few entries to the log
        let entries = empty_entries(N);
        add_entry_batch(&store, &entries);

        let mut rng = thread_rng();
        let low = (0..(N - 1)).choose(&mut rng).unwrap();
        let high = (low..N).choose(&mut rng).unwrap();

        // Cap the size at an amount that will give a random number of entries
        let n_entries = (1..(high - low)).choose(&mut rng).unwrap();
        let max_size =
            entries[low..(low + n_entries)].iter().map(|entry| entry.compute_size()).sum::<u32>();

        // Fetch the entries
        let entries_res = store
            .entries(
                low as u64,
                high as u64,
                Some(max_size as u64),
                GetEntriesContext::empty(false /* can_async */),
            )
            .unwrap();

        assert_eq!(entries_res.len(), n_entries);
        assert_eq!(entries_res, &entries[low..(low + entries_res.len())]);
    }
}
