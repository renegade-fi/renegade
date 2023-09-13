//! Defines the storage layer for the `raft` implementation. We store logs, snapshots,
//! metadata, etc in the storage layer -- concretely an embedded KV store

use std::sync::Arc;

use libmdbx::{TransactionKind, RO};
use protobuf::Message;
use raft::{
    prelude::{
        ConfState, Entry as RaftEntry, HardState, Snapshot as RaftSnapshot, SnapshotMetadata,
    },
    Error as RaftError, GetEntriesContext, RaftState, Result as RaftResult, Storage,
    StorageError as RaftStorageError,
};

use crate::storage::{
    cursor::DbCursor,
    db::{DbTxn, DB},
    ProtoStorageWrapper,
};

use super::error::ReplicationError;

// -------------
// | Constants |
// -------------

/// The name of the raft metadata table in the database
pub const RAFT_METADATA_TABLE: &str = "raft-metadata";
/// The name of the raft logs table in the database
pub const RAFT_LOGS_TABLE: &str = "raft-logs";

/// The name of the raft hard state key in the KV store
pub const HARD_STATE_KEY: &str = "hard-state";
/// The name of the raft conf state key in the KV store
pub const CONF_STATE_KEY: &str = "conf-state";
/// The name of the snapshot metadata key in the KV store
pub const SNAPSHOT_METADATA_KEY: &str = "snapshot-metadata";

// -----------
// | Helpers |
// -----------

/// Parse a raft LSN from a string
fn parse_lsn(s: &str) -> Result<u64, ReplicationError> {
    s.parse::<u64>()
        .map_err(|_| ReplicationError::ParseValue(s.to_string()))
}

/// Format a raft LSN as a string
fn lsn_to_key(lsn: u64) -> String {
    lsn.to_string()
}

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
        db.create_table(RAFT_METADATA_TABLE)
            .map_err(ReplicationError::Storage)?;

        Ok(Self { db })
    }

    /// Read a log entry, returning an error if an entry does not exist for the given index
    pub fn read_log_entry(&self, index: u64) -> Result<RaftEntry, ReplicationError> {
        let tx = self.db.new_read_tx().map_err(ReplicationError::Storage)?;
        let entry: ProtoStorageWrapper<RaftEntry> = tx
            .read(RAFT_LOGS_TABLE, &lsn_to_key(index))
            .map_err(ReplicationError::Storage)?
            .ok_or_else(|| ReplicationError::EntryNotFound)?;

        Ok(entry.into_inner())
    }

    /// A helper to construct a cursor over the logs
    fn logs_cursor<T: TransactionKind>(
        &self,
        tx: &DbTxn<'_, T>,
    ) -> Result<DbCursor<'_, T, String, ProtoStorageWrapper<RaftEntry>>, ReplicationError> {
        tx.cursor(RAFT_LOGS_TABLE)
            .map_err(ReplicationError::Storage)
    }
}

impl Storage for LogStore {
    /// Returns the initial raft state
    fn initial_state(&self) -> RaftResult<RaftState> {
        // Read the hard state
        let tx = self.db.new_read_tx().map_err(RaftError::from)?;
        let hard_state: ProtoStorageWrapper<HardState> = tx
            .read(RAFT_METADATA_TABLE, &HARD_STATE_KEY.to_string())
            .map_err(RaftError::from)?
            .unwrap_or_default();
        let conf_state: ProtoStorageWrapper<ConfState> = tx
            .read(RAFT_METADATA_TABLE, &CONF_STATE_KEY.to_string())
            .map_err(RaftError::from)?
            .unwrap_or_default();

        Ok(RaftState {
            hard_state: hard_state.into_inner(),
            conf_state: conf_state.into_inner(),
        })
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
        let tx = self.db.new_read_tx().map_err(RaftError::from)?;
        let mut cursor = self.logs_cursor(&tx)?;

        // Seek the cursor to the first entry in the range
        cursor.seek_geq(&lsn_to_key(low)).map_err(RaftError::from)?;

        let mut entries = Vec::new();
        let mut remaining_space = max_size.into().map(|v| v as u32).unwrap_or(u32::MAX);

        for record in cursor.map(|entry| {
            entry
                .map_err(RaftError::from)
                .map(|(key, value)| (key, value.into_inner()))
        }) {
            let (key, entry) = record?;
            let lsn = parse_lsn(&key).map_err(RaftError::from)?;

            // If we've reached the end of the range, break
            if lsn >= high {
                break;
            }

            // If we've reached the max size, break
            let size = entry.compute_size();
            if size > remaining_space {
                break;
            }

            // Otherwise, add the entry to the list and update the remaining space
            entries.push(entry);
            remaining_space -= size;
        }

        Ok(entries)
    }

    /// Returns the term for a given index in the log
    fn term(&self, idx: u64) -> RaftResult<u64> {
        self.read_log_entry(idx)
            .map_err(RaftError::from)
            .map(|entry| entry.term)
    }

    fn first_index(&self) -> RaftResult<u64> {
        let tx = self.db.new_read_tx().map_err(RaftError::from)?;
        let mut cursor = self.logs_cursor::<RO>(&tx).map_err(RaftError::from)?;

        match cursor.seek_first().map_err(RaftError::from)? {
            Some((key, _)) => parse_lsn(&key).map_err(RaftError::from),
            None => Ok(0),
        }
    }

    fn last_index(&self) -> RaftResult<u64> {
        let tx = self.db.new_read_tx().map_err(RaftError::from)?;
        let mut cursor = self.logs_cursor::<RO>(&tx).map_err(RaftError::from)?;

        match cursor.seek_last().map_err(RaftError::from)? {
            Some((key, _)) => parse_lsn(&key).map_err(RaftError::from),
            None => Ok(0),
        }
    }

    /// Returns the most recent snapshot of the consensus state
    ///
    /// A snapshot index mustn't be less than `request_index`
    ///
    /// The `to` field indicates the peer this will be sent to, unused here
    fn snapshot(&self, request_index: u64, _to: u64) -> RaftResult<RaftSnapshot> {
        // Read the snapshot metadata from the metadata table
        let tx = self.db.new_read_tx().map_err(RaftError::from)?;
        let metadata: SnapshotMetadata = tx
            .read(RAFT_METADATA_TABLE, &SNAPSHOT_METADATA_KEY.to_string())
            .map_err(RaftError::from)?
            .map(|value: ProtoStorageWrapper<SnapshotMetadata>| value.into_inner())
            .ok_or_else(|| RaftError::Store(RaftStorageError::SnapshotTemporarilyUnavailable))?;

        if metadata.index < request_index {
            return Err(RaftError::Store(
                RaftStorageError::SnapshotTemporarilyUnavailable,
            ));
        }

        let mut snap = RaftSnapshot::new();
        snap.set_metadata(metadata);

        Ok(snap)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::test_helpers::mock_db;

    use super::LogStore;

    /// Test that creating the log store works
    ///
    /// TODO: Remove me
    #[test]
    fn test_constructor() {
        let db = Arc::new(mock_db());
        let _store = LogStore::new(db).unwrap();
    }
}
