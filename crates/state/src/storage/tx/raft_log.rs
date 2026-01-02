//! High level transaction interface for accessing the raft log

use libmdbx::{RW, TransactionKind};
use util::res_some;

use crate::{
    RAFT_LOGS_TABLE, RAFT_METADATA_TABLE,
    replication::{WrappedEntry, WrappedLogId, WrappedSnapshotMeta, WrappedVote},
    storage::{ArchivedValue, cursor::DbCursor, error::StorageError},
};

use super::StateTxn;

// -------------
// | Constants |
// -------------

/// The key for the last purged log
pub const LAST_PURGED_LOG_KEY: &str = "last-purged-raft-log";
/// The key for the local node's vote in the current term
pub const LAST_VOTE_KEY: &str = "last-vote";
/// The name of the snapshot metadata key in the KV store
pub const SNAPSHOT_METADATA_KEY: &str = "snapshot-metadata";

/// The error message used when a log entry cannot be found
const ERR_LOG_NOT_FOUND: &str = "Log entry not found";
/// Error message when a last log cannot be found
const ERR_NO_LAST_LOG: &str = "No last log found";

// -----------
// | Helpers |
// -----------

/// A type alias for the raft LSN key type
///
/// We store the LSN as a big endian encoded byte array.
/// This preserves the numeric ordering on the keys when they are rkyv
/// serialized.
type LsnKey = [u8; 8];

/// Parse a raft LSN from a byte array
pub fn parse_lsn(b: &LsnKey) -> u64 {
    u64::from_be_bytes(*b)
}

/// Format a raft LSN as a byte array
pub fn lsn_to_key(lsn: u64) -> LsnKey {
    lsn.to_be_bytes()
}

/// The key type for the raft logs
pub type LogKeyType = LsnKey;
/// The value type for the raft logs
pub type LogValueType = WrappedEntry;

/// A type alias for an archived entry value
pub(crate) type EntryValue<'a> = ArchivedValue<'a, WrappedEntry>;
/// A type alias for an archived log ID value
pub(crate) type LogIdValue<'a> = ArchivedValue<'a, WrappedLogId>;
/// A type alias for an archived vote value
pub(crate) type VoteValue<'a> = ArchivedValue<'a, WrappedVote>;
/// A type alias for an archived snapshot metadata value
pub(crate) type SnapshotMetaValue<'a> = ArchivedValue<'a, WrappedSnapshotMeta>;

// -----------
// | Getters |
// -----------

impl<T: TransactionKind> StateTxn<'_, T> {
    // --- Logs Metadata --- //

    /// Get the ID of the last purged log
    pub fn get_last_purged_log_id(&self) -> Result<Option<LogIdValue<'_>>, StorageError> {
        self.inner().read(RAFT_METADATA_TABLE, &LAST_PURGED_LOG_KEY.to_string())
    }

    /// Get the local node's vote in the current term
    pub fn get_last_vote(&self) -> Result<Option<VoteValue<'_>>, StorageError> {
        self.inner().read(RAFT_METADATA_TABLE, &LAST_VOTE_KEY.to_string())
    }

    /// Get the metadata of the latest snapshot
    pub fn get_snapshot_metadata(&self) -> Result<Option<SnapshotMetaValue<'_>>, StorageError> {
        self.inner().read(RAFT_METADATA_TABLE, &SNAPSHOT_METADATA_KEY.to_string())
    }

    // --- Log Access --- //

    /// Get the first log index stored in the DB
    pub fn first_raft_log_index(&self) -> Result<Option<u64>, StorageError> {
        let first_kv = self.first_raft_log()?;
        Ok(first_kv.map(|(k, _)| k))
    }

    /// Get the first log stored in the DB
    ///
    /// Returns the owned entry since cursors deserialize values
    pub fn first_raft_log(&self) -> Result<Option<(u64, EntryValue<'_>)>, StorageError> {
        let mut cursor = self.logs_cursor()?;
        let (k, v) = res_some!(cursor.get_current()?);
        let parsed_key = parse_lsn(&k);
        Ok(Some((parsed_key, v)))
    }

    /// Get the last log index stored in the DB
    pub fn last_raft_log_index(&self) -> Result<Option<u64>, StorageError> {
        let last_kv = self.last_raft_log()?;
        Ok(last_kv.map(|(k, _)| k))
    }

    /// Get the last log stored in the DB
    ///
    /// Returns the owned entry since cursors deserialize values
    pub fn last_raft_log(&self) -> Result<Option<(u64, EntryValue<'_>)>, StorageError> {
        let mut cursor = self.logs_cursor()?;
        cursor.seek_last()?;

        let (k, v) = res_some!(cursor.get_current()?);
        let parsed_key = parse_lsn(&k);
        Ok(Some((parsed_key, v)))
    }

    /// Read a log entry, returning an error if it does not exist
    pub fn read_log_entry(&self, index: u64) -> Result<EntryValue<'_>, StorageError> {
        self.inner()
            .read(RAFT_LOGS_TABLE, &lsn_to_key(index))?
            .ok_or_else(|| StorageError::not_found(ERR_LOG_NOT_FOUND))
    }

    /// A helper to construct a cursor over the logs
    pub fn logs_cursor(&self) -> Result<DbCursor<'_, T, LogKeyType, LogValueType>, StorageError> {
        self.inner().cursor(RAFT_LOGS_TABLE)
    }
}

// -----------
// | Setters |
// -----------

impl StateTxn<'_, RW> {
    // --- Log Metadata --- //

    /// Set the ID of the last purged log
    pub fn set_last_purged_log_id(&self, id: &WrappedLogId) -> Result<(), StorageError> {
        self.inner().write(RAFT_METADATA_TABLE, &LAST_PURGED_LOG_KEY.to_string(), id)
    }

    /// Set the local node's vote in the current term
    pub fn set_last_vote(&self, vote: &WrappedVote) -> Result<(), StorageError> {
        self.inner().write(RAFT_METADATA_TABLE, &LAST_VOTE_KEY.to_string(), vote)
    }

    /// Set the metadata of the latest snapshot
    pub fn set_snapshot_metadata(
        &self,
        metadata: &WrappedSnapshotMeta,
    ) -> Result<(), StorageError> {
        self.inner().write(RAFT_METADATA_TABLE, &SNAPSHOT_METADATA_KEY.to_string(), metadata)
    }

    // --- Log Access --- //

    /// Append entries to the raft log
    pub fn append_log_entries<I: IntoIterator<Item = WrappedEntry>>(
        &self,
        entries: I,
    ) -> Result<(), StorageError> {
        let tx = self.inner();
        for entry in entries.into_iter() {
            let key = lsn_to_key(entry.inner.log_id.index);
            tx.write(RAFT_LOGS_TABLE, &key, &entry)?;
        }

        Ok(())
    }

    /// Truncate logs in the DB, deleting those beyond the given index
    /// (inclusive)
    pub fn truncate_logs(&self, index: u64) -> Result<(), StorageError> {
        // Fetch the upper bound
        let idx_lsn = lsn_to_key(index);
        let last_log =
            self.last_raft_log_index()?.ok_or_else(|| StorageError::not_found(ERR_NO_LAST_LOG))?;

        // Delete the logs
        let mut log_cursor = self.logs_cursor()?;
        log_cursor.seek(&idx_lsn)?;
        for _ in index..=last_log {
            log_cursor.delete()?;
        }

        Ok(())
    }

    /// Purge all logs before the given index (inclusive)
    pub fn purge_logs(&self, index: u64) -> Result<(), StorageError> {
        let mut log_cursor = self.logs_cursor()?;
        log_cursor.seek_first()?;

        loop {
            let curr = match log_cursor.get_current()? {
                Some((k, _)) => parse_lsn(&k),
                None => {
                    break;
                },
            };

            if curr <= index {
                log_cursor.delete()?;
            } else {
                break;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use openraft::{EntryPayload, LeaderId, LogId};

    use crate::{
        replication::{Entry, WrappedEntry},
        storage::tx::raft_log::parse_lsn,
        test_helpers::mock_db,
    };

    /// Get an empty log entry with the given index
    fn empty_entry(idx: u64, term: u64, node_id: u64) -> WrappedEntry {
        let leader_id = LeaderId::new(term, node_id);
        let id = LogId::new(leader_id, idx);
        let entry = Entry { log_id: id, payload: EntryPayload::Blank };
        WrappedEntry::from(entry)
    }

    /// Test the logs cursor
    #[test]
    fn test_logs_cursor() {
        const N: u64 = 10;
        let db = mock_db();

        // Add a few logs
        let entries = (1..=N).map(|i| empty_entry(i, 1, 1));
        let tx = db.new_write_tx().unwrap();
        tx.append_log_entries(entries).unwrap();
        tx.commit().unwrap();

        // Get the logs
        let tx = db.new_read_tx().unwrap();
        let mut cursor = tx.logs_cursor().unwrap();
        cursor.seek_first().unwrap();
        for (i, res) in cursor.into_iter().enumerate() {
            let (k, v) = res.unwrap();
            let expected_idx = (i + 1) as u64;
            assert_eq!(parse_lsn(&k), expected_idx);
            assert_eq!(v.inner.log_id.index, expected_idx);
        }
    }

    /// Tests purging logs
    #[test]
    fn test_purge_logs() {
        const N: u64 = 10;
        let db = mock_db();

        // Add a few logs
        let entries = (1..=N).map(|i| empty_entry(i, 1, 1));
        let tx = db.new_write_tx().unwrap();
        tx.append_log_entries(entries).unwrap();
        tx.commit().unwrap();

        // Get the logs
        let tx = db.new_write_tx().unwrap();
        for i in 1..=N {
            let entry = tx.read_log_entry(i).unwrap();
            assert!(entry.inner.log_id.index == i);
        }

        // Purge the logs
        tx.purge_logs(N / 2).unwrap();
        tx.commit().unwrap();

        // All logs <= N / 2 should be purged
        let tx = db.new_read_tx().unwrap();
        for i in 1..=N / 2 {
            let entry = tx.read_log_entry(i);
            assert!(entry.is_err());
        }

        for i in N / 2 + 1..=N {
            let entry = tx.read_log_entry(i).unwrap();
            assert!(entry.inner.log_id.index == i);
        }
    }

    /// Tests truncating logs
    #[test]
    fn test_truncate_logs() {
        const N: u64 = 10;
        let db = mock_db();

        // Add a few logs
        let entries = (1..=N).map(|i| empty_entry(i, 1, 1));
        let tx = db.new_write_tx().unwrap();
        tx.append_log_entries(entries).unwrap();
        tx.commit().unwrap();

        // Get the logs
        let tx = db.new_write_tx().unwrap();
        for i in 1..=N {
            let entry = tx.read_log_entry(i).unwrap();
            assert!(entry.inner.log_id.index == i);
        }

        // Truncate the logs
        tx.truncate_logs(N / 2).unwrap();
        tx.commit().unwrap();

        // All logs >= N / 2 should be truncated
        let tx = db.new_read_tx().unwrap();
        for i in 1..N / 2 {
            let entry = tx.read_log_entry(i).unwrap();
            assert_eq!(entry.inner.log_id.index, i);
        }

        for i in N / 2..=N {
            let entry = tx.read_log_entry(i);
            assert!(entry.is_err());
        }
    }
}
