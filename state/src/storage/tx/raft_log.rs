//! High level transaction interface for accessing the raft log

use libmdbx::{TransactionKind, RW};
use openraft::{LogId, SnapshotMeta, Vote};
use raft::eraftpb::{ConfState, HardState, Snapshot as RaftSnapshot};
use util::res_some;

use crate::{
    replication::error::ReplicationError,
    replicationv2::{Entry, Node, NodeId},
    storage::{cursor::DbCursor, error::StorageError, ProtoStorageWrapper},
    RAFT_LOGS_TABLE, RAFT_METADATA_TABLE,
};

use super::StateTxn;

// -------------
// | Constants |
// -------------

/// The name of the raft hard state key in the KV store
///
/// TODO: Delete this
pub const HARD_STATE_KEY: &str = "hard-state";
/// The name of the raft conf state key in the KV store
///
/// TODO: Delete this
pub const CONF_STATE_KEY: &str = "conf-state";
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

/// Parse a raft LSN from a string
pub fn parse_lsn(s: &str) -> Result<u64, ReplicationError> {
    s.parse::<u64>().map_err(|_| ReplicationError::ParseValue(s.to_string()))
}

/// Format a raft LSN as a string
pub fn lsn_to_key(lsn: u64) -> String {
    lsn.to_string()
}

/// The key type for the raft logs
pub type LogKeyType = String;
/// The value type for the raft logs
pub type LogValueType = Entry;

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    // --- Logs Metadata --- //

    /// Get the ID of the last purged log
    pub fn get_last_purged_log_id(&self) -> Result<Option<LogId<NodeId>>, StorageError> {
        self.inner().read(RAFT_METADATA_TABLE, &LAST_PURGED_LOG_KEY.to_string())
    }

    /// Get the local node's vote in the current term
    pub fn get_last_vote(&self) -> Result<Option<Vote<NodeId>>, StorageError> {
        self.inner().read(RAFT_METADATA_TABLE, &LAST_VOTE_KEY.to_string())
    }

    /// Get the metadata of the latest snapshot
    pub fn get_snapshot_metadata(
        &self,
    ) -> Result<Option<SnapshotMeta<NodeId, Node>>, StorageError> {
        self.inner().read(RAFT_METADATA_TABLE, &SNAPSHOT_METADATA_KEY.to_string())
    }

    // --- Log Access --- //

    /// Get the first log index stored in the DB
    pub fn first_raft_log_index(&self) -> Result<Option<u64>, StorageError> {
        let first_kv = self.first_raft_log()?;
        Ok(first_kv.map(|(k, _)| k))
    }

    /// Get the first log stored in the DB
    pub fn first_raft_log(&self) -> Result<Option<(u64, LogValueType)>, StorageError> {
        let mut cursor = self.logs_cursor()?;
        let (k, v) = res_some!(cursor.get_current()?);
        let parsed_key = parse_lsn(&k).map_err(|_| StorageError::InvalidKey(k))?;
        Ok(Some((parsed_key, v)))
    }

    /// Get the last log index stored in the DB
    pub fn last_raft_log_index(&self) -> Result<Option<u64>, StorageError> {
        let last_kv = self.last_raft_log()?;
        Ok(last_kv.map(|(k, _)| k))
    }

    /// Get the last log stored in the DB
    pub fn last_raft_log(&self) -> Result<Option<(u64, LogValueType)>, StorageError> {
        let mut cursor = self.logs_cursor()?;
        cursor.seek_last()?;

        let (k, v) = res_some!(cursor.get_current()?);
        let parsed_key = parse_lsn(&k).map_err(|_| StorageError::InvalidKey(k))?;
        Ok(Some((parsed_key, v)))
    }

    /// Read a log entry, returning an error if it does not exist
    pub fn read_log_entry(&self, index: u64) -> Result<LogValueType, StorageError> {
        self.inner()
            .read(RAFT_LOGS_TABLE, &lsn_to_key(index))?
            .ok_or_else(|| StorageError::NotFound(ERR_LOG_NOT_FOUND.to_string()))
    }

    /// Read the `ConfState` of the raft from storage
    ///
    /// TODO: Delete this
    pub fn read_conf_state(&self) -> Result<ConfState, StorageError> {
        let conf_state: ProtoStorageWrapper<ConfState> = self
            .inner()
            .read(RAFT_METADATA_TABLE, &CONF_STATE_KEY.to_string())
            .map_err(StorageError::from)?
            .unwrap_or_default();

        Ok(conf_state.into_inner())
    }

    /// Read the `HardState` of the raft from storage
    ///
    /// TODO: Delete this
    pub fn read_hard_state(&self) -> Result<HardState, StorageError> {
        let hard_state: ProtoStorageWrapper<HardState> = self
            .inner()
            .read(RAFT_METADATA_TABLE, &HARD_STATE_KEY.to_string())?
            .unwrap_or_default();

        Ok(hard_state.into_inner())
    }

    /// A helper to construct a cursor over the logs
    pub fn logs_cursor(&self) -> Result<DbCursor<'_, T, LogKeyType, LogValueType>, StorageError> {
        self.inner().cursor(RAFT_LOGS_TABLE)
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    // --- Log Metadata --- //

    /// Set the ID of the last purged log
    pub fn set_last_purged_log_id(&self, id: &LogId<NodeId>) -> Result<(), StorageError> {
        self.inner().write(RAFT_METADATA_TABLE, &LAST_PURGED_LOG_KEY.to_string(), id)
    }

    /// Set the local node's vote in the current term
    pub fn set_last_vote(&self, vote: &Vote<NodeId>) -> Result<(), StorageError> {
        self.inner().write(RAFT_METADATA_TABLE, &LAST_VOTE_KEY.to_string(), vote)
    }

    /// Set the metadata of the latest snapshot
    pub fn set_snapshot_metadata(
        &self,
        metadata: &SnapshotMeta<NodeId, Node>,
    ) -> Result<(), StorageError> {
        self.inner().write(RAFT_METADATA_TABLE, &SNAPSHOT_METADATA_KEY.to_string(), metadata)
    }

    // --- Log Access --- //

    /// Apply a config change to the log store
    ///
    /// TODO: Delete this
    pub fn apply_config_state(&self, change: ConfState) -> Result<(), StorageError> {
        let value = ProtoStorageWrapper(change);
        self.inner().write(RAFT_METADATA_TABLE, &CONF_STATE_KEY.to_string(), &value)
    }

    /// Apply a hard state to the log store
    ///
    /// TODO: Delete this
    pub fn apply_hard_state(&self, state: HardState) -> Result<(), StorageError> {
        let value = ProtoStorageWrapper(state);
        self.inner().write(RAFT_METADATA_TABLE, &HARD_STATE_KEY.to_string(), &value)
    }

    /// Append entries to the raft log
    pub fn append_log_entries<I: IntoIterator<Item = Entry>>(
        &self,
        entries: I,
    ) -> Result<(), StorageError> {
        let tx = self.inner();
        for entry in entries.into_iter() {
            let key = lsn_to_key(entry.log_id.index);
            tx.write(RAFT_LOGS_TABLE, &key, &entry)?;
        }

        Ok(())
    }

    /// Truncate logs in the DB, deleting those beyond the given index
    /// (inclusive)
    pub fn truncate_logs(&self, index: u64) -> Result<(), StorageError> {
        // Fetch the upper bound
        let idx_lsn = lsn_to_key(index);
        let last_log = self
            .last_raft_log_index()?
            .ok_or(StorageError::NotFound(ERR_NO_LAST_LOG.to_string()))?;

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

        let idx_lsn = lsn_to_key(index);
        log_cursor.seek(&idx_lsn)?;
        while log_cursor.has_current()? {
            log_cursor.delete()?;
        }

        Ok(())
    }

    /// Apply a snapshot to the log store
    ///
    /// TODO: Delete this
    pub fn apply_snapshot(&self, _snapshot: &RaftSnapshot) -> Result<(), StorageError> {
        unimplemented!()
    }
}
