//! High level transaction interface for accessing the raft log

use std::cmp;

use libmdbx::{TransactionKind, RW};
use raft::eraftpb::{
    ConfState, Entry as RaftEntry, HardState, Snapshot as RaftSnapshot, SnapshotMetadata,
};

use crate::{
    replication::error::ReplicationError,
    storage::{cursor::DbCursor, error::StorageError, ProtoStorageWrapper},
};

use super::StateTxn;

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

/// The error message used when a log entry cannot be found
const ERR_LOG_NOT_FOUND: &str = "Log entry not found";

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

// -----------
// | Getters |
// -----------

impl<'db, T: TransactionKind> StateTxn<'db, T> {
    /// Read a log entry, returning an error if it does not exist
    pub fn read_log_entry(&self, index: u64) -> Result<RaftEntry, StorageError> {
        let entry: ProtoStorageWrapper<RaftEntry> = self
            .inner()
            .read(RAFT_LOGS_TABLE, &lsn_to_key(index))?
            .ok_or_else(|| StorageError::NotFound(ERR_LOG_NOT_FOUND.to_string()))?;

        Ok(entry.into_inner())
    }

    /// Read the `ConfState` of the raft from storage
    pub fn read_conf_state(&self) -> Result<ConfState, StorageError> {
        let conf_state: ProtoStorageWrapper<ConfState> = self
            .inner()
            .read(RAFT_METADATA_TABLE, &CONF_STATE_KEY.to_string())
            .map_err(StorageError::from)?
            .unwrap_or_default();

        Ok(conf_state.into_inner())
    }

    /// Read the `HardState` of the raft from storage
    pub fn read_hard_state(&self) -> Result<HardState, StorageError> {
        let hard_state: ProtoStorageWrapper<HardState> = self
            .inner()
            .read(RAFT_METADATA_TABLE, &HARD_STATE_KEY.to_string())?
            .unwrap_or_default();

        Ok(hard_state.into_inner())
    }

    /// Read the snapshot metadata from storage
    pub fn read_snapshot_metadata(&self) -> Result<SnapshotMetadata, StorageError> {
        let stored_metadata: ProtoStorageWrapper<SnapshotMetadata> = self
            .inner()
            .read(RAFT_METADATA_TABLE, &SNAPSHOT_METADATA_KEY.to_string())?
            .unwrap_or_default();

        Ok(stored_metadata.into_inner())
    }

    /// A helper to construct a cursor over the logs
    pub fn logs_cursor(
        &self,
    ) -> Result<DbCursor<'_, T, String, ProtoStorageWrapper<RaftEntry>>, ReplicationError> {
        self.inner().cursor(RAFT_LOGS_TABLE).map_err(ReplicationError::Storage)
    }
}

// -----------
// | Setters |
// -----------

impl<'db> StateTxn<'db, RW> {
    /// Apply a config change to the log store
    pub fn apply_config_state(&self, change: ConfState) -> Result<(), StorageError> {
        let value = ProtoStorageWrapper(change);
        self.inner().write(RAFT_METADATA_TABLE, &CONF_STATE_KEY.to_string(), &value)
    }

    /// Apply a hard state to the log store
    pub fn apply_hard_state(&self, state: HardState) -> Result<(), StorageError> {
        let value = ProtoStorageWrapper(state);
        self.inner().write(RAFT_METADATA_TABLE, &HARD_STATE_KEY.to_string(), &value)
    }

    /// Append entries to the raft log
    pub fn append_log_entries(&self, entries: Vec<RaftEntry>) -> Result<(), StorageError> {
        let tx = self.inner();
        for entry in entries.into_iter() {
            let key = lsn_to_key(entry.index);
            let value = ProtoStorageWrapper(entry);

            tx.write(RAFT_LOGS_TABLE, &key, &value)?;
        }

        Ok(())
    }

    /// Apply a snapshot to the log store
    pub fn apply_snapshot(&self, snapshot: &RaftSnapshot) -> Result<(), StorageError> {
        let tx = self.inner();
        let meta = snapshot.get_metadata();

        // Write the `ConfState` to the metadata table
        tx.write(
            RAFT_METADATA_TABLE,
            &CONF_STATE_KEY.to_string(),
            &ProtoStorageWrapper(meta.get_conf_state().clone()),
        )?;

        // Write the `HardState` to the metadata table
        let new_state: ProtoStorageWrapper<HardState> =
            tx.read(RAFT_METADATA_TABLE, &HARD_STATE_KEY.to_string())?.unwrap_or_default();
        let mut new_state = new_state.into_inner();

        new_state.set_term(cmp::max(new_state.get_term(), meta.get_term()));
        new_state.set_commit(meta.index);

        tx.write(
            RAFT_METADATA_TABLE,
            &HARD_STATE_KEY.to_string(),
            &ProtoStorageWrapper(new_state),
        )?;

        // Write the snapshot metadata
        tx.write(
            RAFT_METADATA_TABLE,
            &SNAPSHOT_METADATA_KEY.to_string(),
            &ProtoStorageWrapper(snapshot.get_metadata().clone()),
        )
    }
}
