//! Defines a raft log access via libmdbx
//!
//! We use libmdbx to index and persist raft logs as well as application data,
//! this module fits our DB into the log trait expected by raft

use std::fmt::Debug;
use std::ops::Bound;
use std::{ops::RangeBounds, sync::Arc};

use libmdbx::{RO, RW};
use openraft::storage::LogFlushed;
use openraft::{storage::RaftLogStorage, RaftLogReader};
use openraft::{LogId, LogState, StorageError as RaftStorageError, Vote};

use crate::replication::error::new_log_read_error;
use crate::storage::db::DB;
use crate::storage::error::StorageError;
use crate::storage::tx::raft_log::{lsn_to_key, parse_lsn};
use crate::storage::tx::StateTxn;

use super::error::new_log_write_error;
use super::{Entry, NodeId, TypeConfig};

// -----------
// | Helpers |
// -----------

/// Parse low and high values from a range bound
fn parse_low_high<B: RangeBounds<u64>>(bound: B) -> (u64, u64) {
    let lo = match bound.start_bound() {
        Bound::Included(lo) => *lo,
        Bound::Excluded(lo) => lo + 1,
        Bound::Unbounded => u64::MIN,
    };

    let hi = match bound.end_bound() {
        Bound::Included(hi) => *hi,
        Bound::Excluded(hi) => hi - 1,
        Bound::Unbounded => u64::MAX,
    };

    (lo, hi)
}

// ---------------------------
// | LogStore Implementation |
// ---------------------------

/// The log storage, a thin wrapper around the DB handle
#[derive(Clone)]
pub struct LogStore {
    /// The handle to the DB
    pub(crate) db: Arc<DB>,
}

impl LogStore {
    /// Constructor
    pub fn new(db: Arc<DB>) -> Self {
        Self { db }
    }

    /// Run a callback with a read tx in scope
    fn with_read_tx<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce(&StateTxn<RO>) -> Result<T, StorageError>,
    {
        let tx = self.db.new_read_tx()?;
        let res = f(&tx)?;
        tx.commit()?;

        Ok(res)
    }

    /// Run a callback with a write tx in scope
    fn with_write_tx<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        F: FnOnce(&StateTxn<RW>) -> Result<T, StorageError>,
    {
        let tx = self.db.new_write_tx()?;
        let res = f(&tx)?;
        tx.commit()?;

        Ok(res)
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry>, RaftStorageError<NodeId>> {
        let (low, high) = parse_low_high(range);
        if low > high {
            return Ok(Vec::new());
        }

        self.with_read_tx(|tx| {
            let mut log_cursor = tx.logs_cursor()?;

            // Read the range
            let mut res = Vec::new();
            log_cursor.seek(&lsn_to_key(low))?;
            for record in log_cursor.into_iter() {
                let (key, entry) = record?;
                let index = parse_lsn(&key).expect("invalid LSN");
                if index > high {
                    break;
                }

                res.push(entry);
            }

            Ok(res)
        })
        .map_err(new_log_read_error)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, RaftStorageError<NodeId>> {
        self.with_read_tx(|tx| {
            let last_purged_log_id = tx.get_last_purged_log_id()?;
            let last_log = tx.last_raft_log()?.map(|(_, entry)| entry.log_id);
            let last_log_id = match last_log {
                Some(x) => Some(x),
                None => last_purged_log_id,
            };

            Ok(LogState { last_log_id, last_purged_log_id })
        })
        .map_err(new_log_read_error)
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), RaftStorageError<NodeId>> {
        self.with_write_tx(|tx| tx.set_last_vote(vote)).map_err(new_log_write_error)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, RaftStorageError<NodeId>> {
        self.with_read_tx(|tx| tx.get_last_vote()).map_err(new_log_read_error)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), RaftStorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry>,
    {
        self.with_write_tx(|tx| tx.append_log_entries(entries)).map_err(new_log_write_error)?;

        // Report success to the raft callback
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    /// Truncate all logs after the given id (inclusive)
    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), RaftStorageError<NodeId>> {
        self.with_write_tx(|tx| tx.truncate_logs(log_id.index)).map_err(new_log_write_error)
    }

    /// Purge all logs before the given id (inclusive)
    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), RaftStorageError<NodeId>> {
        self.with_write_tx(|tx| {
            tx.purge_logs(log_id.index)?;
            tx.set_last_purged_log_id(&log_id)
        })
        .map_err(new_log_write_error)
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }
}
