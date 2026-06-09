//! Defines a raft log access via libmdbx
//!
//! We use libmdbx to index and persist raft logs as well as application data,
//! this module fits our DB into the log trait expected by raft

use std::fmt::Debug;
use std::ops::Bound;
use std::{ops::RangeBounds, sync::Arc};

use itertools::Itertools;
use libmdbx::{RO, RW};
use openraft::storage::LogFlushed;
use openraft::{LogId, LogState, StorageError as RaftStorageError, Vote};
use openraft::{RaftLogReader, storage::RaftLogStorage};
use rkyv::rancor;
use rkyv::with::With;
use util::{err_str, res_some};

use crate::replication::error::new_log_read_error;
use crate::replication::rkyv_types::{ArchivedLogId, LogIdDef};
use crate::storage::db::DB;
use crate::storage::error::StorageError;
use crate::storage::tx::StateTxn;
use crate::storage::tx::raft_log::{lsn_to_key, parse_lsn};

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
    async fn with_read_tx<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&StateTxn<RO>) -> Result<T, StorageError> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.new_read_tx()?;
            let res = f(&tx)?;
            tx.commit()?;
            Ok(res)
        })
        .await
        .map_err(err_str!(StorageError::Other))?
    }

    /// Run a callback with a write tx in scope
    async fn with_write_tx<F, T>(&self, f: F) -> Result<T, StorageError>
    where
        T: Send + 'static,
        F: FnOnce(&StateTxn<'_, RW>) -> Result<T, StorageError> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || {
            let tx = db.new_write_tx_with_retry()?;
            let res = f(&tx)?;
            tx.commit()?;
            Ok(res)
        })
        .await
        .map_err(err_str!(StorageError::Other))?
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

        self.with_read_tx(move |tx| {
            let mut log_cursor = tx.logs_cursor()?;

            // Read the range - seek returns false if no key >= low exists
            let mut res = Vec::new();
            if !log_cursor.seek(&lsn_to_key(low))? {
                return Ok(res);
            }

            for record in log_cursor.into_iter() {
                let (key, entry) = record?;
                let index = parse_lsn(&key);
                if index > high {
                    break;
                }

                let entry = entry.deserialize_with()?;
                res.push(entry);
            }

            Ok(res)
        })
        .await
        .map_err(new_log_read_error)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, RaftStorageError<NodeId>> {
        self.with_read_tx(move |tx| {
            let mut last_purged_log_id =
                tx.get_last_purged_log_id()?.map(|v| v.deserialize_with()).transpose()?;

            // A node whose head logs have been compacted MUST report a non-None
            // `last_purged_log_id`. If it is missing while the log no longer starts
            // at the genesis, openraft's `LogIdList::load_log_ids` takes its `None`
            // branch and calls `get_log_id(0)`, which panics on the compacted
            // region (`'LogIndex(0)' violates: try to get log at index 0 but got
            // Some(N)`) and crash-loops the node on every reboot. Reconstruct the
            // purge point from the first retained entry -- raft logs are 1-indexed,
            // so a first index > 1 means lower entries were purged.
            if last_purged_log_id.is_none()
                && let Some((first_idx, first_entry)) = tx.first_raft_log()?
                && first_idx > 1
            {
                let with = With::<ArchivedLogId, LogIdDef>::cast(&first_entry.log_id);
                let first_log_id: LogId<NodeId> = rkyv::deserialize::<_, rancor::Error>(with)
                    .map_err(StorageError::serialization)?;
                last_purged_log_id =
                    Some(LogId::new(first_log_id.leader_id, first_log_id.index - 1));
            }

            let last_log = tx.last_raft_log()?.map(|(_, entry)| entry);
            let last_log_id = match last_log {
                Some(x) => {
                    let archived_id = &x.log_id;
                    let with = With::<ArchivedLogId, LogIdDef>::cast(archived_id);
                    let log_id = rkyv::deserialize::<_, rancor::Error>(with)
                        .map_err(StorageError::serialization)?;

                    Some(log_id)
                },
                None => last_purged_log_id,
            };

            Ok(LogState { last_log_id, last_purged_log_id })
        })
        .await
        .map_err(new_log_read_error)
    }

    async fn save_vote(&mut self, vote: &Vote<NodeId>) -> Result<(), RaftStorageError<NodeId>> {
        let vote = *vote;
        self.with_write_tx(move |tx| tx.set_last_vote(&vote)).await.map_err(new_log_write_error)
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeId>>, RaftStorageError<NodeId>> {
        self.with_read_tx(move |tx| {
            let archived_vote = res_some!(tx.get_last_vote()?);
            let vote = archived_vote.deserialize_with()?;

            Ok(Some(vote))
        })
        .await
        .map_err(new_log_read_error)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), RaftStorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry>,
    {
        // Materialize the entires to appease the borrow checker
        let entries = entries.into_iter().collect_vec();
        self.with_write_tx(move |tx| tx.append_log_entries(entries))
            .await
            .map_err(new_log_write_error)?;

        // Report success to the raft callback
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    /// Truncate all logs after the given id (inclusive)
    async fn truncate(&mut self, log_id: LogId<NodeId>) -> Result<(), RaftStorageError<NodeId>> {
        self.with_write_tx(move |tx| tx.truncate_logs(log_id.index))
            .await
            .map_err(new_log_write_error)
    }

    /// Purge all logs before the given id (inclusive)
    async fn purge(&mut self, log_id: LogId<NodeId>) -> Result<(), RaftStorageError<NodeId>> {
        self.with_write_tx(move |tx| {
            tx.purge_logs(log_id.index)?;
            tx.set_last_purged_log_id(&log_id)
        })
        .await
        .map_err(new_log_write_error)
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }
}

#[cfg(test)]
mod test {
    use openraft::{Entry, EntryPayload, LeaderId, LogId, storage::RaftLogStorage};

    use crate::applicator::test_helpers::mock_applicator;

    use super::LogStore;

    /// A node whose head logs are compacted but whose persisted
    /// `last_purged_log_id` is missing must still report a non-None purge point
    /// from `get_log_state`. Otherwise openraft's `LogIdList::load_log_ids` calls
    /// `get_log_id(0)` and crash-loops with `'LogIndex(0)' violates: try to get
    /// log at index 0`. Regression test for the seed reboot crash-loop.
    #[tokio::test]
    async fn test_get_log_state_reconstructs_missing_purge_point() {
        let applicator = mock_applicator();
        let db = applicator.config.db.clone();

        // Write a single log entry at a high index with NO last_purged persisted,
        // simulating a recovered node whose log head was compacted.
        let leader = LeaderId::new(1 /* term */, 0 /* node */);
        let entry = Entry { log_id: LogId::new(leader, 4950), payload: EntryPayload::Blank };
        let tx = db.new_write_tx().unwrap();
        tx.append_log_entries(vec![entry]).unwrap();
        tx.commit().unwrap();

        let mut log = LogStore::new(db);
        let state = log.get_log_state().await.unwrap();

        assert_eq!(
            state.last_purged_log_id,
            Some(LogId::new(leader, 4949)),
            "purge point must be reconstructed as (first retained index - 1)"
        );
        assert_eq!(state.last_log_id, Some(LogId::new(leader, 4950)));
    }
}
