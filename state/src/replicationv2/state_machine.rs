//! Defines the state machine for the raft node, responsible for applying logs
//! to the state

use std::{path::PathBuf, sync::Arc};

use openraft::{
    storage::RaftStateMachine, EntryPayload, ErrorSubject, ErrorVerb, LogId, OptionalSend,
    Snapshot, SnapshotMeta, StorageError as RaftStorageError, StoredMembership,
};
use tokio::fs::File;
use util::{err_str, res_some};

use crate::{applicator::StateApplicator, replicationv2::error::new_apply_error, storage::db::DB};

use super::{
    error::{new_log_read_error, new_snapshot_error, ReplicationV2Error},
    Entry, Node, NodeId, SnapshotData, TypeConfig,
};

/// The snapshot file name
const SNAPSHOT_FILE: &str = "snapshot.dat";

/// The config for the state machine
#[derive(Clone, Debug)]
pub struct StateMachineConfig {
    /// The directory to place snapshots in
    pub(crate) snapshot_out: String,
}

impl StateMachineConfig {
    /// Constructor
    pub fn new(snapshot_out: String) -> Self {
        Self { snapshot_out }
    }
}

/// The state machine for the raft node
#[derive(Clone)]
pub struct StateMachine {
    /// The index of the last applied log
    pub(crate) last_applied_log: Option<LogId<NodeId>>,
    /// The last cluster membership config
    pub(crate) last_membership: StoredMembership<NodeId, Node>,
    /// The config for the state machine
    pub(crate) config: StateMachineConfig,
    /// The underlying applicator
    pub(crate) applicator: StateApplicator,
}

impl StateMachine {
    /// Constructor
    pub fn new(config: StateMachineConfig, applicator: StateApplicator) -> Self {
        Self { last_applied_log: None, last_membership: Default::default(), config, applicator }
    }

    /// Get a handle on the DB of the state machine
    pub fn db(&self) -> &DB {
        self.applicator.db()
    }

    /// Get an owned handle on the DB
    pub fn db_owned(&self) -> Arc<DB> {
        self.applicator.config.db.clone()
    }

    /// Get the directory at which snapshots are saved
    pub fn snapshot_dir(&self) -> &str {
        &self.config.snapshot_out
    }

    /// Get the path of the snapshot file
    pub fn snapshot_archive_path(&self) -> PathBuf {
        PathBuf::from(self.snapshot_dir()).join(SNAPSHOT_FILE).with_extension("gz")
    }

    /// Get the path to place the snapshot data at
    pub fn snapshot_data_path(&self) -> PathBuf {
        PathBuf::from(self.snapshot_dir()).join(SNAPSHOT_FILE)
    }

    /// Open the file containing the snapshot
    pub async fn open_snapshot_file(&self) -> Result<Option<File>, ReplicationV2Error> {
        let snapshot_path = self.snapshot_archive_path();
        if snapshot_path.exists() {
            let file = tokio::fs::File::open(snapshot_path)
                .await
                .map_err(err_str!(ReplicationV2Error::Snapshot))?;
            Ok(Some(file))
        } else {
            Ok(None)
        }
    }
}

impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(
        &mut self,
    ) -> Result<(Option<LogId<NodeId>>, StoredMembership<NodeId, Node>), RaftStorageError<NodeId>>
    {
        Ok((self.last_applied_log, self.last_membership.clone()))
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<()>, RaftStorageError<NodeId>>
    where
        I: IntoIterator<Item = Entry> + OptionalSend,
        I::IntoIter: OptionalSend,
    {
        for entry in entries.into_iter() {
            let log_id = entry.log_id;
            self.last_applied_log = Some(log_id);
            match entry.payload {
                // Sent by a new leader to confirm its leadership
                EntryPayload::Blank => {},
                EntryPayload::Membership(membership) => {
                    self.last_membership = StoredMembership::new(Some(log_id), membership);
                },
                EntryPayload::Normal(transition) => {
                    self.applicator
                        .handle_state_transition(transition)
                        .map_err(|err| new_apply_error(log_id, err))?;
                },
            }
        }

        Ok(vec![])
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<SnapshotData>, RaftStorageError<NodeId>> {
        // Remove the file if it already exists, we want a blank snapshot
        let snapshot_path = self.snapshot_archive_path();
        if snapshot_path.exists() {
            tokio::fs::remove_file(&snapshot_path).await.map_err(|e| {
                RaftStorageError::from_io_error(ErrorSubject::Snapshot(None), ErrorVerb::Delete, e)
            })?;
        }

        // (Re)create it
        let file = tokio::fs::File::create(snapshot_path).await.map_err(|e| {
            RaftStorageError::from_io_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e)
        })?;

        Ok(Box::new(file))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, Node>,
        snapshot: Box<SnapshotData>,
    ) -> Result<(), RaftStorageError<NodeId>> {
        let snapshot = *snapshot;
        let snap_db = self.open_snap_db_with_file(snapshot).await.map_err(new_snapshot_error)?;
        self.update_from_snapshot(meta, snap_db).await.map_err(new_snapshot_error)
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, RaftStorageError<NodeId>> {
        let tx = self.db().new_read_tx().map_err(new_log_read_error)?;
        let meta = res_some!(tx.get_snapshot_metadata().map_err(new_log_read_error)?);

        // Open the snapshot file
        let file = res_some!(self.open_snapshot_file().await.map_err(new_snapshot_error)?);
        Ok(Some(Snapshot { meta, snapshot: Box::new(file) }))
    }
}
