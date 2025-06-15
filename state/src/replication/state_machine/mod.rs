//! Defines the state machine for the raft node, responsible for applying logs
//! to the state

mod recovery;
mod snapshot;

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use openraft::{
    storage::RaftStateMachine, EntryPayload, ErrorSubject, ErrorVerb, LogId, OptionalSend,
    Snapshot, SnapshotMeta, StorageError as RaftStorageError, StoredMembership,
};
use tokio::fs::File;
use tracing::error;
use util::{err_str, res_some};

use crate::{
    applicator::{error::StateApplicatorError, StateApplicator},
    error::StateError,
    notifications::OpenNotifications,
    replication::error::new_apply_error,
    storage::db::DB,
    Proposal,
};

use super::{
    error::{new_log_read_error, new_snapshot_error, ReplicationError},
    Entry, Node, NodeId, SnapshotData, TypeConfig,
};

/// The snapshot file name
pub(crate) const SNAPSHOT_FILE: &str = "snapshot.dat";
/// The name of the snapshot zip file
pub(crate) const SNAPSHOT_ZIP: &str = "snapshot.gz";
/// The snapshot lock file name
pub(crate) const SNAPSHOT_LOCK: &str = "snapshot.lock";

/// Get the path to the snapshot data file
pub(crate) fn snapshot_data_path(snapshot_dir: &str) -> PathBuf {
    let dir = Path::new(snapshot_dir);
    dir.join(SNAPSHOT_FILE)
}

/// Get the path to the snapshot zip file
pub(crate) fn snapshot_zip_path(snapshot_dir: &str) -> PathBuf {
    let dir = Path::new(snapshot_dir);
    dir.join(SNAPSHOT_ZIP)
}

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
    /// Whether the state machine recovered from a snapshot
    pub(crate) recovered_from_snapshot: bool,
    /// The index of the last applied log
    pub(crate) last_applied_log: Option<LogId<NodeId>>,
    /// The last cluster membership config
    pub(crate) last_membership: StoredMembership<NodeId, Node>,
    /// The config for the state machine
    pub(crate) config: StateMachineConfig,
    /// The set of open notifications on the state machine
    pub(crate) notifications: OpenNotifications,
    /// The underlying applicator
    pub(crate) applicator: StateApplicator,
}

impl StateMachine {
    /// Constructor
    pub async fn new(
        config: StateMachineConfig,
        notifications: OpenNotifications,
        applicator: StateApplicator,
    ) -> Result<Self, ReplicationError> {
        let mut this = Self {
            recovered_from_snapshot: false,
            last_applied_log: None,
            last_membership: Default::default(),
            config,
            notifications,
            applicator,
        };

        // Do not error on an invalid snapshot
        if let Err(e) = this.maybe_recover_snapshot().await {
            error!("Failed to recover from snapshot: {e:?}");
        }

        Ok(this)
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
    pub fn snapshot_dir(&self) -> PathBuf {
        PathBuf::from(&self.config.snapshot_out)
    }

    /// Get the path of the snapshot file
    pub fn snapshot_archive_path(&self) -> PathBuf {
        snapshot_zip_path(&self.config.snapshot_out)
    }

    /// Get the path to place the snapshot data at
    pub fn snapshot_data_path(&self) -> PathBuf {
        snapshot_data_path(&self.config.snapshot_out)
    }

    /// Get the path to the snapshot lock file
    pub fn snapshot_lock_path(&self) -> PathBuf {
        let dir = Path::new(&self.config.snapshot_out);
        dir.join(SNAPSHOT_LOCK)
    }

    /// Create the snapshot directory if it doesn't exist
    pub async fn create_snapshot_dir(&self) -> Result<(), ReplicationError> {
        let snap_dir = self.snapshot_dir();
        if !snap_dir.exists() {
            tokio::fs::create_dir_all(&snap_dir)
                .await
                .map_err(err_str!(ReplicationError::Snapshot))?;
        }

        Ok(())
    }

    /// Create the snapshot lock file
    pub async fn create_snapshot_lock(&self) -> Result<(), ReplicationError> {
        let snapshot_lock = self.snapshot_lock_path();

        // Create the directory if it doesn't exist
        let parent_dir = snapshot_lock.parent();
        if let Some(dir) = parent_dir
            && !dir.exists()
        {
            tokio::fs::create_dir_all(dir).await.map_err(err_str!(ReplicationError::Snapshot))?;
        }

        tokio::fs::File::create(&snapshot_lock)
            .await
            .map_err(err_str!(ReplicationError::Snapshot))?;

        Ok(())
    }

    /// Delete the snapshot lock file
    pub async fn delete_snapshot_lock(&self) -> Result<(), ReplicationError> {
        let snapshot_lock = self.snapshot_lock_path();
        tokio::fs::remove_file(&snapshot_lock).await.map_err(err_str!(ReplicationError::Snapshot))
    }

    /// Open the file containing the snapshot
    pub async fn open_snapshot_file(&self) -> Result<Option<File>, ReplicationError> {
        let snapshot_path = self.snapshot_archive_path();
        if snapshot_path.exists() {
            let file = tokio::fs::File::open(snapshot_path)
                .await
                .map_err(err_str!(ReplicationError::Snapshot))?;
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
        let mut res = Vec::new();
        for entry in entries.into_iter() {
            let log_id = entry.log_id;
            self.last_applied_log = Some(log_id);
            match entry.payload {
                // Sent by a new leader to confirm its leadership
                EntryPayload::Blank => {},
                EntryPayload::Membership(membership) => {
                    self.last_membership = StoredMembership::new(Some(log_id), membership);
                },
                EntryPayload::Normal(proposal) => {
                    let Proposal { id, transition } = proposal;

                    // DB methods will naturally block the applicator without throwing an error, so
                    // we must spawn a blocking thread for each update
                    let applicator = self.applicator.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        applicator.handle_state_transition(transition)
                    })
                    .await
                    .map_err(|e| new_apply_error(log_id, e))?;

                    match res {
                        Err(StateApplicatorError::Rejected(msg)) => {
                            // If the state machine rejected the state transition, notify the client
                            // with an error state
                            self.notifications
                                .notify(id, Err(StateError::TransitionRejected(msg)))
                                .await;
                        },
                        Err(err) => {
                            // If the state machine failed to apply the state transition, notify the
                            // client & propagate the error
                            let err_str = err.to_string();
                            self.notifications.notify(id, Err(StateError::Applicator(err))).await;
                            return Err(new_apply_error(log_id, err_str));
                        },
                        res => {
                            self.notifications
                                .notify(id, res.map_err(StateError::Applicator))
                                .await;
                        },
                    }
                },
            }

            // The consensus engine expects a response for each application, even though
            // ours is empty
            res.push(());
        }

        Ok(res)
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
        self.create_snapshot_dir().await.map_err(new_snapshot_error)?;
        let file = tokio::fs::File::create(snapshot_path).await.map_err(|e| {
            RaftStorageError::from_io_error(ErrorSubject::Snapshot(None), ErrorVerb::Write, e)
        })?;

        Ok(Box::new(file))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeId, Node>,
        _snapshot: Box<SnapshotData>,
    ) -> Result<(), RaftStorageError<NodeId>> {
        // Openraft mysteriously closes the snapshot file outside of unit tests so we
        // need to open it from the file. In tests we use the snapshot argument directly
        // to fit into the builder paradigm in line with the openraft test suite
        let snap_db = {
            #[cfg(test)]
            {
                self.open_snap_db_with_file(*_snapshot).await.map_err(new_snapshot_error)?
            }

            #[cfg(not(test))]
            {
                self.open_snap_db().await.map_err(new_snapshot_error)?
            }
        };
        self.update_from_snapshot(meta, snap_db).await.map_err(new_snapshot_error)?;
        self.delete_snapshot_data().await.map_err(new_snapshot_error)
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

#[cfg(test)]
mod test {
    use common::types::wallet_mocks::mock_empty_wallet;
    use openraft::{storage::RaftStateMachine, Entry, EntryPayload, LeaderId, LogId};

    use crate::{replication::test_helpers::mock_state_machine, Proposal, StateTransition};

    /// Tests applying a log with a waiter on the state
    #[tokio::test]
    async fn test_await_application() {
        let mut sm = mock_state_machine().await;
        let notifs = sm.notifications.clone();

        // Add a proposal and await its notification
        let wallet = mock_empty_wallet();
        let prop = Proposal::from(StateTransition::AddWallet { wallet });
        let rx = notifs.register_notification(prop.id).await;

        // Append a log with this proposal
        let leader_id = LeaderId::new(1 /* term */, 1 /* node */);
        let log_id = LogId::new(leader_id, 1 /* index */);
        let entry = Entry { log_id, payload: EntryPayload::Normal(prop) };
        sm.apply(vec![entry]).await.unwrap();

        // Await the notification
        let res = rx.await.unwrap();
        assert!(res.is_ok());
    }
}
