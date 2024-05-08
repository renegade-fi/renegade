//! Defines the state machine for the raft node, responsible for applying logs
//! to the state

use openraft::{
    storage::RaftStateMachine, EntryPayload, LogId, OptionalSend, RaftSnapshotBuilder, Snapshot,
    SnapshotMeta, StorageError as RaftStorageError, StoredMembership,
};

use crate::{applicator::StateApplicator, replicationv2::error::new_apply_error, storage::db::DB};

use super::{
    error::new_snapshot_error, snapshot::take_db_snapshot, Entry, Node, NodeId, SnapshotData,
    TypeConfig,
};

/// The config for the state machine
#[derive(Clone, Debug)]
pub struct StateMachineConfig {
    /// The directory to place snapshots in
    snapshot_out: String,
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
    last_applied_log: Option<LogId<NodeId>>,
    /// The last cluster membership config
    last_membership: StoredMembership<NodeId, Node>,
    /// The config for the state machine
    config: StateMachineConfig,
    /// The underlying applicator
    applicator: StateApplicator,
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
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, RaftStorageError<NodeId>> {
        take_db_snapshot(&self.config.snapshot_out, self.db()).await.map_err(new_snapshot_error)?;
        todo!("report the snapshot")
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
        todo!("implement snapshotting")
    }

    async fn install_snapshot(
        &mut self,
        _meta: &SnapshotMeta<NodeId, Node>,
        _snapshot: Box<SnapshotData>,
    ) -> Result<(), RaftStorageError<NodeId>> {
        todo!("implement snapshotting")
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, RaftStorageError<NodeId>> {
        // TODO: Implement snapshotting
        Ok(None)
    }
}
