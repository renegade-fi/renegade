//! A raft node that processes events from the consensus layer and the network, and handles
//! interactions with storage

use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

use config::RelayerConfig;
use external_api::bus_message::SystemBusMessage;
use protobuf::Message;
use raft::{
    prelude::{ConfChange, Entry, EntryType, HardState, Message as RaftMessage, Snapshot},
    Config as RaftConfig, RawNode,
};
use rand::{thread_rng, RngCore};
use slog::Logger;
use state_proto::StateTransition;
use system_bus::SystemBus;
use tracing_slog::TracingSlogDrain;

use crate::{
    applicator::{StateApplicator, StateApplicatorConfig},
    storage::db::DB,
};

use super::{error::ReplicationError, log_store::LogStore, network::RaftNetwork};

// -------------
// | Raft Node |
// -------------

/// The interval at which to tick the raft node
const RAFT_TICK_INTERVAL_MS: u64 = 100; // 100 ms
/// The interval at which to poll for new inbound messages
const RAFT_POLL_INTERVAL_MS: u64 = 10; // 10 ms

/// The config for the local replication node
#[derive(Clone)]
pub struct ReplicationNodeConfig<N: RaftNetwork> {
    /// A copy of the relayer's config
    relayer_config: RelayerConfig,
    /// A reference to the networking layer that backs the raft node
    network: N,
    /// A handle on the persistent storage layer underlying the raft node
    db: Arc<DB>,
    /// A handle to the system-global bus
    system_bus: SystemBus<SystemBusMessage>,
}

/// A raft node that replicates the relayer's state machine
pub struct ReplicationNode<N: RaftNetwork> {
    /// The inner raft node
    inner: RawNode<LogStore>,
    /// A handle to the state applicator: the module responsible for applying state
    /// transitions to the state machine when they are committed
    applicator: StateApplicator,
    /// The networking layer backing the raft node
    network: N,
}

impl<N: RaftNetwork> ReplicationNode<N> {
    /// Creates a new replication node
    pub fn new(config: ReplicationNodeConfig<N>) -> Result<Self, ReplicationError> {
        // Build the log store on top of the DB
        let store = LogStore::new(config.db.clone())?;

        // Build a state applicator to handle state transitions
        let applicator = StateApplicator::new(StateApplicatorConfig {
            allow_local: config.relayer_config.allow_local,
            cluster_id: config.relayer_config.cluster_id,
            db: config.db.clone(),
            system_bus: config.system_bus,
        })
        .map_err(ReplicationError::Applicator)?;

        // Build an slog logger and connect it to the tracing logger
        let tracing_drain = TracingSlogDrain;
        let logger = Logger::root(tracing_drain, slog::o!());

        // Build raft node
        // TODO: Replace random node ID with the first 8 bytes of the local peer ID
        let raft_config = RaftConfig {
            id: thread_rng().next_u64(),
            ..Default::default()
        };

        let node = RawNode::new(&raft_config, store, &logger).map_err(ReplicationError::Raft)?;

        Ok(Self {
            inner: node,
            applicator,
            network: config.network,
        })
    }

    /// The main loop of the raft consensus engine, we tick the state machine every
    /// `RAFT_TICK_INTERVAL_MS` milliseconds
    pub fn run(mut self) -> Result<(), ReplicationError> {
        let tick_interval = Duration::from_millis(RAFT_TICK_INTERVAL_MS);
        let poll_interval = Duration::from_millis(RAFT_POLL_INTERVAL_MS);

        let mut last_tick = Instant::now();

        loop {
            thread::sleep(poll_interval);

            // Check for new messages
            while let Some(msg) = self.network.try_recv().map_err(Into::into)? {
                self.inner.step(msg).map_err(ReplicationError::Raft)?;
            }

            // Tick the raft node after the sleep interval has elapsed
            if last_tick.elapsed() >= tick_interval {
                self.inner.tick();
                self.process_ready_state()?;

                last_tick = Instant::now();
            }
        }
    }

    /// Process the ready state of the node
    ///
    /// The ready state includes a collection of all state transition events that have occurred
    /// since the last time the ready state was polled. This includes:
    ///     - Messages to be sent to other nodes
    ///     - Snapshots from the leader
    ///     - Committed entries
    ///     - New entries that should be appended to the log, but not yet applied
    ///     - `HardState` changes, e.g. new leader, new commit index, etc
    /// and more. For mor information see:
    ///     https://docs.rs/raft/latest/raft/index.html#processing-the-ready-state
    fn process_ready_state(&mut self) -> Result<(), ReplicationError> {
        if !self.inner.has_ready() {
            return Ok(());
        }

        let mut ready = self.inner.ready();

        // Send outbound messages
        self.send_outbound_messages(ready.take_messages())?;

        // Apply snapshot
        if !ready.snapshot().is_empty() {
            self.apply_snapshot(ready.snapshot());
        }

        // Commit entries
        self.commit_entries(ready.take_committed_entries())?;

        // Append new entries to the raft log
        self.append_entries(ready.take_entries())?;

        // Update the raft hard state
        if let Some(hard_state) = ready.hs().cloned() {
            self.update_hard_state(hard_state)?;
        }

        // Send persisted messages to peers
        self.send_outbound_messages(ready.take_persisted_messages())?;

        // Advance the raft node and handle the outbound messages and committed entires
        // that are stored in the resultant `LightReady`
        let mut light_ready = self.inner.advance(ready);
        self.send_outbound_messages(light_ready.take_messages())?;
        self.commit_entries(light_ready.take_committed_entries())?;
        self.inner.advance_apply();

        Ok(())
    }

    /// Send outbound messages from the raft ready state
    fn send_outbound_messages(
        &mut self,
        messages: Vec<RaftMessage>,
    ) -> Result<(), ReplicationError> {
        for message in messages {
            self.network.send(message).map_err(|e| e.into())?;
        }

        Ok(())
    }

    /// Apply a raft snapshot from the ready state
    fn apply_snapshot(&mut self, snapshot: &Snapshot) {
        self.inner.mut_store().apply_snapshot(snapshot);
    }

    /// Commit entries from the ready state and apply them to the state machine
    fn commit_entries(&mut self, entries: Vec<Entry>) -> Result<(), ReplicationError> {
        for entry in entries.into_iter() {
            if entry.get_data().is_empty() {
                // Upon new leader election, the leader sends an empty entry
                // as a heartbeat to each follower. No processing is needed
                continue;
            }

            match entry.get_entry_type() {
                EntryType::EntryNormal => {
                    // Apply a normal entry to the state machine
                    let entry_bytes = entry.get_data();
                    let transition: StateTransition = serde_json::from_slice(entry_bytes)
                        .map_err(|e| ReplicationError::ParseValue(e.to_string()))?;

                    self.applicator
                        .handle_state_transition(transition)
                        .map_err(ReplicationError::Applicator)?;
                }
                EntryType::EntryConfChange | EntryType::EntryConfChangeV2 => {
                    // Apply a config change entry to the state machine
                    let mut config_change = ConfChange::new();
                    config_change
                        .merge_from_bytes(entry.get_data())
                        .map_err(|e| ReplicationError::ParseValue(e.to_string()))?;

                    // Forward the config change to the consensus engine
                    let config_state = self
                        .inner
                        .apply_conf_change(&config_change)
                        .map_err(ReplicationError::Raft)?;

                    // Store the new config in the log store
                    self.inner.mut_store().apply_config_state(config_state)?;
                }
            }
        }

        Ok(())
    }

    /// Append new log entries from the ready state
    ///
    /// These entries are not yet committed and should not yet be applied to the state machine
    fn append_entries(&mut self, entries: Vec<Entry>) -> Result<(), ReplicationError> {
        self.inner.mut_store().append_log_entries(entries)
    }

    /// Update the hard state from the ready state
    fn update_hard_state(&mut self, hard_state: HardState) -> Result<(), ReplicationError> {
        self.inner.mut_store().apply_hard_state(hard_state)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use crate::{replication::network::test_helpers::MockNetwork, test_helpers::mock_db};

    use super::{ReplicationNode, ReplicationNodeConfig};

    /// Tests that the constructor works properly, largely this means testing that the `LogStore`
    /// initialization is compatible with the `raft` setup
    #[test]
    fn test_constructor() {
        let db = Arc::new(mock_db());

        // Setup a dummy network, for this test it is okay if both ends resolve
        // to the same channel
        let (network_out, network_in) = crossbeam::channel::unbounded();
        let net = MockNetwork::new(network_out, network_in);

        let node_config = ReplicationNodeConfig {
            relayer_config: Default::default(),
            network: net,
            db: db.clone(),
            system_bus: Default::default(),
        };
        let _node = ReplicationNode::new(node_config).unwrap();
    }
}
