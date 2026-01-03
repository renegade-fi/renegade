//! Test helpers for mocking rafts
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use itertools::Itertools;
use types_gossip::mocks::{mock_peer, mock_peer_id};
use util::concurrency::{AsyncShared, new_async_shared};

use crate::replication::raft::{RaftClient, RaftClientConfig};
use crate::replication::{NodeId, RaftNode};
use crate::storage::db::DB;
use crate::{applicator::test_helpers::mock_applicator, notifications::OpenNotifications};

use crate::replication::{
    log_store::LogStore,
    network::{
        RaftRequest, RaftResponse,
        mock::{MockNetworkNode, SwitchReceiver, SwitchSender, new_switch_queue},
    },
    state_machine::{StateMachine, StateMachineConfig},
};

/// The timeout which mock rafts wait for leader election
const WAIT_FOR_ELECTION: u64 = 100; // 100 ms

// -----------
// | Helpers |
// -----------

/// Create a mock state machine
pub async fn mock_state_machine() -> StateMachine {
    let (sm, _) = mock_state_and_log().await;
    sm
}

/// Create a mock state machine and log store
pub async fn mock_state_and_log() -> (StateMachine, LogStore) {
    let applicator = mock_applicator();
    let db = applicator.config.db.clone();
    let sm_config = StateMachineConfig::new(db.path().to_string());
    let notifications = OpenNotifications::new();
    let sm = StateMachine::new(sm_config, notifications, applicator).await.unwrap();
    let log = LogStore::new(db);

    (sm, log)
}

/// Get the config for a mock raft
pub fn mock_raft_config(initial_nodes: Vec<NodeId>, delay: u64) -> RaftClientConfig {
    // Use mock peer ids for each node
    let initial_nodes = initial_nodes.into_iter().map(|nid| (nid, RaftNode::default())).collect();
    let heartbeat_interval = delay + 5;
    let election_timeout_min = heartbeat_interval * 4;
    let election_timeout_max = heartbeat_interval * 5;

    // All timeouts in ms
    RaftClientConfig {
        cluster_name: "mock-cluster".to_string(),
        election_timeout_min,
        election_timeout_max,
        heartbeat_interval,
        initial_nodes,
        ..Default::default()
    }
}

// ----------------
// | Mock Network |
// ----------------

/// A mock raft node created by the `MockRaft`
#[derive(Clone)]
pub struct MockRaftNode {
    /// The raft
    client: RaftClient,
    /// The db of the raft
    db: Arc<DB>,
}

impl MockRaftNode {
    /// Constructor
    pub fn new(client: RaftClient, db: Arc<DB>) -> Self {
        Self { client, db }
    }

    /// Get the raft
    pub fn get_client(&self) -> &RaftClient {
        &self.client
    }

    /// Get the db
    pub fn get_db(&self) -> &DB {
        &self.db
    }

    /// Clone the db
    pub fn clone_db(&self) -> Arc<DB> {
        self.db.clone()
    }
}

/// A network switch in between rafts
pub struct MockRaft {
    /// The delay added to each message
    delay: u64,
    /// A copy of the sender to the switch
    sender: SwitchSender,
    /// The rafts in the network
    pub(crate) rafts: AsyncShared<HashMap<NodeId, MockRaftNode>>,
}

impl MockRaft {
    /// Get a reference to the ith client
    pub async fn get_client(&self, i: NodeId) -> RaftClient {
        self.rafts.read().await[&i].get_client().clone()
    }

    /// Get a handle to the DB of the ith raft
    pub async fn get_db(&self, i: NodeId) -> Arc<DB> {
        self.rafts.read().await[&i].db.clone()
    }

    /// Create a mock raft with a single node
    pub async fn create_singleton_raft() -> Self {
        Self::create_raft(1, 0 /* network_delay_ms */, true /* init */).await
    }

    /// Create a new network client instance
    pub fn new_network_client(&self) -> MockNetworkNode {
        MockNetworkNode::new_with_delay(self.sender.clone(), self.delay)
    }

    /// Create an initialized raft with `n` nodes
    pub async fn create_initialized_raft(n_nodes: usize) -> Self {
        Self::create_raft(n_nodes, 0 /* network_delay_ms */, true /* init */).await
    }

    /// Create a mock raft network with `n_nodes` nodes and return the rafts
    /// in use
    pub async fn create_raft(n_nodes: usize, network_delay_ms: u64, init: bool) -> Self {
        let (send, recv) = new_switch_queue();
        let mut nodes = HashMap::new();
        let node_ids = (0..n_nodes as u64).collect_vec();
        let mut config = mock_raft_config(node_ids, network_delay_ms);
        config.init = init;

        for i in 0..n_nodes as u64 {
            // Setup the config
            let mut conf = config.clone();
            conf.id = i;

            // Setup the raft dependencies
            let mock_net = MockNetworkNode::new_with_delay(send.clone(), network_delay_ms);
            let applicator = mock_applicator();
            let db = applicator.config.db.clone();
            Self::setup_db(&db);

            let notifications = OpenNotifications::new();
            let sm_conf = StateMachineConfig::new(db.path().to_string());
            let sm = StateMachine::new(sm_conf, notifications, applicator).await.unwrap();

            let client = RaftClient::new(conf, db.clone(), mock_net, sm).await.unwrap();
            nodes.insert(i, MockRaftNode::new(client, db));
        }

        // Spawn a thread to manage the network switch
        let rafts = new_async_shared(nodes);
        tokio::spawn(Self::run(recv, rafts.clone()));

        tokio::time::sleep(Duration::from_millis(WAIT_FOR_ELECTION)).await;

        Self { delay: network_delay_ms, rafts, sender: send }
    }

    /// Setup the DB for a raft node
    ///
    /// In particular, this writes a peer ID to the raft node's DB.
    fn setup_db(db: &DB) {
        let tx = db.new_write_tx().unwrap();
        tx.set_peer_id(&mock_peer_id()).unwrap();
        tx.commit().unwrap();
    }

    /// The event loop for the network switch
    async fn run(mut queue: SwitchReceiver, rafts: AsyncShared<HashMap<NodeId, MockRaftNode>>) {
        loop {
            let (to, req, chan) = queue.recv().await.unwrap();
            let target = { rafts.read().await.get(&to).cloned() };
            if target.is_none() {
                continue; // simulate a msg drop
            }

            let client = target.unwrap().client;
            tokio::spawn(async {
                let resp = Self::forward_req(client, req).await;
                chan.send(resp)
            });
        }
    }

    /// Forward a request to the receiver's raft
    ///
    /// This method panics on errors in the receiver at the moment, this is
    /// okay for tests, but the main implementation should handle failures
    async fn forward_req(client: RaftClient, req: RaftRequest) -> RaftResponse {
        match req {
            RaftRequest::AppendEntries(req) => {
                let resp = client.raft().append_entries(req).await.unwrap();
                RaftResponse::AppendEntries(resp)
            },
            RaftRequest::InstallSnapshot(req) => {
                let resp = client.raft().install_snapshot(req).await.unwrap();
                RaftResponse::InstallSnapshot(Ok(resp))
            },
            RaftRequest::Vote(req) => {
                let resp = client.raft().vote(req).await.unwrap();
                RaftResponse::Vote(resp)
            },
            RaftRequest::ForwardedProposal(update) => {
                client.propose_transition(update).await.unwrap();
                RaftResponse::Ack
            },
        }
    }

    /// Add a node to the network, does not propose a state transition
    pub async fn add_node(&self, nid: NodeId) {
        // Setup a config
        let mut config = mock_raft_config(vec![nid], self.delay);
        config.id = nid;

        // Setup the raft dependencies
        let mock_net = MockNetworkNode::new(self.sender.clone());
        let applicator = mock_applicator();
        let db = applicator.config.db.clone();
        let notifications = OpenNotifications::new();
        let sm_conf = StateMachineConfig::new(db.path().to_string());
        let sm = StateMachine::new(sm_conf, notifications, applicator).await.unwrap();

        let client = RaftClient::new(config, db.clone(), mock_net, sm).await.unwrap();
        let node = MockRaftNode::new(client, db);
        self.rafts.write().await.insert(nid, node);
    }

    /// Remove a node from the network, does not propose a state transition
    pub async fn remove_node(&self, nid: NodeId) {
        let raft = self.rafts.write().await.remove(&nid);
        raft.unwrap().get_client().shutdown().await.unwrap();
    }
}
