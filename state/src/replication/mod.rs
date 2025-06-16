//! Replication primitives for the relayer state
//!
//! Defines replication primitives on top of a base raft implementation. Raft
//! provides a consistent, distributed log with serializable access. We describe
//! state transitions and persist these to the raft log to the raft log

pub mod error;
mod log_store;
pub(crate) mod network;
pub mod raft;
pub(crate) mod state_machine;

pub use network::gossip::GossipNetwork;

use common::types::gossip::WrappedPeerId;
use fxhash::hash64 as fxhash64;
use openraft::{Raft as RaftInner, RaftTypeConfig};
use serde::{Deserialize, Serialize};

use crate::Proposal;

// Declare the types config for the raft
openraft::declare_raft_types! (
    /// The type config for the raft
    pub TypeConfig:
        D = Proposal,
        R = (), // Response
        Node = RaftNode,
        SnapshotData = tokio::fs::File,
);

/// A type alias for entries in the raft log
pub type Entry = <TypeConfig as RaftTypeConfig>::Entry;
/// A type alias for the node id type
pub type NodeId = <TypeConfig as RaftTypeConfig>::NodeId;
/// A type alias for the node type
pub type Node = <TypeConfig as RaftTypeConfig>::Node;
/// A type alias for the snapshot data type
pub type SnapshotData = <TypeConfig as RaftTypeConfig>::SnapshotData;
/// A raft using our type config
pub type Raft = RaftInner<TypeConfig>;

/// The node type for the raft, stores the peer ID associated with the node
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RaftNode {
    /// The peer ID associated with the node
    pub(crate) peer_id: WrappedPeerId,
}

impl RaftNode {
    /// Constructor
    pub fn new(peer_id: WrappedPeerId) -> Self {
        Self { peer_id }
    }
}

/// Translate a peer ID to a raft ID
///
/// We hash the underlying peer ID (a mulltihash of the public key) to get a
/// raft peer ID
pub fn get_raft_id(peer_id: &WrappedPeerId) -> u64 {
    fxhash64(&peer_id)
}

// -------------
// | Mock Raft |
// -------------

/// Test helpers for mocking rafts
#[cfg(any(test, feature = "mocks"))]
pub mod test_helpers {
    use std::{collections::HashMap, sync::Arc, time::Duration};

    use itertools::Itertools;
    use util::concurrency::{new_async_shared, AsyncShared};

    use crate::{
        applicator::test_helpers::mock_applicator, notifications::OpenNotifications,
        storage::db::DB,
    };

    use super::{
        log_store::LogStore,
        network::{
            mock::{new_switch_queue, MockNetworkNode, SwitchReceiver, SwitchSender},
            RaftRequest, RaftResponse,
        },
        raft::{RaftClient, RaftClientConfig},
        state_machine::{StateMachine, StateMachineConfig},
        NodeId, RaftNode,
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
        let initial_nodes =
            initial_nodes.into_iter().map(|nid| (nid, RaftNode::default())).collect();
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
}

// --------------
// | Raft Tests |
// --------------

#[cfg(test)]
mod test {

    use std::time::Duration;

    use common::types::wallet_mocks::mock_empty_wallet;
    use openraft::{testing::StoreBuilder, StorageError as RaftStorageError};
    use rand::{seq::IteratorRandom, thread_rng};

    use crate::{replication::RaftNode, Proposal, StateTransition};

    use super::{
        log_store::LogStore,
        state_machine::StateMachine,
        test_helpers::{mock_state_and_log, MockRaft},
        NodeId, TypeConfig,
    };

    /// A builder for the storage layer, used to fit into the `openraft` test
    /// interface
    struct StorageBuilder;
    impl StoreBuilder<TypeConfig, LogStore, StateMachine> for StorageBuilder {
        async fn build(&self) -> Result<((), LogStore, StateMachine), RaftStorageError<NodeId>> {
            let (sm, log) = mock_state_and_log().await;
            Ok(((), log, sm))
        }
    }

    /// Run the `openraft` test suite on our `RaftStateMachine` and
    /// `RaftLogStore` impls
    #[test]
    fn test_openraft_suite() {
        openraft::testing::Suite::test_all(StorageBuilder).unwrap();
    }

    /// Tests a state transition on a single node raft
    #[tokio::test]
    async fn test_raft_singleton() {
        let node = MockRaft::create_singleton_raft().await;
        let wallet = mock_empty_wallet();

        // Propose a new wallet to the raft
        let id = wallet.wallet_id;
        let client = node.get_client(0).await;
        let update = Proposal::from(StateTransition::AddWallet { wallet });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let db = node.get_db(0).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&id).unwrap();
        assert!(wallet.is_some());
    }

    /// Tests proposing a state transition directly to the leader
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_simple_raft__propose_leader() {
        const N: usize = 5;
        let mut rng = thread_rng();

        // Setup a raft
        let nodes = MockRaft::create_initialized_raft(N).await;
        let leader = nodes.get_client(0).await.leader().await;
        let leader = match leader {
            Some(leader) => leader,
            None => panic!("no leader in raft"),
        };

        // Propose a wallet to the leader
        let target_raft = &nodes.get_client(leader).await;
        let wallet = mock_empty_wallet();
        let wallet_id = wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet });
        target_raft.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check a random node's DB to ensure the wallet exists
        let nid = (0..N).choose(&mut rng).unwrap();
        let db = nodes.get_db(nid as NodeId).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&wallet_id).unwrap();
        assert!(wallet.is_some());
    }

    /// Tests proposing a state transition to a random node, assuming it will be
    /// forwarded to the leader
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_simple_raft__propose_random() {
        const N: usize = 5;
        let mut rng = thread_rng();

        // Setup a raft
        let nodes = MockRaft::create_initialized_raft(N).await;
        let leader = nodes.get_client(0).await.leader().await;
        if leader.is_none() {
            panic!("no leader in raft");
        }

        // Propose a wallet update to a random node
        let nid = (0..N).choose(&mut rng).unwrap();
        let target_raft = nodes.get_client(nid as NodeId).await;
        let wallet = mock_empty_wallet();
        let wallet_id = wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet });
        target_raft.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check a random node's DB to ensure the wallet exists
        let nid = (0..N).choose(&mut rng).unwrap();
        let db = nodes.get_db(nid as NodeId).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&wallet_id).unwrap();
        assert!(wallet.is_some());
    }

    /// Tests adding a new node to the raft
    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_add_node__to_singleton() {
        let mut rng = thread_rng();

        // Begin a singleton cluster
        let raft = MockRaft::create_singleton_raft().await;
        let client = raft.get_client(0).await;
        let wallet = mock_empty_wallet();
        let wallet_id = wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet });
        client.propose_transition(update).await.unwrap();

        // Add a new node
        let new_nid = 2;
        raft.add_node(new_nid).await;

        // Add the node as a learner and wait for replication
        client.add_learner(new_nid, RaftNode::default()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Check the DB of the new node
        let db = raft.get_db(new_nid).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&wallet_id).unwrap();
        assert!(wallet.is_some());

        // Promote the learner, propose a new wallet, ensure consensus is reached
        client.promote_learner(new_nid).await.unwrap();
        let wallet = mock_empty_wallet();
        let wallet_id = wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check the DB of either node
        let nid = [0, new_nid].into_iter().choose(&mut rng).unwrap();
        let db = raft.get_db(nid).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&wallet_id).unwrap();
        assert!(wallet.is_some());
    }

    /// Tests adding a node to a larger established cluster
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_add_node__to_existing() {
        const N: usize = 5;
        let mut rng = thread_rng();

        // Create a cluster of size N
        let raft = MockRaft::create_initialized_raft(N).await;
        let nid = (0..N).choose(&mut rng).unwrap();
        let client = raft.get_client(nid as NodeId).await;

        // Add a new node as a learner
        let new_nid = N as u64 + 1;
        raft.add_node(new_nid).await;
        client.add_learner(new_nid, RaftNode::default()).await.unwrap();
        client.promote_learner(new_nid).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Propose a new state transition
        let new_wallet = mock_empty_wallet();
        let new_wallet_id = new_wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet: new_wallet });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check the DB of the new node
        let db = raft.get_db(new_nid).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&new_wallet_id).unwrap();
        assert!(wallet.is_some());

        // Check the DB of a random node
        let nid = (0..N).choose(&mut rng).unwrap();
        let db = raft.get_db(nid as NodeId).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&new_wallet_id).unwrap();
        assert!(wallet.is_some());
    }

    /// Tests a scale up from 1 to `N` cluster nodes
    #[tokio::test]
    async fn test_raft_scale_up() {
        const N: usize = 5;
        // Create a singleton raft
        let raft = MockRaft::create_singleton_raft().await;
        let client = raft.get_client(0).await;

        // Add nodes one by one until we have a cluster of size N
        for i in 1..N {
            let new_nid = i as u64;
            raft.add_node(new_nid).await;
            client.add_learner(new_nid, RaftNode::default()).await.unwrap();
            client.promote_learner(new_nid).await.unwrap();
        }

        // Propose a new wallet and check that each node in the cluster has the wallet
        // saved in the DB
        let new_wallet = mock_empty_wallet();
        let new_wallet_id = new_wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet: new_wallet });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        for i in 0..N {
            let db = raft.get_db(i as NodeId).await;
            let tx = db.new_read_tx().unwrap();
            let wallet = tx.get_wallet(&new_wallet_id).unwrap();
            assert!(wallet.is_some());
        }
    }

    /// Tests removing a node from a minimal (3 node) raft
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_remove_node__minimal() {
        const N: u64 = 3;
        let mut rng = thread_rng();

        // Create a singleton raft
        let raft = MockRaft::create_initialized_raft(N as usize).await;

        // Remove a node from the cluster
        let removed_nid = (0..N).choose(&mut rng).unwrap();
        raft.remove_node(removed_nid).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Propose removal to another client
        let client_id = (removed_nid + 1) % N;
        let client = raft.get_client(client_id).await;
        client.remove_peer(removed_nid).await.unwrap();

        // Propose a new wallet, ensure that consensus is reached
        let new_wallet = mock_empty_wallet();
        let new_wallet_id = new_wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet: new_wallet });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let db = raft.get_db(client_id).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&new_wallet_id).unwrap();
        assert!(wallet.is_some());
    }

    /// Tests removing the leader from a cluster
    #[tokio::test]
    async fn test_remove_leader() {
        const N: u64 = 5;

        // Create a cluster of size N
        let raft = MockRaft::create_initialized_raft(N as usize).await;
        let client = raft.get_client(0).await;

        // Remove the leader from the cluster
        let leader = client.leader().await.unwrap();
        raft.remove_node(leader).await;
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Propose a removal to a node that was not just removed
        let non_leader_nid = (leader + 1) % N;
        let client = raft.get_client(non_leader_nid as NodeId).await;
        client.remove_peer(leader).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Propose a new wallet, ensure that consensus is reached
        let new_wallet = mock_empty_wallet();
        let new_wallet_id = new_wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet: new_wallet });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check the DB of the non-leader
        let db = raft.get_db(non_leader_nid).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&new_wallet_id).unwrap();
        assert!(wallet.is_some());
    }

    /// Tests scaling down a cluster from `N` nodes to two
    #[tokio::test]
    async fn test_raft_scale_down() {
        const N: usize = 5;
        const SCALE_TO: usize = 2;
        let mut rng = thread_rng();

        // Create a cluster of size N
        let raft = MockRaft::create_initialized_raft(N).await;
        let client = raft.get_client(0).await;

        // Remove nodes until we have a cluster of size SCALE_TO
        // Only nodes {0, 1} remain
        for i in 0..N - SCALE_TO {
            let removed_nid = N - i - 1;
            raft.remove_node(removed_nid as u64).await;
            client.remove_peer(removed_nid as u64).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }

        // Propose a state transition and ensure consensus is reached
        let new_wallet = mock_empty_wallet();
        let new_wallet_id = new_wallet.wallet_id;
        let update = Proposal::from(StateTransition::AddWallet { wallet: new_wallet });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check either of the remaining nodes' DBs
        let nid = [0, 1].into_iter().choose(&mut rng).unwrap();
        let db = raft.get_db(nid).await;
        let tx = db.new_read_tx().unwrap();
        let wallet = tx.get_wallet(&new_wallet_id).unwrap();
        assert!(wallet.is_some());
    }

    #[tokio::test]
    async fn test_concurrent_membership_change() {
        const N: usize = 5;

        // Create a cluster of size N
        let raft = MockRaft::create_initialized_raft(N).await;
        let client = raft.get_client(0).await;
        let client2 = raft.get_client(1).await;

        // Add 2 new learners concurrently
        let learner_1 = N as u64 + 1;
        let learner_2 = N as u64 + 2;
        raft.add_node(learner_1).await;
        raft.add_node(learner_2).await;

        let fut1 =
            tokio::spawn(async move { client.add_learner(learner_1, RaftNode::default()).await });
        let fut2 =
            tokio::spawn(async move { client2.add_learner(learner_2, RaftNode::default()).await });

        fut1.await.unwrap().unwrap();
        fut2.await.unwrap().unwrap();
    }
}
