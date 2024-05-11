//! Defines replication primitives for the relayer state on top of a
//! base raft implementation. Raft provides a consistent, distributed log
//! with serializable access. We describe state transitions and persist these
//! to the raft log

pub mod error;
mod log_store;
mod network;
pub mod raft;
mod snapshot;
mod state_machine;

use openraft::{EmptyNode, Raft as RaftInner, RaftTypeConfig};

use crate::StateTransition;

// Declare the types config for the raft
openraft::declare_raft_types! (
    /// The type config for the raft
    pub TypeConfig:
        D = Box<StateTransition>,
        R = (), // Response
        Node = EmptyNode,
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

#[cfg(test)]
pub mod test_helpers {
    use std::{sync::Arc, time::Duration};

    use futures::stream::StreamExt;
    use itertools::Itertools;
    use tokio_stream::{wrappers::UnboundedReceiverStream, StreamMap};

    use crate::{applicator::test_helpers::mock_applicator, storage::db::DB};

    use super::{
        log_store::LogStore,
        network::{
            mock::{new_switch_queue, MockNetworkNode, SwitchReceiver},
            RaftRequest, RaftResponse,
        },
        raft::{RaftClient, RaftClientConfig},
        state_machine::{StateMachine, StateMachineConfig},
        NodeId,
    };

    /// The timeout which mock rafts wait for leader election
    const WAIT_FOR_ELECTION: u64 = 100; // 100 ms

    // -----------
    // | Helpers |
    // -----------

    /// Create a mock state machine
    pub fn mock_state_machine() -> StateMachine {
        let (sm, _) = mock_state_and_log();
        sm
    }

    /// Create a mock state machine and log store
    pub fn mock_state_and_log() -> (StateMachine, LogStore) {
        let applicator = mock_applicator();
        let db = applicator.config.db.clone();
        let sm_config = StateMachineConfig::new(db.path().to_string());
        let sm = StateMachine::new(sm_config, applicator);
        let log = LogStore::new(db);

        (sm, log)
    }

    /// Get the config for a mock raft
    pub fn mock_raft_config(initial_nodes: Vec<NodeId>) -> RaftClientConfig {
        // All timeouts in ms
        RaftClientConfig {
            cluster_name: "mock-cluster".to_string(),
            election_timeout_min: 10,
            election_timeout_max: 15,
            heartbeat_interval: 5,
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
        client: RaftClient<MockNetworkNode>,
        /// The db of the raft
        db: Arc<DB>,
    }

    impl MockRaftNode {
        /// Constructor
        pub fn new(client: RaftClient<MockNetworkNode>, db: Arc<DB>) -> Self {
            Self { client, db }
        }
        /// Get the raft
        pub fn get_client(&self) -> &RaftClient<MockNetworkNode> {
            &self.client
        }

        /// Get the db
        pub fn get_db(&self) -> &DB {
            &self.db
        }
    }

    /// A network switch in between rafts
    pub struct MockRaft {
        /// The receivers from network nodes in the raft
        receivers: Vec<SwitchReceiver>,
        /// The rafts in the network
        rafts: Vec<RaftClient<MockNetworkNode>>,
    }

    impl MockRaft {
        /// Create a mock raft with a single node
        pub async fn create_singleton_raft() -> MockRaftNode {
            let rafts = Self::create_raft(1).await;
            rafts[0].clone()
        }

        /// Create a mock raft network with `n_nodes` nodes and return the rafts
        /// in use
        pub async fn create_raft(n_nodes: usize) -> Vec<MockRaftNode> {
            let mut receivers = Vec::with_capacity(n_nodes);
            let mut nodes = Vec::with_capacity(n_nodes);
            let node_ids = (0..n_nodes as u64).collect_vec();
            let config = mock_raft_config(node_ids);

            for i in 0..n_nodes as u64 {
                let (send, recv) = new_switch_queue();
                receivers.push(recv);

                let mock_net = MockNetworkNode::new(send);
                let applicator = mock_applicator();
                let db = applicator.config.db.clone();
                let mut conf = config.clone();
                conf.id = i;

                let client = RaftClient::new(conf, db.clone(), mock_net, applicator).await.unwrap();
                nodes.push(MockRaftNode::new(client, db));
            }

            // Spawn a thread to manage the network switch
            let rafts = nodes.iter().map(|n| n.get_client().clone()).collect_vec();
            let this = Self { receivers, rafts };
            tokio::spawn(this.run());
            tokio::time::sleep(Duration::from_millis(WAIT_FOR_ELECTION)).await;

            nodes
        }

        /// The event loop for the network switch
        async fn run(mut self) {
            let mut stream_map = StreamMap::new();
            for (i, receiver) in self.receivers.drain(..).enumerate() {
                let stream = UnboundedReceiverStream::new(receiver);
                stream_map.insert(i, stream);
            }

            loop {
                let (_from, (to, req, chan)) = stream_map.next().await.unwrap();
                let client = self.rafts[to as usize].clone();
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
        async fn forward_req(
            client: RaftClient<MockNetworkNode>,
            req: RaftRequest,
        ) -> RaftResponse {
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
    }
}

#[cfg(test)]
mod test {

    use std::time::Duration;

    use common::types::wallet_mocks::mock_empty_wallet;
    use openraft::{testing::StoreBuilder, StorageError as RaftStorageError};
    use rand::{seq::IteratorRandom, thread_rng};

    use crate::StateTransition;

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
            let (sm, log) = mock_state_and_log();
            Ok(((), log, sm))
        }
    }

    /// Run the `openraft` test suite on our `RaftStateMachine` and
    /// `RaftLogStore` impls
    #[test]
    fn test_openraft_suite() {
        openraft::testing::Suite::test_all(StorageBuilder).unwrap();
    }

    #[tokio::test]
    async fn test_raft_singleton() {
        let node = MockRaft::create_singleton_raft().await;
        let wallet = mock_empty_wallet();

        // Propose a new wallet to the raft
        let id = wallet.wallet_id;
        node.get_client().propose_transition(StateTransition::AddWallet { wallet }).await.unwrap();

        let tx = node.get_db().new_read_tx().unwrap();
        let wallet = tx.get_wallet(&id).unwrap();
        assert!(wallet.is_some());
    }

    #[tokio::test]
    #[allow(non_snake_case)]
    async fn test_simple_raft__propose_leader() {
        const N: usize = 5;
        let mut rng = thread_rng();

        // Setup a raft
        let nodes = MockRaft::create_raft(N).await;
        let leader = nodes[0].get_client().leader().await;
        let leader = match leader {
            Some(leader) => leader,
            None => panic!("no leader in raft"),
        };

        // Propose a wallet to the leader
        let target_raft = &nodes[leader as usize].get_client();
        let wallet = mock_empty_wallet();
        let wallet_id = wallet.wallet_id;
        target_raft.propose_transition(StateTransition::AddWallet { wallet }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check a random node's DB to ensure the wallet exists
        let nid = (0..N).choose(&mut rng).unwrap();
        let tx = nodes[nid].get_db().new_read_tx().unwrap();
        let wallet = tx.get_wallet(&wallet_id).unwrap();
        assert!(wallet.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 5)]
    #[allow(non_snake_case)]
    async fn test_simple_raft__propose_random() {
        const N: usize = 5;
        let mut rng = thread_rng();

        // Setup a raft
        let nodes = MockRaft::create_raft(N).await;
        let leader = nodes[0].get_client().leader().await;
        if leader.is_none() {
            panic!("no leader in raft");
        }

        // Propose a wallet update to a random node
        let nid = (0..N).choose(&mut rng).unwrap();
        let target_raft = nodes[nid].get_client();
        let wallet = mock_empty_wallet();
        let wallet_id = wallet.wallet_id;
        target_raft.propose_transition(StateTransition::AddWallet { wallet }).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check a random node's DB to ensure the wallet exists
        let nid = (0..N).choose(&mut rng).unwrap();
        let tx = nodes[nid].get_db().new_read_tx().unwrap();
        let wallet = tx.get_wallet(&wallet_id).unwrap();
        assert!(wallet.is_some());
    }
}
