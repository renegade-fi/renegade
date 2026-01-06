//! Replication primitives for the relayer state
//!
//! Defines replication primitives on top of a base raft implementation. Raft
//! provides a consistent, distributed log with serializable access. We describe
//! state transitions and persist these to the raft log to the raft log
#![allow(unexpected_cfgs)]

pub mod error;
mod log_store;
#[cfg(any(test, feature = "mocks"))]
mod mock_raft;
pub(crate) mod network;
pub mod raft;
pub mod rkyv_types;
pub(crate) mod state_machine;

use fxhash::hash64 as fxhash64;
use openraft::{Raft as RaftInner, RaftTypeConfig};
use serde::{Deserialize, Serialize};
use types_gossip::WrappedPeerId;

use crate::state_transition::Proposal;

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
#[derive(
    Copy,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Default,
    Serialize,
    Deserialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(derive(Debug))]
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

// --------------
// | Raft Tests |
// --------------

#[cfg(test)]
mod test {

    use std::time::Duration;

    use openraft::{StorageError as RaftStorageError, testing::StoreBuilder};
    use rand::{seq::IteratorRandom, thread_rng};
    use types_account::account::mocks::mock_empty_account;
    use types_gossip::mocks::mock_peer;
    use types_tasks::{TaskQueueKey, mocks::mock_queued_task};

    use crate::{
        replication::mock_raft::{MockRaft, mock_state_and_log},
        state_transition::{Proposal, StateTransition},
    };

    use super::{NodeId, RaftNode, TypeConfig, log_store::LogStore, state_machine::StateMachine};

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
        let mock = MockRaft::create_singleton_raft().await;

        // Build a state transition
        let queue_id = TaskQueueKey::new_v4();
        let task = mock_queued_task(queue_id);
        let executor = mock_peer().peer_id;
        let update = Proposal::from(StateTransition::AppendTask { task: task.clone(), executor });

        // Propose the new task to the raft
        let client = mock.get_client(0).await;
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check that the task was indexed
        let db = mock.get_db(0).await;
        let tx = db.new_read_tx().unwrap();
        let task = tx.get_task(&task.id).unwrap();
        assert!(task.is_some());
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

        // Propose an account to the leader
        let target_raft = &nodes.get_client(leader).await;
        let account = mock_empty_account();
        let account_id = account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account });
        target_raft.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check a random node's DB to ensure the account exists
        let nid = (0..N).choose(&mut rng).unwrap();
        let db = nodes.get_db(nid as NodeId).await;
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&account_id).unwrap();
        assert!(account.is_some());
    }

    /// Tests proposing a state transition to a random node, assuming it will
    /// be forwarded to the leader
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

        // Propose an account to a random node
        let nid = (0..N).choose(&mut rng).unwrap();
        let target_raft = nodes.get_client(nid as NodeId).await;
        let account = mock_empty_account();
        let account_id = account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account });
        target_raft.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check a random node's DB to ensure the account exists
        let nid = (0..N).choose(&mut rng).unwrap();
        let db = nodes.get_db(nid as NodeId).await;
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&account_id).unwrap();
        assert!(account.is_some());
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
        let account = mock_empty_account();
        let account_id = account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account });
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
        let account = tx.get_account(&account_id).unwrap();
        assert!(account.is_some());

        // Promote the learner, propose a new account, ensure consensus is reached
        client.promote_learner(new_nid).await.unwrap();
        let account = mock_empty_account();
        let account_id = account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check the DB of either node
        let nid = [0, new_nid].into_iter().choose(&mut rng).unwrap();
        let db = raft.get_db(nid).await;
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&account_id).unwrap();
        assert!(account.is_some());
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
        let new_account = mock_empty_account();
        let new_account_id = new_account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account: new_account });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check the DB of the new node
        let db = raft.get_db(new_nid).await;
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&new_account_id).unwrap();
        assert!(account.is_some());

        // Check the DB of a random node
        let nid = (0..N).choose(&mut rng).unwrap();
        let db = raft.get_db(nid as NodeId).await;
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&new_account_id).unwrap();
        assert!(account.is_some());
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

        // Propose a new account and check that each node in the cluster has
        // the account saved in the DB
        let new_account = mock_empty_account();
        let new_account_id = new_account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account: new_account });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        for i in 0..N {
            let db = raft.get_db(i as NodeId).await;
            let tx = db.new_read_tx().unwrap();
            let account = tx.get_account(&new_account_id).unwrap();
            assert!(account.is_some());
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

        // Propose a new account, ensure that consensus is reached
        let new_account = mock_empty_account();
        let new_account_id = new_account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account: new_account });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let db = raft.get_db(client_id).await;
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&new_account_id).unwrap();
        assert!(account.is_some());
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

        // Propose a new account, ensure that consensus is reached
        let new_account = mock_empty_account();
        let new_account_id = new_account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account: new_account });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check the DB of the non-leader
        let db = raft.get_db(non_leader_nid).await;
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&new_account_id).unwrap();
        assert!(account.is_some());
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
        let new_account = mock_empty_account();
        let new_account_id = new_account.wallet_id;
        let update = Proposal::from(StateTransition::CreateAccount { account: new_account });
        client.propose_transition(update).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check either of the remaining nodes' DBs
        let nid = [0, 1].into_iter().choose(&mut rng).unwrap();
        let db = raft.get_db(nid).await;
        let tx = db.new_read_tx().unwrap();
        let account = tx.get_account(&new_account_id).unwrap();
        assert!(account.is_some());
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
