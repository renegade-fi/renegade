//! Node startup task; defines the process by which a node bootstraps into the
//! network and (possibly) into an existing cluster's raft

// --------------
// | Task State |
// --------------

use std::{
    error::Error,
    fmt::Display,
    iter,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use constants::{NATIVE_ASSET_ADDRESS, in_bootstrap_mode};
use darkpool_client::{DarkpoolClient, errors::DarkpoolClientError};
use job_types::{
    network_manager::{NetworkManagerControlSignal, NetworkManagerJob, NetworkManagerQueue},
    proof_manager::ProofManagerQueue,
    task_driver::TaskDriverQueue,
};
use serde::Serialize;
use state::{State, error::StateError};
use tracing::instrument;
use types_core::{AccountId, Token, get_all_tokens};
use types_tasks::NodeStartupTaskDescriptor;
use util::log_task;
use util::logging::Outcome;
use util::{
    err_str,
    on_chain::{set_chain_id, set_default_protocol_fee, set_protocol_fee, set_protocol_pubkey},
};

use crate::{
    logging::Task as LogTask,
    state_migration::run_state_migrations,
    task_state::TaskStateWrapper,
    traits::{Descriptor, Task, TaskContext, TaskError, TaskState},
};

/// The name of the node startup task
const NODE_STARTUP_TASK_NAME: &str = "node-startup";

/// Error sending a job to another worker
const ERR_SEND_JOB: &str = "error sending job";

/// The interval at which to poll for adoption into an existing raft cluster
const RAFT_ADOPTION_POLL_INTERVAL_MS: u64 = 1_000; // 1 second
/// The maximum time to wait to be adopted as a learner by an existing cluster
/// before falling back to bootstrapping a new raft
///
/// Only the deterministic seed node bootstraps after this timeout; every other
/// node continues to wait to be adopted. This prevents a restarting node from
/// forming a competing single-node cluster (split brain) while a leader is live.
const RAFT_ADOPTION_TIMEOUT_MS: u64 = 20_000; // 20 seconds

/// Defines the state of the node startup task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeStartupTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// Fetch system parameters from the smart contracts
    FetchConstants,
    /// The task is waiting for the gossip layer to warm up
    GossipWarmup,
    /// Initialize a new raft
    InitializeRaft,
    /// Refresh state when recovering from a snapshot
    RefreshState,
    /// Join an existing raft
    JoinRaft,
    /// Run any state migrations
    RunningStateMigrations,
    /// The task is completed
    Completed,
}

impl TaskState for NodeStartupTaskState {
    fn commit_point() -> Self {
        Self::Completed
    }

    fn completed(&self) -> bool {
        matches!(self, Self::Completed)
    }
}

impl Display for NodeStartupTaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "Pending"),
            Self::FetchConstants => write!(f, "Fetch Constants"),
            Self::GossipWarmup => write!(f, "Gossip Warmup"),
            Self::InitializeRaft => write!(f, "Initialize Raft"),
            Self::RefreshState => write!(f, "Refresh State"),
            Self::JoinRaft => write!(f, "Join Raft"),
            Self::RunningStateMigrations => write!(f, "Running State Migrations"),
            Self::Completed => write!(f, "Completed"),
        }
    }
}

impl Serialize for NodeStartupTaskState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl From<NodeStartupTaskState> for TaskStateWrapper {
    fn from(state: NodeStartupTaskState) -> Self {
        TaskStateWrapper::NodeStartup(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the node startup task
#[derive(Clone, Debug)]
pub enum NodeStartupTaskError {
    /// An error interacting with darkpool
    Darkpool(String),
    /// An error deriving a wallet
    DeriveWallet(String),
    /// An error sending a job to another worker
    Enqueue(String),
    /// An error fetching contract constants
    FetchConstants(String),
    /// An error setting up the task
    Setup(String),
    /// An error interacting with global state
    State(String),
}

impl From<DarkpoolClientError> for NodeStartupTaskError {
    fn from(e: DarkpoolClientError) -> Self {
        NodeStartupTaskError::Darkpool(e.to_string())
    }
}

impl TaskError for NodeStartupTaskError {
    fn retryable(&self) -> bool {
        false
    }
}

impl Display for NodeStartupTaskError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl Error for NodeStartupTaskError {}
impl From<StateError> for NodeStartupTaskError {
    fn from(e: StateError) -> Self {
        Self::State(e.to_string())
    }
}

// --------------------
// | Task Definition |
// --------------------

/// The node startup task
pub struct NodeStartupTask {
    /// The amount of time to wait for the gossip layer to warm up
    pub gossip_warmup_ms: u64,
    /// The darkpool client to use for submitting transactions
    pub darkpool_client: DarkpoolClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// A copy of the relayer-global state
    pub state: State,
    /// The work queue to add proof management jobs to
    pub proof_queue: ProofManagerQueue,
    /// A sender to the task driver queue
    pub task_queue: TaskDriverQueue,
    /// The state of the task
    pub task_state: NodeStartupTaskState,
}

#[async_trait]
impl Task for NodeStartupTask {
    type Error = NodeStartupTaskError;
    type State = NodeStartupTaskState;
    type Descriptor = NodeStartupTaskDescriptor;

    async fn new(descriptor: Self::Descriptor, ctx: TaskContext) -> Result<Self, Self::Error> {
        Ok(Self {
            gossip_warmup_ms: descriptor.gossip_warmup_ms,
            darkpool_client: ctx.darkpool_client,
            network_sender: ctx.network_queue,
            state: ctx.state,
            proof_queue: ctx.proof_queue,
            task_queue: ctx.task_queue,
            task_state: NodeStartupTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(
        task = self.name(),
        state = %self.task_state(),
    ))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.task_state() {
            NodeStartupTaskState::Pending => {
                self.task_state = NodeStartupTaskState::FetchConstants;
            },
            NodeStartupTaskState::FetchConstants => {
                self.fetch_contract_constants().await?;
                self.task_state = NodeStartupTaskState::GossipWarmup;
            },
            NodeStartupTaskState::GossipWarmup => {
                // Wait for the gossip layer to warm up
                self.warmup_gossip().await?;
            },
            NodeStartupTaskState::InitializeRaft => {
                self.initialize_raft().await?;
            },
            NodeStartupTaskState::RefreshState => {
                self.refresh_state().await?;
                self.task_state = NodeStartupTaskState::RunningStateMigrations;
            },
            NodeStartupTaskState::JoinRaft => {
                self.join_raft().await?;
                self.task_state = NodeStartupTaskState::RunningStateMigrations;
            },
            NodeStartupTaskState::RunningStateMigrations => {
                self.run_state_migrations()?;
                self.task_state = NodeStartupTaskState::Completed;
            },
            NodeStartupTaskState::Completed => {
                panic!("step() called in state Completed")
            },
        }

        Ok(())
    }

    // The node startup task never goes through the task queue
    fn bypass_task_queue(&self) -> bool {
        true
    }

    fn completed(&self) -> bool {
        matches!(self.task_state(), Self::State::Completed)
    }

    fn task_state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn name(&self) -> String {
        NODE_STARTUP_TASK_NAME.to_string()
    }
}

impl Descriptor for NodeStartupTaskDescriptor {
    fn bypass_task_queue(&self) -> bool {
        true
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl NodeStartupTask {
    /// Parameterize local constants by pulling them from the contract's storage
    ///
    /// Concretely, this is the contract protocol key and the protocol fee
    async fn fetch_contract_constants(&self) -> Result<(), NodeStartupTaskError> {
        // Do not fetch constants in bootstrap mode
        if in_bootstrap_mode() {
            return Ok(());
        }

        // Fetch the values from the contract
        let protocol_fee = self
            .darkpool_client
            .get_default_protocol_fee()
            .await
            .map_err(err_str!(NodeStartupTaskError::FetchConstants))?;
        let protocol_key = self
            .darkpool_client
            .get_protocol_pubkey()
            .await
            .map_err(err_str!(NodeStartupTaskError::FetchConstants))?;
        log_task!(
            LogTask::NodeStartup,
            Outcome::Ok,
            "Fetched protocol fee and protocol pubkey from on-chain"
        );

        // Fetch the external match fee overrides for each mint
        self.setup_external_match_fees().await?;

        // Set the chain ID
        let chain_id = self.darkpool_client.chain_id().await?;
        set_chain_id(chain_id);

        // Set the values in their constant refs
        set_default_protocol_fee(protocol_fee);
        set_protocol_pubkey(protocol_key);
        Ok(())
    }

    /// Warmup the gossip layer into the network
    pub async fn warmup_gossip(&mut self) -> Result<(), NodeStartupTaskError> {
        log_task!(
            LogTask::NodeStartup,
            Outcome::Started,
            warmup_ms = self.gossip_warmup_ms,
            "warming up gossip layer"
        );
        let wait_time = Duration::from_millis(self.gossip_warmup_ms);
        tokio::time::sleep(wait_time).await;

        // Indicate to the network manager that warmup is complete
        let msg = NetworkManagerJob::internal(NetworkManagerControlSignal::GossipWarmupComplete);
        self.network_sender
            .send(msg)
            .map_err(|_| NodeStartupTaskError::Enqueue(ERR_SEND_JOB.to_string()))?;

        // After warmup, decide whether to join an existing raft or bootstrap one
        self.task_state = self.choose_raft_startup_state().await?;

        Ok(())
    }

    /// Decide whether the node should bootstrap a new raft or join an existing
    /// one.
    ///
    /// A node must never bootstrap a competing cluster while another cluster is
    /// live, otherwise the relayer split-brains. Because all peers in a cluster
    /// share a `cluster_id`, a live leader adopts newly-discovered same-cluster
    /// peers as learners (see `add_peer_batch`), which initializes the local
    /// raft. The decision flow is therefore:
    ///   1. If the local raft is already initialized (recovered from disk, or we
    ///      were already adopted), join.
    ///   2. If gossip discovered no other peers in our cluster, we are the first
    ///      node; bootstrap.
    ///   3. Otherwise wait to be adopted as a learner by an existing leader
    ///      (the local raft becomes initialized) up to a timeout.
    ///   4. If not adopted before the timeout (cold start, or no reachable
    ///      leader), only the deterministic seed bootstraps; all other nodes
    ///      join and await promotion.
    async fn choose_raft_startup_state(
        &self,
    ) -> Result<NodeStartupTaskState, NodeStartupTaskError> {
        // 1. Already a raft member
        if self.state.is_raft_initialized().await? {
            return Ok(NodeStartupTaskState::JoinRaft);
        }

        // Collect the peers in our cluster that gossip discovered during warmup
        let my_peer_id = self.state.get_peer_id()?;
        let cluster_id = self.state.get_cluster_id()?;
        let peers = self.state.get_cluster_peers(&cluster_id).await?;
        let others: Vec<_> = peers.into_iter().filter(|p| *p != my_peer_id).collect();

        // 2. No peers discovered; we are the first node in a fresh cluster
        if others.is_empty() {
            log_task!(
                LogTask::NodeStartup,
                Outcome::Started,
                "no cluster peers discovered, bootstrapping new raft"
            );
            return Ok(NodeStartupTaskState::InitializeRaft);
        }

        // 3. An existing cluster may be live; wait to be adopted as a learner
        log_task!(
            LogTask::NodeStartup,
            Outcome::Started,
            num_peers = others.len(),
            "cluster peers discovered, awaiting adoption into existing raft"
        );
        if self.await_raft_adoption().await? {
            log_task!(LogTask::NodeStartup, Outcome::Ok, "adopted into existing raft");
            return Ok(NodeStartupTaskState::JoinRaft);
        }

        // 4. Not adopted; break cold-start symmetry with a deterministic seed
        if is_cluster_seed(&my_peer_id, &others) {
            log_task!(
                LogTask::NodeStartup,
                Outcome::Started,
                "not adopted before timeout; this node is the cluster seed, bootstrapping new raft"
            );
            Ok(NodeStartupTaskState::InitializeRaft)
        } else {
            log_task!(
                LogTask::NodeStartup,
                Outcome::Started,
                "not adopted before timeout; awaiting promotion from the cluster seed"
            );
            Ok(NodeStartupTaskState::JoinRaft)
        }
    }

    /// Poll until the local raft becomes initialized (i.e. an existing leader
    /// adopted this node as a learner) or the adoption timeout elapses.
    ///
    /// Returns `true` if the node was adopted.
    async fn await_raft_adoption(&self) -> Result<bool, NodeStartupTaskError> {
        let timeout = Duration::from_millis(RAFT_ADOPTION_TIMEOUT_MS);
        let interval = Duration::from_millis(RAFT_ADOPTION_POLL_INTERVAL_MS);
        let start = Instant::now();
        while start.elapsed() < timeout {
            if self.state.is_raft_initialized().await? {
                return Ok(true);
            }
            tokio::time::sleep(interval).await;
        }

        // Final check after the timeout
        Ok(self.state.is_raft_initialized().await?)
    }

    /// Initialize a new raft cluster
    async fn initialize_raft(&mut self) -> Result<(), NodeStartupTaskError> {
        // Get the list of other peers in the cluster
        let my_cluster = self.state.get_cluster_id()?;
        let peers = self.state.get_cluster_peers(&my_cluster).await?;

        log_task!(
            LogTask::NodeStartup,
            Outcome::Started,
            num_peers = peers.len(),
            "initializing raft with peers"
        );
        self.state.initialize_raft(peers).await?;

        // Await election of a leader
        log_task!(LogTask::NodeStartup, Outcome::Started, "awaiting leader election");
        self.state.await_leader().await.map_err(err_str!(NodeStartupTaskError::State))?;

        let leader = self.state.get_leader().unwrap();
        log_task!(LogTask::NodeStartup, Outcome::Ok, subject = %leader, "leader elected");

        let my_peer_id = self.state.get_peer_id()?;
        if leader != my_peer_id {
            log_task!(LogTask::NodeStartup, Outcome::Ok, "elected leader is a cluster peer");
            self.task_state = NodeStartupTaskState::JoinRaft;
        } else {
            self.task_state = NodeStartupTaskState::RefreshState;
        }

        Ok(())
    }

    /// Refresh state when recovering from a snapshot
    async fn refresh_state(&self) -> Result<(), NodeStartupTaskError> {
        // Do not refresh state in bootstrap mode
        if in_bootstrap_mode() {
            return Ok(());
        }

        // If the node did not recover from a snapshot we need not refresh
        if !self.state.was_recovered_from_snapshot() {
            return Ok(());
        }

        // For each account, refresh the account from on-chain state
        let account_ids = self.state.get_all_account_ids().await?;
        for account_id in account_ids {
            self.refresh_account(account_id).await?;
        }

        Ok(())
    }

    /// Manage the process to join an existing raft cluster
    #[allow(clippy::unused_async)]
    async fn join_raft(&self) -> Result<(), NodeStartupTaskError> {
        log_task!(LogTask::NodeStartup, Outcome::Started, "joining raft cluster");

        // Wait for promotion to a voter
        log_task!(LogTask::NodeStartup, Outcome::Started, "awaiting promotion to voter");
        self.state.await_promotion().await.map_err(err_str!(NodeStartupTaskError::State))?;
        log_task!(LogTask::NodeStartup, Outcome::Ok, "promoted to voter");

        Ok(())
    }

    /// Run state migrations that need to happen on the next node startup
    ///
    /// These migrations are necessarily not permanent parts of the codebase,
    /// but rather intended to cleanup state, initialize new tables, etc.
    ///
    /// Migrations should be idempotent for safety
    fn run_state_migrations(&self) -> Result<(), NodeStartupTaskError> {
        run_state_migrations(&self.state);
        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Enqueue an account refresh task
    async fn refresh_account(&self, account_id: AccountId) -> Result<(), NodeStartupTaskError> {
        self.state
            .append_account_refresh_task(account_id)
            .await
            .map_err(|e| NodeStartupTaskError::State(e.to_string()))?;

        Ok(())
    }

    /// Setup the external match fee overrides for all tokens
    async fn setup_external_match_fees(&self) -> Result<(), NodeStartupTaskError> {
        let tokens: Vec<Token> = get_all_tokens()
            .into_iter()
            .chain(iter::once(Token::from_addr(NATIVE_ASSET_ADDRESS)))
            .collect();

        let usdc = Token::usdc().get_alloy_address();
        for token in tokens {
            if token.get_alloy_address() == usdc {
                continue;
            }

            // Fetch the fee override from the contract
            let addr = token.get_alloy_address();
            let fee = self.darkpool_client.get_protocol_fee(addr, usdc).await?;

            // Write the fee into the mapping
            set_protocol_fee(&addr, &usdc, fee);
        }

        Ok(())
    }
}

/// Whether `me` is the deterministic bootstrap seed for the cluster.
///
/// The seed is the cluster member with the smallest id. Every node computes the
/// same seed from the same membership set, so exactly one node bootstraps on a
/// cold start while the rest join and await promotion.
fn is_cluster_seed<T: Ord>(me: &T, others: &[T]) -> bool {
    others.iter().all(|peer| me < peer)
}

#[cfg(test)]
mod tests {
    use super::is_cluster_seed;

    /// The smallest id is the seed; a larger id is not
    #[test]
    fn test_seed_is_minimum() {
        assert!(is_cluster_seed(&1u64, &[2, 3, 4]));
        assert!(!is_cluster_seed(&3u64, &[1, 2, 4]));
    }

    /// A node with no discovered peers is trivially the seed
    #[test]
    fn test_seed_alone() {
        let others: [u64; 0] = [];
        assert!(is_cluster_seed(&5u64, &others));
    }

    /// Exactly one member of a cluster computes itself as the seed
    #[test]
    fn test_seed_is_unique() {
        let members = [10u64, 20, 30];
        let seed_count = members
            .iter()
            .filter(|m| {
                let others: Vec<u64> = members.iter().copied().filter(|x| x != **m).collect();
                is_cluster_seed(*m, &others)
            })
            .count();
        assert_eq!(seed_count, 1);
    }
}
