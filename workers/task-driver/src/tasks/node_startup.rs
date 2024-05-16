//! Node startup task; defines the process by which a node bootstraps into the
//! network and (possibly) into an existing cluster's raft

// --------------
// | Task State |
// --------------

use std::{error::Error, fmt::Display, time::Duration};

use arbitrum_client::client::ArbitrumClient;
use async_trait::async_trait;
use common::types::tasks::NodeStartupTaskDescriptor;
use job_types::{
    network_manager::{NetworkManagerControlSignal, NetworkManagerJob, NetworkManagerQueue},
    proof_manager::ProofManagerQueue,
};
use serde::Serialize;
use state::{error::StateError, State};
use tracing::{info, instrument};

use crate::{
    driver::StateWrapper,
    traits::{Task, TaskContext, TaskError, TaskState},
};

/// The name of the node startup task
const NODE_STARTUP_TASK_NAME: &str = "node-startup";

/// Error sending a job to another worker
const ERR_SEND_JOB: &str = "error sending job";

/// Defines the state of the node startup task
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum NodeStartupTaskState {
    /// The task is awaiting scheduling
    Pending,
    /// The task is waiting for the gossip layer to warm up
    GossipWarmup,
    /// Initialize a new raft
    InitializeRaft,
    /// Join an existing raft
    JoinRaft,
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
            Self::GossipWarmup => write!(f, "Gossip Warmup"),
            Self::InitializeRaft => write!(f, "Initialize Raft"),
            Self::JoinRaft => write!(f, "Join Raft"),
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

impl From<NodeStartupTaskState> for StateWrapper {
    fn from(state: NodeStartupTaskState) -> Self {
        StateWrapper::NodeStartup(state)
    }
}

// ---------------
// | Task Errors |
// ---------------

/// The error type for the node startup task
#[derive(Clone, Debug)]
pub enum NodeStartupTaskError {
    /// An error sending a job to another worker
    Enqueue(String),
    /// An error interacting with global state
    State(String),
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
    /// The arbitrum client to use for submitting transactions
    pub arbitrum_client: ArbitrumClient,
    /// A sender to the network manager's work queue
    pub network_sender: NetworkManagerQueue,
    /// A copy of the relayer-global state
    pub state: State,
    /// The work queue to add proof management jobs to
    pub proof_manager_work_queue: ProofManagerQueue,
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
            arbitrum_client: ctx.arbitrum_client,
            network_sender: ctx.network_queue,
            state: ctx.state,
            proof_manager_work_queue: ctx.proof_queue,
            task_state: NodeStartupTaskState::Pending,
        })
    }

    #[allow(clippy::blocks_in_conditions)]
    #[instrument(skip_all, err, fields(
        task = self.name(),
        state = %self.state(),
    ))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.state() {
            NodeStartupTaskState::Pending => {
                self.task_state = NodeStartupTaskState::GossipWarmup;
            },
            NodeStartupTaskState::GossipWarmup => {
                // Wait for the gossip layer to warm up
                self.warmup_gossip().await?;
            },
            NodeStartupTaskState::InitializeRaft => {
                self.initialize_raft().await?;
                self.task_state = NodeStartupTaskState::Completed;
            },
            NodeStartupTaskState::JoinRaft => {
                self.join_raft().await?;
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
        matches!(self.state(), Self::State::Completed)
    }

    fn state(&self) -> Self::State {
        self.task_state.clone()
    }

    fn name(&self) -> String {
        NODE_STARTUP_TASK_NAME.to_string()
    }
}

// -----------------------
// | Task Implementation |
// -----------------------

impl NodeStartupTask {
    /// Warmup the gossip layer into the network
    pub async fn warmup_gossip(&mut self) -> Result<(), NodeStartupTaskError> {
        info!("Warming up gossip layer for {}ms", self.gossip_warmup_ms);
        let wait_time = Duration::from_millis(self.gossip_warmup_ms);
        tokio::time::sleep(wait_time).await;

        // Indicate to the network manager that warmup is complete
        let msg = NetworkManagerJob::internal(NetworkManagerControlSignal::GossipWarmupComplete);
        self.network_sender
            .send(msg)
            .map_err(|_| NodeStartupTaskError::Enqueue(ERR_SEND_JOB.to_string()))?;

        // After warmup, check for an existing raft cluster
        if self.state.is_raft_initialized() {
            self.task_state = NodeStartupTaskState::JoinRaft;
        } else {
            self.task_state = NodeStartupTaskState::InitializeRaft;
        }

        Ok(())
    }

    /// Initialize a new raft cluster
    async fn initialize_raft(&self) -> Result<(), NodeStartupTaskError> {
        // Get the list of other peers in the cluster
        let my_cluster = self.state.get_cluster_id().await?;
        let peers = self.state.get_cluster_peers(&my_cluster).await?;

        info!("initializing raft with {} peers", peers.len());
        self.state.initialize_raft(peers).await?;
        Ok(())
    }

    /// Manage the process to join an existing raft cluster
    ///
    /// TODO: Implement snapshot & promotion requests if joining an existing
    /// cluster
    #[allow(clippy::unused_async)]
    async fn join_raft(&self) -> Result<(), NodeStartupTaskError> {
        println!("joining raft cluster");
        Ok(())
    }
}
