//! Node startup task; defines the process by which a node bootstraps into the
//! network and (possibly) into an existing cluster's raft

// --------------
// | Task State |
// --------------

use std::{error::Error, fmt::Display, time::Duration};

use arbitrum_client::{client::ArbitrumClient, errors::ArbitrumClientError};
use async_trait::async_trait;
use common::types::{
    tasks::{LookupWalletTaskDescriptor, NewWalletTaskDescriptor, NodeStartupTaskDescriptor},
    wallet::{
        derivation::{
            derive_blinder_seed, derive_share_seed, derive_wallet_id, derive_wallet_keychain,
        },
        KeyChain, Wallet, WalletIdentifier,
    },
};
use constants::Scalar;
use ethers::signers::LocalWallet;
use job_types::{
    network_manager::{NetworkManagerControlSignal, NetworkManagerJob, NetworkManagerQueue},
    proof_manager::ProofManagerQueue,
    task_driver::TaskDriverQueue,
};
use serde::Serialize;
use state::{error::StateError, State};
use tracing::{info, instrument};
use util::{
    arbitrum::{PROTOCOL_FEE, PROTOCOL_PUBKEY},
    err_str,
};

use crate::{
    await_task,
    driver::StateWrapper,
    tasks::lookup_wallet::ERR_WALLET_NOT_FOUND,
    traits::{Task, TaskContext, TaskError, TaskState},
};

/// The name of the node startup task
const NODE_STARTUP_TASK_NAME: &str = "node-startup";

/// Error sending a job to another worker
const ERR_SEND_JOB: &str = "error sending job";
/// Error deserializing the arbitrum private key
const ERR_INVALID_KEY: &str = "invalid arbitrum private key";

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
    /// Setup the relayer's wallet, the wallet at which the relayer will receive
    /// fees
    SetupRelayerWallet,
    /// Refresh state when recovering from a snapshot
    RefreshState,
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
            Self::FetchConstants => write!(f, "Fetch Constants"),
            Self::GossipWarmup => write!(f, "Gossip Warmup"),
            Self::InitializeRaft => write!(f, "Initialize Raft"),
            Self::SetupRelayerWallet => write!(f, "Setup Relayer Wallet"),
            Self::RefreshState => write!(f, "Refresh State"),
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
    /// An error interacting with arbitrum
    Arbitrum(String),
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

impl From<ArbitrumClientError> for NodeStartupTaskError {
    fn from(e: ArbitrumClientError) -> Self {
        Self::Arbitrum(e.to_string())
    }
}

// --------------------
// | Task Definition |
// --------------------

/// The node startup task
pub struct NodeStartupTask {
    /// The amount of time to wait for the gossip layer to warm up
    pub gossip_warmup_ms: u64,
    /// The arbitrum private key
    pub keypair: LocalWallet,
    /// The arbitrum client to use for submitting transactions
    pub arbitrum_client: ArbitrumClient,
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
        let keypair = LocalWallet::from_bytes(&descriptor.key_bytes)
            .map_err(|_| NodeStartupTaskError::Setup(ERR_INVALID_KEY.to_string()))?;

        Ok(Self {
            gossip_warmup_ms: descriptor.gossip_warmup_ms,
            keypair,
            arbitrum_client: ctx.arbitrum_client,
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
        state = %self.state(),
    ))]
    async fn step(&mut self) -> Result<(), Self::Error> {
        // Dispatch based on the current transaction step
        match self.state() {
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
                self.task_state = NodeStartupTaskState::SetupRelayerWallet;
            },
            NodeStartupTaskState::SetupRelayerWallet => {
                self.setup_relayer_wallet().await?;
                self.task_state = NodeStartupTaskState::RefreshState;
            },
            NodeStartupTaskState::RefreshState => {
                self.refresh_state().await?;
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
    /// Parameterize local constants by pulling them from the contract's storage
    ///
    /// Concretely, this is the contract protocol key and the protocol fee
    async fn fetch_contract_constants(&self) -> Result<(), NodeStartupTaskError> {
        // Fetch the values from the contract
        let protocol_fee = self
            .arbitrum_client
            .get_protocol_fee()
            .await
            .map_err(err_str!(NodeStartupTaskError::FetchConstants))?;
        let protocol_key = self
            .arbitrum_client
            .get_protocol_pubkey()
            .await
            .map_err(err_str!(NodeStartupTaskError::FetchConstants))?;
        info!("Fetched protocol fee and protocol pubkey from on-chain");

        // Set the values in their constant refs
        PROTOCOL_FEE.set(protocol_fee).expect("protocol fee already set");
        PROTOCOL_PUBKEY.set(protocol_key).expect("protocol pubkey already set");
        Ok(())
    }

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
        if self.state.is_raft_initialized().await.map_err(err_str!(NodeStartupTaskError::State))? {
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

        // Await election of a leader
        info!("awaiting leader election");
        self.state.await_leader().await.map_err(err_str!(NodeStartupTaskError::State))?;
        info!("leader elected: {}", self.state.get_leader().unwrap());

        Ok(())
    }

    /// Setup the relayer's wallet, the wallet at which the relayer will receive
    /// fees
    ///
    /// If the wallet is found on-chain, recover it. Otherwise, create a new one
    async fn setup_relayer_wallet(&self) -> Result<(), NodeStartupTaskError> {
        let chain_id = self
            .arbitrum_client
            .chain_id()
            .await
            .map_err(err_str!(NodeStartupTaskError::Arbitrum))?;

        // Derive the keychain, blinder seed, and share seed from the relayer pkey
        let blinder_seed = derive_blinder_seed(&self.keypair)
            .map_err(err_str!(NodeStartupTaskError::DeriveWallet))?;
        let share_seed = derive_share_seed(&self.keypair)
            .map_err(err_str!(NodeStartupTaskError::DeriveWallet))?;
        let keychain = derive_wallet_keychain(&self.keypair, chain_id)
            .map_err(err_str!(NodeStartupTaskError::DeriveWallet))?;

        // Set the node metadata entry for the relayer's wallet
        let wallet_id = derive_wallet_id(&self.keypair)
            .map_err(err_str!(NodeStartupTaskError::DeriveWallet))?;

        // Attempt to find the wallet on-chain
        if self.find_wallet_onchain(wallet_id, blinder_seed, share_seed, keychain.clone()).await? {
            info!("found relayer wallet on-chain");
            return Ok(());
        }

        // Otherwise, create a new wallet
        self.create_wallet(wallet_id, blinder_seed, share_seed, keychain).await
    }

    /// Refresh state when recovering from a snapshot
    async fn refresh_state(&self) -> Result<(), NodeStartupTaskError> {
        // If the node did not recover from a snapshot we need not refresh
        if !self.state.was_recovered_from_snapshot() {
            return Ok(());
        }

        // For each wallet, check if a newer version is known on-chain
        for wallet in self.state.get_all_wallets().await?.into_iter() {
            let nullifier = wallet.get_wallet_nullifier();
            if self.arbitrum_client.check_nullifier_used(nullifier).await? {
                self.refresh_wallet(&wallet).await?;
            }
        }

        Ok(())
    }

    /// Manage the process to join an existing raft cluster
    #[allow(clippy::unused_async)]
    async fn join_raft(&self) -> Result<(), NodeStartupTaskError> {
        info!("joining raft cluster");

        // Wait for promotion to a voter
        info!("awaiting promotion to voter");
        self.state.await_promotion().await.map_err(err_str!(NodeStartupTaskError::State))?;
        info!("promoted to voter");

        Ok(())
    }

    // -----------
    // | Helpers |
    // -----------

    /// Attempt to fetch a wallet from on-chain
    async fn find_wallet_onchain(
        &self,
        wallet_id: WalletIdentifier,
        blinder_seed: Scalar,
        share_seed: Scalar,
        keychain: KeyChain,
    ) -> Result<bool, NodeStartupTaskError> {
        info!("Finding relayer wallet on-chain");
        let descriptor =
            LookupWalletTaskDescriptor::new(wallet_id, blinder_seed, share_seed, keychain)
                .expect("infallible");
        let res = await_task(descriptor.into(), &self.state, self.task_queue.clone()).await;

        match res {
            Ok(_) => Ok(true),
            Err(e) => {
                // If the error is that the wallet was not found, return false and create a new
                // wallet. Otherwise, propagate the error
                if e.contains(ERR_WALLET_NOT_FOUND) {
                    Ok(false)
                } else {
                    Err(NodeStartupTaskError::Setup(e))
                }
            },
        }
    }

    /// Create a new wallet for the relayer
    async fn create_wallet(
        &self,
        wallet_id: WalletIdentifier,
        blinder_seed: Scalar,
        share_seed: Scalar,
        keychain: KeyChain,
    ) -> Result<(), NodeStartupTaskError> {
        info!("Creating new relayer wallet");
        let wallet = Wallet::new_empty_wallet(wallet_id, blinder_seed, share_seed, keychain);
        let descriptor = NewWalletTaskDescriptor::new(wallet)
            .map_err(err_str!(NodeStartupTaskError::DeriveWallet))?;

        await_task(descriptor.into(), &self.state, self.task_queue.clone())
            .await
            .map_err(err_str!(NodeStartupTaskError::Setup))
    }

    /// Enqueue a wallet lookup task to refresh a wallet
    async fn refresh_wallet(&self, wallet: &Wallet) -> Result<(), NodeStartupTaskError> {
        // The seeds for the lookup wallet task may be taken as the last known values in
        // their respective CSPRNGs:
        // - The blinder seed is the private share of the blinder
        // - The secret share seed is the last private share of the wallet
        let blinder_seed = wallet.private_blinder_share();
        let share_seed = wallet.get_last_private_share();

        let descriptor = LookupWalletTaskDescriptor::new(
            wallet.wallet_id,
            blinder_seed,
            share_seed,
            wallet.key_chain.clone(),
        )
        .expect("infallible");

        // Enqueue the task and wait for the log entry to be persisted
        let (_id, waiter) = self.state.append_task(descriptor.into()).await?;
        waiter.await?;

        Ok(())
    }
}
