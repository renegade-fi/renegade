//! Node startup task; defines the process by which a node bootstraps into the
//! network and (possibly) into an existing cluster's raft

// --------------
// | Task State |
// --------------

use std::{error::Error, fmt::Display, iter, time::Duration};

use alloy::signers::{k256::ecdsa::SigningKey, local::PrivateKeySigner};
use async_trait::async_trait;
use common::types::{
    tasks::{LookupWalletTaskDescriptor, NewWalletTaskDescriptor, NodeStartupTaskDescriptor},
    token::{Token, get_all_tokens},
    wallet::{
        Wallet, WalletIdentifier,
        derivation::{
            derive_blinder_seed, derive_share_seed, derive_wallet_id, derive_wallet_keychain,
        },
        keychain::KeyChain,
    },
};
use constants::{NATIVE_ASSET_ADDRESS, Scalar, in_bootstrap_mode};
use darkpool_client::{DarkpoolClient, errors::DarkpoolClientError};
use job_types::{
    network_manager::{NetworkManagerControlSignal, NetworkManagerJob, NetworkManagerQueue},
    proof_manager::ProofManagerQueue,
    task_driver::TaskDriverQueue,
};
use serde::Serialize;
use state::{State, error::StateError};
use tracing::{error, info, instrument};
use util::{
    err_str,
    on_chain::{PROTOCOL_FEE, PROTOCOL_PUBKEY, set_external_match_fee},
};

use crate::{
    await_task,
    state_migration::remove_phantom_orders,
    task_state::StateWrapper,
    traits::{Task, TaskContext, TaskError, TaskState},
    utils::ERR_WALLET_NOT_FOUND,
};

/// The name of the node startup task
const NODE_STARTUP_TASK_NAME: &str = "node-startup";

/// Error sending a job to another worker
const ERR_SEND_JOB: &str = "error sending job";
/// Error deserializing the private key
const ERR_INVALID_KEY: &str = "invalid private key";

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
            Self::SetupRelayerWallet => write!(f, "Setup Relayer Wallet"),
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
    /// Whether the relayer needs a wallet created for it or not
    pub needs_relayer_wallet: bool,
    /// The private key
    pub keypair: PrivateKeySigner,
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
        let signing_key = SigningKey::from_slice(descriptor.key_bytes.as_slice())
            .map_err(|_| NodeStartupTaskError::Setup(ERR_INVALID_KEY.to_string()))?;
        let pkey = PrivateKeySigner::from_signing_key(signing_key);

        Ok(Self {
            gossip_warmup_ms: descriptor.gossip_warmup_ms,
            needs_relayer_wallet: descriptor.needs_relayer_wallet,
            keypair: pkey,
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
            },
            NodeStartupTaskState::SetupRelayerWallet => {
                self.setup_relayer_wallet().await?;
                self.task_state = NodeStartupTaskState::RefreshState;
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
        // Do not fetch constants in bootstrap mode
        if in_bootstrap_mode() {
            return Ok(());
        }

        // Fetch the values from the contract
        let protocol_fee = self
            .darkpool_client
            .get_protocol_fee()
            .await
            .map_err(err_str!(NodeStartupTaskError::FetchConstants))?;
        let protocol_key = self
            .darkpool_client
            .get_protocol_pubkey()
            .await
            .map_err(err_str!(NodeStartupTaskError::FetchConstants))?;
        info!("Fetched protocol fee and protocol pubkey from on-chain");

        // Fetch the external match fee overrides for each mint
        self.setup_external_match_fees().await?;

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
    async fn initialize_raft(&mut self) -> Result<(), NodeStartupTaskError> {
        // Get the list of other peers in the cluster
        let my_cluster = self.state.get_cluster_id()?;
        let peers = self.state.get_cluster_peers(&my_cluster).await?;

        info!("initializing raft with {} peers", peers.len());
        self.state.initialize_raft(peers).await?;

        // Await election of a leader
        info!("awaiting leader election");
        self.state.await_leader().await.map_err(err_str!(NodeStartupTaskError::State))?;

        let leader = self.state.get_leader().unwrap();
        info!("leader elected: {}", leader);

        let my_peer_id = self.state.get_peer_id()?;
        if leader != my_peer_id {
            info!("elected leader is a cluster peer");
            self.task_state = NodeStartupTaskState::JoinRaft;
        } else {
            self.task_state = NodeStartupTaskState::SetupRelayerWallet;
        }

        Ok(())
    }

    /// Setup the relayer's wallet, the wallet at which the relayer will receive
    /// fees
    ///
    /// If the wallet is found on-chain, recover it. Otherwise, create a new one
    async fn setup_relayer_wallet(&self) -> Result<(), NodeStartupTaskError> {
        // Do not setup a wallet in bootstrap mode
        if in_bootstrap_mode() {
            return Ok(());
        }

        // If the state setup did not allocate a wallet id, we do not need a wallet
        if !self.needs_relayer_wallet {
            info!("no relayer wallet needed, skipping creation...");
            return Ok(());
        }

        // Derive the keychain, blinder seed, and share seed from the relayer pkey
        let chain_id = self.darkpool_client.chain_id().await?;
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
        // Do not refresh state in bootstrap mode
        if in_bootstrap_mode() {
            return Ok(());
        }

        // If the node did not recover from a snapshot we need not refresh
        if !self.state.was_recovered_from_snapshot() {
            return Ok(());
        }

        // For each wallet, check if a newer version is known on-chain
        for wallet in self.state.get_all_wallets().await?.into_iter() {
            let nullifier = wallet.get_wallet_nullifier();
            if self.darkpool_client.check_nullifier_used(nullifier).await? {
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

    /// Run state migrations that need to happen on the next node startup
    ///
    /// These migrations are necessarily not permanent parts of the codebase,
    /// but rather intended to cleanup state, initialize new tables, etc.
    ///
    /// Migrations should be idempotent for safety
    fn run_state_migrations(&self) -> Result<(), NodeStartupTaskError> {
        // Remove phantom orders in the order book
        let state = self.state.clone();
        tokio::task::spawn(async move {
            info!("removing phantom orders...");
            if let Err(e) = remove_phantom_orders(&state).await {
                error!("error removing phantom orders: {e}");
            } else {
                info!("done removing phantom orders");
            }
        });

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
        let descriptor = LookupWalletTaskDescriptor::new(
            wallet_id,
            blinder_seed,
            share_seed,
            keychain.secret_keys,
        )
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
        let descriptor = NewWalletTaskDescriptor::new(wallet, blinder_seed)
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
            wallet.key_chain.secret_keys.clone(),
        )
        .expect("infallible");

        // Enqueue the task and wait for the log entry to be persisted
        let (_id, waiter) = self.state.append_task(descriptor.into()).await?;
        waiter.await?;

        Ok(())
    }

    /// Setup the external match fee overrides for all tokens
    async fn setup_external_match_fees(&self) -> Result<(), NodeStartupTaskError> {
        let tokens: Vec<Token> = get_all_tokens()
            .into_iter()
            .chain(iter::once(Token::from_addr(NATIVE_ASSET_ADDRESS)))
            .collect();

        for token in tokens {
            // Fetch the fee override from the contract
            let addr = token.get_alloy_address();
            let fee = self.darkpool_client.get_external_match_fee(addr).await?;

            // Write the fee into the mapping
            let addr_bigint = token.get_addr_biguint();
            set_external_match_fee(&addr_bigint, fee);
        }

        Ok(())
    }
}
