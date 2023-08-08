//! Defines the core implementation of the on-chain event listener

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::Duration,
};

use circuit_types::wallet::Nullifier;

use common::types::{
    merkle::{MerkleAuthenticationPath, MerkleTreeCoords},
    wallet::Wallet,
    CancelChannel,
};
use crossbeam::channel::Sender as CrossbeamSender;
use gossip_api::gossip::GossipOutbound;
use job_types::{handshake_manager::HandshakeExecutionJob, proof_manager::ProofManagerJob};
use lazy_static::lazy_static;
use mpc_stark::algebra::scalar::Scalar;
use renegade_crypto::fields::{
    starknet_felt_to_biguint, starknet_felt_to_scalar, starknet_felt_to_u64,
};
use starknet::{
    core::{
        types::{
            BlockId, BlockTag, EmittedEvent, EventFilter, FieldElement as StarknetFieldElement,
            StarknetError,
        },
        utils::get_selector_from_name,
    },
    providers::{
        jsonrpc::{HttpTransport, JsonRpcClient},
        MaybeUnknownErrorCode, Provider, ProviderError, StarknetErrorWithMessage,
    },
};
use starknet_client::client::StarknetClient;
use state::RelayerState;
use tokio::sync::mpsc::UnboundedSender as TokioSender;
use tokio::time::{sleep_until, Instant};
use tracing::log;

use super::error::OnChainEventListenerError;

// -------------
// | Constants |
// -------------

/// The chunk size to request paginated events in
const EVENT_CHUNK_SIZE: u64 = 100;
/// The interval at which the worker should poll for new contract events
const EVENTS_POLL_INTERVAL_MS: u64 = 5_000; // 5 seconds

lazy_static! {
    /// The event selector for a Merkle root update
    static ref MERKLE_ROOT_CHANGED_EVENT_SELECTOR: StarknetFieldElement = get_selector_from_name("Merkle_root_changed").unwrap();
    /// The event selector for a Merkle internal node change
    static ref MERKLE_NODE_CHANGED_EVENT_SELECTOR: StarknetFieldElement = get_selector_from_name("Merkle_internal_node_changed").unwrap();
    /// The event selector for a nullifier spend
    static ref NULLIFIER_SPENT_EVENT_SELECTOR: StarknetFieldElement = get_selector_from_name("Nullifier_spent").unwrap();
}

// ----------
// | Worker |
// ----------

/// The configuration passed to the listener upon startup
#[derive(Clone)]
pub struct OnChainEventListenerConfig {
    /// A client for connecting to Starknet gateway and jsonrpc nodes
    pub starknet_client: StarknetClient,
    /// A copy of the relayer global state
    pub global_state: RelayerState,
    /// A sender to the handshake manager's job queue, used to enqueue
    /// MPC shootdown jobs
    pub handshake_manager_job_queue: TokioSender<HandshakeExecutionJob>,
    /// The worker job queue for the ProofGenerationManager
    pub proof_generation_work_queue: CrossbeamSender<ProofManagerJob>,
    /// The work queue for the network manager, used to send outbound gossip messages
    pub network_manager_work_queue: TokioSender<GossipOutbound>,
    /// The channel on which the coordinator may send a cancel signal
    pub cancel_channel: CancelChannel,
}

impl OnChainEventListenerConfig {
    /// Determines whether the parameters needed to enable the on-chain event
    /// listener are present. If not the worker should not startup
    pub fn enabled(&self) -> bool {
        self.starknet_client.jsonrpc_enabled()
    }
}

/// The worker responsible for listening for on-chain events, translating them to jobs for
/// other workers, and forwarding these jobs to the relevant workers
pub struct OnChainEventListener {
    /// The executor run in a separate thread
    pub(super) executor: Option<OnChainEventListenerExecutor>,
    /// The thread handle of the executor
    pub(super) executor_handle: Option<JoinHandle<OnChainEventListenerError>>,
}

// ------------
// | Executor |
// ------------

/// The executor that runs in a thread and polls events from on-chain state
#[derive(Clone)]
pub struct OnChainEventListenerExecutor {
    /// The earliest block that the client will poll events from
    start_block: u64,
    /// The latest block for which the local node has updated Merkle state
    merkle_last_consistent_block: Arc<AtomicU64>,
    /// The event pagination token
    pagination_token: Arc<AtomicU64>,
    /// A copy of the config that the executor maintains
    config: OnChainEventListenerConfig,
    /// A copy of the relayer-global state
    global_state: RelayerState,
}

impl OnChainEventListenerExecutor {
    /// Create a new executor
    pub fn new(config: OnChainEventListenerConfig) -> Self {
        let global_state = config.global_state.clone();

        Self {
            config,
            start_block: 0,
            merkle_last_consistent_block: Arc::new(0.into()),
            pagination_token: Arc::new(0.into()),
            global_state,
        }
    }

    /// Shorthand for fetching a reference to the starknet client
    fn starknet_client(&self) -> &StarknetClient {
        &self.config.starknet_client
    }

    /// Helper to fetch the RPC client in the executor's config
    fn rpc_client(&self) -> &JsonRpcClient<HttpTransport> {
        self.config.starknet_client.get_jsonrpc_client()
    }

    /// Helper to get the contract address from the underlying client
    fn contract_address(&self) -> StarknetFieldElement {
        self.config.starknet_client.contract_address
    }

    /// The main execution loop for the executor
    pub async fn execute(mut self) -> OnChainEventListenerError {
        // Get the current block number to start from
        let starting_block_number = self
            .starknet_client()
            .get_block_number()
            .await
            .map_err(|err| OnChainEventListenerError::StarknetClient(err.to_string()));
        if starting_block_number.is_err() {
            return starting_block_number.err().unwrap();
        }

        self.start_block = starting_block_number.unwrap();
        self.merkle_last_consistent_block
            .store(self.start_block, Ordering::Relaxed);
        log::info!(
            "Starting on-chain event listener with current block {}",
            self.start_block
        );

        // Poll for new events in a loop
        loop {
            // Sleep for some time then re-poll events
            sleep_until(Instant::now() + Duration::from_millis(EVENTS_POLL_INTERVAL_MS)).await;
            let mut self_clone = self.clone();
            tokio::spawn(async move {
                if let Err(e) = self_clone.poll_contract_events().await {
                    log::error!("error polling events: {e}");
                };
            });
        }
    }

    /// Poll for new contract events
    async fn poll_contract_events(&mut self) -> Result<(), OnChainEventListenerError> {
        log::debug!("polling for events...");
        loop {
            let (events, more_pages) = self.fetch_next_events_page().await?;
            for event in events.into_iter() {
                self.handle_event(event).await?;
            }

            if !more_pages {
                break;
            }
        }

        Ok(())
    }

    /// Fetch the next page of events from the contract
    ///
    /// Returns the events in the next page and a boolean indicating whether
    /// the caller should continue paging
    async fn fetch_next_events_page(
        &mut self,
    ) -> Result<(Vec<EmittedEvent>, bool), OnChainEventListenerError> {
        let filter = EventFilter {
            from_block: Some(BlockId::Number(self.start_block)),
            to_block: Some(BlockId::Tag(BlockTag::Pending)),
            address: Some(self.contract_address()),
            keys: Some(vec![vec![
                *MERKLE_ROOT_CHANGED_EVENT_SELECTOR,
                *MERKLE_NODE_CHANGED_EVENT_SELECTOR,
                *NULLIFIER_SPENT_EVENT_SELECTOR,
            ]]),
        };

        let pagination_token = self.pagination_token.load(Ordering::Relaxed).to_string();
        let resp = self
            .rpc_client()
            .get_events(filter, Some(pagination_token), EVENT_CHUNK_SIZE)
            .await;

        let resp = match resp {
            Ok(events_page) => Ok(events_page),
            // If the error is an unknown continuation token, ignore it and stop paging
            Err(ProviderError::StarknetError(StarknetErrorWithMessage { code, message })) => {
                if let MaybeUnknownErrorCode::Known(StarknetError::InvalidContinuationToken) = code
                {
                    return Ok((Vec::new(), false));
                };

                Err(OnChainEventListenerError::Rpc(message))
            }

            // Otherwise propagate the error
            Err(err) => Err(OnChainEventListenerError::Rpc(err.to_string())),
        }?;

        // Update the executor held continuation token used across calls to `getEvents`
        if let Some(pagination_token) = resp.continuation_token.clone() {
            let parsed_token = u64::from_str(&pagination_token).unwrap();
            self.pagination_token.store(parsed_token, Ordering::Relaxed);
        } else {
            // If no explicit pagination token is given, increment the pagination token by the
            // number of events received. Ideally the API would do this, but it simply returns None
            // to indicate no more pages are ready. We would like to persist this token across polls
            // to getEvents.
            self.pagination_token
                .fetch_add(resp.events.len() as u64, Ordering::Relaxed);
        }

        let continue_paging = resp.continuation_token.is_some();
        Ok((resp.events, continue_paging))
    }

    /// Handle an event from the contract
    async fn handle_event(&self, event: EmittedEvent) -> Result<(), OnChainEventListenerError> {
        // Dispatch based on key
        let key = event.keys[0];
        if key == *MERKLE_ROOT_CHANGED_EVENT_SELECTOR {
            log::info!("Handling merkle root update event");

            // Skip this event if all Merkle events for this block have been consumed
            let last_consistent_block = self.merkle_last_consistent_block.load(Ordering::Relaxed);
            let event_block = event.block_number.unwrap_or(last_consistent_block);
            if event_block <= last_consistent_block {
                return Ok(());
            }

            self.handle_root_changed(event_block).await?;

            // Update the last consistent block
            self.merkle_last_consistent_block
                .store(event_block, Ordering::Relaxed);
        } else if key == *NULLIFIER_SPENT_EVENT_SELECTOR {
            // Parse the nullifier from the felt
            log::info!("Handling nullifier spent event");
            let nullifier = starknet_felt_to_scalar(&event.data[0]);
            self.handle_nullifier_spent(nullifier).await?;
        }

        Ok(())
    }

    /// Handle a nullifier spent event
    async fn handle_nullifier_spent(
        &self,
        nullifier: Nullifier,
    ) -> Result<(), OnChainEventListenerError> {
        // Send an MPC shootdown request to the handshake manager
        self.config
            .handshake_manager_job_queue
            .send(HandshakeExecutionJob::MpcShootdown { nullifier })
            .map_err(|err| OnChainEventListenerError::SendMessage(err.to_string()))?;

        // Nullify any orders that used this nullifier in their validity proof
        self.config.global_state.nullify_orders(nullifier).await;

        Ok(())
    }

    /// Handle a root change event
    async fn handle_root_changed(
        &self,
        block_number: u64,
    ) -> Result<(), OnChainEventListenerError> {
        // Fetch all the internal node changed events in this block
        let filter = EventFilter {
            from_block: Some(BlockId::Number(block_number)),
            to_block: Some(BlockId::Number(block_number + 1)),
            address: Some(self.contract_address()),
            keys: Some(vec![vec![*MERKLE_NODE_CHANGED_EVENT_SELECTOR]]),
        };

        // Maps updated tree coordinates to their new values
        let mut node_change_events = HashMap::new();
        let mut pagination_token = Some("0".to_string());

        while pagination_token.is_some() {
            // Fetch the next page of events
            let events_batch = self
                .rpc_client()
                .get_events(filter.clone(), pagination_token, 100 /* chunk_size */)
                .await
                .map_err(|err| OnChainEventListenerError::Rpc(err.to_string()))?;

            for event in events_batch.events.into_iter() {
                // Build tree coordinate from event
                let height: usize = starknet_felt_to_u64(&event.data[0]) as usize;
                let index = starknet_felt_to_biguint(&event.data[1]);
                let tree_coordinate = MerkleTreeCoords::new(height, index);

                // Add the value to the list of changes
                // The events stream comes in transaction order, so the most recent value of each
                // internal node in the block will overwrite older values and be the final value stored
                let new_value = starknet_felt_to_scalar(&event.data[2]);
                node_change_events.insert(tree_coordinate, new_value);
            }

            pagination_token = events_batch.continuation_token;
        }

        // Lock the wallet state and apply them one by one to the wallet Merkle paths
        let locked_wallet_index = self.global_state.read_wallet_index().await;
        for wallet_id in locked_wallet_index.get_all_wallet_ids() {
            // Merge in the map of updated nodes into the wallet's merkle proof
            let mut locked_wallet = locked_wallet_index.write_wallet(&wallet_id).await.unwrap();
            if locked_wallet.merkle_proof.is_none() {
                continue;
            }

            // Increment the staleness counter; tracks the number of roots since the orders in this wallet
            // had `VALID COMMITMENTS` proven
            locked_wallet
                .proof_staleness
                .fetch_add(1u32, Ordering::Relaxed);

            self.update_wallet_merkle_path(
                locked_wallet.merkle_proof.as_mut().unwrap(),
                &node_change_events,
            );

            // Check if the wallet needs a new commitment proof
            if locked_wallet.needs_new_commitment_proof() {
                // Clone out of the wallet lock so that the lock may be dropped
                let self_clone = self.clone();
                let wallet_clone = locked_wallet.clone();

                tokio::spawn(async move {
                    if let Err(e) = self_clone
                        .update_wallet_commitment_proofs(wallet_clone)
                        .await
                    {
                        log::error!("error updating wallet commitment proofs: {e}");
                    }
                });
            }
        }

        Ok(())
    }

    /// A helper to update the Merkle path of a wallet given the Merkle internal nodes
    /// that have changed
    fn update_wallet_merkle_path(
        &self,
        merkle_proof: &mut MerkleAuthenticationPath,
        updated_nodes: &HashMap<MerkleTreeCoords, Scalar>,
    ) {
        for (i, coord) in merkle_proof
            .compute_authentication_path_coords()
            .iter()
            .enumerate()
        {
            if let Some(updated_value) = updated_nodes.get(coord) {
                merkle_proof.path_siblings[i] = *updated_value;
            }
        }
    }

    /// Generate a new commitment proof for a wallet's orders on a fresh Merkle state
    async fn update_wallet_commitment_proofs(
        &self,
        wallet: Wallet,
    ) -> Result<(), OnChainEventListenerError> {
        // Calling this function on a wallet without a Merkle proof should not happen, but we do
        // not fail the worker in the case that it does
        if wallet.merkle_proof.is_none() {
            log::error!("tried to update VALID COMMITMENTS for a wallet that has no Merkle authentication path");
            return Ok(());
        }

        unimplemented!("Implement wallet commitment proof task in encryption redesign")
    }
}
