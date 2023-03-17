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

use circuits::{
    types::wallet::Nullifier, zk_circuits::valid_commitments::ValidCommitmentsStatement,
    zk_gadgets::merkle::MerkleOpening,
};

use crossbeam::channel::Sender as CrossbeamSender;
use crypto::fields::{starknet_felt_to_biguint, starknet_felt_to_scalar, starknet_felt_to_u64};
use curve25519_dalek::scalar::Scalar;
use reqwest::Url;
use starknet::core::{types::FieldElement as StarknetFieldElement, utils::get_selector_from_name};
use starknet_providers::jsonrpc::{
    models::{BlockId, EmittedEvent, ErrorCode, EventFilter},
    HttpTransport, JsonRpcClient, JsonRpcClientError, RpcError,
};
use tokio::sync::{mpsc::UnboundedSender as TokioSender, oneshot};
use tokio::time::{sleep_until, Instant};
use tracing::log;

use crate::{
    gossip_api::{
        gossip::{GossipOutbound, PubsubMessage},
        orderbook_management::{OrderBookManagementMessage, ORDER_BOOK_TOPIC},
    },
    handshake::jobs::HandshakeExecutionJob,
    proof_generation::jobs::{ProofJob, ProofManagerJob, ValidCommitmentsBundle},
    state::{
        wallet::{MerkleAuthenticationPath, Wallet},
        MerkleTreeCoords, OrderIdentifier, RelayerState,
    },
    CancelChannel,
};

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
#[derive(Debug, Clone)]
pub struct OnChainEventListenerConfig {
    /// The starknet HTTP api url
    pub starknet_api_gateway: Option<String>,
    /// The infura API key to use for API access
    pub infura_api_key: Option<String>,
    /// The address of the Darkpool contract in the target network
    pub contract_address: String,
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
        self.starknet_api_gateway.is_some()
    }
}

/// The worker responsible for listening for on-chain events, translating them to jobs for
/// other workers, and forwarding these jobs to the relevant workers
#[derive(Debug)]
pub struct OnChainEventListener {
    /// The config passed to the listener at startup
    #[allow(unused)]
    pub(super) config: OnChainEventListenerConfig,
    /// The executor run in a separate thread
    pub(super) executor: Option<OnChainEventListenerExecutor>,
    /// The thread handle of the executor
    pub(super) executor_handle: Option<JoinHandle<OnChainEventListenerError>>,
}

// ------------
// | Executor |
// ------------

/// The executor that runs in a thread and polls events from on-chain state
#[derive(Clone, Debug)]
pub struct OnChainEventListenerExecutor {
    /// The JSON-RPC client used to connect to StarkNet
    rpc_client: Arc<JsonRpcClient<HttpTransport>>,
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
        let rpc_client = JsonRpcClient::new(HttpTransport::new(
            Url::parse(&config.starknet_api_gateway.clone().unwrap_or_default()).unwrap(),
        ));
        let global_state = config.global_state.clone();

        Self {
            rpc_client: Arc::new(rpc_client),
            config,
            start_block: 0,
            merkle_last_consistent_block: Arc::new(0.into()),
            pagination_token: Arc::new(0.into()),
            global_state,
        }
    }

    /// The main execution loop for the executor
    pub async fn execute(mut self) -> OnChainEventListenerError {
        // Get the current block number to start from
        let starting_block_number = self.get_block_number().await;
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

    /// Get the current StarkNet block number
    async fn get_block_number(&self) -> Result<u64, OnChainEventListenerError> {
        self.rpc_client
            .block_number()
            .await
            .map_err(|err| OnChainEventListenerError::Rpc(err.to_string()))
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
            to_block: None,
            address: Some(StarknetFieldElement::from_str(&self.config.contract_address).unwrap()),
            keys: None,
        };

        let pagination_token = self.pagination_token.load(Ordering::Relaxed).to_string();
        let resp = self
            .rpc_client
            .get_events(filter, Some(pagination_token), EVENT_CHUNK_SIZE)
            .await;

        // If the error is an unknown continuation token, ignore it and stop paging
        if let Err(JsonRpcClientError::RpcError(RpcError::Code(
            ErrorCode::InvalidContinuationToken,
        ))) = resp
        {
            return Ok((Vec::new(), false));
        }

        // Otherwise, propagate the error
        let resp = resp.map_err(|err| OnChainEventListenerError::Rpc(err.to_string()))?;

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
            if event.block_number <= last_consistent_block {
                return Ok(());
            }

            let block_number = BlockId::Number(event.block_number);
            self.handle_root_changed(block_number).await?;

            // Update the last consistent block
            self.merkle_last_consistent_block
                .store(event.block_number, Ordering::Relaxed);
        } else if key == *NULLIFIER_SPENT_EVENT_SELECTOR {
            // Parse the nullifier from the felt
            log::info!("Handling nullifier spent event");
            let match_nullifier = starknet_felt_to_scalar(&event.data[0]);
            self.handle_nullifier_spent(match_nullifier).await?;
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
            .send(HandshakeExecutionJob::MpcShootdown {
                match_nullifier: nullifier,
            })
            .map_err(|err| OnChainEventListenerError::SendMessage(err.to_string()))?;

        // Nullify any orders that used this nullifier in their validity proof
        self.config.global_state.nullify_orders(nullifier).await;

        Ok(())
    }

    /// Handle a root change event
    async fn handle_root_changed(
        &self,
        block_number: BlockId,
    ) -> Result<(), OnChainEventListenerError> {
        // Fetch all the internal node changed events in this block
        let contract_addr = StarknetFieldElement::from_str(&self.config.contract_address).unwrap();
        let filter = EventFilter {
            from_block: Some(block_number.clone()),
            to_block: None,
            address: Some(contract_addr),
            keys: Some(vec![*MERKLE_NODE_CHANGED_EVENT_SELECTOR]),
        };

        // Maps updated tree coordinates to their new values
        let mut node_change_events = HashMap::new();
        let mut pagination_token = Some("0".to_string());

        while pagination_token.is_some() {
            // Fetch the next page of events
            let events_batch = self
                .rpc_client
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

        // Generate new witness and statement variables from the freshly synced state
        let merkle_proof = wallet.merkle_proof.clone().unwrap();
        let new_root = merkle_proof.compute_root();
        let new_opening: MerkleOpening = wallet.merkle_proof.clone().unwrap().into();
        let wallet_match_nullifier = wallet.get_match_nullifier();

        // Loop over orders and enqueue a proof generation job for each
        let locked_order_book = self.global_state.read_order_book().await;
        let mut proof_response_channels = HashMap::new();
        for order_id in wallet.orders.keys() {
            let stale_witness = locked_order_book.get_validity_proof_witness(order_id).await;
            if stale_witness.is_none() {
                log::error!("tried to update VALID COMMITMENTS for order without existing witness");
                return Ok(());
            }
            let mut stale_witness = stale_witness.unwrap();

            stale_witness.wallet_opening = new_opening.clone();

            // Enqueue a job with the proof manager
            let (response_sender, response_receiver) = oneshot::channel();
            let job = ProofJob::ValidCommitments {
                witness: stale_witness,
                statement: ValidCommitmentsStatement {
                    nullifier: wallet_match_nullifier,
                    merkle_root: new_root,
                    pk_settle: wallet.public_keys.pk_settle,
                },
            };

            self.config
                .proof_generation_work_queue
                .send(ProofManagerJob {
                    type_: job,
                    response_channel: response_sender,
                })
                .map_err(|err| OnChainEventListenerError::SendMessage(err.to_string()))?;

            proof_response_channels.insert(order_id, response_receiver);
        }
        drop(locked_order_book); // release lock

        // Await proof responses for all orders
        // TODO: Gossip the new proof to all cluster peers
        for (order_id, channel) in proof_response_channels.into_iter() {
            let proof = channel
                .await
                .map_err(|err| OnChainEventListenerError::ProofGeneration(err.to_string()))?;

            self.update_order_proof(*order_id, proof.into()).await?;
        }

        Ok(())
    }

    /// Update the order validity proof in the global state and gossip
    /// the new proof to the cluster
    async fn update_order_proof(
        &self,
        order_id: OrderIdentifier,
        proof: ValidCommitmentsBundle,
    ) -> Result<(), OnChainEventListenerError> {
        // Update the locally stored proof
        self.global_state
            .add_order_validity_proof(&order_id, proof.clone())
            .await;

        // Gossip the new validity proof onto the pubsub mesh
        let cluster = self.global_state.local_cluster_id.clone();
        let message = OrderBookManagementMessage::OrderProofUpdated {
            order_id,
            cluster,
            proof,
        };

        self.config
            .network_manager_work_queue
            .send(GossipOutbound::Pubsub {
                topic: ORDER_BOOK_TOPIC.to_string(),
                message: PubsubMessage::OrderBookManagement(message),
            })
            .map_err(|err| OnChainEventListenerError::SendMessage(err.to_string()))
    }
}
