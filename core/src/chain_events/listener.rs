//! Defines the core implementation of the on-chain event listener

use std::{str::FromStr, thread::JoinHandle, time::Duration};

use crossbeam::channel::Receiver;
use reqwest::Url;
use starknet::core::types::FieldElement;
use starknet_providers::jsonrpc::{
    models::{BlockId, EmittedEvent, ErrorCode, EventFilter},
    HttpTransport, JsonRpcClient, JsonRpcClientError, RpcError,
};
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
    /// The channel on which the coordinator may send a cancel signal
    pub cancel_channel: Receiver<()>,
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
#[derive(Debug)]
pub struct OnChainEventListenerExecutor {
    /// The JSON-RPC client used to connect to StarkNet
    rpc_client: JsonRpcClient<HttpTransport>,
    /// The earliest block that the client will poll events from
    start_block: u64,
    /// The event pagination token
    pagination_token: Option<String>,
    /// A copy of the config that the executor maintains
    config: OnChainEventListenerConfig,
}

impl OnChainEventListenerExecutor {
    /// Create a new executor
    pub fn new(config: OnChainEventListenerConfig) -> Self {
        let rpc_client = JsonRpcClient::new(HttpTransport::new(
            Url::parse(&config.starknet_api_gateway.clone().unwrap_or_default()).unwrap(),
        ));

        Self {
            rpc_client,
            config,
            start_block: 0,
            pagination_token: None,
        }
    }

    /// The main execution loop for the executor
    pub async fn execute(mut self) -> OnChainEventListenerError {
        // Get the current block number to start from
        let starting_block_number = self.get_block_number().await;
        if starting_block_number.is_err() {
            return starting_block_number.err().unwrap();
        }

        let starting_block_number = starting_block_number.unwrap();
        log::info!("Starting on-chain event listener with current block {starting_block_number}");
        self.start_block = starting_block_number;

        // Poll for new events in a loop
        loop {
            // Sleep for some time then re-poll events
            sleep_until(Instant::now() + Duration::from_millis(EVENTS_POLL_INTERVAL_MS)).await;
            if let Err(e) = self.poll_contract_events().await {
                log::error!("error polling events: {e}");
            };
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
            for event in events.iter() {
                log::info!("found event with keys: {:?}", event.keys);
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
            address: Some(FieldElement::from_str(&self.config.contract_address).unwrap()),
            keys: None,
        };

        let resp = self
            .rpc_client
            .get_events(filter, self.pagination_token.clone(), EVENT_CHUNK_SIZE)
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
            self.pagination_token = Some(pagination_token);
        } else {
            // If no explicit pagination token is given, increment the pagination token by the
            // number of events received. Ideally the API would do this, but it simply returns None
            // to indication no more pages are ready. We would like to persist this token across polls
            // to getEvents.
            let curr_token: usize = self
                .pagination_token
                .clone()
                .unwrap_or_else(|| "0".to_string())
                .parse()
                .unwrap();
            self.pagination_token = Some((curr_token + resp.events.len()).to_string());
        }

        let continue_paging = resp.continuation_token.is_some();
        Ok((resp.events, continue_paging))
    }
}
