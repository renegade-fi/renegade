//! Defines the core implementation of the on-chain event listener

use std::{thread::JoinHandle, time::Duration};

use crossbeam::channel::Receiver;
use reqwest::Url;
use starknet_providers::jsonrpc::{HttpTransport, JsonRpcClient};
use tokio::time::{sleep_until, Instant};
use tracing::log;

use super::error::OnChainEventListenerError;

// -------------
// | Constants |
// -------------

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
    /// A copy of the config that the executor maintains
    config: OnChainEventListenerConfig,
}

impl OnChainEventListenerExecutor {
    /// Create a new executor
    pub fn new(config: OnChainEventListenerConfig) -> Self {
        let rpc_client = JsonRpcClient::new(HttpTransport::new(
            Url::parse(&config.starknet_api_gateway.clone().unwrap_or_default()).unwrap(),
        ));

        Self { rpc_client, config }
    }

    /// The main execution loop for the executor
    pub async fn execute(self) -> OnChainEventListenerError {
        // Get the current block number to start from
        let starting_block_number = self.get_block_number().await;
        if starting_block_number.is_err() {
            return starting_block_number.err().unwrap();
        }

        let starting_block_number = starting_block_number.unwrap();
        log::info!("Starting on-chain event listener with current block {starting_block_number}");

        // Poll for new events in a loop
        loop {
            // Sleep for some time then re-poll events
            sleep_until(Instant::now() + Duration::from_millis(EVENTS_POLL_INTERVAL_MS)).await;
            self.poll_contract_events().await;
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
    async fn poll_contract_events(&self) {
        log::info!("polling for events...");
    }
}
