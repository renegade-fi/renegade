//! Defines the Worker logic for the PriceReporterManger, which simply
//! dispatches jobs to the PriceReporterExecutor.

use async_trait::async_trait;
use common::{
    default_wrapper::DefaultOption,
    types::{exchange::Exchange, CancelChannel},
    worker::Worker,
};
use external_api::bus_message::SystemBusMessage;
use job_types::price_reporter::PriceReporterReceiver;
use std::thread::{self, JoinHandle};
use system_bus::SystemBus;
use tokio::runtime::Builder as TokioBuilder;
use url::Url;

use crate::manager::external_executor::ExternalPriceReporterExecutor;

use super::{
    errors::PriceReporterError,
    manager::{native_executor::PriceReporterExecutor, PriceReporter},
};

/// The number of threads backing the price reporter manager
const PRICE_REPORTER_MANAGER_NUM_THREADS: usize = 2;

/// The config passed from the coordinator to the PriceReporter
#[derive(Clone, Debug)]
pub struct PriceReporterConfig {
    /// The global system bus
    pub system_bus: SystemBus<SystemBusMessage>,
    /// The receiver for jobs from other workers
    pub job_receiver: DefaultOption<PriceReporterReceiver>,
    /// Exchange connection config options
    pub exchange_conn_config: ExchangeConnectionsConfig,
    /// The URL of an external price reporter service
    pub price_reporter_url: Option<Url>,
    /// Whether or not the worker is disabled
    pub disabled: bool,
    /// Exchanges that are explicitly disabled for price reporting
    pub disabled_exchanges: Vec<Exchange>,
    /// The channel on which the coordinator may mandate that the price reporter
    /// manager cancel its execution
    pub cancel_channel: CancelChannel,
}

/// The configuration options that may be used by exchange connections
#[derive(Clone, Debug, Default)]
pub struct ExchangeConnectionsConfig {
    /// The coinbase API key that the price reporter may use
    pub coinbase_key_name: Option<String>,
    /// The coinbase API secret that the price reporter may use
    pub coinbase_key_secret: Option<String>,
    /// The ethereum RPC node websocket addresses for on-chain data
    pub eth_websocket_addr: Option<String>,
}

impl ExchangeConnectionsConfig {
    /// Whether or not the Coinbase connection is configured
    pub fn coinbase_configured(&self) -> bool {
        self.coinbase_key_name.is_some() && self.coinbase_key_secret.is_some()
    }

    /// Whether or not the Uniswap V3 connection is configured
    pub fn uniswap_v3_configured(&self) -> bool {
        self.eth_websocket_addr.is_some()
    }
}

impl PriceReporterConfig {
    /// Returns true if the necessary configuration information is present
    /// for a given exchange
    ///
    /// For example; we do not connect to Coinbase if a Coinbase API key
    /// and secret is not provided
    pub(crate) fn exchange_configured(&self, exchange: Exchange) -> bool {
        let disabled = self.disabled_exchanges.contains(&exchange);

        let configured = if self.price_reporter_url.is_some() {
            // If we are using the external price reporter, we assume all exchanges are
            // configured
            true
        } else {
            match exchange {
                Exchange::Coinbase => self.exchange_conn_config.coinbase_configured(),
                Exchange::UniswapV3 => self.exchange_conn_config.uniswap_v3_configured(),
                _ => true,
            }
        };

        !disabled && configured
    }
}

#[async_trait]
impl Worker for PriceReporter {
    type WorkerConfig = PriceReporterConfig;
    type Error = PriceReporterError;

    async fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        Ok(Self { config, manager_executor_handle: None })
    }

    fn is_recoverable(&self) -> bool {
        // Recovery for each PriceReporter is implemented via Error propagation; all
        // panics in the PriceReporter are unrecoverable
        false
    }

    fn name(&self) -> String {
        "price-reporter-manager-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.manager_executor_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Start the loop that dispatches incoming jobs to the executor
        let job_receiver = self.config.job_receiver.take().unwrap();
        let cancel_channel = self.config.cancel_channel.clone();
        let config = self.config.clone();

        // Build a tokio runtime to drive the price reporter
        let runtime = TokioBuilder::new_multi_thread()
            .worker_threads(PRICE_REPORTER_MANAGER_NUM_THREADS)
            .enable_all()
            .build()
            .unwrap();

        let manager_executor_handle = if self.config.price_reporter_url.is_some() {
            let manager_executor =
                ExternalPriceReporterExecutor::new(job_receiver, config, cancel_channel);

            thread::Builder::new()
                .name("price-reporter-manager-executor".to_string())
                .spawn(move || runtime.block_on(manager_executor.execution_loop()).err().unwrap())
                .map_err(|err| PriceReporterError::ManagerSetup(err.to_string()))
        } else {
            let manager_executor = PriceReporterExecutor::new(job_receiver, config, cancel_channel);

            thread::Builder::new()
                .name("price-reporter-manager-executor".to_string())
                .spawn(move || runtime.block_on(manager_executor.execution_loop()).err().unwrap())
                .map_err(|err| PriceReporterError::ManagerSetup(err.to_string()))
        }?;

        self.manager_executor_handle = Some(manager_executor_handle);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!();
    }
}
