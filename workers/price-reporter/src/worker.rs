//! Defines the Worker logic for the PriceReporterManger, which simply dispatches jobs to the
//! PriceReporterManagerExecutor.
use common::{
    default_wrapper::DefaultWrapper,
    types::{exchange::Exchange, CancelChannel},
    worker::Worker,
};
use external_api::bus_message::SystemBusMessage;
use job_types::price_reporter::PriceReporterManagerJob;
use std::thread::{self, JoinHandle};
use system_bus::SystemBus;
use tokio::{runtime::Builder as TokioBuilder, sync::mpsc::UnboundedReceiver as TokioReceiver};

use super::{
    errors::PriceReporterManagerError,
    manager::{PriceReporterManager, PriceReporterManagerExecutor},
};

/// The number of threads backing the price reporter manager
const PRICE_REPORTER_MANAGER_NUM_THREADS: usize = 2;

/// The config passed from the coordinator to the PriceReporterManager
#[derive(Clone, Debug)]
pub struct PriceReporterManagerConfig {
    /// The global system bus
    pub system_bus: SystemBus<SystemBusMessage>,
    /// The receiver for jobs from other workers
    pub job_receiver: DefaultWrapper<Option<TokioReceiver<PriceReporterManagerJob>>>,
    /// The coinbase API key that the price reporter may use
    pub coinbase_api_key: Option<String>,
    /// The coinbase API secret that the price reporter may use
    pub coinbase_api_secret: Option<String>,
    /// The ethereum RPC node websocket addresses for on-chain data
    pub eth_websocket_addr: Option<String>,
    /// Whether or not the worker is disabled
    pub disabled: bool,
    /// Whether or not to disable binance streaming
    ///
    /// Used in locations that Binance has IP blocked
    pub disable_binance: bool,
    /// The channel on which the coordinator may mandate that the price reporter manager cancel its
    /// execution
    pub cancel_channel: CancelChannel,
}

impl PriceReporterManagerConfig {
    /// Returns true if the necessary configuration information is present
    /// for a given exchange
    ///
    /// For example; we do not connect to Coinbase if a Coinbase API key
    /// and secret is not provided
    pub(crate) fn exchange_configured(&self, exchange: Exchange) -> bool {
        match exchange {
            Exchange::Coinbase => {
                self.coinbase_api_key.is_some() && self.coinbase_api_secret.is_some()
            }
            Exchange::UniswapV3 => self.eth_websocket_addr.is_some(),
            _ => true,
        }
    }
}

impl Worker for PriceReporterManager {
    type WorkerConfig = PriceReporterManagerConfig;
    type Error = PriceReporterManagerError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        Ok(Self {
            config,
            manager_executor_handle: None,
            manager_runtime: None,
        })
    }

    fn is_recoverable(&self) -> bool {
        // Recovery for each PriceReporter is implemented via Error propagation; all panics in the
        // PriceReporterManager are unrecoverable
        false
    }

    fn name(&self) -> String {
        "price-reporter-manager-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.manager_executor_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Spawn a tokio thread pool to run the manager in
        let tokio_runtime = TokioBuilder::new_multi_thread()
            .worker_threads(PRICE_REPORTER_MANAGER_NUM_THREADS)
            .enable_io()
            .enable_time()
            .build()
            .map_err(|err| PriceReporterManagerError::ManagerSetup(err.to_string()))?;

        // Start the loop that dispatches incoming jobs to the executor
        let manager_executor = PriceReporterManagerExecutor::new(
            self.config.job_receiver.take().unwrap(),
            self.config.clone(),
            self.config.cancel_channel.clone(),
        );

        let manager_executor_handle = {
            thread::Builder::new()
                .name("price-reporter-manager-executor".to_string())
                .spawn(move || {
                    // Build a tokio runtime to drive the price reporter
                    let runtime = TokioBuilder::new_multi_thread()
                        .worker_threads(PRICE_REPORTER_MANAGER_NUM_THREADS)
                        .enable_all()
                        .build()
                        .unwrap();

                    runtime
                        .block_on(manager_executor.execution_loop())
                        .err()
                        .unwrap()
                })
                .map_err(|err| PriceReporterManagerError::ManagerSetup(err.to_string()))
        }?;

        self.manager_executor_handle = Some(manager_executor_handle);
        self.manager_runtime = Some(tokio_runtime);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!();
    }
}
