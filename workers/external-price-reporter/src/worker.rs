//! Defines the Worker logic for the ExtenalPriceReporterManager, which simply
//! dispatches jobs to the ExternalPriceReporterExecutor.

use std::thread::{Builder as ThreadBuilder, JoinHandle};

use common::{
    default_wrapper::DefaultOption,
    types::{exchange::Exchange, CancelChannel},
    worker::Worker,
};
use external_api::bus_message::SystemBusMessage;
use job_types::price_reporter::PriceReporterReceiver;
use system_bus::SystemBus;
use tokio::runtime::Builder as TokioBuilder;
use util::err_str;

use crate::{
    errors::ExternalPriceReporterError,
    manager::{ExternalPriceReporter, ExternalPriceReporterExecutor},
};

/// The number of threads backing the external price reporter manager
const EXTERNAL_PRICE_REPORTER_MANAGER_NUM_THREADS: usize = 2;

/// The config passed from the coordinator to the ExternalPriceReporter
#[derive(Clone, Debug)]
pub struct ExternalPriceReporterConfig {
    /// The global system bus
    pub system_bus: SystemBus<SystemBusMessage>,
    /// The receiver for jobs from other workers
    pub job_receiver: DefaultOption<PriceReporterReceiver>,
    /// The WS URL of the external price reporter service
    pub price_reporter_url: String,
    /// Whether or not the worker is disabled
    pub disabled: bool,
    /// Exchanges that are explicitly disabled for price reporting
    pub disabled_exchanges: Vec<Exchange>,
    /// The channel on which the coordinator may mandate that the price reporter
    /// manager cancel its execution
    pub cancel_channel: CancelChannel,
}

impl Worker for ExternalPriceReporter {
    type WorkerConfig = ExternalPriceReporterConfig;
    type Error = ExternalPriceReporterError;

    fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error> {
        Ok(Self { config, manager_executor_handle: None })
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn name(&self) -> String {
        "external-price-reporter-manager-main".to_string()
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.manager_executor_handle.take().unwrap()]
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Start the loop that dispatches incoming jobs to the executor
        let manager_executor = ExternalPriceReporterExecutor::new(
            self.config.job_receiver.take().unwrap(),
            self.config.clone(),
            self.config.cancel_channel.clone(),
        );

        let manager_executor_handle = {
            ThreadBuilder::new()
                .name("external-price-reporter-manager-executor".to_string())
                .spawn(move || {
                    // Build a tokio runtime to drive the price reporter
                    let runtime = TokioBuilder::new_multi_thread()
                        .worker_threads(EXTERNAL_PRICE_REPORTER_MANAGER_NUM_THREADS)
                        .enable_all()
                        .build()
                        .unwrap();

                    runtime.block_on(manager_executor.execution_loop()).err().unwrap()
                })
                .map_err(err_str!(ExternalPriceReporterError::ManagerSetup))
        }?;

        self.manager_executor_handle = Some(manager_executor_handle);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}
