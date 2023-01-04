use crossbeam::channel::Receiver;
use std::thread::{self, JoinHandle};
use tokio::runtime::Builder as TokioBuilder;

use crate::{system_bus::SystemBus, types::SystemBusMessage, worker::Worker, CancelChannel};

use super::{
    errors::PriceReporterManagerError,
    jobs::PriceReporterManagerJob,
    manager::{PriceReporterManager, PriceReporterManagerExecutor},
};

/// The number of threads backing the price reporter manager
// This should not be substantially decreased, as the threads may deadlock upon waiting for raw
// ExchangeConnections
const PRICE_REPORTER_MANAGER_NUM_THREADS: usize = 32;

/// The config passed from the coordinator to the PriceReporterManager
#[derive(Clone, Debug)]
pub struct PriceReporterManagerConfig {
    /// The global system bus
    pub(crate) system_bus: SystemBus<SystemBusMessage>,
    /// The receiver for jobs from other workers
    pub(crate) job_receiver: Receiver<PriceReporterManagerJob>,
    /// The channel on which the coordinator may mandate that the price reporter manager cancel its
    /// execution
    pub(crate) cancel_channel: CancelChannel,
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
        let tokio_handle = tokio_runtime.handle().clone();
        let mut manager_executor =
            PriceReporterManagerExecutor::new(self.config.system_bus.clone(), tokio_handle)?;
        let config = self.config.clone();
        let manager_executor_handle = {
            thread::Builder::new()
                .name("price-reporter-manager-executor".to_string())
                .spawn(move || loop {
                    // Check for cancel before sleeping
                    if !config.cancel_channel.is_empty() {
                        return PriceReporterManagerError::Cancelled(
                            "received cancel signal".to_string(),
                        );
                    }
                    // Dequeue the next job
                    let job = config.job_receiver.recv().expect("recv should not panic");
                    // Check for cancel after receiving job
                    if !config.cancel_channel.is_empty() {
                        return PriceReporterManagerError::Cancelled(
                            "received cancel signal".to_string(),
                        );
                    }
                    // Send the job to the executor
                    let execution_result = manager_executor.handle_job(job);
                    if let Err(manager_error) = execution_result {
                        println!(
                            "Error in PriceReporterManager execution loop: {}",
                            manager_error
                        );
                        return manager_error;
                    }
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
