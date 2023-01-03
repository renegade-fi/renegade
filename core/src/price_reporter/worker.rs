use crossbeam::channel::Receiver;
use std::thread::{self, JoinHandle};

use crate::{worker::Worker, CancelChannel};

use super::{
    errors::PriceReporterManagerError,
    jobs::PriceReporterManagerJob,
    manager::{PriceReporterManager, PriceReporterManagerExecutor},
};

/// The config passed from the coordinator to the PriceReporterManager
#[derive(Clone, Debug)]
pub struct PriceReporterManagerConfig {
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
        // Start the loop that dispatches incoming jobs to the executor
        let manager_executor = PriceReporterManagerExecutor::new()?;
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
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!();
    }
}
