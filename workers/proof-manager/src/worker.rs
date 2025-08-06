//! Defines the main threading model of the proof generation module as a worker
//! that can be scheduled by the coordinator thread

use std::thread::{Builder, JoinHandle};

use async_trait::async_trait;
use common::{default_wrapper::DefaultOption, types::CancelChannel, worker::Worker};
use job_types::proof_manager::ProofManagerReceiver;
use reqwest::Url;

use crate::implementations::native_proof_manager::NativeProofManager;

use super::error::ProofManagerError;

/// The name of the main worker thread
const MAIN_THREAD_NAME: &str = "proof-generation-main";

// ----------
// | Config |
// ----------

/// The configuration of the manager, used to hold work queues and tunables
#[derive(Clone, Debug)]
pub struct ProofManagerConfig {
    /// The URL of the prover service to use
    ///
    /// If not configured, the relayer will generate all proofs itself
    pub prover_service_url: Option<Url>,
    /// The password for the prover service
    pub prover_service_password: Option<String>,
    /// The job queue on which the manager may receive proof generation jobs
    pub job_queue: ProofManagerReceiver,
    /// The cancel channel that the coordinator uses to signal to the proof
    /// generation module that it should shut down
    pub cancel_channel: CancelChannel,
}

impl ProofManagerConfig {
    /// Whether to use the external prover service
    pub fn use_external_prover(&self) -> bool {
        self.prover_service_url.is_some()
    }
}

// -----------------
// | Proof Manager |
// -----------------

/// The proof manager provides a messaging interface and implementation for
/// proving statements related to system state transitions
#[derive(Debug, Clone)]
pub struct ProofManager {
    /// The config of the proof manager
    pub(crate) config: ProofManagerConfig,
    /// The handle of the main driver thread in the proof generation module
    join_handle: DefaultOption<JoinHandle<ProofManagerError>>,
}

#[async_trait]
impl Worker for ProofManager {
    type WorkerConfig = ProofManagerConfig;
    type Error = ProofManagerError;

    async fn new(config: Self::WorkerConfig) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        Ok(Self { config, join_handle: DefaultOption::default() })
    }

    fn name(&self) -> String {
        "proof-generation".to_string()
    }

    fn is_recoverable(&self) -> bool {
        false
    }

    fn start(&mut self) -> Result<(), Self::Error> {
        // Take ownership of the thread pool and job queue
        let handle = if self.config.use_external_prover() {
            self.start_external_proof_manager()?
        } else {
            self.start_native_proof_manager()?
        };

        self.join_handle.replace(handle);
        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Self::Error> {
        unimplemented!("")
    }

    fn join(&mut self) -> Vec<JoinHandle<Self::Error>> {
        vec![self.join_handle.take().unwrap()]
    }
}

impl ProofManager {
    /// Start a native proof manager
    fn start_native_proof_manager(
        &self,
    ) -> Result<JoinHandle<ProofManagerError>, ProofManagerError> {
        let manager = NativeProofManager::new(self.config.clone())?;
        let handle = Builder::new()
            .name(MAIN_THREAD_NAME.to_string())
            .spawn(move || manager.run().err().unwrap())
            .map_err(|err| ProofManagerError::Setup(err.to_string()))?;

        Ok(handle)
    }

    /// Start an external proof manager
    fn start_external_proof_manager(
        &self,
    ) -> Result<JoinHandle<ProofManagerError>, ProofManagerError> {
        unimplemented!("external proof manager not implemented")
    }
}
