//! An implementation of the proof manager which uses an external prover service

use common::types::CancelChannel;
use constants::in_bootstrap_mode;
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerReceiver};
use tracing::{error, info, instrument};
use util::concurrency::runtime::sleep_forever_blocking;

use crate::{
    error::ProofManagerError,
    implementations::external_proof_manager::prover_service_client::ProofServiceClient,
    worker::ProofManagerConfig,
};

mod api_types;
mod prover_service_client;

/// The number of worker threads to use for the external proof manager
const WORKER_THREADS: usize = 3;

// -----------
// | Manager |
// -----------

/// An external proof service client
pub struct ExternalProofManager {
    /// The HTTP client to use for connecting to the prover service
    client: ProofServiceClient,
    /// The job queue on which to receive proof generation jobs
    job_queue: ProofManagerReceiver,
    /// The channel on which a coordinator may cancel execution
    cancel_channel: CancelChannel,
}

impl ExternalProofManager {
    /// Create a new external proof manager
    pub fn new(config: ProofManagerConfig) -> Result<Self, ProofManagerError> {
        Ok(Self {
            client: ProofServiceClient::new(&config)?,
            job_queue: config.job_queue,
            cancel_channel: config.cancel_channel,
        })
    }

    /// Run the proof manager's execution loop
    pub fn run(self) -> Result<(), ProofManagerError> {
        // If the relayer is in bootstrap mode, sleep forever
        if in_bootstrap_mode() {
            sleep_forever_blocking();
        }

        // Otherwise, start a Tokio runtime for the worker and spawn the work loop
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(WORKER_THREADS)
            .enable_all()
            .build()
            .map_err(ProofManagerError::setup)?;
        runtime.block_on(async { self.work_loop() })
    }

    /// The work loop of the external proof manager
    fn work_loop(self) -> Result<(), ProofManagerError> {
        loop {
            // Check the cancel channel before blocking on a job
            if self
                .cancel_channel
                .has_changed()
                .map_err(|err| ProofManagerError::RecvError(err.to_string()))?
            {
                info!("Proof manager cancelled, shutting down...");
                return Err(ProofManagerError::Cancelled("received cancel signal".to_string()));
            }

            // Block on a job
            let job = self
                .job_queue
                .recv()
                .map_err(|err| ProofManagerError::RecvError(err.to_string()))?
                .consume();

            // Handle the job
            let client = self.client.clone();
            tokio::spawn(async move {
                if let Err(err) = Self::handle_proof_job(client, job).await {
                    error!("Error handling proof job: {err:?}");
                }
            });
        }
    }

    /// Handle a proof generation job
    #[instrument(name = "handle_proof_job", skip_all)]
    async fn handle_proof_job(
        client: ProofServiceClient,
        job: ProofManagerJob,
    ) -> Result<(), ProofManagerError> {
        let bundle = match job.type_ {
            ProofJob::ValidWalletCreate { witness, statement } => {
                // Prove `VALID WALLET CREATE`
                client.prove_valid_wallet_create(witness, statement).await
            },
            ProofJob::ValidWalletUpdate { witness, statement } => {
                // Prove `VALID WALLET UPDATE`
                client.prove_valid_wallet_update(witness, statement).await
            },
            ProofJob::ValidCommitments { witness, statement } => {
                // Prove `VALID COMMITMENTS`
                client.prove_valid_commitments(witness, statement).await
            },
            ProofJob::ValidReblind { witness, statement } => {
                // Prove `VALID REBLIND`
                client.prove_valid_reblind(witness, statement).await
            },
            ProofJob::ValidMatchSettleSingleprover {
                witness,
                statement,
                commitment_link0,
                commitment_link1,
            } => {
                // Prove `VALID MATCH SETTLE`
                client
                    .prove_valid_match_settle(
                        witness,
                        statement,
                        commitment_link0,
                        commitment_link1,
                    )
                    .await
            },
            ProofJob::ValidMatchSettleAtomic { witness, statement, commitments_link } => {
                // Prove `VALID MATCH SETTLE ATOMIC`
                client.prove_valid_match_settle_atomic(witness, statement, commitments_link).await
            },
            ProofJob::ValidMalleableMatchSettleAtomic { witness, statement, commitments_link } => {
                // Prove `VALID MALLEABLE MATCH SETTLE ATOMIC`
                client
                    .prove_valid_malleable_match_settle_atomic(witness, statement, commitments_link)
                    .await
            },
            ProofJob::ValidFeeRedemption { witness, statement } => {
                // Prove `VALID FEE REDEMPTION`
                client.prove_valid_fee_redemption(witness, statement).await
            },
            ProofJob::ValidOfflineFeeSettlement { witness, statement } => {
                // Prove `VALID OFFLINE FEE SETTLEMENT`
                client.prove_valid_offline_fee_settlement(witness, statement).await
            },
            _ => return Err(ProofManagerError::prover("unsupported proof type")),
        }?;

        // Ignore send errors
        let _err = job.response_channel.send(bundle);
        Ok(())
    }
}
