//! An implementation of the proof manager which uses an external prover service

use constants::in_bootstrap_mode;
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerReceiver};
use tracing::{error, info, instrument};
use types_runtime::CancelChannel;
use util::{channels::TracedMessage, concurrency::runtime::sleep_forever_blocking};

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
                .map_err(|err| ProofManagerError::RecvError(err.to_string()))?;

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
        traced_job: TracedMessage<ProofManagerJob>,
    ) -> Result<(), ProofManagerError> {
        let job = traced_job.consume();
        let response = match job.type_ {
            // Update proofs
            ProofJob::ValidBalanceCreate { witness, statement } => {
                client.prove_valid_balance_create(witness, statement).await
            },
            ProofJob::ValidDeposit { witness, statement } => {
                client.prove_valid_deposit(witness, statement).await
            },
            ProofJob::ValidOrderCancellation { witness, statement } => {
                client.prove_valid_order_cancellation(witness, statement).await
            },
            ProofJob::ValidWithdrawal { witness, statement } => {
                client.prove_valid_withdrawal(witness, statement).await
            },
            // Validity proofs
            ProofJob::IntentAndBalanceValidity { witness, statement } => {
                client.prove_intent_and_balance_validity(witness, statement).await
            },
            ProofJob::IntentAndBalanceFirstFillValidity { witness, statement } => {
                client.prove_intent_and_balance_first_fill_validity(witness, statement).await
            },
            ProofJob::IntentOnlyValidity { witness, statement } => {
                client.prove_intent_only_validity(witness, statement).await
            },
            ProofJob::IntentOnlyFirstFillValidity { witness, statement } => {
                client.prove_intent_only_first_fill_validity(witness, statement).await
            },
            ProofJob::NewOutputBalanceValidity { witness, statement } => {
                client.prove_new_output_balance_validity(witness, statement).await
            },
            ProofJob::OutputBalanceValidity { witness, statement } => {
                client.prove_output_balance_validity(witness, statement).await
            },
            // Settlement proofs
            ProofJob::IntentAndBalanceBoundedSettlement {
                witness,
                statement,
                validity_link_hint,
            } => {
                client
                    .prove_intent_and_balance_bounded_settlement(
                        witness,
                        statement,
                        validity_link_hint,
                    )
                    .await
            },
            ProofJob::IntentAndBalancePrivateSettlement {
                witness,
                statement,
                validity_link_hint_0,
                validity_link_hint_1,
                output_balance_link_hint_0,
                output_balance_link_hint_1,
            } => {
                client
                    .prove_intent_and_balance_private_settlement(
                        witness,
                        statement,
                        validity_link_hint_0,
                        validity_link_hint_1,
                        output_balance_link_hint_0,
                        output_balance_link_hint_1,
                    )
                    .await
            },
            ProofJob::IntentAndBalancePublicSettlement {
                witness,
                statement,
                party_id,
                validity_link_hint,
                output_balance_link_hint,
            } => {
                client
                    .prove_intent_and_balance_public_settlement(
                        witness,
                        statement,
                        party_id,
                        validity_link_hint,
                        output_balance_link_hint,
                    )
                    .await
            },
            ProofJob::IntentOnlyBoundedSettlement { witness, statement, validity_link_hint } => {
                client
                    .prove_intent_only_bounded_settlement(witness, statement, validity_link_hint)
                    .await
            },
            ProofJob::IntentOnlyPublicSettlement { witness, statement, validity_link_hint } => {
                client
                    .prove_intent_only_public_settlement(witness, statement, validity_link_hint)
                    .await
            },
            // Fee proofs
            ProofJob::ValidNoteRedemption { witness, statement } => {
                client.prove_valid_note_redemption(witness, statement).await
            },
            ProofJob::ValidPrivateProtocolFeePayment { witness, statement } => {
                client.prove_valid_private_protocol_fee_payment(witness, statement).await
            },
            ProofJob::ValidPrivateRelayerFeePayment { witness, statement } => {
                client.prove_valid_private_relayer_fee_payment(witness, statement).await
            },
            ProofJob::ValidPublicProtocolFeePayment { witness, statement } => {
                client.prove_valid_public_protocol_fee_payment(witness, statement).await
            },
            ProofJob::ValidPublicRelayerFeePayment { witness, statement } => {
                client.prove_valid_public_relayer_fee_payment(witness, statement).await
            },
        }?;

        // Ignore send errors
        let _err = job.response_channel.send(response);
        Ok(())
    }
}
