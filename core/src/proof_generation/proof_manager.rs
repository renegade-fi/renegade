//! The proof manager manages job queues for generating proofs when updates
//! happen to the state. It provides an abstracted messaging interface for other
//! workers to submit proof requests to.

use std::{sync::Arc, thread::JoinHandle};

use circuits::{
    singleprover_prove,
    zk_circuits::{
        valid_commitments::{ValidCommitments, ValidCommitmentsStatement},
        valid_reblind::{ValidReblind, ValidReblindStatement},
        valid_settle::ValidSettle,
        valid_wallet_create::ValidWalletCreate,
        valid_wallet_update::ValidWalletUpdate,
    },
    MAX_BALANCES, MAX_ORDERS,
};
use crossbeam::channel::Receiver;
use rayon::ThreadPool;
use tracing::log;

use crate::{proof_generation::jobs::ProofJob, CancelChannel, MAX_FEES};

use super::{
    error::ProofManagerError,
    jobs::{
        ProofBundle, ProofManagerJob, ValidCommitmentsBundle, ValidReblindBundle,
        ValidSettleBundle, ValidWalletCreateBundle, ValidWalletUpdateBundle,
    },
    SizedValidCommitmentsWitness, SizedValidReblindWitness, SizedValidSettleStatement,
    SizedValidSettleWitness, SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
    SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
};

// -------------
// | Constants |
// -------------
/// Error message when sending a proof response fails
const ERR_SENDING_RESPONSE: &str = "error sending proof response, channel closed";
/// The number of threads to allocate towards the proof generation worker pool
pub(crate) const PROOF_GENERATION_N_THREADS: usize = 3;

// --------------------
// | Proof Generation |
// --------------------

/// The proof manager provides a messaging interface and implementation for proving statements
/// related to system state transitions
#[derive(Debug)]
pub struct ProofManager {
    /// The queue on which the proof manager receives new jobs
    /// TODO: Remove this lint allowance
    #[allow(dead_code)]
    pub(crate) job_queue: Option<Receiver<ProofManagerJob>>,
    /// The handle of the main driver thread in the proof generation module
    pub(crate) join_handle: Option<JoinHandle<ProofManagerError>>,
    /// The threadpool of workers generating proofs for the system
    pub(crate) thread_pool: Arc<ThreadPool>,
    /// The channel on which a coordinator may cancel execution
    pub(crate) cancel_channel: CancelChannel,
}

impl ProofManager {
    /// The execution loop blocks on the job queue then schedules proof generation
    /// jobs onto a thread pool
    pub(crate) fn execution_loop(
        job_queue: Receiver<ProofManagerJob>,
        thread_pool: Arc<ThreadPool>,
        cancel_channel: CancelChannel,
    ) -> Result<(), ProofManagerError> {
        loop {
            // Check the cancel channel before blocking on a job
            if cancel_channel
                .has_changed()
                .map_err(|err| ProofManagerError::RecvError(err.to_string()))?
            {
                log::info!("Proof manager cancelled, shutting down...");
                return Err(ProofManagerError::Cancelled(
                    "received cancel signal".to_string(),
                ));
            }

            // Dequeue the next job and hand it to the thread pool
            let job = job_queue
                .recv()
                .map_err(|err| ProofManagerError::JobQueueClosed(err.to_string()))?;

            thread_pool.spawn(move || {
                if let Err(e) = Self::handle_proof_job(job) {
                    println!("Error handling proof manager job: {}", e)
                }
            });
        }
    }

    /// The main job handler, run by a thread in the pool
    fn handle_proof_job(job: ProofManagerJob) -> Result<(), ProofManagerError> {
        match job.type_ {
            ProofJob::ValidWalletCreate { witness, statement } => {
                // Prove `VALID WALLET CREATE`
                let proof_bundle = Self::prove_valid_wallet_create(witness, statement)?;
                job.response_channel
                    .send(ProofBundle::ValidWalletCreate(proof_bundle))
                    .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))
            }

            ProofJob::ValidReblind { witness, statement } => {
                // Prove `VALID REBLIND`
                let proof_bundle = Self::prove_valid_reblind(witness, statement)?;
                job.response_channel
                    .send(ProofBundle::ValidReblind(proof_bundle))
                    .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))
            }

            ProofJob::ValidCommitments { witness, statement } => {
                // Prove `VALID COMMITMENTS`
                let proof_bundle = Self::prove_valid_commitments(witness, statement)?;
                job.response_channel
                    .send(ProofBundle::ValidCommitments(proof_bundle))
                    .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))
            }

            ProofJob::ValidWalletUpdate { witness, statement } => {
                let proof_bundle = Self::prove_valid_wallet_update(witness, statement)?;
                job.response_channel
                    .send(ProofBundle::ValidWalletUpdate(proof_bundle))
                    .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))
            }

            ProofJob::ValidSettle { witness, statement } => {
                // Prove `VALID SETTLE`
                let proof_bundle = Self::prove_valid_settle(statement, witness)?;
                job.response_channel
                    .send(ProofBundle::ValidSettle(proof_bundle))
                    .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))
            }
        }
    }

    /// Create a proof of `VALID WALLET CREATE`
    fn prove_valid_wallet_create(
        witness: SizedValidWalletCreateWitness,
        statement: SizedValidWalletCreateStatement,
    ) -> Result<ValidWalletCreateBundle, ProofManagerError> {
        // Build the statement and witness for the proof
        let (commitment, proof) = singleprover_prove::<
            ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement.clone())
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ValidWalletCreateBundle {
            commitment,
            statement,
            proof,
        })
    }

    /// Create a proof of `VALID REBLIND`
    fn prove_valid_reblind(
        witness: SizedValidReblindWitness,
        statement: ValidReblindStatement,
    ) -> Result<ValidReblindBundle, ProofManagerError> {
        // Prove the statement `VALID REBLIND`
        let (witness_comm, proof) = singleprover_prove::<
            ValidReblind<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement.clone())
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ValidReblindBundle {
            commitment: witness_comm,
            statement,
            proof,
        })
    }

    /// Create a proof of `VALID COMMITMENTS`
    fn prove_valid_commitments(
        witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> Result<ValidCommitmentsBundle, ProofManagerError> {
        // Prove the statement `VALID COMMITMENTS`
        let (witness_comm, proof) = singleprover_prove::<
            ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement.clone())
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ValidCommitmentsBundle {
            commitment: witness_comm,
            statement,
            proof,
        })
    }

    /// Create a proof of `VALID WALLET UPDATE`
    fn prove_valid_wallet_update(
        witness: SizedValidWalletUpdateWitness,
        statement: SizedValidWalletUpdateStatement,
    ) -> Result<ValidWalletUpdateBundle, ProofManagerError> {
        let (witness_comm, proof) = singleprover_prove::<
            ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement.clone())
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ValidWalletUpdateBundle {
            commitment: witness_comm,
            statement,
            proof,
        })
    }

    /// Create a proof of `VALID SETTLE`
    fn prove_valid_settle(
        statement: SizedValidSettleStatement,
        witness: SizedValidSettleWitness,
    ) -> Result<ValidSettleBundle, ProofManagerError> {
        let (witness_comm, proof) = singleprover_prove::<
            ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement.clone())
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ValidSettleBundle {
            commitment: witness_comm,
            statement,
            proof,
        })
    }
}
