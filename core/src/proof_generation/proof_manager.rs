//! The proof manager manages job queues for generating proofs when updates
//! happen to the state. It provides an abstracted messaging interface for other
//! workers to submit proof requests to.

use std::{convert::TryInto, sync::Arc, thread::JoinHandle};

use circuits::{
    native_helpers::compute_wallet_commitment,
    singleprover_prove,
    types::{balance::Balance, fee::Fee, keychain::KeyChain, order::Order},
    zk_circuits::{
        valid_commitments::{ValidCommitments, ValidCommitmentsStatement},
        valid_match_encryption::{
            ValidMatchEncryption, ValidMatchEncryptionStatement, ValidMatchEncryptionWitness,
        },
        valid_wallet_create::{
            ValidWalletCreate, ValidWalletCreateStatement, ValidWalletCreateWitness,
        },
    },
    MAX_BALANCES, MAX_ORDERS,
};
use crossbeam::channel::Receiver;
use crypto::fields::prime_field_to_scalar;
use curve25519_dalek::scalar::Scalar;
use rayon::ThreadPool;
use tracing::log;

use crate::{
    proof_generation::jobs::ProofJob, types::SizedValidCommitmentsWitness, CancelChannel,
    SizedWallet, MAX_FEES,
};

use super::{
    error::ProofManagerError,
    jobs::{
        ProofBundle, ProofManagerJob, ValidCommitmentsBundle, ValidMatchEncryptBundle,
        ValidWalletCreateBundle,
    },
};

// -------------
// | Constants |
// -------------
/// Error message when sending a proof response fails
const ERR_SENDING_RESPONSE: &str = "error sending proof response, channel closed";
/// The number of threads to allocate towards the proof generation worker pool
pub(crate) const PROOF_GENERATION_N_THREADS: usize = 2;

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

            thread_pool.install(move || {
                if let Err(e) = Self::handle_proof_job(job) {
                    println!("Error handling proof manager job: {}", e)
                }
            });
        }
    }

    /// The main job handler, run by a thread in the pool
    fn handle_proof_job(job: ProofManagerJob) -> Result<(), ProofManagerError> {
        match job.type_ {
            ProofJob::ValidWalletCreate {
                fees,
                keys,
                randomness,
            } => {
                // Prove `VALID WALLET CREATE`
                let proof_bundle = Self::prove_valid_wallet_create(fees, keys, randomness)?;
                job.response_channel
                    .send(ProofBundle::ValidWalletCreate(proof_bundle))
                    .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))?
            }

            ProofJob::ValidCommitments { witness, statement } => {
                // Prove `VALID COMMITMENTS`
                let proof_bundle = Self::prove_valid_commitments(witness, statement)?;
                job.response_channel
                    .send(ProofBundle::ValidCommitments(proof_bundle))
                    .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))?
            }

            ProofJob::ValidMatchEncrypt { statement, witness } => {
                // Prove `VALID MATCH ENCRYPTION`
                let proof_bundle = Self::prove_valid_match_encrypt(statement, witness)?;
                job.response_channel
                    .send(ProofBundle::ValidMatchEncryption(proof_bundle))
                    .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))?;
            }
        };

        Ok(())
    }

    /// Create a proof of `VALID WALLET CREATE`
    fn prove_valid_wallet_create(
        fees: Vec<Fee>,
        keys: KeyChain,
        randomness: Scalar,
    ) -> Result<ValidWalletCreateBundle, ProofManagerError> {
        // Build an empty wallet and compute its commitment
        let sized_fees: [Fee; MAX_FEES] = fees.try_into().unwrap();
        let empty_wallet = SizedWallet {
            balances: vec![Balance::default(); MAX_BALANCES].try_into().unwrap(),
            orders: vec![Order::default(); MAX_ORDERS].try_into().unwrap(),
            fees: sized_fees.clone(),
            keys,
            randomness,
        };

        let wallet_commit = compute_wallet_commitment(&empty_wallet);

        // Build the statement and witness for the proof
        let statement = ValidWalletCreateStatement {
            wallet_commitment: prime_field_to_scalar(&wallet_commit),
        };
        let witness = ValidWalletCreateWitness::<MAX_FEES> {
            fees: sized_fees,
            keys,
            wallet_randomness: randomness,
        };

        let (commitment, proof) = singleprover_prove::<
            ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement)
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ValidWalletCreateBundle {
            commitment,
            statement,
            proof,
        })
    }

    /// Create a proof of `VALID COMMITMENTS`
    #[allow(clippy::too_many_arguments)]
    fn prove_valid_commitments(
        witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> Result<ValidCommitmentsBundle, ProofManagerError> {
        // Prove the statement `VALID COMMITMENTS`
        let (witness_comm, proof) = singleprover_prove::<
            ValidCommitments<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement)
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ValidCommitmentsBundle {
            commitment: witness_comm,
            statement,
            proof,
        })
    }

    /// Create a proof of `VALID MATCH ENCRYPTION`
    fn prove_valid_match_encrypt(
        statement: ValidMatchEncryptionStatement,
        witness: ValidMatchEncryptionWitness,
    ) -> Result<ValidMatchEncryptBundle, ProofManagerError> {
        log::info!("generating proof of VALID MATCH ENCRYPTION");
        let (witness_comm, proof) =
            singleprover_prove::<ValidMatchEncryption<252 /* SCALAR_BITS */>>(
                witness,
                statement.clone(),
            )
            .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ValidMatchEncryptBundle {
            commitment: witness_comm,
            statement,
            proof,
        })
    }
}
