//! The proof manager manages job queues for generating proofs when updates
//! happen to the state. It provides an abstracted messaging interface for other
//! workers to submit proof requests to.

use std::{sync::Arc, thread::JoinHandle};

use circuit_types::traits::{SingleProverCircuit, setup_preprocessed_keys};
use circuits::{
    singleprover_prove_with_hint,
    zk_circuits::{
        valid_commitments::{
            SizedValidCommitments, SizedValidCommitmentsWitness, ValidCommitmentsStatement,
        },
        valid_fee_redemption::{
            SizedValidFeeRedemption, SizedValidFeeRedemptionStatement,
            SizedValidFeeRedemptionWitness,
        },
        valid_malleable_match_settle_atomic::{
            SizedValidMalleableMatchSettleAtomic, SizedValidMalleableMatchSettleAtomicStatement,
            SizedValidMalleableMatchSettleAtomicWitness,
        },
        valid_match_settle::{
            SizedValidMatchSettle, SizedValidMatchSettleStatement, SizedValidMatchSettleWitness,
        },
        valid_match_settle_atomic::{
            SizedValidMatchSettleAtomic, SizedValidMatchSettleAtomicStatement,
            SizedValidMatchSettleAtomicWitness,
        },
        valid_offline_fee_settlement::{
            SizedValidOfflineFeeSettlement, SizedValidOfflineFeeSettlementStatement,
            SizedValidOfflineFeeSettlementWitness,
        },
        valid_reblind::{SizedValidReblind, SizedValidReblindWitness, ValidReblindStatement},
        valid_relayer_fee_settlement::{
            SizedValidRelayerFeeSettlement, SizedValidRelayerFeeSettlementStatement,
            SizedValidRelayerFeeSettlementWitness,
        },
        valid_wallet_create::{
            SizedValidWalletCreate, SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
        },
        valid_wallet_update::{
            SizedValidWalletUpdate, SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
        },
    },
};
use common::types::{CancelChannel, proof_bundles::ProofBundle};
use constants::in_bootstrap_mode;
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerReceiver};
use rayon::ThreadPool;
use tracing::{error, info, info_span, instrument};
use util::{channels::TracedMessage, concurrency::runtime::sleep_forever_blocking, err_str};

use super::error::ProofManagerError;

// -------------
// | Constants |
// -------------

/// Error message when sending a proof response fails
const ERR_SENDING_RESPONSE: &str = "error sending proof response, channel closed";

// --------------------
// | Proof Generation |
// --------------------

/// The proof manager provides a messaging interface and implementation for
/// proving statements related to system state transitions
#[derive(Debug)]
pub struct ProofManager {
    /// The queue on which the proof manager receives new jobs
    pub(crate) job_queue: Option<ProofManagerReceiver>,
    /// The handle of the main driver thread in the proof generation module
    pub(crate) join_handle: Option<JoinHandle<ProofManagerError>>,
    /// The threadpool of workers generating proofs for the system
    pub(crate) thread_pool: Arc<ThreadPool>,
    /// The channel on which a coordinator may cancel execution
    pub(crate) cancel_channel: CancelChannel,
}

impl ProofManager {
    /// The execution loop blocks on the job queue then schedules proof
    /// generation jobs onto a thread pool
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) fn execution_loop(
        job_queue: ProofManagerReceiver,
        thread_pool: Arc<ThreadPool>,
        cancel_channel: CancelChannel,
    ) -> Result<(), ProofManagerError> {
        // If the relayer is in bootstrap mode, sleep forever
        if in_bootstrap_mode() {
            sleep_forever_blocking();
        }

        // Preprocess the circuits
        thread_pool.spawn_fifo(|| {
            ProofManager::preprocess_circuits().unwrap();
        });

        loop {
            // Check the cancel channel before blocking on a job
            if cancel_channel
                .has_changed()
                .map_err(|err| ProofManagerError::RecvError(err.to_string()))?
            {
                info!("Proof manager cancelled, shutting down...");
                return Err(ProofManagerError::Cancelled("received cancel signal".to_string()));
            }

            // Dequeue the next job and hand it to the thread pool
            let job = job_queue
                .recv()
                .map_err(|err| ProofManagerError::JobQueueClosed(err.to_string()))?;

            thread_pool.spawn_fifo(move || {
                let _span = info_span!("handle_proof_job").entered();
                if let Err(e) = Self::handle_proof_job(job) {
                    error!("Error handling proof manager job: {}", e)
                }
            });
        }
    }

    /// The main job handler, run by a thread in the pool
    #[instrument(name = "handle_proof_job", skip(job))]
    fn handle_proof_job(job: TracedMessage<ProofManagerJob>) -> Result<(), ProofManagerError> {
        let ProofManagerJob { type_, response_channel } = job.consume();
        let proof_bundle = match type_ {
            ProofJob::ValidWalletCreate { witness, statement } => {
                // Prove `VALID WALLET CREATE`
                Self::prove_valid_wallet_create(witness, statement)
            },

            ProofJob::ValidReblind { witness, statement } => {
                // Prove `VALID REBLIND`
                Self::prove_valid_reblind(witness, statement)
            },

            ProofJob::ValidCommitments { witness, statement } => {
                // Prove `VALID COMMITMENTS`
                Self::prove_valid_commitments(witness, statement)
            },

            ProofJob::ValidWalletUpdate { witness, statement } => {
                Self::prove_valid_wallet_update(witness, statement)
            },

            ProofJob::ValidMatchSettleSingleprover { witness, statement } => {
                // Prove `VALID MATCH MPC`
                Self::prove_valid_match_mpc(witness, statement)
            },

            ProofJob::ValidMatchSettleAtomic { witness, statement } => {
                // Prove `VALID MATCH SETTLE ATOMIC`
                Self::prove_valid_match_settle_atomic(witness, statement)
            },

            ProofJob::ValidMalleableMatchSettleAtomic { witness, statement } => {
                // Prove `VALID MALLEABLE MATCH SETTLE ATOMIC`
                Self::prove_valid_malleable_match_settle_atomic(witness, statement)
            },

            ProofJob::ValidRelayerFeeSettlement { witness, statement } => {
                // Prove `VALID RELAYER FEE SETTLEMENT`
                Self::prove_valid_relayer_fee_settlement(witness, statement)
            },

            ProofJob::ValidOfflineFeeSettlement { witness, statement } => {
                // Prove `VALID OFFLINE FEE SETTLEMENT`
                Self::prove_valid_offline_fee_settlement(witness, statement)
            },

            ProofJob::ValidFeeRedemption { witness, statement } => {
                // Prove `VALID FEE REDEMPTION`
                Self::prove_valid_fee_redemption(witness, statement)
            },
        }?;

        response_channel
            .send(proof_bundle)
            .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))
    }

    /// Initialize the proving key/verification key & circuit layout caches for
    /// all of the circuits
    pub(crate) fn preprocess_circuits() -> Result<(), ProofManagerError> {
        // Set up the proving & verification keys for all of the circuits
        setup_preprocessed_keys::<SizedValidWalletCreate>();
        setup_preprocessed_keys::<SizedValidWalletUpdate>();
        setup_preprocessed_keys::<SizedValidCommitments>();
        setup_preprocessed_keys::<SizedValidReblind>();
        setup_preprocessed_keys::<SizedValidMatchSettle>();
        setup_preprocessed_keys::<SizedValidRelayerFeeSettlement>();
        setup_preprocessed_keys::<SizedValidOfflineFeeSettlement>();
        setup_preprocessed_keys::<SizedValidFeeRedemption>();

        // Set up layouts for all of the circuits
        SizedValidWalletCreate::get_circuit_layout().map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidWalletUpdate::get_circuit_layout().map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidCommitments::get_circuit_layout().map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidReblind::get_circuit_layout().map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidMatchSettle::get_circuit_layout().map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidRelayerFeeSettlement::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidOfflineFeeSettlement::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidFeeRedemption::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;

        Ok(())
    }

    /// Create a proof of `VALID WALLET CREATE`
    #[instrument(skip_all, err)]
    fn prove_valid_wallet_create(
        witness: SizedValidWalletCreateWitness,
        statement: SizedValidWalletCreateStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID WALLET CREATE`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidWalletCreate>(witness, statement.clone())
                .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_wallet_create(statement, proof, link_hint))
    }

    /// Create a proof of `VALID REBLIND`
    #[instrument(skip_all, err)]
    fn prove_valid_reblind(
        witness: SizedValidReblindWitness,
        statement: ValidReblindStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID REBLIND`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidReblind>(witness, statement.clone())
                .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_reblind(statement, proof, link_hint))
    }

    /// Create a proof of `VALID COMMITMENTS`
    #[instrument(skip_all, err)]
    fn prove_valid_commitments(
        witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID COMMITMENTS`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidCommitments>(witness, statement)
                .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_commitments(statement, proof, link_hint))
    }

    /// Create a proof of `VALID WALLET UPDATE`
    #[instrument(skip_all, err)]
    fn prove_valid_wallet_update(
        witness: SizedValidWalletUpdateWitness,
        statement: SizedValidWalletUpdateStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID WALLET UPDATE`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidWalletUpdate>(witness, statement.clone())
                .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_wallet_update(statement, proof, link_hint))
    }

    /// Create a proof of `VALID MATCH SETTLE`
    #[instrument(skip_all, err)]
    fn prove_valid_match_mpc(
        witness: SizedValidMatchSettleWitness,
        statement: SizedValidMatchSettleStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID MATCH SETTLE`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidMatchSettle>(witness, statement.clone())
                .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_match_settle(statement, proof, link_hint))
    }

    /// Create a proof of `VALID MATCH SETTLE ATOMIC`
    #[instrument(skip_all, err)]
    fn prove_valid_match_settle_atomic(
        witness: SizedValidMatchSettleAtomicWitness,
        statement: SizedValidMatchSettleAtomicStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID MATCH SETTLE ATOMIC`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidMatchSettleAtomic>(witness, statement.clone())
                .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_match_settle_atomic(statement, proof, link_hint))
    }

    /// Create a proof of `VALID MALLEABLE MATCH SETTLE ATOMIC`
    #[instrument(skip_all, err)]
    fn prove_valid_malleable_match_settle_atomic(
        witness: SizedValidMalleableMatchSettleAtomicWitness,
        statement: SizedValidMalleableMatchSettleAtomicStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID MALLEABLE MATCH SETTLE ATOMIC`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidMalleableMatchSettleAtomic>(
                witness,
                statement.clone(),
            )
            .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_malleable_match_settle_atomic(statement, proof, link_hint))
    }

    /// Create a proof of `VALID RELAYER FEE SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_valid_relayer_fee_settlement(
        witness: SizedValidRelayerFeeSettlementWitness,
        statement: SizedValidRelayerFeeSettlementStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID RELAYER FEE SETTLEMENT`
        let (proof, link_hint) = singleprover_prove_with_hint::<SizedValidRelayerFeeSettlement>(
            witness,
            statement.clone(),
        )
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_relayer_fee_settlement(statement, proof, link_hint))
    }

    /// Create a proof of `VALID OFFLINE FEE SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_valid_offline_fee_settlement(
        witness: SizedValidOfflineFeeSettlementWitness,
        statement: SizedValidOfflineFeeSettlementStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID OFFLINE FEE SETTLEMENT`
        let (proof, link_hint) = singleprover_prove_with_hint::<SizedValidOfflineFeeSettlement>(
            witness,
            statement.clone(),
        )
        .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_offline_fee_settlement(statement, proof, link_hint))
    }

    /// Create a proof of `VALID FEE REDEMPTION`
    #[instrument(skip_all, err)]
    fn prove_valid_fee_redemption(
        witness: SizedValidFeeRedemptionWitness,
        statement: SizedValidFeeRedemptionStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID FEE REDEMPTION`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidFeeRedemption>(witness, statement.clone())
                .map_err(|err| ProofManagerError::Prover(err.to_string()))?;

        Ok(ProofBundle::new_valid_fee_redemption(statement, proof, link_hint))
    }
}
