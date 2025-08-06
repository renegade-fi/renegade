//! A prover implementation which uses the native prover service

use std::sync::Arc;

use ark_mpc::{PARTY0, PARTY1, network::PartyId};
use circuit_types::{
    PlonkLinkProof, ProofLinkingHint,
    traits::{SingleProverCircuit, setup_preprocessed_keys},
};
use circuits::{
    singleprover_prove_with_hint,
    zk_circuits::{
        proof_linking::{
            link_sized_commitments_atomic_match_settle, link_sized_commitments_match_settle,
            link_sized_commitments_reblind,
        },
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
use common::{
    default_wrapper::{DefaultOption, default_option},
    types::{CancelChannel, proof_bundles::ProofBundle},
};
use constants::in_bootstrap_mode;
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerReceiver};
use rayon::{ThreadPool, ThreadPoolBuilder};
use tracing::{error, info, info_span, instrument};
use util::{channels::TracedMessage, concurrency::runtime::sleep_forever_blocking, err_str};

use crate::{
    error::ProofManagerError, implementations::external_proof_manager::default_link_hint,
    worker::ProofManagerConfig,
};

/// The name prefix for worker threads
const WORKER_THREAD_PREFIX: &str = "proof-generation-worker";
/// The stack size for worker threads
const WORKER_STACK_SIZE: usize = 10 * 1024 * 1024; // 10 MB

/// Error message when sending a proof response fails
const ERR_SENDING_RESPONSE: &str = "error sending proof response, channel closed";

/// A native prover, generates all proofs locally
#[derive(Clone)]
pub struct NativeProofManager {
    /// The job queue on which to receive proof generation jobs
    job_queue: DefaultOption<ProofManagerReceiver>,
    /// The threadpool of workers generating proofs for the system
    thread_pool: Arc<ThreadPool>,
    /// The channel on which a coordinator may cancel execution
    cancel_channel: DefaultOption<CancelChannel>,
}

impl NativeProofManager {
    /// Create a new native proof manager
    pub fn new(config: ProofManagerConfig) -> Result<Self, ProofManagerError> {
        // Build a thread pool for the worker
        let thread_pool = ThreadPoolBuilder::new()
            .thread_name(|i| format!("{}-{}", WORKER_THREAD_PREFIX, i))
            .stack_size(WORKER_STACK_SIZE)
            .build()
            .map_err(|err| ProofManagerError::Setup(err.to_string()))?;

        Ok(Self {
            job_queue: default_option(config.job_queue),
            thread_pool: Arc::new(thread_pool),
            cancel_channel: default_option(config.cancel_channel),
        })
    }

    /// Run the proof manager's execution loop
    pub fn run(mut self) -> Result<(), ProofManagerError> {
        // If the relayer is in bootstrap mode, sleep forever
        if in_bootstrap_mode() {
            sleep_forever_blocking();
        }

        // Preprocess the circuits
        self.thread_pool.spawn_fifo(|| {
            Self::preprocess_circuits().unwrap();
        });

        // Take the job queue and cancel channel for the coordinator loop
        let job_queue = self.job_queue.take().expect("job queue not set");
        let cancel_channel = self.cancel_channel.take().expect("cancel channel not set");
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

            // Clone the thread pool for the worker thread
            let self_clone = self.clone();
            self.thread_pool.spawn_fifo(move || {
                let _span = info_span!("handle_proof_job").entered();
                if let Err(e) = self_clone.handle_proof_job(job) {
                    error!("Error handling proof manager job: {}", e)
                }
            });
        }
    }

    /// The main job handler, run by a thread in the pool
    #[instrument(name = "handle_proof_job", skip_all)]
    fn handle_proof_job(
        &self,
        job: TracedMessage<ProofManagerJob>,
    ) -> Result<(), ProofManagerError> {
        let ProofManagerJob { type_, response_channel } = job.consume();
        let proof_bundle = match type_ {
            ProofJob::ValidWalletCreate { witness, statement } => {
                // Prove `VALID WALLET CREATE`
                self.prove_valid_wallet_create(witness, statement)
            },

            ProofJob::ValidReblind { witness, statement } => {
                // Prove `VALID REBLIND`
                self.prove_valid_reblind(witness, statement)
            },

            ProofJob::ValidCommitments { witness, statement } => {
                // Prove `VALID COMMITMENTS`
                self.prove_valid_commitments(witness, statement)
            },

            ProofJob::ValidCommitmentsReblindLink { commitments_hint, reblind_hint } => {
                // Link a proof of `VALID COMMITMENTS` with a proof of `VALID REBLIND`
                self.link_commitments_reblind(commitments_hint, reblind_hint)
            },

            ProofJob::ValidWalletUpdate { witness, statement } => {
                self.prove_valid_wallet_update(witness, statement)
            },

            ProofJob::ValidMatchSettleSingleprover {
                witness,
                statement,
                commitment_link0,
                commitment_link1,
            } => {
                // Prove `VALID MATCH MPC`
                self.prove_valid_match_mpc(witness, statement, commitment_link0, commitment_link1)
            },

            ProofJob::ValidMatchSettleAtomic { witness, statement, commitments_link } => {
                // Prove `VALID MATCH SETTLE ATOMIC`
                self.prove_valid_match_settle_atomic(witness, statement, commitments_link)
            },

            ProofJob::ValidMalleableMatchSettleAtomic { witness, statement, commitments_link } => {
                // Prove `VALID MALLEABLE MATCH SETTLE ATOMIC`
                self.prove_valid_malleable_match_settle_atomic(witness, statement, commitments_link)
            },

            ProofJob::ValidRelayerFeeSettlement { witness, statement } => {
                // Prove `VALID RELAYER FEE SETTLEMENT`
                self.prove_valid_relayer_fee_settlement(witness, statement)
            },

            ProofJob::ValidOfflineFeeSettlement { witness, statement } => {
                // Prove `VALID OFFLINE FEE SETTLEMENT`
                self.prove_valid_offline_fee_settlement(witness, statement)
            },

            ProofJob::ValidFeeRedemption { witness, statement } => {
                // Prove `VALID FEE REDEMPTION`
                self.prove_valid_fee_redemption(witness, statement)
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
        &self,
        witness: SizedValidWalletCreateWitness,
        statement: SizedValidWalletCreateStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID WALLET CREATE`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidWalletCreate>(witness, statement.clone())?;
        Ok(ProofBundle::new_valid_wallet_create(statement, proof, link_hint))
    }

    /// Create a proof of `VALID WALLET UPDATE`
    #[instrument(skip_all, err)]
    fn prove_valid_wallet_update(
        &self,
        witness: SizedValidWalletUpdateWitness,
        statement: SizedValidWalletUpdateStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID WALLET UPDATE`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidWalletUpdate>(witness, statement.clone())?;
        Ok(ProofBundle::new_valid_wallet_update(statement, proof, link_hint))
    }

    /// Create a proof of `VALID REBLIND`
    #[instrument(skip_all, err)]
    fn prove_valid_reblind(
        &self,
        witness: SizedValidReblindWitness,
        statement: ValidReblindStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID REBLIND`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidReblind>(witness, statement.clone())?;
        Ok(ProofBundle::new_valid_reblind(statement, proof, link_hint))
    }

    /// Create a proof of `VALID COMMITMENTS`
    #[instrument(skip_all, err)]
    fn prove_valid_commitments(
        &self,
        witness: SizedValidCommitmentsWitness,
        statement: ValidCommitmentsStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID COMMITMENTS`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidCommitments>(witness, statement)?;
        Ok(ProofBundle::new_valid_commitments(statement, proof, link_hint))
    }

    /// Link a proof of `VALID COMMITMENTS` with a proof of `VALID REBLIND`
    #[instrument(skip_all, err)]
    fn link_commitments_reblind(
        &self,
        commitments_hint: ProofLinkingHint,
        reblind_hint: ProofLinkingHint,
    ) -> Result<ProofBundle, ProofManagerError> {
        let link_proof = link_sized_commitments_reblind(&commitments_hint, &reblind_hint)?;
        let link_hint = default_link_hint();
        let bundle = ProofBundle::new_valid_commitments_reblind_link(link_proof, link_hint);
        Ok(bundle)
    }

    /// Create a proof of `VALID MATCH SETTLE`
    #[instrument(skip_all, err)]
    fn prove_valid_match_mpc(
        &self,
        witness: SizedValidMatchSettleWitness,
        statement: SizedValidMatchSettleStatement,
        commitment_link0: ProofLinkingHint,
        commitment_link1: ProofLinkingHint,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID MATCH SETTLE`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidMatchSettle>(witness, statement.clone())?;

        // Link the individual proofs of `VALID COMMITMENTS` into the proof of
        // `VALID MATCH SETTLE`
        let thread1 = || self.link_commitments_match_settle(PARTY0, &commitment_link1, &link_hint);
        let thread0 = || self.link_commitments_match_settle(PARTY1, &commitment_link0, &link_hint);
        let (link_res0, link_res1) = self.thread_pool.join(thread0, thread1);
        let link0 = link_res0?;
        let link1 = link_res1?;
        Ok(ProofBundle::new_valid_match_settle(statement, proof, link0, link1, link_hint))
    }

    /// Generate a link proof for a party's proof of `VALID COMMITMENTS` and a
    /// proof of `VALID MATCH SETTLE`
    fn link_commitments_match_settle(
        &self,
        party_id: PartyId,
        commitment_link_hint: &ProofLinkingHint,
        match_settle_link_hint: &ProofLinkingHint,
    ) -> Result<PlonkLinkProof, ProofManagerError> {
        let link_proof = link_sized_commitments_match_settle(
            party_id,
            commitment_link_hint,
            match_settle_link_hint,
        )?;
        Ok(link_proof)
    }

    /// Create a proof of `VALID MATCH SETTLE ATOMIC`
    #[instrument(skip_all, err)]
    fn prove_valid_match_settle_atomic(
        &self,
        witness: SizedValidMatchSettleAtomicWitness,
        statement: SizedValidMatchSettleAtomicStatement,
        commitments_link: ProofLinkingHint,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID MATCH SETTLE ATOMIC`
        let (proof, link_hint) = singleprover_prove_with_hint::<SizedValidMatchSettleAtomic>(
            witness,
            statement.clone(),
        )?;

        // Prove the `VALID COMMITMENTS` <-> `VALID MATCH SETTLE ATOMIC` link
        let link_proof = link_sized_commitments_atomic_match_settle(&commitments_link, &link_hint)?;
        Ok(ProofBundle::new_valid_match_settle_atomic(statement, proof, link_proof, link_hint))
    }

    /// Create a proof of `VALID MALLEABLE MATCH SETTLE ATOMIC`
    #[instrument(skip_all, err)]
    fn prove_valid_malleable_match_settle_atomic(
        &self,
        witness: SizedValidMalleableMatchSettleAtomicWitness,
        statement: SizedValidMalleableMatchSettleAtomicStatement,
        commitments_link: ProofLinkingHint,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID MALLEABLE MATCH SETTLE ATOMIC`
        let (proof, link_hint) = singleprover_prove_with_hint::<
            SizedValidMalleableMatchSettleAtomic,
        >(witness, statement.clone())?;

        // Prove the `VALID COMMITMENTS` <-> `VALID MALLEABLE MATCH SETTLE ATOMIC` link
        let link_proof = link_sized_commitments_atomic_match_settle(&commitments_link, &link_hint)?;
        Ok(ProofBundle::new_valid_malleable_match_settle_atomic(
            statement, proof, link_proof, link_hint,
        ))
    }

    /// Create a proof of `VALID RELAYER FEE SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_valid_relayer_fee_settlement(
        &self,
        witness: SizedValidRelayerFeeSettlementWitness,
        statement: SizedValidRelayerFeeSettlementStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID RELAYER FEE SETTLEMENT`
        let (proof, link_hint) = singleprover_prove_with_hint::<SizedValidRelayerFeeSettlement>(
            witness,
            statement.clone(),
        )?;

        Ok(ProofBundle::new_valid_relayer_fee_settlement(statement, proof, link_hint))
    }

    /// Create a proof of `VALID OFFLINE FEE SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_valid_offline_fee_settlement(
        &self,
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
        &self,
        witness: SizedValidFeeRedemptionWitness,
        statement: SizedValidFeeRedemptionStatement,
    ) -> Result<ProofBundle, ProofManagerError> {
        // Prove the statement `VALID FEE REDEMPTION`
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedValidFeeRedemption>(witness, statement.clone())?;

        Ok(ProofBundle::new_valid_fee_redemption(statement, proof, link_hint))
    }
}
