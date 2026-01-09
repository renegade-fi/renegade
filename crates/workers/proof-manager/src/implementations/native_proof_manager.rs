//! A prover implementation which uses the native prover service

use std::sync::Arc;

use circuit_types::traits::{SingleProverCircuit, setup_preprocessed_keys};
use circuits_core::{
    singleprover_prove, singleprover_prove_with_hint,
    zk_circuits::{
        fees::{
            valid_note_redemption::{
                SizedValidNoteRedemption, SizedValidNoteRedemptionWitness,
                ValidNoteRedemptionStatement,
            },
            valid_private_protocol_fee_payment::{
                SizedValidPrivateProtocolFeePayment, SizedValidPrivateProtocolFeePaymentWitness,
                ValidPrivateProtocolFeePaymentStatement,
            },
            valid_private_relayer_fee_payment::{
                SizedValidPrivateRelayerFeePayment, SizedValidPrivateRelayerFeePaymentWitness,
                ValidPrivateRelayerFeePaymentStatement,
            },
            valid_public_protocol_fee_payment::{
                SizedValidPublicProtocolFeePayment, SizedValidPublicProtocolFeePaymentWitness,
                ValidPublicProtocolFeePaymentStatement,
            },
            valid_public_relayer_fee_payment::{
                SizedValidPublicRelayerFeePayment, SizedValidPublicRelayerFeePaymentWitness,
                ValidPublicRelayerFeePaymentStatement,
            },
        },
        settlement::{
            intent_and_balance_bounded_settlement::{
                IntentAndBalanceBoundedSettlementCircuit,
                IntentAndBalanceBoundedSettlementStatement,
                IntentAndBalanceBoundedSettlementWitness,
            },
            intent_and_balance_private_settlement::{
                IntentAndBalancePrivateSettlementCircuit,
                IntentAndBalancePrivateSettlementStatement,
                IntentAndBalancePrivateSettlementWitness,
            },
            intent_and_balance_public_settlement::{
                IntentAndBalancePublicSettlementCircuit, IntentAndBalancePublicSettlementStatement,
                IntentAndBalancePublicSettlementWitness,
            },
            intent_only_bounded_settlement::{
                IntentOnlyBoundedSettlementCircuit, IntentOnlyBoundedSettlementStatement,
                IntentOnlyBoundedSettlementWitness,
            },
            intent_only_public_settlement::{
                IntentOnlyPublicSettlementCircuit, IntentOnlyPublicSettlementStatement,
                IntentOnlyPublicSettlementWitness,
            },
        },
        valid_balance_create::{
            ValidBalanceCreate, ValidBalanceCreateStatement, ValidBalanceCreateWitness,
        },
        valid_deposit::{SizedValidDeposit, SizedValidDepositWitness, ValidDepositStatement},
        valid_order_cancellation::{
            SizedValidOrderCancellationCircuit, SizedValidOrderCancellationWitness,
            ValidOrderCancellationStatement,
        },
        valid_withdrawal::{
            SizedValidWithdrawal, SizedValidWithdrawalWitness, ValidWithdrawalStatement,
        },
        validity_proofs::{
            intent_and_balance::{
                IntentAndBalanceValidityStatement, SizedIntentAndBalanceValidityCircuit,
                SizedIntentAndBalanceValidityWitness,
            },
            intent_and_balance_first_fill::{
                IntentAndBalanceFirstFillValidityStatement,
                SizedIntentAndBalanceFirstFillValidityCircuit,
                SizedIntentAndBalanceFirstFillValidityWitness,
            },
            intent_only::{
                IntentOnlyValidityStatement, SizedIntentOnlyValidityCircuit,
                SizedIntentOnlyValidityWitness,
            },
            intent_only_first_fill::{
                IntentOnlyFirstFillValidityCircuit, IntentOnlyFirstFillValidityStatement,
                IntentOnlyFirstFillValidityWitness,
            },
            new_output_balance::{
                NewOutputBalanceValidityStatement, SizedNewOutputBalanceValidityCircuit,
                SizedNewOutputBalanceValidityWitness,
            },
            output_balance::{
                OutputBalanceValidityStatement, SizedOutputBalanceValidityCircuit,
                SizedOutputBalanceValidityWitness,
            },
        },
    },
};
use constants::in_bootstrap_mode;
use job_types::proof_manager::{
    ProofJob, ProofManagerJob, ProofManagerReceiver, ProofManagerResponse,
};
use rayon::{ThreadPool, ThreadPoolBuilder};
use tracing::{error, info, info_span, instrument};
use types_proofs::{ProofAndHintBundle, ProofBundle};
use types_runtime::CancelChannel;
use util::{DefaultOption, default_option};
use util::{channels::TracedMessage, concurrency::runtime::sleep_forever_blocking, err_str};

use crate::{error::ProofManagerError, worker::ProofManagerConfig};

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
        let proof_response = match type_ {
            // Update proofs
            ProofJob::ValidBalanceCreate { witness, statement } => {
                self.prove_valid_balance_create(witness, statement)
            },
            ProofJob::ValidDeposit { witness, statement } => {
                self.prove_valid_deposit(witness, statement)
            },
            ProofJob::ValidOrderCancellation { witness, statement } => {
                self.prove_valid_order_cancellation(witness, statement)
            },
            ProofJob::ValidWithdrawal { witness, statement } => {
                self.prove_valid_withdrawal(witness, statement)
            },
            // Validity proofs
            ProofJob::IntentAndBalanceValidity { witness, statement } => {
                self.prove_intent_and_balance_validity(witness, statement)
            },
            ProofJob::IntentAndBalanceFirstFillValidity { witness, statement } => {
                self.prove_intent_and_balance_first_fill_validity(witness, statement)
            },
            ProofJob::IntentOnlyValidity { witness, statement } => {
                self.prove_intent_only_validity(witness, statement)
            },
            ProofJob::IntentOnlyFirstFillValidity { witness, statement } => {
                self.prove_intent_only_first_fill_validity(witness, statement)
            },
            ProofJob::NewOutputBalanceValidity { witness, statement } => {
                self.prove_new_output_balance_validity(witness, statement)
            },
            ProofJob::OutputBalanceValidity { witness, statement } => {
                self.prove_output_balance_validity(witness, statement)
            },
            // Settlement proofs
            ProofJob::IntentAndBalanceBoundedSettlement { witness, statement } => {
                self.prove_intent_and_balance_bounded_settlement(witness, statement)
            },
            ProofJob::IntentAndBalancePrivateSettlement { witness, statement } => {
                self.prove_intent_and_balance_private_settlement(witness, statement)
            },
            ProofJob::IntentAndBalancePublicSettlement { witness, statement } => {
                self.prove_intent_and_balance_public_settlement(witness, statement)
            },
            ProofJob::IntentOnlyBoundedSettlement { witness, statement } => {
                self.prove_intent_only_bounded_settlement(witness, statement)
            },
            ProofJob::IntentOnlyPublicSettlement { witness, statement } => {
                self.prove_intent_only_public_settlement(witness, statement)
            },
            // Fee proofs
            ProofJob::ValidNoteRedemption { witness, statement } => {
                self.prove_valid_note_redemption(witness, statement)
            },
            ProofJob::ValidPrivateProtocolFeePayment { witness, statement } => {
                self.prove_valid_private_protocol_fee_payment(witness, statement)
            },
            ProofJob::ValidPrivateRelayerFeePayment { witness, statement } => {
                self.prove_valid_private_relayer_fee_payment(witness, statement)
            },
            ProofJob::ValidPublicProtocolFeePayment { witness, statement } => {
                self.prove_valid_public_protocol_fee_payment(witness, statement)
            },
            ProofJob::ValidPublicRelayerFeePayment { witness, statement } => {
                self.prove_valid_public_relayer_fee_payment(witness, statement)
            },
        }?;

        response_channel
            .send(proof_response)
            .map_err(|_| ProofManagerError::Response(ERR_SENDING_RESPONSE.to_string()))
    }

    /// Initialize the proving key/verification key & circuit layout caches for
    /// all of the circuits
    pub(crate) fn preprocess_circuits() -> Result<(), ProofManagerError> {
        // Set up the proving & verification keys for all of the circuits
        // Update proofs
        setup_preprocessed_keys::<ValidBalanceCreate>();
        setup_preprocessed_keys::<SizedValidDeposit>();
        setup_preprocessed_keys::<SizedValidOrderCancellationCircuit>();
        setup_preprocessed_keys::<SizedValidWithdrawal>();
        // Validity proofs
        setup_preprocessed_keys::<SizedIntentAndBalanceValidityCircuit>();
        setup_preprocessed_keys::<SizedIntentAndBalanceFirstFillValidityCircuit>();
        setup_preprocessed_keys::<SizedIntentOnlyValidityCircuit>();
        setup_preprocessed_keys::<IntentOnlyFirstFillValidityCircuit>();
        setup_preprocessed_keys::<SizedNewOutputBalanceValidityCircuit>();
        setup_preprocessed_keys::<SizedOutputBalanceValidityCircuit>();
        // Settlement proofs
        setup_preprocessed_keys::<IntentAndBalanceBoundedSettlementCircuit>();
        setup_preprocessed_keys::<IntentAndBalancePrivateSettlementCircuit>();
        setup_preprocessed_keys::<IntentAndBalancePublicSettlementCircuit>();
        setup_preprocessed_keys::<IntentOnlyBoundedSettlementCircuit>();
        setup_preprocessed_keys::<IntentOnlyPublicSettlementCircuit>();
        // Fee proofs
        setup_preprocessed_keys::<SizedValidNoteRedemption>();
        setup_preprocessed_keys::<SizedValidPrivateProtocolFeePayment>();
        setup_preprocessed_keys::<SizedValidPrivateRelayerFeePayment>();
        setup_preprocessed_keys::<SizedValidPublicProtocolFeePayment>();
        setup_preprocessed_keys::<SizedValidPublicRelayerFeePayment>();

        // Set up layouts for all of the circuits
        // Update proofs
        ValidBalanceCreate::get_circuit_layout().map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidDeposit::get_circuit_layout().map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidOrderCancellationCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidWithdrawal::get_circuit_layout().map_err(err_str!(ProofManagerError::Setup))?;
        // Validity proofs
        SizedIntentAndBalanceValidityCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedIntentAndBalanceFirstFillValidityCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedIntentOnlyValidityCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        IntentOnlyFirstFillValidityCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedNewOutputBalanceValidityCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedOutputBalanceValidityCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        // Settlement proofs
        IntentAndBalanceBoundedSettlementCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        IntentAndBalancePrivateSettlementCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        IntentAndBalancePublicSettlementCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        IntentOnlyBoundedSettlementCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        IntentOnlyPublicSettlementCircuit::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        // Fee proofs
        SizedValidNoteRedemption::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidPrivateProtocolFeePayment::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidPrivateRelayerFeePayment::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidPublicProtocolFeePayment::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;
        SizedValidPublicRelayerFeePayment::get_circuit_layout()
            .map_err(err_str!(ProofManagerError::Setup))?;

        Ok(())
    }

    // Update proofs
    /// Create a proof of `VALID BALANCE CREATE`
    #[instrument(skip_all, err)]
    fn prove_valid_balance_create(
        &self,
        witness: ValidBalanceCreateWitness,
        statement: ValidBalanceCreateStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof = singleprover_prove::<ValidBalanceCreate>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidBalanceCreate(bundle))
    }

    /// Create a proof of `VALID DEPOSIT`
    #[instrument(skip_all, err)]
    fn prove_valid_deposit(
        &self,
        witness: SizedValidDepositWitness,
        statement: ValidDepositStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof = singleprover_prove::<SizedValidDeposit>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidDeposit(bundle))
    }

    /// Create a proof of `VALID ORDER CANCELLATION`
    #[instrument(skip_all, err)]
    fn prove_valid_order_cancellation(
        &self,
        witness: SizedValidOrderCancellationWitness,
        statement: ValidOrderCancellationStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof = singleprover_prove::<SizedValidOrderCancellationCircuit>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidOrderCancellation(bundle))
    }

    /// Create a proof of `VALID WITHDRAWAL`
    #[instrument(skip_all, err)]
    fn prove_valid_withdrawal(
        &self,
        witness: SizedValidWithdrawalWitness,
        statement: ValidWithdrawalStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof = singleprover_prove::<SizedValidWithdrawal>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidWithdrawal(bundle))
    }

    // Validity proofs
    /// Create a proof of `INTENT AND BALANCE VALIDITY`
    #[instrument(skip_all, err)]
    fn prove_intent_and_balance_validity(
        &self,
        witness: SizedIntentAndBalanceValidityWitness,
        statement: IntentAndBalanceValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<
            SizedIntentAndBalanceValidityCircuit,
        >(&witness, &statement)?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentAndBalanceValidity(bundle))
    }

    /// Create a proof of `INTENT AND BALANCE FIRST FILL VALIDITY`
    #[instrument(skip_all, err)]
    fn prove_intent_and_balance_first_fill_validity(
        &self,
        witness: SizedIntentAndBalanceFirstFillValidityWitness,
        statement: IntentAndBalanceFirstFillValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<
            SizedIntentAndBalanceFirstFillValidityCircuit,
        >(&witness, &statement)?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentAndBalanceFirstFillValidity(bundle))
    }

    /// Create a proof of `INTENT ONLY VALIDITY`
    #[instrument(skip_all, err)]
    fn prove_intent_only_validity(
        &self,
        witness: SizedIntentOnlyValidityWitness,
        statement: IntentOnlyValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) =
            singleprover_prove_with_hint::<SizedIntentOnlyValidityCircuit>(&witness, &statement)?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentOnlyValidity(bundle))
    }

    /// Create a proof of `INTENT ONLY FIRST FILL VALIDITY`
    #[instrument(skip_all, err)]
    fn prove_intent_only_first_fill_validity(
        &self,
        witness: IntentOnlyFirstFillValidityWitness,
        statement: IntentOnlyFirstFillValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<IntentOnlyFirstFillValidityCircuit>(
            &witness, &statement,
        )?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentOnlyFirstFillValidity(bundle))
    }

    /// Create a proof of `NEW OUTPUT BALANCE VALIDITY`
    #[instrument(skip_all, err)]
    fn prove_new_output_balance_validity(
        &self,
        witness: SizedNewOutputBalanceValidityWitness,
        statement: NewOutputBalanceValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<
            SizedNewOutputBalanceValidityCircuit,
        >(&witness, &statement)?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::NewOutputBalanceValidity(bundle))
    }

    /// Create a proof of `OUTPUT BALANCE VALIDITY`
    #[instrument(skip_all, err)]
    fn prove_output_balance_validity(
        &self,
        witness: SizedOutputBalanceValidityWitness,
        statement: OutputBalanceValidityStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<SizedOutputBalanceValidityCircuit>(
            &witness, &statement,
        )?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::OutputBalanceValidity(bundle))
    }

    // Settlement proofs
    /// Create a proof of `INTENT AND BALANCE BOUNDED SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_intent_and_balance_bounded_settlement(
        &self,
        witness: IntentAndBalanceBoundedSettlementWitness,
        statement: IntentAndBalanceBoundedSettlementStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<
            IntentAndBalanceBoundedSettlementCircuit,
        >(&witness, &statement)?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentAndBalanceBoundedSettlement(bundle))
    }

    /// Create a proof of `INTENT AND BALANCE PRIVATE SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_intent_and_balance_private_settlement(
        &self,
        witness: IntentAndBalancePrivateSettlementWitness,
        statement: IntentAndBalancePrivateSettlementStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePrivateSettlementCircuit,
        >(&witness, &statement)?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentAndBalancePrivateSettlement(bundle))
    }

    /// Create a proof of `INTENT AND BALANCE PUBLIC SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_intent_and_balance_public_settlement(
        &self,
        witness: IntentAndBalancePublicSettlementWitness,
        statement: IntentAndBalancePublicSettlementStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<
            IntentAndBalancePublicSettlementCircuit,
        >(&witness, &statement)?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentAndBalancePublicSettlement(bundle))
    }

    /// Create a proof of `INTENT ONLY BOUNDED SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_intent_only_bounded_settlement(
        &self,
        witness: IntentOnlyBoundedSettlementWitness,
        statement: IntentOnlyBoundedSettlementStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<IntentOnlyBoundedSettlementCircuit>(
            &witness, &statement,
        )?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentOnlyBoundedSettlement(bundle))
    }

    /// Create a proof of `INTENT ONLY PUBLIC SETTLEMENT`
    #[instrument(skip_all, err)]
    fn prove_intent_only_public_settlement(
        &self,
        witness: IntentOnlyPublicSettlementWitness,
        statement: IntentOnlyPublicSettlementStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let (proof, link_hint) = singleprover_prove_with_hint::<IntentOnlyPublicSettlementCircuit>(
            &witness, &statement,
        )?;
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentOnlyPublicSettlement(bundle))
    }

    // Fee proofs
    /// Create a proof of `VALID NOTE REDEMPTION`
    #[instrument(skip_all, err)]
    fn prove_valid_note_redemption(
        &self,
        witness: SizedValidNoteRedemptionWitness,
        statement: ValidNoteRedemptionStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof = singleprover_prove::<SizedValidNoteRedemption>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidNoteRedemption(bundle))
    }

    /// Create a proof of `VALID PRIVATE PROTOCOL FEE PAYMENT`
    #[instrument(skip_all, err)]
    fn prove_valid_private_protocol_fee_payment(
        &self,
        witness: SizedValidPrivateProtocolFeePaymentWitness,
        statement: ValidPrivateProtocolFeePaymentStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof =
            singleprover_prove::<SizedValidPrivateProtocolFeePayment>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidPrivateProtocolFeePayment(bundle))
    }

    /// Create a proof of `VALID PRIVATE RELAYER FEE PAYMENT`
    #[instrument(skip_all, err)]
    fn prove_valid_private_relayer_fee_payment(
        &self,
        witness: SizedValidPrivateRelayerFeePaymentWitness,
        statement: ValidPrivateRelayerFeePaymentStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof = singleprover_prove::<SizedValidPrivateRelayerFeePayment>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidPrivateRelayerFeePayment(bundle))
    }

    /// Create a proof of `VALID PUBLIC PROTOCOL FEE PAYMENT`
    #[instrument(skip_all, err)]
    fn prove_valid_public_protocol_fee_payment(
        &self,
        witness: SizedValidPublicProtocolFeePaymentWitness,
        statement: ValidPublicProtocolFeePaymentStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof = singleprover_prove::<SizedValidPublicProtocolFeePayment>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidPublicProtocolFeePayment(bundle))
    }

    /// Create a proof of `VALID PUBLIC RELAYER FEE PAYMENT`
    #[instrument(skip_all, err)]
    fn prove_valid_public_relayer_fee_payment(
        &self,
        witness: SizedValidPublicRelayerFeePaymentWitness,
        statement: ValidPublicRelayerFeePaymentStatement,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        let proof = singleprover_prove::<SizedValidPublicRelayerFeePayment>(&witness, &statement)?;
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidPublicRelayerFeePayment(bundle))
    }
}
