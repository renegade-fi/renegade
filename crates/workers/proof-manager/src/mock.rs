//! Defines a mock for the proof manager that doesn't prove statements, but
//! instead immediately returns dummy proofs that will not verify

use circuit_types::traits::SingleProverCircuit;
use circuits_core::test_helpers::circuits::check_constraints_satisfied;
use circuits_core::zk_circuits::{
    fees::{
        valid_note_redemption::{
            SizedValidNoteRedemption, SizedValidNoteRedemptionWitness, ValidNoteRedemptionStatement,
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
            IntentAndBalanceBoundedSettlementCircuit, IntentAndBalanceBoundedSettlementStatement,
            IntentAndBalanceBoundedSettlementWitness,
        },
        intent_and_balance_private_settlement::{
            IntentAndBalancePrivateSettlementCircuit, IntentAndBalancePrivateSettlementStatement,
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
};
use job_types::proof_manager::{
    ProofJob, ProofManagerJob, ProofManagerReceiver, ProofManagerResponse,
};
use tokio::runtime::Handle;
use tracing::{error, instrument};
use types_proofs::mocks::{dummy_link_hint, dummy_link_proof, dummy_proof};
use types_proofs::{
    IntentOnlySettlementProofBundle, PrivateSettlementProofBundle, ProofAndHintBundle, ProofBundle,
    PublicSettlementProofBundle,
};
use util::channels::TracedMessage;

use crate::error::ProofManagerError;

/// The error message emitted when a response channel closes early
const ERR_RESPONSE_CHANNEL_CLOSED: &str = "error sending proof, channel closed";

// -----------
// | Helpers |
// -----------

/// The mock proof manager
#[derive(Default)]
pub struct MockProofManager;
#[allow(clippy::needless_pass_by_value)]
impl MockProofManager {
    /// Start a mock proof manager
    pub fn start(job_queue: ProofManagerReceiver, skip_constraints: bool) {
        Handle::current().spawn_blocking(move || {
            if let Err(e) = Self::execution_loop(&job_queue, skip_constraints) {
                error!("error in mock proof manager: {e}");
            }
        });
    }

    /// The execution loop for the mock
    fn execution_loop(
        job_queue: &ProofManagerReceiver,
        skip_constraints: bool,
    ) -> Result<(), ProofManagerError> {
        loop {
            match job_queue.recv() {
                Err(_) => {
                    return Err(ProofManagerError::JobQueueClosed("job queue closed".to_string()));
                },
                Ok(job) => Self::handle_job(job, skip_constraints)?,
            }
        }
    }

    /// Handle a job by immediately returning a dummy proof
    #[instrument(name = "handle_proof_manager_job", skip(job))]
    fn handle_job(
        job: TracedMessage<ProofManagerJob>,
        skip_constraints: bool,
    ) -> Result<(), ProofManagerError> {
        let ProofManagerJob { type_, response_channel } = job.consume();
        let response = match type_ {
            // Update proofs
            ProofJob::ValidBalanceCreate { witness, statement } => {
                Self::valid_balance_create(witness, statement, skip_constraints)
            },
            ProofJob::ValidDeposit { witness, statement } => {
                Self::valid_deposit(witness, statement, skip_constraints)
            },
            ProofJob::ValidOrderCancellation { witness, statement } => {
                Self::valid_order_cancellation(witness, statement, skip_constraints)
            },
            ProofJob::ValidWithdrawal { witness, statement } => {
                Self::valid_withdrawal(witness, statement, skip_constraints)
            },
            // Validity proofs
            ProofJob::IntentAndBalanceValidity { witness, statement } => {
                Self::intent_and_balance_validity(witness, statement, skip_constraints)
            },
            ProofJob::IntentAndBalanceFirstFillValidity { witness, statement } => {
                Self::intent_and_balance_first_fill_validity(witness, statement, skip_constraints)
            },
            ProofJob::IntentOnlyValidity { witness, statement } => {
                Self::intent_only_validity(witness, statement, skip_constraints)
            },
            ProofJob::IntentOnlyFirstFillValidity { witness, statement } => {
                Self::intent_only_first_fill_validity(witness, statement, skip_constraints)
            },
            ProofJob::NewOutputBalanceValidity { witness, statement } => {
                Self::new_output_balance_validity(witness, statement, skip_constraints)
            },
            ProofJob::OutputBalanceValidity { witness, statement } => {
                Self::output_balance_validity(witness, statement, skip_constraints)
            },
            // Settlement proofs
            ProofJob::IntentAndBalanceBoundedSettlement { witness, statement, .. } => {
                Self::intent_and_balance_bounded_settlement(witness, statement, skip_constraints)
            },
            ProofJob::IntentAndBalancePrivateSettlement { witness, statement, .. } => {
                Self::intent_and_balance_private_settlement(witness, statement, skip_constraints)
            },
            ProofJob::IntentAndBalancePublicSettlement { witness, statement, .. } => {
                Self::intent_and_balance_public_settlement(witness, statement, skip_constraints)
            },
            ProofJob::IntentOnlyBoundedSettlement { witness, statement, .. } => {
                Self::intent_only_bounded_settlement(witness, statement, skip_constraints)
            },
            ProofJob::IntentOnlyPublicSettlement { witness, statement, .. } => {
                Self::intent_only_public_settlement(witness, statement, skip_constraints)
            },
            // Fee proofs
            ProofJob::ValidNoteRedemption { witness, statement } => {
                Self::valid_note_redemption(witness, statement, skip_constraints)
            },
            ProofJob::ValidPrivateProtocolFeePayment { witness, statement } => {
                Self::valid_private_protocol_fee_payment(witness, statement, skip_constraints)
            },
            ProofJob::ValidPrivateRelayerFeePayment { witness, statement } => {
                Self::valid_private_relayer_fee_payment(witness, statement, skip_constraints)
            },
            ProofJob::ValidPublicProtocolFeePayment { witness, statement } => {
                Self::valid_public_protocol_fee_payment(witness, statement, skip_constraints)
            },
            ProofJob::ValidPublicRelayerFeePayment { witness, statement } => {
                Self::valid_public_relayer_fee_payment(witness, statement, skip_constraints)
            },
        }?;

        response_channel.send(response).expect(ERR_RESPONSE_CHANNEL_CLOSED);
        Ok(())
    }

    // Update proofs
    /// Generate a dummy proof of `VALID BALANCE CREATE`
    fn valid_balance_create(
        witness: ValidBalanceCreateWitness,
        statement: ValidBalanceCreateStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<ValidBalanceCreate>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidBalanceCreate(bundle))
    }

    /// Generate a dummy proof of `VALID DEPOSIT`
    fn valid_deposit(
        witness: SizedValidDepositWitness,
        statement: ValidDepositStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedValidDeposit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidDeposit(bundle))
    }

    /// Generate a dummy proof of `VALID ORDER CANCELLATION`
    fn valid_order_cancellation(
        witness: SizedValidOrderCancellationWitness,
        statement: ValidOrderCancellationStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedValidOrderCancellationCircuit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidOrderCancellation(bundle))
    }

    /// Generate a dummy proof of `VALID WITHDRAWAL`
    fn valid_withdrawal(
        witness: SizedValidWithdrawalWitness,
        statement: ValidWithdrawalStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedValidWithdrawal>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidWithdrawal(bundle))
    }

    // Validity proofs
    /// Generate a dummy proof of `INTENT AND BALANCE VALIDITY`
    fn intent_and_balance_validity(
        witness: SizedIntentAndBalanceValidityWitness,
        statement: IntentAndBalanceValidityStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedIntentAndBalanceValidityCircuit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentAndBalanceValidity(bundle))
    }

    /// Generate a dummy proof of `INTENT AND BALANCE FIRST FILL VALIDITY`
    fn intent_and_balance_first_fill_validity(
        witness: SizedIntentAndBalanceFirstFillValidityWitness,
        statement: IntentAndBalanceFirstFillValidityStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedIntentAndBalanceFirstFillValidityCircuit>(
                &witness, &statement,
            )?;
        }
        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentAndBalanceFirstFillValidity(bundle))
    }

    /// Generate a dummy proof of `INTENT ONLY VALIDITY`
    fn intent_only_validity(
        witness: SizedIntentOnlyValidityWitness,
        statement: IntentOnlyValidityStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedIntentOnlyValidityCircuit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentOnlyValidity(bundle))
    }

    /// Generate a dummy proof of `INTENT ONLY FIRST FILL VALIDITY`
    fn intent_only_first_fill_validity(
        witness: IntentOnlyFirstFillValidityWitness,
        statement: IntentOnlyFirstFillValidityStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<IntentOnlyFirstFillValidityCircuit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::IntentOnlyFirstFillValidity(bundle))
    }

    /// Generate a dummy proof of `NEW OUTPUT BALANCE VALIDITY`
    fn new_output_balance_validity(
        witness: SizedNewOutputBalanceValidityWitness,
        statement: NewOutputBalanceValidityStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedNewOutputBalanceValidityCircuit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::NewOutputBalanceValidity(bundle))
    }

    /// Generate a dummy proof of `OUTPUT BALANCE VALIDITY`
    fn output_balance_validity(
        witness: SizedOutputBalanceValidityWitness,
        statement: OutputBalanceValidityStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedOutputBalanceValidityCircuit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let link_hint = dummy_link_hint();
        let bundle = ProofAndHintBundle::new(proof, statement, link_hint);
        Ok(ProofManagerResponse::OutputBalanceValidity(bundle))
    }

    // Settlement proofs
    /// Generate a dummy proof of `INTENT AND BALANCE BOUNDED SETTLEMENT`
    fn intent_and_balance_bounded_settlement(
        witness: IntentAndBalanceBoundedSettlementWitness,
        statement: IntentAndBalanceBoundedSettlementStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<IntentAndBalanceBoundedSettlementCircuit>(
                &witness, &statement,
            )?;
        }
        let proof = dummy_proof();
        let link_proof = dummy_link_proof();
        let bundle = IntentOnlySettlementProofBundle::new(proof, statement, link_proof);
        Ok(ProofManagerResponse::IntentAndBalanceBoundedSettlement(bundle))
    }

    /// Generate a dummy proof of `INTENT AND BALANCE PRIVATE SETTLEMENT`
    fn intent_and_balance_private_settlement(
        witness: IntentAndBalancePrivateSettlementWitness,
        statement: IntentAndBalancePrivateSettlementStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<IntentAndBalancePrivateSettlementCircuit>(
                &witness, &statement,
            )?;
        }
        let proof = dummy_proof();
        let bundle = PrivateSettlementProofBundle::new(
            proof,
            statement,
            dummy_link_proof(),
            dummy_link_proof(),
            dummy_link_proof(),
            dummy_link_proof(),
        );
        Ok(ProofManagerResponse::IntentAndBalancePrivateSettlement(bundle))
    }

    /// Generate a dummy proof of `INTENT AND BALANCE PUBLIC SETTLEMENT`
    fn intent_and_balance_public_settlement(
        witness: IntentAndBalancePublicSettlementWitness,
        statement: IntentAndBalancePublicSettlementStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<IntentAndBalancePublicSettlementCircuit>(
                &witness, &statement,
            )?;
        }
        let proof = dummy_proof();
        let bundle = PublicSettlementProofBundle::new(
            proof,
            statement,
            dummy_link_proof(),
            dummy_link_proof(),
        );
        Ok(ProofManagerResponse::IntentAndBalancePublicSettlement(bundle))
    }

    /// Generate a dummy proof of `INTENT ONLY BOUNDED SETTLEMENT`
    fn intent_only_bounded_settlement(
        witness: IntentOnlyBoundedSettlementWitness,
        statement: IntentOnlyBoundedSettlementStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<IntentOnlyBoundedSettlementCircuit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let link_proof = dummy_link_proof();
        let bundle = IntentOnlySettlementProofBundle::new(proof, statement, link_proof);
        Ok(ProofManagerResponse::IntentOnlyBoundedSettlement(bundle))
    }

    /// Generate a dummy proof of `INTENT ONLY PUBLIC SETTLEMENT`
    fn intent_only_public_settlement(
        witness: IntentOnlyPublicSettlementWitness,
        statement: IntentOnlyPublicSettlementStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<IntentOnlyPublicSettlementCircuit>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let link_proof = dummy_link_proof();
        let bundle = IntentOnlySettlementProofBundle::new(proof, statement, link_proof);
        Ok(ProofManagerResponse::IntentOnlyPublicSettlement(bundle))
    }

    // Fee proofs
    /// Generate a dummy proof of `VALID NOTE REDEMPTION`
    fn valid_note_redemption(
        witness: SizedValidNoteRedemptionWitness,
        statement: ValidNoteRedemptionStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedValidNoteRedemption>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidNoteRedemption(bundle))
    }

    /// Generate a dummy proof of `VALID PRIVATE PROTOCOL FEE PAYMENT`
    fn valid_private_protocol_fee_payment(
        witness: SizedValidPrivateProtocolFeePaymentWitness,
        statement: ValidPrivateProtocolFeePaymentStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedValidPrivateProtocolFeePayment>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidPrivateProtocolFeePayment(bundle))
    }

    /// Generate a dummy proof of `VALID PRIVATE RELAYER FEE PAYMENT`
    fn valid_private_relayer_fee_payment(
        witness: SizedValidPrivateRelayerFeePaymentWitness,
        statement: ValidPrivateRelayerFeePaymentStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedValidPrivateRelayerFeePayment>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidPrivateRelayerFeePayment(bundle))
    }

    /// Generate a dummy proof of `VALID PUBLIC PROTOCOL FEE PAYMENT`
    fn valid_public_protocol_fee_payment(
        witness: SizedValidPublicProtocolFeePaymentWitness,
        statement: ValidPublicProtocolFeePaymentStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedValidPublicProtocolFeePayment>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidPublicProtocolFeePayment(bundle))
    }

    /// Generate a dummy proof of `VALID PUBLIC RELAYER FEE PAYMENT`
    fn valid_public_relayer_fee_payment(
        witness: SizedValidPublicRelayerFeePaymentWitness,
        statement: ValidPublicRelayerFeePaymentStatement,
        skip_constraints: bool,
    ) -> Result<ProofManagerResponse, ProofManagerError> {
        if !skip_constraints {
            Self::check_constraints::<SizedValidPublicRelayerFeePayment>(&witness, &statement)?;
        }
        let proof = dummy_proof();
        let bundle = ProofBundle::new(proof, statement);
        Ok(ProofManagerResponse::ValidPublicRelayerFeePayment(bundle))
    }

    /// Check constraint satisfaction for a witness and statement
    ///
    /// This helper effectively wraps a boolean in the error type needed by the
    /// interface
    fn check_constraints<C: SingleProverCircuit>(
        witness: &C::Witness,
        statement: &C::Statement,
    ) -> Result<(), ProofManagerError> {
        if !check_constraints_satisfied::<C>(witness, statement) {
            let err = format!("invalid witness and statement for {}", C::name());
            Err(ProofManagerError::Prover(err))
        } else {
            Ok(())
        }
    }
}
