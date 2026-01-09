//! Defines job types that may be enqueued by other workers in the local node
//! for the proof generation module to process
//!
//! See the whitepaper https://renegade.fi/whitepaper.pdf for a formal specification
//! of the types defined here

use circuits_core::zk_circuits::{
    fees::{
        valid_note_redemption::{SizedValidNoteRedemptionWitness, ValidNoteRedemptionStatement},
        valid_private_protocol_fee_payment::{
            SizedValidPrivateProtocolFeePaymentWitness, ValidPrivateProtocolFeePaymentStatement,
        },
        valid_private_relayer_fee_payment::{
            SizedValidPrivateRelayerFeePaymentWitness, ValidPrivateRelayerFeePaymentStatement,
        },
        valid_public_protocol_fee_payment::{
            SizedValidPublicProtocolFeePaymentWitness, ValidPublicProtocolFeePaymentStatement,
        },
        valid_public_relayer_fee_payment::{
            SizedValidPublicRelayerFeePaymentWitness, ValidPublicRelayerFeePaymentStatement,
        },
    },
    settlement::{
        intent_and_balance_bounded_settlement::{
            IntentAndBalanceBoundedSettlementStatement, IntentAndBalanceBoundedSettlementWitness,
        },
        intent_and_balance_private_settlement::{
            IntentAndBalancePrivateSettlementStatement, IntentAndBalancePrivateSettlementWitness,
        },
        intent_and_balance_public_settlement::{
            IntentAndBalancePublicSettlementStatement, IntentAndBalancePublicSettlementWitness,
        },
        intent_only_bounded_settlement::{
            IntentOnlyBoundedSettlementStatement, IntentOnlyBoundedSettlementWitness,
        },
        intent_only_public_settlement::{
            IntentOnlyPublicSettlementStatement, IntentOnlyPublicSettlementWitness,
        },
    },
    valid_balance_create::{ValidBalanceCreateStatement, ValidBalanceCreateWitness},
    valid_deposit::{SizedValidDepositWitness, ValidDepositStatement},
    valid_order_cancellation::{
        SizedValidOrderCancellationWitness, ValidOrderCancellationStatement,
    },
    valid_withdrawal::{SizedValidWithdrawalWitness, ValidWithdrawalStatement},
    validity_proofs::{
        intent_and_balance::{
            IntentAndBalanceValidityStatement, SizedIntentAndBalanceValidityWitness,
        },
        intent_and_balance_first_fill::{
            IntentAndBalanceFirstFillValidityStatement,
            SizedIntentAndBalanceFirstFillValidityWitness,
        },
        intent_only::{IntentOnlyValidityStatement, SizedIntentOnlyValidityWitness},
        intent_only_first_fill::{
            IntentOnlyFirstFillValidityStatement, IntentOnlyFirstFillValidityWitness,
        },
        new_output_balance::{
            NewOutputBalanceValidityStatement, SizedNewOutputBalanceValidityWitness,
        },
        output_balance::{OutputBalanceValidityStatement, SizedOutputBalanceValidityWitness},
    },
};
use tokio::sync::oneshot::Sender;
use types_proofs::{
    IntentAndBalanceBoundedSettlementBundle, IntentAndBalanceFirstFillValidityBundle,
    IntentAndBalancePrivateSettlementBundle, IntentAndBalancePublicSettlementBundle,
    IntentAndBalanceValidityBundle, IntentOnlyBoundedSettlementBundle,
    IntentOnlyFirstFillValidityBundle, IntentOnlyPublicSettlementBundle, IntentOnlyValidityBundle,
    NewOutputBalanceValidityBundle, OutputBalanceValidityBundle, ValidBalanceCreateBundle,
    ValidDepositBundle, ValidNoteRedemptionBundle, ValidOrderCancellationBundle,
    ValidPrivateProtocolFeePaymentBundle, ValidPrivateRelayerFeePaymentBundle,
    ValidPublicProtocolFeePaymentBundle, ValidPublicRelayerFeePaymentBundle, ValidWithdrawalBundle,
};
use util::channels::{
    TracedCrossbeamReceiver, TracedCrossbeamSender, new_traced_crossbeam_channel,
};

/// The queue type for the proof manager
pub type ProofManagerQueue = TracedCrossbeamSender<ProofManagerJob>;
/// The receiver type for the proof manager
pub type ProofManagerReceiver = TracedCrossbeamReceiver<ProofManagerJob>;

/// Create a new proof manager queue and receiver
pub fn new_proof_manager_queue() -> (ProofManagerQueue, ProofManagerReceiver) {
    new_traced_crossbeam_channel()
}

// -------------
// | Job Types |
// -------------

/// A response type representing any proof bundle that the proof manager can
/// return
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum ProofManagerResponse {
    // Update proofs
    /// A proof bundle for `VALID BALANCE CREATE`
    ValidBalanceCreate(ValidBalanceCreateBundle),
    /// A proof bundle for `VALID DEPOSIT`
    ValidDeposit(ValidDepositBundle),
    /// A proof bundle for `VALID ORDER CANCELLATION`
    ValidOrderCancellation(ValidOrderCancellationBundle),
    /// A proof bundle for `VALID WITHDRAWAL`
    ValidWithdrawal(ValidWithdrawalBundle),
    // Validity proofs
    /// A proof bundle for `INTENT AND BALANCE VALIDITY`
    IntentAndBalanceValidity(IntentAndBalanceValidityBundle),
    /// A proof bundle for `INTENT AND BALANCE FIRST FILL VALIDITY`
    IntentAndBalanceFirstFillValidity(IntentAndBalanceFirstFillValidityBundle),
    /// A proof bundle for `INTENT ONLY VALIDITY`
    IntentOnlyValidity(IntentOnlyValidityBundle),
    /// A proof bundle for `INTENT ONLY FIRST FILL VALIDITY`
    IntentOnlyFirstFillValidity(IntentOnlyFirstFillValidityBundle),
    /// A proof bundle for `NEW OUTPUT BALANCE VALIDITY`
    NewOutputBalanceValidity(NewOutputBalanceValidityBundle),
    /// A proof bundle for `OUTPUT BALANCE VALIDITY`
    OutputBalanceValidity(OutputBalanceValidityBundle),
    // Settlement proofs
    /// A proof bundle for `INTENT AND BALANCE BOUNDED SETTLEMENT`
    IntentAndBalanceBoundedSettlement(IntentAndBalanceBoundedSettlementBundle),
    /// A proof bundle for `INTENT AND BALANCE PRIVATE SETTLEMENT`
    IntentAndBalancePrivateSettlement(IntentAndBalancePrivateSettlementBundle),
    /// A proof bundle for `INTENT AND BALANCE PUBLIC SETTLEMENT`
    IntentAndBalancePublicSettlement(IntentAndBalancePublicSettlementBundle),
    /// A proof bundle for `INTENT ONLY BOUNDED SETTLEMENT`
    IntentOnlyBoundedSettlement(IntentOnlyBoundedSettlementBundle),
    /// A proof bundle for `INTENT ONLY PUBLIC SETTLEMENT`
    IntentOnlyPublicSettlement(IntentOnlyPublicSettlementBundle),
    // Fee proofs
    /// A proof bundle for `VALID NOTE REDEMPTION`
    ValidNoteRedemption(ValidNoteRedemptionBundle),
    /// A proof bundle for `VALID PRIVATE PROTOCOL FEE PAYMENT`
    ValidPrivateProtocolFeePayment(ValidPrivateProtocolFeePaymentBundle),
    /// A proof bundle for `VALID PRIVATE RELAYER FEE PAYMENT`
    ValidPrivateRelayerFeePayment(ValidPrivateRelayerFeePaymentBundle),
    /// A proof bundle for `VALID PUBLIC PROTOCOL FEE PAYMENT`
    ValidPublicProtocolFeePayment(ValidPublicProtocolFeePaymentBundle),
    /// A proof bundle for `VALID PUBLIC RELAYER FEE PAYMENT`
    ValidPublicRelayerFeePayment(ValidPublicRelayerFeePaymentBundle),
}

/// Represents a job enqueued in the proof manager's work queue
#[derive(Debug)]
pub struct ProofManagerJob {
    /// The type of job being requested
    pub type_: ProofJob,
    /// The response channel to send the proof back along
    pub response_channel: Sender<ProofManagerResponse>,
}

/// The job type and parameterization
#[derive(Clone, Debug)]
#[allow(clippy::large_enum_variant, clippy::enum_variant_names)]
pub enum ProofJob {
    // Update proofs
    /// Prove `VALID BALANCE CREATE`
    ValidBalanceCreate {
        witness: ValidBalanceCreateWitness,
        statement: ValidBalanceCreateStatement,
    },
    /// Prove `VALID DEPOSIT`
    ValidDeposit { witness: SizedValidDepositWitness, statement: ValidDepositStatement },
    /// Prove `VALID ORDER CANCELLATION`
    ValidOrderCancellation {
        witness: SizedValidOrderCancellationWitness,
        statement: ValidOrderCancellationStatement,
    },
    /// Prove `VALID WITHDRAWAL`
    ValidWithdrawal { witness: SizedValidWithdrawalWitness, statement: ValidWithdrawalStatement },
    // Validity proofs
    /// Prove `INTENT AND BALANCE VALIDITY`
    IntentAndBalanceValidity {
        witness: SizedIntentAndBalanceValidityWitness,
        statement: IntentAndBalanceValidityStatement,
    },
    /// Prove `INTENT AND BALANCE FIRST FILL VALIDITY`
    IntentAndBalanceFirstFillValidity {
        witness: SizedIntentAndBalanceFirstFillValidityWitness,
        statement: IntentAndBalanceFirstFillValidityStatement,
    },
    /// Prove `INTENT ONLY VALIDITY`
    IntentOnlyValidity {
        witness: SizedIntentOnlyValidityWitness,
        statement: IntentOnlyValidityStatement,
    },
    /// Prove `INTENT ONLY FIRST FILL VALIDITY`
    IntentOnlyFirstFillValidity {
        witness: IntentOnlyFirstFillValidityWitness,
        statement: IntentOnlyFirstFillValidityStatement,
    },
    /// Prove `NEW OUTPUT BALANCE VALIDITY`
    NewOutputBalanceValidity {
        witness: SizedNewOutputBalanceValidityWitness,
        statement: NewOutputBalanceValidityStatement,
    },
    /// Prove `OUTPUT BALANCE VALIDITY`
    OutputBalanceValidity {
        witness: SizedOutputBalanceValidityWitness,
        statement: OutputBalanceValidityStatement,
    },
    // Settlement proofs
    /// Prove `INTENT AND BALANCE BOUNDED SETTLEMENT`
    IntentAndBalanceBoundedSettlement {
        witness: IntentAndBalanceBoundedSettlementWitness,
        statement: IntentAndBalanceBoundedSettlementStatement,
    },
    /// Prove `INTENT AND BALANCE PRIVATE SETTLEMENT`
    IntentAndBalancePrivateSettlement {
        witness: IntentAndBalancePrivateSettlementWitness,
        statement: IntentAndBalancePrivateSettlementStatement,
    },
    /// Prove `INTENT AND BALANCE PUBLIC SETTLEMENT`
    IntentAndBalancePublicSettlement {
        witness: IntentAndBalancePublicSettlementWitness,
        statement: IntentAndBalancePublicSettlementStatement,
    },
    /// Prove `INTENT ONLY BOUNDED SETTLEMENT`
    IntentOnlyBoundedSettlement {
        witness: IntentOnlyBoundedSettlementWitness,
        statement: IntentOnlyBoundedSettlementStatement,
    },
    /// Prove `INTENT ONLY PUBLIC SETTLEMENT`
    IntentOnlyPublicSettlement {
        witness: IntentOnlyPublicSettlementWitness,
        statement: IntentOnlyPublicSettlementStatement,
    },
    // Fee proofs
    /// Prove `VALID NOTE REDEMPTION`
    ValidNoteRedemption {
        witness: SizedValidNoteRedemptionWitness,
        statement: ValidNoteRedemptionStatement,
    },
    /// Prove `VALID PRIVATE PROTOCOL FEE PAYMENT`
    ValidPrivateProtocolFeePayment {
        witness: SizedValidPrivateProtocolFeePaymentWitness,
        statement: ValidPrivateProtocolFeePaymentStatement,
    },
    /// Prove `VALID PRIVATE RELAYER FEE PAYMENT`
    ValidPrivateRelayerFeePayment {
        witness: SizedValidPrivateRelayerFeePaymentWitness,
        statement: ValidPrivateRelayerFeePaymentStatement,
    },
    /// Prove `VALID PUBLIC PROTOCOL FEE PAYMENT`
    ValidPublicProtocolFeePayment {
        witness: SizedValidPublicProtocolFeePaymentWitness,
        statement: ValidPublicProtocolFeePaymentStatement,
    },
    /// Prove `VALID PUBLIC RELAYER FEE PAYMENT`
    ValidPublicRelayerFeePayment {
        witness: SizedValidPublicRelayerFeePaymentWitness,
        statement: ValidPublicRelayerFeePaymentStatement,
    },
}
