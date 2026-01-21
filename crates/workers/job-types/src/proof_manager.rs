//! Defines job types that may be enqueued by other workers in the local node
//! for the proof generation module to process
//!
//! See the whitepaper https://renegade.fi/whitepaper.pdf for a formal specification
//! of the types defined here

use ark_mpc::network::PartyId;
use circuit_types::ProofLinkingHint;
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

// ------------
// | Response |
// ------------

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

impl From<ProofManagerResponse> for ValidBalanceCreateBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidBalanceCreate(bundle) => bundle,
            other => panic!("Expected ValidBalanceCreate, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for ValidDepositBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidDeposit(bundle) => bundle,
            other => panic!("Expected ValidDeposit, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for ValidOrderCancellationBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidOrderCancellation(bundle) => bundle,
            other => panic!("Expected ValidOrderCancellation, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for ValidWithdrawalBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidWithdrawal(bundle) => bundle,
            other => panic!("Expected ValidWithdrawal, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentAndBalanceValidityBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentAndBalanceValidity(bundle) => bundle,
            other => panic!("Expected IntentAndBalanceValidity, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentAndBalanceFirstFillValidityBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentAndBalanceFirstFillValidity(bundle) => bundle,
            other => panic!("Expected IntentAndBalanceFirstFillValidity, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentOnlyValidityBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentOnlyValidity(bundle) => bundle,
            other => panic!("Expected IntentOnlyValidity, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentOnlyFirstFillValidityBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentOnlyFirstFillValidity(bundle) => bundle,
            other => panic!("Expected IntentOnlyFirstFillValidity, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for NewOutputBalanceValidityBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::NewOutputBalanceValidity(bundle) => bundle,
            other => panic!("Expected NewOutputBalanceValidity, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for OutputBalanceValidityBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::OutputBalanceValidity(bundle) => bundle,
            other => panic!("Expected OutputBalanceValidity, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentAndBalanceBoundedSettlementBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentAndBalanceBoundedSettlement(bundle) => bundle,
            other => panic!("Expected IntentAndBalanceBoundedSettlement, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentAndBalancePrivateSettlementBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentAndBalancePrivateSettlement(bundle) => bundle,
            other => panic!("Expected IntentAndBalancePrivateSettlement, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentAndBalancePublicSettlementBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentAndBalancePublicSettlement(bundle) => bundle,
            other => panic!("Expected IntentAndBalancePublicSettlement, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentOnlyBoundedSettlementBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentOnlyBoundedSettlement(bundle) => bundle,
            other => panic!("Expected IntentOnlyBoundedSettlement, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for IntentOnlyPublicSettlementBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::IntentOnlyPublicSettlement(bundle) => bundle,
            other => panic!("Expected IntentOnlyPublicSettlement, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for ValidNoteRedemptionBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidNoteRedemption(bundle) => bundle,
            other => panic!("Expected ValidNoteRedemption, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for ValidPrivateProtocolFeePaymentBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidPrivateProtocolFeePayment(bundle) => bundle,
            other => panic!("Expected ValidPrivateProtocolFeePayment, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for ValidPrivateRelayerFeePaymentBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidPrivateRelayerFeePayment(bundle) => bundle,
            other => panic!("Expected ValidPrivateRelayerFeePayment, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for ValidPublicProtocolFeePaymentBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidPublicProtocolFeePayment(bundle) => bundle,
            other => panic!("Expected ValidPublicProtocolFeePayment, got {:?}", other),
        }
    }
}

impl From<ProofManagerResponse> for ValidPublicRelayerFeePaymentBundle {
    fn from(value: ProofManagerResponse) -> Self {
        match value {
            ProofManagerResponse::ValidPublicRelayerFeePayment(bundle) => bundle,
            other => panic!("Expected ValidPublicRelayerFeePayment, got {:?}", other),
        }
    }
}

// ------------
// | Job Type |
// ------------

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
        /// The link hint for the validity proof
        validity_link_hint: ProofLinkingHint,
    },
    /// Prove `INTENT AND BALANCE PRIVATE SETTLEMENT`
    IntentAndBalancePrivateSettlement {
        witness: IntentAndBalancePrivateSettlementWitness,
        statement: IntentAndBalancePrivateSettlementStatement,
        /// The link hint for party 0's validity proof
        validity_link_hint_0: ProofLinkingHint,
        /// The link hint for party 1's validity proof
        validity_link_hint_1: ProofLinkingHint,
        /// The link hint for party 0's output balance validity proof
        output_balance_link_hint_0: ProofLinkingHint,
        /// The link hint for party 1's output balance validity proof
        output_balance_link_hint_1: ProofLinkingHint,
    },
    /// Prove `INTENT AND BALANCE PUBLIC SETTLEMENT`
    IntentAndBalancePublicSettlement {
        witness: IntentAndBalancePublicSettlementWitness,
        statement: IntentAndBalancePublicSettlementStatement,
        /// The party ID (0 or 1) for two-party settlements
        party_id: PartyId,
        /// The link hint for the validity proof
        validity_link_hint: ProofLinkingHint,
    },
    /// Prove `INTENT ONLY BOUNDED SETTLEMENT`
    IntentOnlyBoundedSettlement {
        witness: IntentOnlyBoundedSettlementWitness,
        statement: IntentOnlyBoundedSettlementStatement,
        /// The link hint for the validity proof
        validity_link_hint: ProofLinkingHint,
    },
    /// Prove `INTENT ONLY PUBLIC SETTLEMENT`
    IntentOnlyPublicSettlement {
        witness: IntentOnlyPublicSettlementWitness,
        statement: IntentOnlyPublicSettlementStatement,
        /// The link hint for the validity proof
        validity_link_hint: ProofLinkingHint,
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
