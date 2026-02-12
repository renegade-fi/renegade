//! API types for the prover service
//!
//! Copied here to avoid cyclic dependencies between the relayer and the prover
//! service

//! The API for the prover service

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#![deny(clippy::needless_pass_by_ref_mut)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::unused_async)]

use circuit_types::{PlonkLinkProof, PlonkProof, ProofLinkingHint};
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
use serde::{Deserialize, Serialize};

// ------------------
// | Response Types |
// ------------------

/// A generic response representing a Plonk proof
#[derive(Serialize, Deserialize)]
pub struct ProofResponse {
    /// The proof
    pub proof: PlonkProof,
}

/// A generic response type representing a Plonk proof and a linking hint
#[derive(Serialize, Deserialize)]
pub struct ProofAndHintResponse {
    /// The proof
    pub proof: PlonkProof,
    /// The proof's link hint
    pub link_hint: ProofLinkingHint,
}

/// A settlement proof response with a linking proof
///
/// Sent by the prover service for settlement proofs that compute a single
/// linking proof
#[derive(Serialize, Deserialize)]
pub struct SettlementProofResponse {
    /// The settlement proof
    pub proof: PlonkProof,
    /// The linking proof
    pub link_proof: PlonkLinkProof,
}

/// A private settlement proof response with multiple linking proofs
///
/// Sent by the prover service for private settlement proofs that compute
/// multiple linking proofs
#[derive(Serialize, Deserialize)]
pub struct PrivateSettlementProofResponse {
    /// The settlement proof
    pub proof: PlonkProof,
    /// Party 0's validity linking proof
    pub validity_link_proof_0: PlonkLinkProof,
    /// Party 1's validity linking proof
    pub validity_link_proof_1: PlonkLinkProof,
    /// Party 0's output balance linking proof
    pub output_balance_link_proof_0: PlonkLinkProof,
    /// Party 1's output balance linking proof
    pub output_balance_link_proof_1: PlonkLinkProof,
}

/// A public settlement proof response with validity and output-balance links
///
/// Sent by the prover service for intent-and-balance public settlement proofs
/// that compute both linking proofs for a single party
#[derive(Serialize, Deserialize)]
pub struct PublicSettlementProofResponse {
    /// The settlement proof
    pub proof: PlonkProof,
    /// The validity linking proof
    pub validity_link_proof: PlonkLinkProof,
    /// The output balance linking proof
    pub output_balance_link_proof: PlonkLinkProof,
}

// -----------------
// | Request Types |
// -----------------

// Update proofs
/// A request to prove `VALID BALANCE CREATE`
#[derive(Serialize, Deserialize)]
pub struct ValidBalanceCreateRequest {
    /// The statement (public variables)
    pub statement: ValidBalanceCreateStatement,
    /// The witness
    pub witness: ValidBalanceCreateWitness,
}

/// A request to prove `VALID DEPOSIT`
#[derive(Serialize, Deserialize)]
pub struct ValidDepositRequest {
    /// The statement (public variables)
    pub statement: ValidDepositStatement,
    /// The witness
    pub witness: SizedValidDepositWitness,
}

/// A request to prove `VALID ORDER CANCELLATION`
#[derive(Serialize, Deserialize)]
pub struct ValidOrderCancellationRequest {
    /// The statement (public variables)
    pub statement: ValidOrderCancellationStatement,
    /// The witness
    pub witness: SizedValidOrderCancellationWitness,
}

/// A request to prove `VALID WITHDRAWAL`
#[derive(Serialize, Deserialize)]
pub struct ValidWithdrawalRequest {
    /// The statement (public variables)
    pub statement: ValidWithdrawalStatement,
    /// The witness
    pub witness: SizedValidWithdrawalWitness,
}

// Validity proofs
/// A request to prove `INTENT AND BALANCE VALIDITY`
#[derive(Serialize, Deserialize)]
pub struct IntentAndBalanceValidityRequest {
    /// The statement (public variables)
    pub statement: IntentAndBalanceValidityStatement,
    /// The witness
    pub witness: SizedIntentAndBalanceValidityWitness,
}

/// A request to prove `INTENT AND BALANCE FIRST FILL VALIDITY`
#[derive(Serialize, Deserialize)]
pub struct IntentAndBalanceFirstFillValidityRequest {
    /// The statement (public variables)
    pub statement: IntentAndBalanceFirstFillValidityStatement,
    /// The witness
    pub witness: SizedIntentAndBalanceFirstFillValidityWitness,
}

/// A request to prove `INTENT ONLY VALIDITY`
#[derive(Serialize, Deserialize)]
pub struct IntentOnlyValidityRequest {
    /// The statement (public variables)
    pub statement: IntentOnlyValidityStatement,
    /// The witness
    pub witness: SizedIntentOnlyValidityWitness,
}

/// A request to prove `INTENT ONLY FIRST FILL VALIDITY`
#[derive(Serialize, Deserialize)]
pub struct IntentOnlyFirstFillValidityRequest {
    /// The statement (public variables)
    pub statement: IntentOnlyFirstFillValidityStatement,
    /// The witness
    pub witness: IntentOnlyFirstFillValidityWitness,
}

/// A request to prove `NEW OUTPUT BALANCE VALIDITY`
#[derive(Serialize, Deserialize)]
pub struct NewOutputBalanceValidityRequest {
    /// The statement (public variables)
    pub statement: NewOutputBalanceValidityStatement,
    /// The witness
    pub witness: SizedNewOutputBalanceValidityWitness,
}

/// A request to prove `OUTPUT BALANCE VALIDITY`
#[derive(Serialize, Deserialize)]
pub struct OutputBalanceValidityRequest {
    /// The statement (public variables)
    pub statement: OutputBalanceValidityStatement,
    /// The witness
    pub witness: SizedOutputBalanceValidityWitness,
}

// Settlement proofs
/// A request to prove `INTENT AND BALANCE BOUNDED SETTLEMENT`
#[derive(Serialize, Deserialize)]
pub struct IntentAndBalanceBoundedSettlementRequest {
    /// The statement (public variables)
    pub statement: IntentAndBalanceBoundedSettlementStatement,
    /// The witness
    pub witness: IntentAndBalanceBoundedSettlementWitness,
    /// The link hint for the validity proof
    pub validity_link_hint: ProofLinkingHint,
}

/// A request to prove `INTENT AND BALANCE PRIVATE SETTLEMENT`
#[derive(Serialize, Deserialize)]
pub struct IntentAndBalancePrivateSettlementRequest {
    /// The statement (public variables)
    pub statement: IntentAndBalancePrivateSettlementStatement,
    /// The witness
    pub witness: IntentAndBalancePrivateSettlementWitness,
    /// The link hint for party 0's validity proof
    pub validity_link_hint_0: ProofLinkingHint,
    /// The link hint for party 1's validity proof
    pub validity_link_hint_1: ProofLinkingHint,
    /// The link hint for party 0's output balance validity proof
    pub output_balance_link_hint_0: ProofLinkingHint,
    /// The link hint for party 1's output balance validity proof
    pub output_balance_link_hint_1: ProofLinkingHint,
}

/// A request to prove `INTENT AND BALANCE PUBLIC SETTLEMENT`
#[derive(Serialize, Deserialize)]
pub struct IntentAndBalancePublicSettlementRequest {
    /// The statement (public variables)
    pub statement: IntentAndBalancePublicSettlementStatement,
    /// The witness
    pub witness: IntentAndBalancePublicSettlementWitness,
    /// The party ID (0 or 1) for two-party settlements
    pub party_id: u8,
    /// The link hint for the validity proof
    pub validity_link_hint: ProofLinkingHint,
    /// The link hint for the output balance validity proof
    pub output_balance_link_hint: ProofLinkingHint,
}

/// A request to prove `INTENT ONLY BOUNDED SETTLEMENT`
#[derive(Serialize, Deserialize)]
pub struct IntentOnlyBoundedSettlementRequest {
    /// The statement (public variables)
    pub statement: IntentOnlyBoundedSettlementStatement,
    /// The witness
    pub witness: IntentOnlyBoundedSettlementWitness,
    /// The link hint for the validity proof
    pub validity_link_hint: ProofLinkingHint,
}

/// A request to prove `INTENT ONLY PUBLIC SETTLEMENT`
#[derive(Serialize, Deserialize)]
pub struct IntentOnlyPublicSettlementRequest {
    /// The statement (public variables)
    pub statement: IntentOnlyPublicSettlementStatement,
    /// The witness
    pub witness: IntentOnlyPublicSettlementWitness,
    /// The link hint for the validity proof
    pub validity_link_hint: ProofLinkingHint,
}

// Fee proofs
/// A request to prove `VALID NOTE REDEMPTION`
#[derive(Serialize, Deserialize)]
pub struct ValidNoteRedemptionRequest {
    /// The statement (public variables)
    pub statement: ValidNoteRedemptionStatement,
    /// The witness
    pub witness: SizedValidNoteRedemptionWitness,
}

/// A request to prove `VALID PRIVATE PROTOCOL FEE PAYMENT`
#[derive(Serialize, Deserialize)]
pub struct ValidPrivateProtocolFeePaymentRequest {
    /// The statement (public variables)
    pub statement: ValidPrivateProtocolFeePaymentStatement,
    /// The witness
    pub witness: SizedValidPrivateProtocolFeePaymentWitness,
}

/// A request to prove `VALID PRIVATE RELAYER FEE PAYMENT`
#[derive(Serialize, Deserialize)]
pub struct ValidPrivateRelayerFeePaymentRequest {
    /// The statement (public variables)
    pub statement: ValidPrivateRelayerFeePaymentStatement,
    /// The witness
    pub witness: SizedValidPrivateRelayerFeePaymentWitness,
}

/// A request to prove `VALID PUBLIC PROTOCOL FEE PAYMENT`
#[derive(Serialize, Deserialize)]
pub struct ValidPublicProtocolFeePaymentRequest {
    /// The statement (public variables)
    pub statement: ValidPublicProtocolFeePaymentStatement,
    /// The witness
    pub witness: SizedValidPublicProtocolFeePaymentWitness,
}

/// A request to prove `VALID PUBLIC RELAYER FEE PAYMENT`
#[derive(Serialize, Deserialize)]
pub struct ValidPublicRelayerFeePaymentRequest {
    /// The statement (public variables)
    pub statement: ValidPublicRelayerFeePaymentStatement,
    /// The witness
    pub witness: SizedValidPublicRelayerFeePaymentWitness,
}
