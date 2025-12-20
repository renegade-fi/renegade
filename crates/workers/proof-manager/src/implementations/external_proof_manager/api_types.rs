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
use circuits::{
    self,
    zk_circuits::{
        valid_commitments::{SizedValidCommitmentsWitness, ValidCommitmentsStatement},
        valid_fee_redemption::{SizedValidFeeRedemptionStatement, SizedValidFeeRedemptionWitness},
        valid_malleable_match_settle_atomic::{
            SizedValidMalleableMatchSettleAtomicStatement,
            SizedValidMalleableMatchSettleAtomicWitness,
        },
        valid_match_settle::{SizedValidMatchSettleStatement, SizedValidMatchSettleWitness},
        valid_match_settle_atomic::{
            SizedValidMatchSettleAtomicStatement, SizedValidMatchSettleAtomicWitness,
        },
        valid_offline_fee_settlement::{
            SizedValidOfflineFeeSettlementStatement, SizedValidOfflineFeeSettlementWitness,
        },
        valid_reblind::{SizedValidReblindWitness, ValidReblindStatement},
        valid_wallet_create::{SizedValidWalletCreateStatement, SizedValidWalletCreateWitness},
        valid_wallet_update::{SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness},
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

/// A proof-link response
///
/// Sent by the prover service when only a linking proof has been requested
#[derive(Serialize, Deserialize)]
pub struct ProofLinkResponse {
    /// The proof-linking proof
    pub link_proof: PlonkLinkProof,
}

/// A response including a plonk proof and a proof-linking proof
///
/// This type is returned in response to requests which themselves include a
/// link hint for the prover service to link against
#[derive(Serialize, Deserialize)]
pub struct ProofAndLinkResponse {
    /// The plonk proof
    pub plonk_proof: PlonkProof,
    /// The proof-linking proof
    pub link_proof: PlonkLinkProof,
}

// -----------------
// | Request Types |
// -----------------

/// A request to prove `VALID WALLET CREATE`
#[derive(Serialize, Deserialize)]
pub struct ValidWalletCreateRequest {
    /// The statement (public variables)
    pub statement: SizedValidWalletCreateStatement,
    /// The witness
    pub witness: SizedValidWalletCreateWitness,
}

/// A request to prove `VALID WALLET UPDATE`
#[derive(Serialize, Deserialize)]
pub struct ValidWalletUpdateRequest {
    /// The statement (public variables)
    pub statement: SizedValidWalletUpdateStatement,
    /// The witness
    pub witness: SizedValidWalletUpdateWitness,
}

/// A request to prove `VALID COMMITMENTS`
#[derive(Serialize, Deserialize)]
pub struct ValidCommitmentsRequest {
    /// The statement (public variables)
    pub statement: ValidCommitmentsStatement,
    /// The witness
    pub witness: SizedValidCommitmentsWitness,
}

/// A request to generate a proof-link of `VALID COMMITMENTS` <-> `VALID
/// REBLIND`
#[derive(Serialize, Deserialize)]
pub struct LinkCommitmentsReblindRequest {
    /// The link hint for `VALID COMMITMENTS`
    pub valid_commitments_hint: ProofLinkingHint,
    /// The link hint for `VALID REBLIND`
    pub valid_reblind_hint: ProofLinkingHint,
}

/// A request to prove `VALID REBLIND`
#[derive(Serialize, Deserialize)]
pub struct ValidReblindRequest {
    /// The statement (public variables)
    pub statement: ValidReblindStatement,
    /// The witness
    pub witness: SizedValidReblindWitness,
}

/// A request to prove `VALID MATCH SETTLE`
#[derive(Serialize, Deserialize)]
pub struct ValidMatchSettleRequest {
    /// The statement (public variables)
    pub statement: SizedValidMatchSettleStatement,
    /// The witness
    pub witness: SizedValidMatchSettleWitness,
    /// The link hint for `VALID COMMITMENTS` for party 0
    pub valid_commitments_hint0: ProofLinkingHint,
    /// The link hint for `VALID COMMITMENTS` for party 1
    pub valid_commitments_hint1: ProofLinkingHint,
}

/// A response to a request to prove `VALID MATCH SETTLE`
///
/// This type includes two link proofs, so it warrants its own type
#[derive(Serialize, Deserialize)]
pub struct ValidMatchSettleResponse {
    /// The plonk proof
    pub plonk_proof: PlonkProof,
    /// The proof-linking proof for party 0
    pub link_proof0: PlonkLinkProof,
    /// The proof-linking proof for party 1
    pub link_proof1: PlonkLinkProof,
}

/// A request to prove `VALID MATCH SETTLE ATOMIC`
#[derive(Serialize, Deserialize)]
pub struct ValidMatchSettleAtomicRequest {
    /// The statement (public variables)
    pub statement: SizedValidMatchSettleAtomicStatement,
    /// The witness
    pub witness: SizedValidMatchSettleAtomicWitness,
    /// The link hint for `VALID COMMITMENTS`
    pub valid_commitments_hint: ProofLinkingHint,
}

/// A request to prove `VALID MALLEABLE MATCH SETTLE ATOMIC`
#[derive(Serialize, Deserialize)]
pub struct ValidMalleableMatchSettleAtomicRequest {
    /// The statement (public variables)
    pub statement: SizedValidMalleableMatchSettleAtomicStatement,
    /// The witness
    pub witness: SizedValidMalleableMatchSettleAtomicWitness,
    /// The link hint for `VALID COMMITMENTS`
    pub valid_commitments_hint: ProofLinkingHint,
}

/// A request to prove `VALID FEE REDEMPTION`
#[derive(Serialize, Deserialize)]
pub struct ValidFeeRedemptionRequest {
    /// The statement (public variables)
    pub statement: SizedValidFeeRedemptionStatement,
    /// The witness
    pub witness: SizedValidFeeRedemptionWitness,
}

/// A request to prove `VALID OFFLINE FEE SETTLEMENT`
#[derive(Serialize, Deserialize)]
pub struct ValidOfflineFeeSettlementRequest {
    /// The statement (public variables)
    pub statement: SizedValidOfflineFeeSettlementStatement,
    /// The witness
    pub witness: SizedValidOfflineFeeSettlementWitness,
}
