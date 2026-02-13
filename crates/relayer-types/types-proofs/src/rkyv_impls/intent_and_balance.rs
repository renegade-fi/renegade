//! Rkyv remotes for `INTENT AND BALANCE VALIDITY` bundles and witnesses.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use circuit_types::{
    Nullifier, PlonkProof, ProofLinkingHint,
    merkle::{MerkleRoot, SizedMerkleOpening},
};
use circuits_core::zk_circuits::validity_proofs::intent_and_balance::{
    IntentAndBalanceValidityStatement, SizedIntentAndBalanceValidityWitness,
};
use constants::Scalar;
use darkpool_types::{
    balance::{DarkpoolBalance, DarkpoolStateBalance, PostMatchBalanceShare},
    intent::{DarkpoolStateIntent, Intent},
    rkyv_remotes::ScalarDef,
    state_wrapper::PartialCommitment,
};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bundles::{IntentAndBalanceValidityBundle, ProofAndHintBundleInner};
use crate::rkyv_impls::{
    plonk_proof_def::{PlonkProofDef, ProofLinkingHintDef},
    shared_types::{MerkleOpeningDef, PartialCommitmentDef, PostMatchBalanceShareDef},
};

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentAndBalanceValidityStatement)]
#[rkyv(archived = ArchivedIntentAndBalanceValidityStatementDef)]
pub struct IntentAndBalanceValidityStatementDef {
    #[rkyv(with = ScalarDef)]
    pub intent_merkle_root: MerkleRoot,
    #[rkyv(with = ScalarDef)]
    pub old_intent_nullifier: Nullifier,
    #[rkyv(with = PartialCommitmentDef)]
    pub new_intent_partial_commitment: PartialCommitment,
    #[rkyv(with = ScalarDef)]
    pub intent_recovery_id: Scalar,
    #[rkyv(with = ScalarDef)]
    pub balance_merkle_root: MerkleRoot,
    #[rkyv(with = ScalarDef)]
    pub old_balance_nullifier: Nullifier,
    #[rkyv(with = PartialCommitmentDef)]
    pub balance_partial_commitment: PartialCommitment,
    #[rkyv(with = ScalarDef)]
    pub balance_recovery_id: Scalar,
}

impl From<IntentAndBalanceValidityStatementDef> for IntentAndBalanceValidityStatement {
    fn from(value: IntentAndBalanceValidityStatementDef) -> Self {
        Self {
            intent_merkle_root: value.intent_merkle_root,
            old_intent_nullifier: value.old_intent_nullifier,
            new_intent_partial_commitment: value.new_intent_partial_commitment,
            intent_recovery_id: value.intent_recovery_id,
            balance_merkle_root: value.balance_merkle_root,
            old_balance_nullifier: value.old_balance_nullifier,
            balance_partial_commitment: value.balance_partial_commitment,
            balance_recovery_id: value.balance_recovery_id,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = ProofAndHintBundleInner<IntentAndBalanceValidityStatement>)]
#[rkyv(archived = ArchivedIntentAndBalanceValidityBundleInnerDef)]
pub struct IntentAndBalanceValidityBundleInnerDef {
    #[rkyv(with = PlonkProofDef)]
    pub proof: PlonkProof,
    #[rkyv(with = IntentAndBalanceValidityStatementDef)]
    pub statement: IntentAndBalanceValidityStatement,
    #[rkyv(with = ProofLinkingHintDef)]
    pub linking_hint: ProofLinkingHint,
}

impl From<IntentAndBalanceValidityBundleInnerDef>
    for ProofAndHintBundleInner<IntentAndBalanceValidityStatement>
{
    fn from(value: IntentAndBalanceValidityBundleInnerDef) -> Self {
        Self { proof: value.proof, statement: value.statement, linking_hint: value.linking_hint }
    }
}

fn inner(
    bundle: &IntentAndBalanceValidityBundle,
) -> ProofAndHintBundleInner<IntentAndBalanceValidityStatement> {
    bundle.as_ref().clone()
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentAndBalanceValidityBundle)]
#[rkyv(archived = ArchivedIntentAndBalanceValidityBundleDef)]
pub struct IntentAndBalanceValidityBundleDef {
    #[rkyv(getter = inner, with = IntentAndBalanceValidityBundleInnerDef)]
    pub inner: ProofAndHintBundleInner<IntentAndBalanceValidityStatement>,
}

impl From<IntentAndBalanceValidityBundleDef> for IntentAndBalanceValidityBundle {
    fn from(value: IntentAndBalanceValidityBundleDef) -> Self {
        Self::from_inner(value.inner)
    }
}

// -----------------------
// | Witness Remote Type |
// -----------------------

/// Rkyv remote for `SizedIntentAndBalanceValidityWitness`
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = SizedIntentAndBalanceValidityWitness)]
#[rkyv(archived = ArchivedIntentAndBalanceValidityWitnessDef)]
pub struct IntentAndBalanceValidityWitnessDef {
    // --- Intent --- //
    pub old_intent: DarkpoolStateIntent,
    #[rkyv(with = MerkleOpeningDef)]
    pub old_intent_opening: SizedMerkleOpening,
    pub intent: Intent,
    #[rkyv(with = ScalarDef)]
    pub new_amount_public_share: Scalar,

    // --- Balance --- //
    pub old_balance: DarkpoolStateBalance,
    #[rkyv(with = MerkleOpeningDef)]
    pub old_balance_opening: SizedMerkleOpening,
    pub balance: DarkpoolBalance,
    #[rkyv(with = PostMatchBalanceShareDef)]
    pub post_match_balance_shares: PostMatchBalanceShare,
}

impl From<IntentAndBalanceValidityWitnessDef> for SizedIntentAndBalanceValidityWitness {
    fn from(value: IntentAndBalanceValidityWitnessDef) -> Self {
        Self {
            old_intent: value.old_intent,
            old_intent_opening: value.old_intent_opening,
            intent: value.intent,
            new_amount_public_share: value.new_amount_public_share,
            old_balance: value.old_balance,
            old_balance_opening: value.old_balance_opening,
            balance: value.balance,
            post_match_balance_shares: value.post_match_balance_shares,
        }
    }
}
