//! Rkyv remotes for `INTENT ONLY VALIDITY` bundles and witnesses.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use circuit_types::{
    Nullifier, PlonkProof, ProofLinkingHint,
    merkle::{MerkleRoot, SizedMerkleOpening},
};
use circuits_core::zk_circuits::validity_proofs::intent_only::{
    IntentOnlyValidityStatement, SizedIntentOnlyValidityWitness,
};
use constants::Scalar;
use darkpool_types::{
    intent::{DarkpoolStateIntent, Intent},
    rkyv_remotes::{AddressDef, ScalarDef},
    state_wrapper::PartialCommitment,
};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bundles::{IntentOnlyValidityBundle, ProofAndHintBundleInner};
use crate::rkyv_impls::{
    plonk_proof_def::{PlonkProofDef, ProofLinkingHintDef},
    shared_types::{MerkleOpeningDef, PartialCommitmentDef},
};

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentOnlyValidityStatement)]
#[rkyv(archived = ArchivedIntentOnlyValidityStatementDef)]
pub struct IntentOnlyValidityStatementDef {
    #[rkyv(with = AddressDef)]
    pub owner: alloy_primitives::Address,
    #[rkyv(with = ScalarDef)]
    pub merkle_root: MerkleRoot,
    #[rkyv(with = ScalarDef)]
    pub old_intent_nullifier: Nullifier,
    #[rkyv(with = ScalarDef)]
    pub new_amount_public_share: Scalar,
    #[rkyv(with = PartialCommitmentDef)]
    pub new_intent_partial_commitment: PartialCommitment,
    #[rkyv(with = ScalarDef)]
    pub recovery_id: Scalar,
}

impl From<IntentOnlyValidityStatementDef> for IntentOnlyValidityStatement {
    fn from(value: IntentOnlyValidityStatementDef) -> Self {
        Self {
            owner: value.owner,
            merkle_root: value.merkle_root,
            old_intent_nullifier: value.old_intent_nullifier,
            new_amount_public_share: value.new_amount_public_share,
            new_intent_partial_commitment: value.new_intent_partial_commitment,
            recovery_id: value.recovery_id,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = ProofAndHintBundleInner<IntentOnlyValidityStatement>)]
#[rkyv(archived = ArchivedIntentOnlyValidityBundleInnerDef)]
pub struct IntentOnlyValidityBundleInnerDef {
    #[rkyv(with = PlonkProofDef)]
    pub proof: PlonkProof,
    #[rkyv(with = IntentOnlyValidityStatementDef)]
    pub statement: IntentOnlyValidityStatement,
    #[rkyv(with = ProofLinkingHintDef)]
    pub linking_hint: ProofLinkingHint,
}

impl From<IntentOnlyValidityBundleInnerDef>
    for ProofAndHintBundleInner<IntentOnlyValidityStatement>
{
    fn from(value: IntentOnlyValidityBundleInnerDef) -> Self {
        Self { proof: value.proof, statement: value.statement, linking_hint: value.linking_hint }
    }
}

fn inner(
    bundle: &IntentOnlyValidityBundle,
) -> ProofAndHintBundleInner<IntentOnlyValidityStatement> {
    bundle.as_ref().clone()
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentOnlyValidityBundle)]
#[rkyv(archived = ArchivedIntentOnlyValidityBundleDef)]
pub struct IntentOnlyValidityBundleDef {
    #[rkyv(getter = inner, with = IntentOnlyValidityBundleInnerDef)]
    pub inner: ProofAndHintBundleInner<IntentOnlyValidityStatement>,
}

impl From<IntentOnlyValidityBundleDef> for IntentOnlyValidityBundle {
    fn from(value: IntentOnlyValidityBundleDef) -> Self {
        Self::from_inner(value.inner)
    }
}

// -----------------------
// | Witness Remote Type |
// -----------------------

/// Rkyv remote for `SizedIntentOnlyValidityWitness`
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = SizedIntentOnlyValidityWitness)]
#[rkyv(archived = ArchivedIntentOnlyValidityWitnessDef)]
pub struct IntentOnlyValidityWitnessDef {
    pub old_intent: DarkpoolStateIntent,
    #[rkyv(with = MerkleOpeningDef)]
    pub old_intent_opening: SizedMerkleOpening,
    pub intent: Intent,
}

impl From<IntentOnlyValidityWitnessDef> for SizedIntentOnlyValidityWitness {
    fn from(value: IntentOnlyValidityWitnessDef) -> Self {
        Self {
            old_intent: value.old_intent,
            old_intent_opening: value.old_intent_opening,
            intent: value.intent,
        }
    }
}
