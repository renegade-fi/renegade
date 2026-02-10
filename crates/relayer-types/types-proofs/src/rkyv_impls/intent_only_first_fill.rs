//! Rkyv remotes for `INTENT ONLY FIRST FILL VALIDITY` bundles.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use circuit_types::{Commitment as PrimitiveCommitment, PlonkProof, ProofLinkingHint};
use circuits_core::zk_circuits::validity_proofs::intent_only_first_fill::IntentOnlyFirstFillValidityStatement;
use constants::Scalar;
use darkpool_types::{intent::IntentShare, rkyv_remotes::{AddressDef, ScalarDef}};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bundles::{IntentOnlyFirstFillValidityBundle, ProofAndHintBundleInner};
use crate::rkyv_impls::{
    plonk_proof_def::{PlonkProofDef, ProofLinkingHintDef},
    shared_types::IntentShareDef,
};

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentOnlyFirstFillValidityStatement)]
#[rkyv(archived = ArchivedIntentOnlyFirstFillValidityStatementDef)]
pub struct IntentOnlyFirstFillValidityStatementDef {
    #[rkyv(with = AddressDef)]
    pub owner: alloy_primitives::Address,
    #[rkyv(with = ScalarDef)]
    pub intent_private_commitment: PrimitiveCommitment,
    #[rkyv(with = ScalarDef)]
    pub recovery_id: Scalar,
    #[rkyv(with = IntentShareDef)]
    pub intent_public_share: IntentShare,
}

impl From<IntentOnlyFirstFillValidityStatementDef> for IntentOnlyFirstFillValidityStatement {
    fn from(value: IntentOnlyFirstFillValidityStatementDef) -> Self {
        Self {
            owner: value.owner,
            intent_private_commitment: value.intent_private_commitment,
            recovery_id: value.recovery_id,
            intent_public_share: value.intent_public_share,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = ProofAndHintBundleInner<IntentOnlyFirstFillValidityStatement>)]
#[rkyv(archived = ArchivedIntentOnlyFirstFillValidityBundleInnerDef)]
pub struct IntentOnlyFirstFillValidityBundleInnerDef {
    #[rkyv(with = PlonkProofDef)]
    pub proof: PlonkProof,
    #[rkyv(with = IntentOnlyFirstFillValidityStatementDef)]
    pub statement: IntentOnlyFirstFillValidityStatement,
    #[rkyv(with = ProofLinkingHintDef)]
    pub linking_hint: ProofLinkingHint,
}

impl From<IntentOnlyFirstFillValidityBundleInnerDef>
    for ProofAndHintBundleInner<IntentOnlyFirstFillValidityStatement>
{
    fn from(value: IntentOnlyFirstFillValidityBundleInnerDef) -> Self {
        Self { proof: value.proof, statement: value.statement, linking_hint: value.linking_hint }
    }
}

fn inner(
    bundle: &IntentOnlyFirstFillValidityBundle,
) -> ProofAndHintBundleInner<IntentOnlyFirstFillValidityStatement> {
    bundle.as_ref().clone()
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentOnlyFirstFillValidityBundle)]
#[rkyv(archived = ArchivedIntentOnlyFirstFillValidityBundleDef)]
pub struct IntentOnlyFirstFillValidityBundleDef {
    #[rkyv(getter = inner, with = IntentOnlyFirstFillValidityBundleInnerDef)]
    pub inner: ProofAndHintBundleInner<IntentOnlyFirstFillValidityStatement>,
}

impl From<IntentOnlyFirstFillValidityBundleDef> for IntentOnlyFirstFillValidityBundle {
    fn from(value: IntentOnlyFirstFillValidityBundleDef) -> Self {
        Self::from_inner(value.inner)
    }
}
