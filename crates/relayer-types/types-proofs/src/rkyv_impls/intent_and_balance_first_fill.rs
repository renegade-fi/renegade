//! Rkyv remotes for `INTENT AND BALANCE FIRST FILL VALIDITY` bundles.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use circuit_types::{
    Commitment as PrimitiveCommitment, Nullifier, PlonkProof, ProofLinkingHint, merkle::MerkleRoot,
};
use circuits_core::zk_circuits::validity_proofs::intent_and_balance_first_fill::IntentAndBalanceFirstFillValidityStatement;
use constants::Scalar;
use darkpool_types::{intent::PreMatchIntentShare, rkyv_remotes::ScalarDef, state_wrapper::PartialCommitment};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bundles::{IntentAndBalanceFirstFillValidityBundle, ProofAndHintBundleInner};
use crate::rkyv_impls::{
    plonk_proof_def::{PlonkProofDef, ProofLinkingHintDef},
    shared_types::{PartialCommitmentDef, PreMatchIntentShareDef},
};

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentAndBalanceFirstFillValidityStatement)]
#[rkyv(archived = ArchivedIntentAndBalanceFirstFillValidityStatementDef)]
pub struct IntentAndBalanceFirstFillValidityStatementDef {
    #[rkyv(with = ScalarDef)]
    pub merkle_root: MerkleRoot,
    #[rkyv(with = PreMatchIntentShareDef)]
    pub intent_public_share: PreMatchIntentShare,
    #[rkyv(with = ScalarDef)]
    pub intent_private_share_commitment: PrimitiveCommitment,
    #[rkyv(with = ScalarDef)]
    pub intent_recovery_id: Scalar,
    #[rkyv(with = PartialCommitmentDef)]
    pub balance_partial_commitment: PartialCommitment,
    #[rkyv(with = ScalarDef)]
    pub old_balance_nullifier: Nullifier,
    #[rkyv(with = ScalarDef)]
    pub balance_recovery_id: Scalar,
}

impl From<IntentAndBalanceFirstFillValidityStatementDef>
    for IntentAndBalanceFirstFillValidityStatement
{
    fn from(value: IntentAndBalanceFirstFillValidityStatementDef) -> Self {
        Self {
            merkle_root: value.merkle_root,
            intent_public_share: value.intent_public_share,
            intent_private_share_commitment: value.intent_private_share_commitment,
            intent_recovery_id: value.intent_recovery_id,
            balance_partial_commitment: value.balance_partial_commitment,
            old_balance_nullifier: value.old_balance_nullifier,
            balance_recovery_id: value.balance_recovery_id,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = ProofAndHintBundleInner<IntentAndBalanceFirstFillValidityStatement>)]
#[rkyv(archived = ArchivedIntentAndBalanceFirstFillValidityBundleInnerDef)]
pub struct IntentAndBalanceFirstFillValidityBundleInnerDef {
    #[rkyv(with = PlonkProofDef)]
    pub proof: PlonkProof,
    #[rkyv(with = IntentAndBalanceFirstFillValidityStatementDef)]
    pub statement: IntentAndBalanceFirstFillValidityStatement,
    #[rkyv(with = ProofLinkingHintDef)]
    pub linking_hint: ProofLinkingHint,
}

impl From<IntentAndBalanceFirstFillValidityBundleInnerDef>
    for ProofAndHintBundleInner<IntentAndBalanceFirstFillValidityStatement>
{
    fn from(value: IntentAndBalanceFirstFillValidityBundleInnerDef) -> Self {
        Self { proof: value.proof, statement: value.statement, linking_hint: value.linking_hint }
    }
}

fn inner(
    bundle: &IntentAndBalanceFirstFillValidityBundle,
) -> ProofAndHintBundleInner<IntentAndBalanceFirstFillValidityStatement> {
    bundle.as_ref().clone()
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentAndBalanceFirstFillValidityBundle)]
#[rkyv(archived = ArchivedIntentAndBalanceFirstFillValidityBundleDef)]
pub struct IntentAndBalanceFirstFillValidityBundleDef {
    #[rkyv(getter = inner, with = IntentAndBalanceFirstFillValidityBundleInnerDef)]
    pub inner: ProofAndHintBundleInner<IntentAndBalanceFirstFillValidityStatement>,
}

impl From<IntentAndBalanceFirstFillValidityBundleDef> for IntentAndBalanceFirstFillValidityBundle {
    fn from(value: IntentAndBalanceFirstFillValidityBundleDef) -> Self {
        Self::from_inner(value.inner)
    }
}
