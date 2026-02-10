//! Rkyv remotes for `INTENT AND BALANCE VALIDITY` bundles.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use circuit_types::{Nullifier, PlonkProof, ProofLinkingHint, merkle::MerkleRoot};
use circuits_core::zk_circuits::validity_proofs::intent_and_balance::IntentAndBalanceValidityStatement;
use constants::Scalar;
use darkpool_types::{rkyv_remotes::ScalarDef, state_wrapper::PartialCommitment};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bundles::{IntentAndBalanceValidityBundle, ProofAndHintBundleInner};
use crate::rkyv_impls::{
    plonk_proof_def::{PlonkProofDef, ProofLinkingHintDef},
    shared_types::PartialCommitmentDef,
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
