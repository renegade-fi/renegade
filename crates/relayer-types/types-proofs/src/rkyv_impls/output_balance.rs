//! Rkyv remotes for `OUTPUT BALANCE VALIDITY` bundles and witnesses.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use circuit_types::{
    Nullifier, PlonkProof, ProofLinkingHint,
    merkle::{MerkleRoot, SizedMerkleOpening},
};
use circuits_core::zk_circuits::validity_proofs::output_balance::{
    OutputBalanceValidityStatement, SizedOutputBalanceValidityWitness,
};
use constants::Scalar;
use darkpool_types::{
    balance::{DarkpoolBalance, DarkpoolStateBalance, PostMatchBalanceShare},
    rkyv_remotes::ScalarDef,
    state_wrapper::PartialCommitment,
};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bundles::{OutputBalanceValidityBundle, ProofAndHintBundleInner};
use crate::rkyv_impls::{
    plonk_proof_def::{PlonkProofDef, ProofLinkingHintDef},
    shared_types::{MerkleOpeningDef, PartialCommitmentDef, PostMatchBalanceShareDef},
};

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = OutputBalanceValidityStatement)]
#[rkyv(archived = ArchivedOutputBalanceValidityStatementDef)]
pub struct OutputBalanceValidityStatementDef {
    #[rkyv(with = ScalarDef)]
    pub merkle_root: MerkleRoot,
    #[rkyv(with = ScalarDef)]
    pub old_balance_nullifier: Nullifier,
    #[rkyv(with = PartialCommitmentDef)]
    pub new_partial_commitment: PartialCommitment,
    #[rkyv(with = ScalarDef)]
    pub recovery_id: Scalar,
}

impl From<OutputBalanceValidityStatementDef> for OutputBalanceValidityStatement {
    fn from(value: OutputBalanceValidityStatementDef) -> Self {
        Self {
            merkle_root: value.merkle_root,
            old_balance_nullifier: value.old_balance_nullifier,
            new_partial_commitment: value.new_partial_commitment,
            recovery_id: value.recovery_id,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = ProofAndHintBundleInner<OutputBalanceValidityStatement>)]
#[rkyv(archived = ArchivedOutputBalanceValidityBundleInnerDef)]
pub struct OutputBalanceValidityBundleInnerDef {
    #[rkyv(with = PlonkProofDef)]
    pub proof: PlonkProof,
    #[rkyv(with = OutputBalanceValidityStatementDef)]
    pub statement: OutputBalanceValidityStatement,
    #[rkyv(with = ProofLinkingHintDef)]
    pub linking_hint: ProofLinkingHint,
}

impl From<OutputBalanceValidityBundleInnerDef>
    for ProofAndHintBundleInner<OutputBalanceValidityStatement>
{
    fn from(value: OutputBalanceValidityBundleInnerDef) -> Self {
        Self { proof: value.proof, statement: value.statement, linking_hint: value.linking_hint }
    }
}

fn inner(
    bundle: &OutputBalanceValidityBundle,
) -> ProofAndHintBundleInner<OutputBalanceValidityStatement> {
    bundle.as_ref().clone()
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = OutputBalanceValidityBundle)]
#[rkyv(archived = ArchivedOutputBalanceValidityBundleDef)]
pub struct OutputBalanceValidityBundleDef {
    #[rkyv(getter = inner, with = OutputBalanceValidityBundleInnerDef)]
    pub inner: ProofAndHintBundleInner<OutputBalanceValidityStatement>,
}

impl From<OutputBalanceValidityBundleDef> for OutputBalanceValidityBundle {
    fn from(value: OutputBalanceValidityBundleDef) -> Self {
        Self::from_inner(value.inner)
    }
}

// -----------------------
// | Witness Remote Type |
// -----------------------

/// Rkyv remote for `SizedOutputBalanceValidityWitness`
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = SizedOutputBalanceValidityWitness)]
#[rkyv(archived = ArchivedOutputBalanceValidityWitnessDef)]
pub struct OutputBalanceValidityWitnessDef {
    pub old_balance: DarkpoolStateBalance,
    #[rkyv(with = MerkleOpeningDef)]
    pub balance_opening: SizedMerkleOpening,
    pub balance: DarkpoolBalance,
    #[rkyv(with = PostMatchBalanceShareDef)]
    pub post_match_balance_shares: PostMatchBalanceShare,
}

impl From<OutputBalanceValidityWitnessDef> for SizedOutputBalanceValidityWitness {
    fn from(value: OutputBalanceValidityWitnessDef) -> Self {
        Self {
            old_balance: value.old_balance,
            balance_opening: value.balance_opening,
            balance: value.balance,
            post_match_balance_shares: value.post_match_balance_shares,
        }
    }
}
