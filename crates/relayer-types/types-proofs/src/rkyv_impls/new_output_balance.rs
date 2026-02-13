//! Rkyv remotes for `NEW OUTPUT BALANCE VALIDITY` bundles and witnesses.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use circuit_types::{
    Nullifier, PlonkProof, ProofLinkingHint,
    merkle::{MerkleRoot, SizedMerkleOpening},
    primitives::schnorr::SchnorrSignature,
};
use circuits_core::zk_circuits::validity_proofs::new_output_balance::{
    NewOutputBalanceValidityStatement, SizedNewOutputBalanceValidityWitness,
};
use constants::Scalar;
use darkpool_types::{
    balance::{DarkpoolBalance, DarkpoolStateBalance, PostMatchBalanceShare, PreMatchBalanceShare},
    rkyv_remotes::{ScalarDef, SchnorrSignatureDef},
    state_wrapper::PartialCommitment,
};
use rkyv::{Archive, Deserialize, Serialize};

use crate::bundles::{NewOutputBalanceValidityBundle, ProofAndHintBundleInner};
use crate::rkyv_impls::{
    plonk_proof_def::{PlonkProofDef, ProofLinkingHintDef},
    shared_types::{
        MerkleOpeningDef, PartialCommitmentDef, PostMatchBalanceShareDef, PreMatchBalanceShareDef,
    },
};

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = NewOutputBalanceValidityStatement)]
#[rkyv(archived = ArchivedNewOutputBalanceValidityStatementDef)]
pub struct NewOutputBalanceValidityStatementDef {
    #[rkyv(with = ScalarDef)]
    pub existing_balance_merkle_root: MerkleRoot,
    #[rkyv(with = ScalarDef)]
    pub existing_balance_nullifier: Nullifier,
    #[rkyv(with = PreMatchBalanceShareDef)]
    pub pre_match_balance_shares: PreMatchBalanceShare,
    #[rkyv(with = PartialCommitmentDef)]
    pub new_balance_partial_commitment: PartialCommitment,
    #[rkyv(with = ScalarDef)]
    pub recovery_id: Scalar,
}

impl From<NewOutputBalanceValidityStatementDef> for NewOutputBalanceValidityStatement {
    fn from(value: NewOutputBalanceValidityStatementDef) -> Self {
        Self {
            existing_balance_merkle_root: value.existing_balance_merkle_root,
            existing_balance_nullifier: value.existing_balance_nullifier,
            pre_match_balance_shares: value.pre_match_balance_shares,
            new_balance_partial_commitment: value.new_balance_partial_commitment,
            recovery_id: value.recovery_id,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = ProofAndHintBundleInner<NewOutputBalanceValidityStatement>)]
#[rkyv(archived = ArchivedNewOutputBalanceValidityBundleInnerDef)]
pub struct NewOutputBalanceValidityBundleInnerDef {
    #[rkyv(with = PlonkProofDef)]
    pub proof: PlonkProof,
    #[rkyv(with = NewOutputBalanceValidityStatementDef)]
    pub statement: NewOutputBalanceValidityStatement,
    #[rkyv(with = ProofLinkingHintDef)]
    pub linking_hint: ProofLinkingHint,
}

impl From<NewOutputBalanceValidityBundleInnerDef>
    for ProofAndHintBundleInner<NewOutputBalanceValidityStatement>
{
    fn from(value: NewOutputBalanceValidityBundleInnerDef) -> Self {
        Self { proof: value.proof, statement: value.statement, linking_hint: value.linking_hint }
    }
}

fn inner(
    bundle: &NewOutputBalanceValidityBundle,
) -> ProofAndHintBundleInner<NewOutputBalanceValidityStatement> {
    bundle.as_ref().clone()
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = NewOutputBalanceValidityBundle)]
#[rkyv(archived = ArchivedNewOutputBalanceValidityBundleDef)]
pub struct NewOutputBalanceValidityBundleDef {
    #[rkyv(getter = inner, with = NewOutputBalanceValidityBundleInnerDef)]
    pub inner: ProofAndHintBundleInner<NewOutputBalanceValidityStatement>,
}

impl From<NewOutputBalanceValidityBundleDef> for NewOutputBalanceValidityBundle {
    fn from(value: NewOutputBalanceValidityBundleDef) -> Self {
        Self::from_inner(value.inner)
    }
}

// -----------------------
// | Witness Remote Type |
// -----------------------

/// Rkyv remote for `SizedNewOutputBalanceValidityWitness`
#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = SizedNewOutputBalanceValidityWitness)]
#[rkyv(archived = ArchivedNewOutputBalanceValidityWitnessDef)]
pub struct NewOutputBalanceValidityWitnessDef {
    // --- New Balance --- //
    pub new_balance: DarkpoolStateBalance,
    pub balance: DarkpoolBalance,
    #[rkyv(with = PostMatchBalanceShareDef)]
    pub post_match_balance_shares: PostMatchBalanceShare,

    // --- Bootstrapping Balance --- //
    pub existing_balance: DarkpoolStateBalance,
    #[rkyv(with = MerkleOpeningDef)]
    pub existing_balance_opening: SizedMerkleOpening,
    #[rkyv(with = SchnorrSignatureDef)]
    pub new_balance_authorization_signature: SchnorrSignature,
}

impl From<NewOutputBalanceValidityWitnessDef> for SizedNewOutputBalanceValidityWitness {
    fn from(value: NewOutputBalanceValidityWitnessDef) -> Self {
        Self {
            new_balance: value.new_balance,
            balance: value.balance,
            post_match_balance_shares: value.post_match_balance_shares,
            existing_balance: value.existing_balance,
            existing_balance_opening: value.existing_balance_opening,
            new_balance_authorization_signature: value.new_balance_authorization_signature,
        }
    }
}
