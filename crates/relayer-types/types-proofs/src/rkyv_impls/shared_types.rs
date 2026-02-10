//! Shared rkyv remotes used across validity proof bundles.
#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use circuit_types::{fixed_point::FixedPointShare, primitives::schnorr::SchnorrPublicKeyShare};
use constants::Scalar;
use darkpool_types::{
    balance::PreMatchBalanceShare,
    intent::{IntentShare, PreMatchIntentShare},
    rkyv_remotes::{FixedPointShareDef, ScalarDef, SchnorrPublicKeyShareDef},
    state_wrapper::PartialCommitment,
};
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = IntentShare)]
#[rkyv(archived = ArchivedIntentShareDef)]
pub struct IntentShareDef {
    #[rkyv(with = ScalarDef)]
    pub in_token: Scalar,
    #[rkyv(with = ScalarDef)]
    pub out_token: Scalar,
    #[rkyv(with = ScalarDef)]
    pub owner: Scalar,
    #[rkyv(with = FixedPointShareDef)]
    pub min_price: FixedPointShare,
    #[rkyv(with = ScalarDef)]
    pub amount_in: Scalar,
}

impl From<IntentShareDef> for IntentShare {
    fn from(value: IntentShareDef) -> Self {
        Self {
            in_token: value.in_token,
            out_token: value.out_token,
            owner: value.owner,
            min_price: value.min_price,
            amount_in: value.amount_in,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = PreMatchIntentShare)]
#[rkyv(archived = ArchivedPreMatchIntentShareDef)]
pub struct PreMatchIntentShareDef {
    #[rkyv(with = ScalarDef)]
    pub in_token: Scalar,
    #[rkyv(with = ScalarDef)]
    pub out_token: Scalar,
    #[rkyv(with = ScalarDef)]
    pub owner: Scalar,
    #[rkyv(with = FixedPointShareDef)]
    pub min_price: FixedPointShare,
}

impl From<PreMatchIntentShareDef> for PreMatchIntentShare {
    fn from(value: PreMatchIntentShareDef) -> Self {
        Self {
            in_token: value.in_token,
            out_token: value.out_token,
            owner: value.owner,
            min_price: value.min_price,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = PreMatchBalanceShare)]
#[rkyv(archived = ArchivedPreMatchBalanceShareDef)]
pub struct PreMatchBalanceShareDef {
    #[rkyv(with = ScalarDef)]
    pub mint: Scalar,
    #[rkyv(with = ScalarDef)]
    pub owner: Scalar,
    #[rkyv(with = ScalarDef)]
    pub relayer_fee_recipient: Scalar,
    #[rkyv(with = SchnorrPublicKeyShareDef)]
    pub authority: SchnorrPublicKeyShare,
}

impl From<PreMatchBalanceShareDef> for PreMatchBalanceShare {
    fn from(value: PreMatchBalanceShareDef) -> Self {
        Self {
            mint: value.mint,
            owner: value.owner,
            relayer_fee_recipient: value.relayer_fee_recipient,
            authority: value.authority,
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug, Clone)]
#[rkyv(derive(Debug))]
#[rkyv(remote = PartialCommitment)]
#[rkyv(archived = ArchivedPartialCommitmentDef)]
pub struct PartialCommitmentDef {
    #[rkyv(with = ScalarDef)]
    pub private_commitment: Scalar,
    #[rkyv(with = ScalarDef)]
    pub partial_public_commitment: Scalar,
}

impl From<PartialCommitmentDef> for PartialCommitment {
    fn from(value: PartialCommitmentDef) -> Self {
        Self {
            private_commitment: value.private_commitment,
            partial_public_commitment: value.partial_public_commitment,
        }
    }
}
