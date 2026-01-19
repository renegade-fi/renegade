//! Descriptor for the create balance task

use alloy::primitives::Address;
use circuit_types::{Amount, schnorr::SchnorrPublicKey};
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::{AddressDef, SchnorrPublicKeyDef};
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
#[cfg(feature = "rkyv")]
use types_account::account::deposit::DepositAuthDef;
use types_core::AccountId;

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the `CreateBalance`
/// task
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct CreateBalanceTaskDescriptor {
    /// The account ID to create the balance for
    pub account_id: AccountId,
    /// The address to deposit from
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub from_address: Address,
    /// The token address for the balance
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub token: Address,
    /// The amount for the balance
    pub amount: Amount,
    /// The authority public key
    #[cfg_attr(feature = "rkyv", rkyv(with = SchnorrPublicKeyDef))]
    pub authority: SchnorrPublicKey,
    /// The deposit authorization
    #[cfg_attr(feature = "rkyv", rkyv(with = DepositAuthDef))]
    pub auth: DepositAuth,
}

impl CreateBalanceTaskDescriptor {
    /// Create a new create balance task descriptor
    pub fn new(
        account_id: AccountId,
        from_address: Address,
        token: Address,
        amount: Amount,
        authority: SchnorrPublicKey,
        auth: DepositAuth,
    ) -> Self {
        Self { account_id, from_address, token, amount, authority, auth }
    }
}

impl From<CreateBalanceTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: CreateBalanceTaskDescriptor) -> Self {
        TaskDescriptor::CreateBalance(descriptor)
    }
}
