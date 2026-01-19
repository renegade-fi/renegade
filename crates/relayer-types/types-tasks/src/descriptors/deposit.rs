//! Descriptor for the deposit task

use alloy::primitives::Address;
use circuit_types::{Amount, schnorr::SchnorrPublicKey};
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
use types_core::AccountId;
#[cfg(feature = "rkyv")]
use {
    darkpool_types::rkyv_remotes::{AddressDef, SchnorrPublicKeyDef},
    types_account::account::deposit::DepositAuthDef,
};

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the `Deposit`
/// task
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct DepositTaskDescriptor {
    /// The account ID to deposit into
    pub account_id: AccountId,
    /// The address to deposit from
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub from_address: Address,
    /// The token address to deposit
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub token: Address,
    /// The amount to deposit
    pub amount: Amount,
    /// The deposit authorization
    #[cfg_attr(feature = "rkyv", rkyv(with = DepositAuthDef))]
    pub auth: DepositAuth,
    /// The authority public key
    #[cfg_attr(feature = "rkyv", rkyv(with = SchnorrPublicKeyDef))]
    pub authority: SchnorrPublicKey,
}

impl DepositTaskDescriptor {
    /// Create a new deposit task descriptor
    pub fn new(
        account_id: AccountId,
        from_address: Address,
        token: Address,
        amount: Amount,
        auth: DepositAuth,
        authority: SchnorrPublicKey,
    ) -> Self {
        Self { account_id, from_address, token, amount, auth, authority }
    }
}

impl From<DepositTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: DepositTaskDescriptor) -> Self {
        TaskDescriptor::Deposit(descriptor)
    }
}
