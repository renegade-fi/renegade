//! Descriptor for the create balance task

use alloy::primitives::Address;
use circuit_types::{Amount, schnorr::SchnorrPublicKey};
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::{AddressDef, SchnorrPublicKeyDef};
use renegade_solidity_abi::v2::IDarkpoolV2::DepositAuth;
#[cfg(feature = "rkyv")]
use types_account::account::deposit::DepositAuthDef;
use types_core::AccountId;

use crate::TaskError;

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the
/// `CreateBalance` task
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
    ) -> Result<Self, TaskError> {
        Self::validate_authority(&authority)?;
        Ok(Self { account_id, from_address, token, amount, authority, auth })
    }

    /// Validate the authority curve point
    ///
    /// This amounts to validating that the point is on the curve and in the
    /// prime-order subgroup.
    fn validate_authority(authority: &SchnorrPublicKey) -> Result<(), TaskError> {
        if authority.point.is_zero() {
            return Err(TaskError::descriptor("authority point is zero"));
        }

        if !authority.point.is_on_curve() {
            return Err(TaskError::descriptor("authority point is not on the curve"));
        }

        if !authority.point.in_correct_subgroup() {
            return Err(TaskError::descriptor("authority point is not in the correct subgroup"));
        }
        Ok(())
    }
}

impl From<CreateBalanceTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: CreateBalanceTaskDescriptor) -> Self {
        TaskDescriptor::CreateBalance(descriptor)
    }
}
