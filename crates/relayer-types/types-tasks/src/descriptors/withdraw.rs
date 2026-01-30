//! Descriptor for the withdraw task

use alloy::primitives::Address;
use circuit_types::Amount;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
use types_core::AccountId;

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the
/// `Withdraw` task
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct WithdrawTaskDescriptor {
    /// The account ID to withdraw from
    pub account_id: AccountId,
    /// The token address for the balance to withdraw
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub token: Address,
    /// The amount to withdraw
    pub amount: Amount,
    /// The signature authorizing the withdrawal
    pub signature: Vec<u8>,
}

impl WithdrawTaskDescriptor {
    /// Create a new withdraw task descriptor
    pub fn new(account_id: AccountId, token: Address, amount: Amount, signature: Vec<u8>) -> Self {
        Self { account_id, token, amount, signature }
    }
}

impl From<WithdrawTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: WithdrawTaskDescriptor) -> Self {
        TaskDescriptor::Withdraw(descriptor)
    }
}
