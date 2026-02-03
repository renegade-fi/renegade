//! Descriptor for the new account task

use alloy::primitives::Address;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use types_account::keychain::KeyChain;
use types_core::AccountId;

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the `NewAccount`
/// task
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct NewAccountTaskDescriptor {
    /// The account ID to create
    pub account_id: AccountId,
    /// The keychain for the account
    pub keychain: KeyChain,
    /// The owner address for the account
    #[cfg_attr(feature = "rkyv", rkyv(with = AddressDef))]
    pub owner_address: Address,
}

impl NewAccountTaskDescriptor {
    /// Create a new account task descriptor
    pub fn new(account_id: AccountId, keychain: KeyChain, owner_address: Address) -> Self {
        Self { account_id, keychain, owner_address }
    }
}

impl From<NewAccountTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: NewAccountTaskDescriptor) -> Self {
        TaskDescriptor::NewAccount(descriptor)
    }
}
