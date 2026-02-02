//! Descriptor for the refresh account task

#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};
use types_account::keychain::KeyChain;
use types_core::AccountId;

use super::TaskDescriptor;

/// The task descriptor for the `RefreshAccount` task
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct RefreshAccountTaskDescriptor {
    /// The account ID to refresh
    pub account_id: AccountId,
    /// The keychain for the account
    pub keychain: KeyChain,
}

impl RefreshAccountTaskDescriptor {
    /// Create a new refresh account task descriptor
    pub fn new(account_id: AccountId, keychain: KeyChain) -> Self {
        Self { account_id, keychain }
    }
}

impl From<RefreshAccountTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: RefreshAccountTaskDescriptor) -> Self {
        TaskDescriptor::RefreshAccount(descriptor)
    }
}
