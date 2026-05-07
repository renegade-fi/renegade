//! Descriptor for the refresh account task

use alloy::primitives::Address;
#[cfg(feature = "rkyv")]
use darkpool_types::rkyv_remotes::AddressDef;
#[cfg(feature = "rkyv")]
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize, with::Map};
use serde::{Deserialize, Serialize};
use types_account::keychain::KeyChain;
use types_core::AccountId;

use super::TaskDescriptor;

/// The task descriptor for the `RefreshAccount` task
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "rkyv", derive(Archive, RkyvSerialize, RkyvDeserialize))]
pub struct RefreshAccountTaskDescriptor {
    /// The account ID to refresh
    pub account_id: AccountId,
    /// The keychain for the account
    pub keychain: KeyChain,
    /// Tokens to refresh balances for in addition to those that appear
    /// in the wallet's active public intents. See
    /// `SyncAccountRequest::additional_tokens` for rationale.
    #[serde(default)]
    #[cfg_attr(feature = "rkyv", rkyv(with = Map<AddressDef>))]
    pub additional_tokens: Vec<Address>,
}

impl RefreshAccountTaskDescriptor {
    /// Create a new refresh account task descriptor
    pub fn new(account_id: AccountId, keychain: KeyChain) -> Self {
        Self { account_id, keychain, additional_tokens: Vec::new() }
    }

    /// Set additional tokens whose balances should be refreshed
    /// regardless of whether they appear in the wallet's active intents.
    pub fn with_additional_tokens(mut self, tokens: Vec<Address>) -> Self {
        self.additional_tokens = tokens;
        self
    }
}

impl From<RefreshAccountTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: RefreshAccountTaskDescriptor) -> Self {
        TaskDescriptor::RefreshAccount(descriptor)
    }
}
