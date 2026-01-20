//! Descriptor for the create order task

use darkpool_types::intent::Intent;
use types_account::{
    order::{OrderMetadata, PrivacyRing},
    order_auth::OrderAuth,
};
use types_core::AccountId;

use super::TaskDescriptor;

/// The task descriptor containing only the parameterization of the
/// `CreateOrder` task
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct CreateOrderTaskDescriptor {
    /// The account ID creating the order
    pub account_id: AccountId,
    /// The intent
    pub intent: Intent,
    /// The privacy ring in which the intent is allocated
    pub ring: PrivacyRing,
    /// The metadata for the order
    pub metadata: OrderMetadata,
    /// The order authorization payload provided by the user
    pub auth: OrderAuth,
}

impl CreateOrderTaskDescriptor {
    /// Create a new create order task descriptor
    pub fn new(
        account_id: AccountId,
        intent: Intent,
        ring: PrivacyRing,
        metadata: OrderMetadata,
        auth: OrderAuth,
    ) -> Self {
        Self { account_id, intent, ring, metadata, auth }
    }
}

impl From<CreateOrderTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: CreateOrderTaskDescriptor) -> Self {
        TaskDescriptor::CreateOrder(descriptor)
    }
}
