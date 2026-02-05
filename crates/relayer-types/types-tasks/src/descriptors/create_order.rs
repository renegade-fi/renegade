//! Descriptor for the create order task

use alloy::primitives::Address;
use darkpool_types::intent::Intent;
use renegade_solidity_abi::v2::IDarkpoolV2::{PublicIntentPermit, SignatureWithNonce};
use types_account::{
    MatchingPoolName, OrderId,
    order::{OrderMetadata, PrivacyRing},
    order_auth::OrderAuth,
};
use types_core::AccountId;
use util::on_chain::get_chain_id;

use super::TaskDescriptor;
use crate::TaskError;

/// The error message for an invalid public order auth
const INVALID_PUBLIC_ORDER_AUTH: &str = "invalid public order auth";

/// The task descriptor containing only the parameterization of the
/// `CreateOrder` task
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct CreateOrderTaskDescriptor {
    /// The account ID creating the order
    pub account_id: AccountId,
    /// The order ID for the new order
    pub order_id: OrderId,
    /// The intent
    pub intent: Intent,
    /// The privacy ring in which the intent is allocated
    pub ring: PrivacyRing,
    /// The metadata for the order
    pub metadata: OrderMetadata,
    /// The order authorization payload provided by the user
    pub auth: OrderAuth,
    /// The matching pool to assign the order to
    pub matching_pool: MatchingPoolName,
}

impl CreateOrderTaskDescriptor {
    /// Create a new create order task descriptor
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: AccountId,
        order_id: OrderId,
        intent: Intent,
        ring: PrivacyRing,
        metadata: OrderMetadata,
        auth: OrderAuth,
        matching_pool: MatchingPoolName,
    ) -> Result<Self, TaskError> {
        validate_order_auth(&intent, &auth)?;
        Ok(Self { account_id, order_id, intent, ring, metadata, auth, matching_pool })
    }
}

impl From<CreateOrderTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: CreateOrderTaskDescriptor) -> Self {
        TaskDescriptor::CreateOrder(descriptor)
    }
}

// -------------------
// | Auth Validation |
// -------------------

/// Validate the order auth provided
pub fn validate_order_auth(intent: &Intent, auth: &OrderAuth) -> Result<(), TaskError> {
    let owner = intent.owner;
    match auth {
        OrderAuth::PublicOrder { permit, intent_signature } => {
            validate_public_order_auth(owner, permit, intent_signature)
        },
        _ => unimplemented!("auth validation not implemented for this order auth type"),
    }
}

/// Validate the public order auth provided
fn validate_public_order_auth(
    owner: Address,
    permit: &PublicIntentPermit,
    auth: &SignatureWithNonce,
) -> Result<(), TaskError> {
    let chain_id = get_chain_id();
    let valid = permit.validate(chain_id, auth, owner).map_err(TaskError::validation)?;

    if !valid {
        return Err(TaskError::validation(INVALID_PUBLIC_ORDER_AUTH));
    }
    Ok(())
}
