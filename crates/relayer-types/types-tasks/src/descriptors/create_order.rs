//! Descriptor for the create order task

use alloy::primitives::Address;
use darkpool_types::intent::Intent;
use renegade_solidity_abi::v2::IDarkpoolV2::{PublicIntentPermit, SignatureWithNonce};
use types_account::{
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
        executor: Address,
        intent: Intent,
        ring: PrivacyRing,
        metadata: OrderMetadata,
        auth: OrderAuth,
    ) -> Result<Self, TaskError> {
        validate_order_auth(executor, &intent, &auth)?;
        Ok(Self { account_id, intent, ring, metadata, auth })
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
pub fn validate_order_auth(
    executor: Address,
    intent: &Intent,
    auth: &OrderAuth,
) -> Result<(), TaskError> {
    match auth {
        OrderAuth::PublicOrder { intent_signature } => {
            validate_public_order_auth(executor, intent, intent_signature)
        },
        _ => unimplemented!("auth validation not implemented for this order auth type"),
    }
}

/// Validate the public order auth provided
fn validate_public_order_auth(
    executor: Address,
    intent: &Intent,
    auth: &SignatureWithNonce,
) -> Result<(), TaskError> {
    let chain_id = get_chain_id();

    let addr = intent.owner;
    let permit = PublicIntentPermit { intent: intent.clone().into(), executor };
    let valid = permit.validate(chain_id, auth, addr).map_err(TaskError::order_auth_validation)?;

    if !valid {
        return Err(TaskError::order_auth_validation(INVALID_PUBLIC_ORDER_AUTH));
    }
    Ok(())
}
