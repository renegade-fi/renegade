//! Descriptor for the cancel order task

use alloy::primitives::U256;
use renegade_solidity_abi::v2::IDarkpoolV2::SignatureWithNonce;
use types_account::OrderId;
use types_account::order_auth::OrderAuth;
#[cfg(feature = "rkyv")]
use types_account::order_auth::SignatureWithNonceDef;
use types_core::AccountId;
use util::on_chain::get_chain_id;

use super::TaskDescriptor;
use crate::TaskError;

/// The cancel domain prefix (matches contract's CANCEL_DOMAIN)
const CANCEL_DOMAIN: &[u8] = b"cancel";

/// The error message for an invalid cancel signature
const INVALID_CANCEL_SIGNATURE: &str = "invalid cancel signature";

/// The task descriptor for the `CancelOrder` task
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "rkyv", derive(rkyv::Archive, rkyv::Serialize, rkyv::Deserialize))]
#[cfg_attr(feature = "rkyv", rkyv(derive(Debug)))]
pub struct CancelOrderTaskDescriptor {
    /// The account ID that owns the order
    pub account_id: AccountId,
    /// The order ID to cancel
    pub order_id: OrderId,
    /// The original order authorization
    pub order_auth: OrderAuth,
    /// The signature authorizing the cancellation
    #[cfg_attr(feature = "rkyv", rkyv(with = SignatureWithNonceDef))]
    pub cancel_signature: SignatureWithNonce,
}

impl CancelOrderTaskDescriptor {
    /// Create a new cancel order task descriptor, validating the cancel
    /// signature
    pub fn new(
        account_id: AccountId,
        order_id: OrderId,
        order_auth: OrderAuth,
        cancel_signature: SignatureWithNonce,
    ) -> Result<Self, TaskError> {
        validate_cancel_signature(&order_auth, &cancel_signature)?;
        Ok(Self { account_id, order_id, order_auth, cancel_signature })
    }
}

impl From<CancelOrderTaskDescriptor> for TaskDescriptor {
    fn from(descriptor: CancelOrderTaskDescriptor) -> Self {
        TaskDescriptor::CancelOrder(descriptor)
    }
}

// -------------------
// | Auth Validation |
// -------------------

/// Validate the cancel signature
fn validate_cancel_signature(
    auth: &OrderAuth,
    cancel_signature: &SignatureWithNonce,
) -> Result<(), TaskError> {
    let chain_id = get_chain_id();
    let (permit, intent_signature) = auth.into_public();
    let nullifier = permit.compute_nullifier(intent_signature.nonce);

    // Build the cancel payload: "cancel" || intentNullifier
    let nullifier_bytes = nullifier.to_be_bytes::<{ U256::BYTES }>();
    let cancel_payload = [CANCEL_DOMAIN, nullifier_bytes.as_slice()].concat();

    // Validate the cancel signature recovers to the intent owner
    let owner = permit.intent.owner;
    let valid = cancel_signature
        .validate(&cancel_payload, chain_id, owner)
        .map_err(TaskError::order_auth_validation)?;

    if !valid {
        return Err(TaskError::order_auth_validation(INVALID_CANCEL_SIGNATURE));
    }
    Ok(())
}
