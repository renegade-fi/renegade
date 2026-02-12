//! Descriptor for the create order task

use alloy::primitives::Address;
use circuit_types::{
    Commitment,
    schnorr::{SchnorrPublicKey, SchnorrSignature},
};
use crypto::fields::scalar_to_u256;
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
/// The error message for an invalid natively settled private order auth
const INVALID_INTENT_SIGNATURE: &str = "invalid intent signature";
/// The error message for an invalid new output balance signature
const INVALID_NEW_OUTPUT_BALANCE_SIGNATURE: &str = "invalid new output balance signature";

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
    pub fn new_ring0(
        account_id: AccountId,
        order_id: OrderId,
        intent: Intent,
        metadata: OrderMetadata,
        auth: OrderAuth,
        matching_pool: MatchingPoolName,
    ) -> Result<Self, TaskError> {
        // Validate the order auth
        let (permit, intent_signature) = auth.into_public();
        validate_public_order_auth(intent.owner, &permit, &intent_signature)?;

        let ring = PrivacyRing::Ring0;
        Ok(Self { account_id, order_id, intent, ring, metadata, auth, matching_pool })
    }

    /// Create a new ring 1 descriptor
    pub fn new_ring1(
        account_id: AccountId,
        order_id: OrderId,
        intent: Intent,
        intent_commitment: Commitment,
        metadata: OrderMetadata,
        auth: OrderAuth,
        matching_pool: MatchingPoolName,
    ) -> Result<Self, TaskError> {
        // Validate the order auth
        let intent_signature = auth.into_natively_settled_private_order();
        validate_natively_settled_private_order_auth(
            intent.owner,
            intent_commitment,
            &intent_signature,
        )?;

        let ring = PrivacyRing::Ring1;
        Ok(Self { account_id, order_id, intent, ring, metadata, auth, matching_pool })
    }

    /// Create a new ring 2 descriptor
    ///
    /// We only require the intent commitment and new balance commitment for
    /// validation purposes. An output balance commitment need not be provided
    /// if the order will settle into an existing output balance.
    #[allow(clippy::too_many_arguments)]
    pub fn new_ring2(
        account_id: AccountId,
        order_id: OrderId,
        intent: Intent,
        intent_commitment: Commitment,
        new_balance_commitment: Option<Commitment>,
        authority: SchnorrPublicKey,
        metadata: OrderMetadata,
        auth: OrderAuth,
        matching_pool: MatchingPoolName,
    ) -> Result<Self, TaskError> {
        // Validate the order auth
        let (intent_signature, new_output_balance_signature) = auth.into_renegade_settled_order();
        validate_renegade_settled_order_auth(
            intent_commitment,
            new_balance_commitment,
            &intent_signature,
            &new_output_balance_signature,
            authority,
        )?;

        let ring = PrivacyRing::Ring2;
        Ok(Self { account_id, order_id, intent, ring, metadata, auth, matching_pool })
    }

    /// Create a new ring 3 descriptor
    ///
    /// Ring 3 uses the same auth as ring 2 (Schnorr signatures over intent
    /// and balance commitments), but restricts the order to private fills
    /// only.
    #[allow(clippy::too_many_arguments)]
    pub fn new_ring3(
        account_id: AccountId,
        order_id: OrderId,
        intent: Intent,
        intent_commitment: Commitment,
        new_balance_commitment: Option<Commitment>,
        authority: SchnorrPublicKey,
        metadata: OrderMetadata,
        auth: OrderAuth,
        matching_pool: MatchingPoolName,
    ) -> Result<Self, TaskError> {
        // Validate the order auth (same as ring 2)
        let (intent_signature, new_output_balance_signature) = auth.into_renegade_settled_order();
        validate_renegade_settled_order_auth(
            intent_commitment,
            new_balance_commitment,
            &intent_signature,
            &new_output_balance_signature,
            authority,
        )?;

        let ring = PrivacyRing::Ring3;
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

/// Validate the auth for a natively settled private order
fn validate_natively_settled_private_order_auth(
    owner: Address,
    intent_commitment: Commitment,
    intent_signature: &SignatureWithNonce,
) -> Result<(), TaskError> {
    let chain_id = get_chain_id();
    let commitment_u256 = scalar_to_u256(&intent_commitment);

    // Validate the signature
    let payload = commitment_u256.to_be_bytes::<32>();
    let valid =
        intent_signature.validate(&payload, chain_id, owner).map_err(TaskError::validation)?;

    if !valid {
        return Err(TaskError::validation(INVALID_INTENT_SIGNATURE));
    }
    Ok(())
}

/// Validate the auth for a renegade settled order
fn validate_renegade_settled_order_auth(
    intent_commitment: Commitment,
    new_balance_commitment: Option<Commitment>,
    intent_signature: &SchnorrSignature,
    new_output_balance_signature: &SchnorrSignature,
    authority: SchnorrPublicKey,
) -> Result<(), TaskError> {
    // Validate the intent signature
    if !authority.verify(&intent_commitment, intent_signature) {
        return Err(TaskError::validation(INVALID_INTENT_SIGNATURE));
    }

    // Validate the new output balance signature
    if let Some(comm) = new_balance_commitment
        && !authority.verify(&comm, new_output_balance_signature)
    {
        return Err(TaskError::validation(INVALID_NEW_OUTPUT_BALANCE_SIGNATURE));
    }

    Ok(())
}
