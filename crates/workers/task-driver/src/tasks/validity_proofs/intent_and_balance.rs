//! Helpers for intent and balance validity proofs
//!
//! These helpers are used when generating validity proofs for Ring 2/3 orders,
//! where both the intent and the capitalizing balance are in the darkpool
//! Merkle state.

use circuit_types::schnorr::SchnorrSignature;
use circuits_core::zk_circuits::validity_proofs::{
    intent_and_balance::{
        INTENT_PARTIAL_COMMITMENT_SIZE, IntentAndBalanceValidityStatement,
        SizedIntentAndBalanceValidityWitness,
    },
    intent_and_balance_first_fill::{
        BALANCE_PARTIAL_COMMITMENT_SIZE, IntentAndBalanceFirstFillValidityStatement,
        SizedIntentAndBalanceFirstFillValidityWitness,
    },
};
use darkpool_types::balance::{DarkpoolStateBalance, PostMatchBalance};
use job_types::proof_manager::ProofJob;
use types_account::{MerkleAuthenticationPath, OrderId, order::Order};
use types_core::AccountId;
use types_proofs::{
    IntentAndBalanceFirstFillValidityBundle, IntentAndBalanceValidityBundle, ValidityProofBundle,
};

use crate::{
    tasks::validity_proofs::error::ValidityProofsError, traits::TaskContext,
    utils::enqueue_proof_job,
};

/// Update the intent-and-balance validity proof for a given order
///
/// Branches on whether this is the first fill or a subsequent fill.
pub async fn update_intent_and_balance_validity_proof(
    account_id: AccountId,
    order_id: OrderId,
    order_auth: SchnorrSignature,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    // No proof needed if the matchable amount is zero
    let matchable_amount = ctx.state.get_order_matchable_amount(&order_id).await?;
    if matchable_amount == 0 {
        return Ok(());
    }

    // Fetch the state elements input to this validity proof
    let order = get_order(&order_id, ctx).await?;
    let balance = get_capitalizing_balance(account_id, &order, ctx).await?;
    let balance_merkle_proof = get_balance_merkle_proof(account_id, &order, ctx).await?;

    if !order.metadata.has_been_filled {
        update_first_fill_validity_proof(&order, &balance, balance_merkle_proof, order_auth, ctx)
            .await
    } else {
        update_subsequent_fill_validity_proof(&order, &balance, balance_merkle_proof, ctx).await
    }
}

// --------------
// | First Fill |
// --------------

/// Generate a validity proof for the intent-and-balance circuit on the first
/// fill
async fn update_first_fill_validity_proof(
    order: &Order,
    balance: &DarkpoolStateBalance,
    balance_merkle_proof: MerkleAuthenticationPath,
    order_auth: SchnorrSignature,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    let (witness, statement) =
        generate_first_fill_witness_statement(order, balance, balance_merkle_proof, order_auth)?;
    let witness_clone = witness.clone();

    let job = ProofJob::IntentAndBalanceFirstFillValidity { witness, statement };
    let proof_recv = enqueue_proof_job(job, ctx).map_err(ValidityProofsError::proof_generation)?;

    let bundle: IntentAndBalanceFirstFillValidityBundle =
        proof_recv.await.map_err(ValidityProofsError::proof_generation)?.into();

    let validity_bundle = ValidityProofBundle::IntentAndBalanceFirstFill {
        bundle,
        witness: witness_clone,
    };
    let waiter = ctx.state.add_intent_validity_proof(order.id, validity_bundle).await?;
    waiter.await?;
    Ok(())
}

/// Generate a witness and statement for the first fill of an
/// intent-and-balance validity proof
fn generate_first_fill_witness_statement(
    order: &Order,
    balance: &DarkpoolStateBalance,
    balance_merkle_proof: MerkleAuthenticationPath,
    order_auth: SchnorrSignature,
) -> Result<
    (SizedIntentAndBalanceFirstFillValidityWitness, IntentAndBalanceFirstFillValidityStatement),
    ValidityProofsError,
> {
    let initial_intent = &order.intent;

    // Clone before mutations; compute recovery_id and private commitment
    let mut intent_clone = initial_intent.clone();
    let intent_recovery_id = intent_clone.compute_recovery_id();
    let intent_private_share_commitment = intent_clone.compute_private_commitment();

    let private_intent_shares = initial_intent.private_shares();
    let intent_public_share = initial_intent.public_share();
    let new_amount_public_share = intent_public_share.amount_in;

    // Compute balance state rotation values
    let old_balance_nullifier = balance.compute_nullifier();
    let merkle_root = balance_merkle_proof.compute_root();
    let balance_opening = balance_merkle_proof.into();

    // Build the new balance with re-encrypted post-match shares
    let mut new_balance = balance.clone();
    let post_match_balance = PostMatchBalance::from(balance.inner.clone());
    let post_match_balance_shares = new_balance.stream_cipher_encrypt(&post_match_balance);
    new_balance.update_from_post_match(&post_match_balance_shares);

    let balance_recovery_id = new_balance.compute_recovery_id();
    let balance_partial_commitment =
        new_balance.compute_partial_commitment(BALANCE_PARTIAL_COMMITMENT_SIZE);

    let witness = SizedIntentAndBalanceFirstFillValidityWitness {
        intent: initial_intent.inner.clone(),
        initial_intent_share_stream: initial_intent.share_stream.clone(),
        initial_intent_recovery_stream: initial_intent.recovery_stream.clone(),
        private_intent_shares,
        new_amount_public_share,
        intent_authorization_signature: order_auth,
        old_balance: balance.clone(),
        balance: balance.inner.clone(),
        post_match_balance_shares,
        balance_opening,
    };

    let statement = IntentAndBalanceFirstFillValidityStatement {
        merkle_root,
        intent_public_share: intent_public_share.into(),
        intent_private_share_commitment,
        intent_recovery_id,
        balance_partial_commitment,
        old_balance_nullifier,
        balance_recovery_id,
    };

    Ok((witness, statement))
}

// -------------------
// | Subsequent Fill |
// -------------------

/// Generate a validity proof for the intent-and-balance circuit on a
/// subsequent fill
async fn update_subsequent_fill_validity_proof(
    order: &Order,
    balance: &DarkpoolStateBalance,
    balance_merkle_proof: MerkleAuthenticationPath,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    let intent_merkle_proof = ctx
        .state
        .get_intent_merkle_proof(&order.id)
        .await?
        .ok_or(ValidityProofsError::MerkleProofNotFound)?;

    let (witness, statement) = generate_subsequent_fill_witness_statement(
        order,
        balance,
        intent_merkle_proof,
        balance_merkle_proof,
    )?;
    let witness_clone = witness.clone();

    let job = ProofJob::IntentAndBalanceValidity { witness, statement };
    let proof_recv = enqueue_proof_job(job, ctx).map_err(ValidityProofsError::proof_generation)?;

    let bundle: IntentAndBalanceValidityBundle =
        proof_recv.await.map_err(ValidityProofsError::proof_generation)?.into();

    let validity_bundle =
        ValidityProofBundle::IntentAndBalance { bundle, witness: witness_clone };
    let waiter = ctx.state.add_intent_validity_proof(order.id, validity_bundle).await?;
    waiter.await?;
    Ok(())
}

/// Generate a witness and statement for a subsequent fill of an
/// intent-and-balance validity proof
fn generate_subsequent_fill_witness_statement(
    order: &Order,
    balance: &DarkpoolStateBalance,
    intent_merkle_proof: MerkleAuthenticationPath,
    balance_merkle_proof: MerkleAuthenticationPath,
) -> Result<
    (SizedIntentAndBalanceValidityWitness, IntentAndBalanceValidityStatement),
    ValidityProofsError,
> {
    let old_intent = &order.intent;

    // --- Intent rotation --- //
    let intent_merkle_root = intent_merkle_proof.compute_root();
    let old_intent_opening = intent_merkle_proof.into();
    let old_intent_nullifier = old_intent.compute_nullifier();

    // Re-encrypt the `amount_in` field for the new intent
    let mut new_intent = old_intent.clone();
    let new_amount = new_intent.inner.amount_in;
    let new_amount_public_share = new_intent.stream_cipher_encrypt(&new_amount);
    new_intent.public_share.amount_in = new_amount_public_share;

    let intent_recovery_id = new_intent.compute_recovery_id();
    let new_intent_partial_commitment =
        new_intent.compute_partial_commitment(INTENT_PARTIAL_COMMITMENT_SIZE);

    // --- Balance rotation --- //
    let balance_merkle_root = balance_merkle_proof.compute_root();
    let old_balance_opening = balance_merkle_proof.into();
    let old_balance_nullifier = balance.compute_nullifier();

    // Build the new balance with re-encrypted post-match shares
    let mut new_balance = balance.clone();
    let post_match_balance = PostMatchBalance::from(balance.inner.clone());
    let post_match_balance_shares = new_balance.stream_cipher_encrypt(&post_match_balance);
    new_balance.update_from_post_match(&post_match_balance_shares);

    let balance_recovery_id = new_balance.compute_recovery_id();
    let balance_partial_commitment =
        new_balance.compute_partial_commitment(BALANCE_PARTIAL_COMMITMENT_SIZE);

    let witness = SizedIntentAndBalanceValidityWitness {
        old_intent: old_intent.clone(),
        old_intent_opening,
        intent: old_intent.inner.clone(),
        new_amount_public_share,
        old_balance: balance.clone(),
        old_balance_opening,
        balance: balance.inner.clone(),
        post_match_balance_shares,
    };

    let statement = IntentAndBalanceValidityStatement {
        intent_merkle_root,
        old_intent_nullifier,
        new_intent_partial_commitment,
        intent_recovery_id,
        balance_merkle_root,
        old_balance_nullifier,
        balance_partial_commitment,
        balance_recovery_id,
    };

    Ok((witness, statement))
}

// -----------
// | Helpers |
// -----------

/// Fetch an order from state by its ID
async fn get_order(order_id: &OrderId, ctx: &TaskContext) -> Result<Order, ValidityProofsError> {
    ctx.state
        .get_account_order(order_id)
        .await?
        .ok_or(ValidityProofsError::state("Order not found"))
}

/// Fetch the darkpool balance that capitalizes the given order's intent
async fn get_capitalizing_balance(
    account_id: AccountId,
    order: &Order,
    ctx: &TaskContext,
) -> Result<DarkpoolStateBalance, ValidityProofsError> {
    let mint = order.intent.inner.in_token;
    let balance = ctx
        .state
        .get_account_darkpool_balance(&account_id, &mint)
        .await?
        .ok_or(ValidityProofsError::state("darkpool balance not found for intent"))?;

    Ok(balance.state_wrapper)
}

/// Fetch the balance Merkle proof for the order's capitalizing balance
async fn get_balance_merkle_proof(
    account_id: AccountId,
    order: &Order,
    ctx: &TaskContext,
) -> Result<MerkleAuthenticationPath, ValidityProofsError> {
    let mint = order.intent.inner.in_token;
    ctx.state
        .get_balance_merkle_proof(&account_id, &mint)
        .await?
        .ok_or(ValidityProofsError::state("balance merkle proof not found"))
}
