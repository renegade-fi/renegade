//! Helpers for intent only validity proofs

use circuits_core::zk_circuits::validity_proofs::{
    intent_and_balance::INTENT_PARTIAL_COMMITMENT_SIZE,
    intent_only::{IntentOnlyValidityStatement, SizedIntentOnlyValidityWitness},
    intent_only_first_fill::{
        IntentOnlyFirstFillValidityStatement, IntentOnlyFirstFillValidityWitness,
    },
};
use job_types::proof_manager::ProofJob;
use types_account::{MerkleAuthenticationPath, OrderId, order::Order};
use types_proofs::{
    IntentOnlyFirstFillValidityBundle, IntentOnlyValidityBundle, ValidityProofBundle,
};

use crate::{
    tasks::validity_proofs::error::ValidityProofsError, traits::TaskContext,
    utils::enqueue_proof_job,
};

/// Update the intent-only validity proof for a given order
pub async fn update_intent_only_validity_proof(
    order_id: OrderId,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    // No proof needed if the matchable amount is zero
    let matchable_amount = ctx.state.get_order_matchable_amount(&order_id).await?;
    if matchable_amount == 0 {
        return Ok(());
    }

    let order = ctx
        .state
        .get_account_order(&order_id)
        .await?
        .ok_or(ValidityProofsError::state("Order not found"))?;

    // Branch on first fill
    if !order.metadata.has_been_filled {
        // First fill
        update_intent_only_validity_proof_first_fill(&order, ctx).await?;
    } else {
        // Subsequent fill
        update_intent_only_validity_proof_subsequent_fill(&order, ctx).await?;
    }

    Ok(())
}

// --------------
// | First Fill |
// --------------

/// Generate a validity proof for the intent only circuit on the first fill
async fn update_intent_only_validity_proof_first_fill(
    order: &Order,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    let (witness, statement) = generate_intent_only_first_fill_witness_statement(order)?;

    let job = ProofJob::IntentOnlyFirstFillValidity { witness, statement };
    let proof_recv = enqueue_proof_job(job, ctx).map_err(ValidityProofsError::ProofGeneration)?;

    let bundle: IntentOnlyFirstFillValidityBundle =
        proof_recv.await.map_err(|e| ValidityProofsError::ProofGeneration(e.to_string()))?.into();

    let bundle = ValidityProofBundle::IntentOnlyFirstFill(bundle);
    let waiter = ctx.state.add_intent_validity_proof(order.id, bundle).await?;
    waiter.await?;
    Ok(())
}

/// Generate a witness and statement for an intent's first fill
fn generate_intent_only_first_fill_witness_statement(
    order: &Order,
) -> Result<
    (IntentOnlyFirstFillValidityWitness, IntentOnlyFirstFillValidityStatement),
    ValidityProofsError,
> {
    let initial_intent = &order.intent;

    // Clone before mutations; compute recovery_id and commitment
    let mut intent_clone = initial_intent.clone();
    let recovery_id = intent_clone.compute_recovery_id();
    let intent_private_commitment = intent_clone.compute_private_commitment();

    let private_shares = initial_intent.private_shares();
    let intent_public_share = initial_intent.public_share();

    let witness = IntentOnlyFirstFillValidityWitness {
        intent: initial_intent.inner.clone(),
        initial_intent_share_stream: initial_intent.share_stream.clone(),
        initial_intent_recovery_stream: initial_intent.recovery_stream.clone(),
        private_shares,
    };
    let statement = IntentOnlyFirstFillValidityStatement {
        owner: initial_intent.inner.owner,
        intent_private_commitment,
        recovery_id,
        intent_public_share,
    };

    Ok((witness, statement))
}

// -------------------
// | Subsequent Fill |
// -------------------

/// Generate a validity proof for the intent only circuit on a subsequent fill
async fn update_intent_only_validity_proof_subsequent_fill(
    order: &Order,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    let merkle_proof = ctx
        .state
        .get_intent_merkle_proof(&order.id)
        .await?
        .ok_or(ValidityProofsError::MerkleProofNotFound)?;

    let (witness, statement) =
        generate_intent_only_subsequent_fill_witness_statement(order, merkle_proof)?;

    let job = ProofJob::IntentOnlyValidity { witness, statement };
    let proof_recv = enqueue_proof_job(job, ctx).map_err(ValidityProofsError::ProofGeneration)?;

    let bundle: IntentOnlyValidityBundle =
        proof_recv.await.map_err(ValidityProofsError::proof_generation)?.into();

    let bundle = ValidityProofBundle::IntentOnly(bundle);
    let waiter = ctx.state.add_intent_validity_proof(order.id, bundle).await?;
    waiter.await?;
    Ok(())
}

/// Generate a witness and statement for an intent's subsequent fill
fn generate_intent_only_subsequent_fill_witness_statement(
    order: &Order,
    merkle_proof: MerkleAuthenticationPath,
) -> Result<(SizedIntentOnlyValidityWitness, IntentOnlyValidityStatement), ValidityProofsError> {
    let old_intent = &order.intent;

    let merkle_root = merkle_proof.compute_root();
    let old_intent_opening = merkle_proof.into();

    let old_intent_nullifier = old_intent.compute_nullifier();

    let mut new_intent = old_intent.clone();
    let new_amount = new_intent.inner.amount_in;
    let new_amount_public_share = new_intent.stream_cipher_encrypt(&new_amount);
    new_intent.public_share.amount_in = new_amount_public_share;

    let recovery_id = new_intent.compute_recovery_id();
    let new_intent_partial_commitment =
        new_intent.compute_partial_commitment(INTENT_PARTIAL_COMMITMENT_SIZE);

    let witness = SizedIntentOnlyValidityWitness {
        old_intent: old_intent.clone(),
        old_intent_opening,
        intent: old_intent.inner.clone(),
    };
    let statement = IntentOnlyValidityStatement {
        owner: old_intent.inner.owner,
        merkle_root,
        old_intent_nullifier,
        new_amount_public_share,
        new_intent_partial_commitment,
        recovery_id,
    };

    Ok((witness, statement))
}
