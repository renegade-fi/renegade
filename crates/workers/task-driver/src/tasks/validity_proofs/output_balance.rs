//! Helpers for output balance validity proofs
//!
//! These helpers generate either:
//! - `NEW OUTPUT BALANCE VALIDITY` when no darkpool output balance exists
//! - `OUTPUT BALANCE VALIDITY` when a darkpool output balance already exists

use alloy::primitives::Address;
use circuit_types::schnorr::SchnorrSignature;
use circuit_types::traits::BaseType;
use circuits_core::zk_circuits::validity_proofs::{
    new_output_balance::{
        NEW_BALANCE_PARTIAL_COMMITMENT_SIZE, NewOutputBalanceValidityStatement,
        SizedNewOutputBalanceValidityWitness,
    },
    output_balance::{OutputBalanceValidityStatement, SizedOutputBalanceValidityWitness},
};
use darkpool_types::balance::{
    DarkpoolBalance, DarkpoolStateBalance, PostMatchBalance, PostMatchBalanceShare,
    PreMatchBalanceShare,
};
use job_types::proof_manager::ProofJob;
use types_account::{MerkleAuthenticationPath, OrderId, keychain::KeyChain, order::Order};
use types_core::AccountId;
use types_proofs::{
    NewOutputBalanceValidityBundle, OutputBalanceValidityBundle, ValidityProofBundle,
};

use crate::{
    tasks::validity_proofs::error::ValidityProofsError, traits::TaskContext,
    utils::enqueue_proof_job,
};

/// The number of public shares to include in the output balance partial
/// commitment.
const OUTPUT_BALANCE_PARTIAL_COMMITMENT_SIZE: usize =
    DarkpoolBalance::NUM_SCALARS - PostMatchBalanceShare::NUM_SCALARS;

/// Update the output balance validity proof for a given order.
///
/// The order's `out_token` determines the output balance mint.
/// If the output darkpool balance already exists in state, this generates
/// `OUTPUT BALANCE VALIDITY`. Otherwise, it generates
/// `NEW OUTPUT BALANCE VALIDITY`, bootstrapping authorization from the
/// order's input balance (`in_token`).
///
/// If `force` is true, the proof will be generated even if one exists in state.
pub async fn update_output_balance_validity_proof(
    account_id: AccountId,
    order_id: OrderId,
    new_output_balance_auth: SchnorrSignature,
    force: bool,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    // No proof needed if the matchable amount is zero
    let matchable_amount = ctx.state.get_order_matchable_amount(&order_id).await?;
    if matchable_amount == 0 {
        return Ok(());
    }

    // Fetch the order for which the balance is an output balance
    let order = get_order(&order_id, ctx).await?;
    let output_mint = order.intent.inner.out_token;
    let input_mint = order.intent.inner.in_token;

    // Skip proof generation if one already exists and force is not set
    let has_proof = ctx.state.has_output_balance_validity_proof(account_id, output_mint).await?;
    if !force && has_proof {
        return Ok(());
    }

    let existing_output_balance =
        ctx.state.get_account_darkpool_balance(&account_id, &output_mint).await?;
    if let Some(output_balance) = existing_output_balance {
        update_existing_output_balance_proof(
            account_id,
            output_mint,
            output_balance.state_wrapper,
            ctx,
        )
        .await
    } else {
        update_new_output_balance_proof(
            account_id,
            output_mint,
            input_mint,
            new_output_balance_auth,
            ctx,
        )
        .await
    }
}

// ----------------------------
// | Existing Output Balance  |
// ----------------------------

/// Generate and store `OUTPUT BALANCE VALIDITY` for an existing output balance.
async fn update_existing_output_balance_proof(
    account_id: AccountId,
    mint: Address,
    output_balance: DarkpoolStateBalance,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    let merkle_proof = ctx
        .state
        .get_balance_merkle_proof(&account_id, &mint)
        .await?
        .ok_or(ValidityProofsError::state("output balance merkle proof not found"))?;

    let (witness, statement) = generate_existing_witness_statement(&output_balance, merkle_proof)?;
    let witness_clone = witness.clone();

    let job = ProofJob::OutputBalanceValidity { witness, statement };
    let proof_recv = enqueue_proof_job(job, ctx).map_err(ValidityProofsError::proof_generation)?;

    let bundle: OutputBalanceValidityBundle =
        proof_recv.await.map_err(ValidityProofsError::proof_generation)?.into();

    let validity_bundle = ValidityProofBundle::OutputBalance { bundle, witness: witness_clone };
    let waiter = ctx.state.add_balance_validity_proof(account_id, mint, validity_bundle).await?;
    waiter.await?;
    Ok(())
}

/// Generate a witness and statement for `OUTPUT BALANCE VALIDITY`.
fn generate_existing_witness_statement(
    output_balance: &DarkpoolStateBalance,
    merkle_proof: MerkleAuthenticationPath,
) -> Result<(SizedOutputBalanceValidityWitness, OutputBalanceValidityStatement), ValidityProofsError>
{
    let merkle_root = merkle_proof.compute_root();
    let balance_opening = merkle_proof.into();
    let old_balance_nullifier = output_balance.compute_nullifier();

    // Re-encrypt the post-match fields for the new version
    let mut new_balance = output_balance.clone();
    let post_match_balance = PostMatchBalance::from(output_balance.inner.clone());
    let post_match_balance_shares = new_balance.stream_cipher_encrypt(&post_match_balance);
    new_balance.update_from_post_match(&post_match_balance_shares);

    let recovery_id = new_balance.compute_recovery_id();
    let new_partial_commitment =
        new_balance.compute_partial_commitment(OUTPUT_BALANCE_PARTIAL_COMMITMENT_SIZE);

    let witness = SizedOutputBalanceValidityWitness {
        old_balance: (*output_balance).clone(),
        balance_opening,
        balance: output_balance.inner.clone(),
        post_match_balance_shares,
    };

    let statement = OutputBalanceValidityStatement {
        merkle_root,
        old_balance_nullifier,
        new_partial_commitment,
        recovery_id,
    };

    Ok((witness, statement))
}

// -----------------------
// | New Output Balance  |
// -----------------------

/// Generate and store `NEW OUTPUT BALANCE VALIDITY` for a new output balance.
///
/// Authorization is bootstrapped from the existing balance at
/// `existing_balance_mint`.
async fn update_new_output_balance_proof(
    account_id: AccountId,
    mint: Address,
    existing_balance_mint: Address,
    new_output_balance_auth: SchnorrSignature,
    ctx: &TaskContext,
) -> Result<(), ValidityProofsError> {
    let mut keychain = ctx
        .state
        .get_account_keychain(&account_id)
        .await?
        .ok_or(ValidityProofsError::state("keychain not found"))?;

    let (existing_balance, existing_balance_merkle_proof) =
        get_balance_and_merkle_proof(account_id, existing_balance_mint, ctx).await?;

    let new_output_balance = create_new_output_balance(mint, &existing_balance, &mut keychain);

    // Persist the updated keychain (streams were consumed when sampling seeds)
    let waiter = ctx.state.update_account_keychain(account_id, keychain).await?;
    waiter.await?;

    let (witness, statement) = generate_new_witness_statement(
        new_output_balance,
        existing_balance,
        existing_balance_merkle_proof,
        new_output_balance_auth,
    )?;

    let witness_clone = witness.clone();
    let job = ProofJob::NewOutputBalanceValidity { witness, statement };
    let proof_recv = enqueue_proof_job(job, ctx).map_err(ValidityProofsError::proof_generation)?;

    let bundle: NewOutputBalanceValidityBundle =
        proof_recv.await.map_err(ValidityProofsError::proof_generation)?.into();

    let validity_bundle = ValidityProofBundle::NewOutputBalance { bundle, witness: witness_clone };
    let waiter = ctx.state.add_balance_validity_proof(account_id, mint, validity_bundle).await?;
    waiter.await?;
    Ok(())
}

/// Generate a witness and statement for `NEW OUTPUT BALANCE VALIDITY`.
fn generate_new_witness_statement(
    mut new_output_balance: DarkpoolStateBalance,
    existing_balance: DarkpoolStateBalance,
    existing_balance_merkle_proof: MerkleAuthenticationPath,
    new_output_balance_auth: SchnorrSignature,
) -> Result<
    (SizedNewOutputBalanceValidityWitness, NewOutputBalanceValidityStatement),
    ValidityProofsError,
> {
    let existing_balance_merkle_root = existing_balance_merkle_proof.compute_root();
    let existing_balance_opening = existing_balance_merkle_proof.into();
    let existing_balance_nullifier = existing_balance.compute_nullifier();

    // Clone before mutation; `compute_recovery_id` advances stream state.
    let initial_new_output_balance = new_output_balance.clone();
    let pre_match_balance_shares =
        PreMatchBalanceShare::from(initial_new_output_balance.public_share.clone());
    let post_match_balance_shares =
        PostMatchBalanceShare::from(initial_new_output_balance.public_share.clone());

    let recovery_id = new_output_balance.compute_recovery_id();
    let new_balance_partial_commitment =
        new_output_balance.compute_partial_commitment(NEW_BALANCE_PARTIAL_COMMITMENT_SIZE);

    let witness = SizedNewOutputBalanceValidityWitness {
        new_balance: initial_new_output_balance.clone(),
        balance: initial_new_output_balance.inner.clone(),
        post_match_balance_shares,
        existing_balance,
        existing_balance_opening,
        new_balance_authorization_signature: new_output_balance_auth,
    };

    let statement = NewOutputBalanceValidityStatement {
        existing_balance_merkle_root,
        existing_balance_nullifier,
        pre_match_balance_shares,
        new_balance_partial_commitment,
        recovery_id,
    };

    Ok((witness, statement))
}

// -----------
// | Helpers |
// -----------

/// Create a new zeroed darkpool output balance from the account keychain.
///
/// Inherits `owner`, `authority`, and `relayer_fee_recipient` from the
/// existing balance used to bootstrap authorization.
fn create_new_output_balance(
    mint: Address,
    existing_balance: &DarkpoolStateBalance,
    keychain: &mut KeyChain,
) -> DarkpoolStateBalance {
    let share_stream = keychain.sample_share_stream();
    let recovery_stream = keychain.sample_recovery_id_stream();

    let new_balance = DarkpoolBalance::new(
        mint,
        existing_balance.inner.owner,
        existing_balance.inner.relayer_fee_recipient,
        existing_balance.inner.authority,
    );
    DarkpoolStateBalance::new(new_balance, share_stream.seed, recovery_stream.seed)
}

/// Fetch the order for the given order id
async fn get_order(order_id: &OrderId, ctx: &TaskContext) -> Result<Order, ValidityProofsError> {
    ctx.state
        .get_account_order(order_id)
        .await?
        .ok_or(ValidityProofsError::state("order not found"))
}

/// Fetch a darkpool balance and its Merkle proof for the given account and
/// mint.
async fn get_balance_and_merkle_proof(
    account_id: AccountId,
    mint: Address,
    ctx: &TaskContext,
) -> Result<(DarkpoolStateBalance, MerkleAuthenticationPath), ValidityProofsError> {
    let balance = ctx
        .state
        .get_account_darkpool_balance(&account_id, &mint)
        .await?
        .ok_or(ValidityProofsError::state("darkpool balance not found"))?;
    let merkle_proof = ctx
        .state
        .get_balance_merkle_proof(&account_id, &mint)
        .await?
        .ok_or(ValidityProofsError::state("balance merkle proof not found"))?;

    Ok((balance.state_wrapper, merkle_proof))
}
