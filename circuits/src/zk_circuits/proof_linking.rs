//! Helpers for linking proofs between circuits
//!
//! TODO: Figure out which proving and verifying keys to use once we generate
//! them for the circuits

use core::panic;

use ark_mpc::{network::PartyId, PARTY0, PARTY1};
use circuit_types::{
    errors::ProverError, traits::SingleProverCircuit, Fabric, MpcPlonkLinkProof,
    MpcProofLinkingHint, PlonkLinkProof, PlonkProof, ProofLinkingHint,
};
use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS, MERKLE_HEIGHT};
use mpc_plonk::{
    multiprover::proof_system::MultiproverPlonkKzgSnark, proof_system::PlonkKzgSnark,
    transcript::SolidityTranscript,
};
use mpc_relation::proof_linking::GroupLayout;

use crate::zk_circuits::{valid_reblind::ValidReblind, VALID_REBLIND_COMMITMENTS_LINK};

use super::{
    valid_match_settle::ValidMatchSettle, VALID_COMMITMENTS_MATCH_SETTLE_LINK0,
    VALID_COMMITMENTS_MATCH_SETTLE_LINK1,
};

// ---------------------------------------
// | Valid Reblind <-> Valid Commitments |
// ---------------------------------------

/// Link a proof of VALID COMMITMENTS with a proof of VALID REBLIND using the
/// system wide sizing constants
pub fn link_sized_commitments_reblind(
    reblind_link_hint: &ProofLinkingHint,
    commitments_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_commitments_reblind::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>(
        reblind_link_hint,
        commitments_link_hint,
    )
}

/// Link a proof of VALID COMMITMENTS with a proof of VALID REBLIND
pub fn link_commitments_reblind<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
>(
    reblind_link_hint: &ProofLinkingHint,
    commitments_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Get the group layout for the reblind <-> commitments link group
    #[rustfmt::skip]
    let layout =
        get_reblind_commitments_group_layout::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>()?;
    let pk = ValidReblind::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>::proving_key();

    PlonkKzgSnark::link_proofs::<SolidityTranscript>(
        reblind_link_hint,
        commitments_link_hint,
        &layout,
        &pk.commit_key,
    )
    .map_err(ProverError::Plonk)
}

/// Validate a link between a proof of VALID COMMITMENTS with a proof of VALID
/// REBLIND
pub fn validate_commitments_reblind_link<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
>(
    link_proof: &PlonkLinkProof,
    reblind_proof: &PlonkProof,
    commitments_proof: &PlonkProof,
) -> Result<(), ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Get the group layout for the reblind <-> commitments link group
    #[rustfmt::skip]
    let layout =
        get_reblind_commitments_group_layout::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>()?;
    let vk = ValidReblind::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>::verifying_key();

    PlonkKzgSnark::verify_link_proof::<SolidityTranscript>(
        reblind_proof,
        commitments_proof,
        link_proof,
        &layout,
        &vk.open_key,
    )
    .map_err(ProverError::Plonk)
}

/// Get the group layout for the reblind <-> commitments link group
fn get_reblind_commitments_group_layout<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
>() -> Result<GroupLayout, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    let circuit_layout =
        ValidReblind::<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>::get_circuit_layout()
            .map_err(ProverError::Plonk)?;
    Ok(circuit_layout.get_group_layout(VALID_REBLIND_COMMITMENTS_LINK))
}

// --------------------------------
// | Commitments <-> Match Settle |
// --------------------------------

/// Link a proof of VALID COMMITMENTS with a proof of MATCH SETTLE using the
/// system wide sizing constants in a singleprover context
pub fn link_sized_commitments_match_settle(
    party_id: PartyId,
    commitments_link_hint: &ProofLinkingHint,
    match_settle_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_commitments_match_settle::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>(
        party_id,
        commitments_link_hint,
        match_settle_link_hint,
    )
}

/// Link a proof of VALID COMMITMENTS with a proof of MATCH SETTLE using the
/// system wide sizing constants in a multiprover context
pub fn link_sized_commitments_match_settle_multiprover(
    party_id: PartyId,
    commitments_link_hint: &MpcProofLinkingHint,
    match_settle_link_hint: &MpcProofLinkingHint,
    fabric: &Fabric,
) -> Result<MpcPlonkLinkProof, ProverError> {
    link_commitments_match_settle_multiprover::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>(
        party_id,
        commitments_link_hint,
        match_settle_link_hint,
        fabric,
    )
}

/// Link a proof of VALID COMMITMENTS with a proof of MATCH SETTLE in a
/// singleprover context
pub fn link_commitments_match_settle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    party_id: PartyId,
    commitments_link_hint: &ProofLinkingHint,
    match_settle_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Get the group layout for the match settle <-> commitments link group
    let layout =
        get_commitments_match_settle_group_layout::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>(party_id)?;
    let pk = ValidMatchSettle::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>::proving_key();

    PlonkKzgSnark::link_proofs::<SolidityTranscript>(
        commitments_link_hint,
        match_settle_link_hint,
        &layout,
        &pk.commit_key,
    )
    .map_err(ProverError::Plonk)
}

/// Link a proof of MATCH SETTLE with a proof of VALID COMMITMENTS in a
/// multiprover context
pub fn link_commitments_match_settle_multiprover<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    party_id: PartyId,
    commitments_link_hint: &MpcProofLinkingHint,
    match_settle_link_hint: &MpcProofLinkingHint,
    fabric: &Fabric,
) -> Result<MpcPlonkLinkProof, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Get the group layout for the match settle <-> commitments link group
    let layout =
        get_commitments_match_settle_group_layout::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>(party_id)?;
    let pk = ValidMatchSettle::proving_key();

    MultiproverPlonkKzgSnark::link_proofs(
        commitments_link_hint,
        match_settle_link_hint,
        &layout,
        &pk.commit_key,
        fabric,
    )
    .map_err(ProverError::Plonk)
}

/// Validate a link between a proof of MATCH SETTLE with a proof of VALID
/// COMMITMENTS
pub fn validate_commitments_match_settle_link<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    party_id: PartyId,
    link_proof: &PlonkLinkProof,
    commitments_proof: &PlonkProof,
    match_settle_proof: &PlonkProof,
) -> Result<(), ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Get the group layout for the match settle <-> commitments link group
    let layout =
        get_commitments_match_settle_group_layout::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>(party_id)?;
    let vk = ValidMatchSettle::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>::verifying_key();

    PlonkKzgSnark::verify_link_proof::<SolidityTranscript>(
        commitments_proof,
        match_settle_proof,
        link_proof,
        &layout,
        &vk.open_key,
    )
    .map_err(ProverError::Plonk)
}

/// Get the group layout for the match settle <-> commitments link group
fn get_commitments_match_settle_group_layout<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    party_id: PartyId,
) -> Result<GroupLayout, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Match the group id by party id
    let group_id = match party_id {
        PARTY0 => VALID_COMMITMENTS_MATCH_SETTLE_LINK0,
        PARTY1 => VALID_COMMITMENTS_MATCH_SETTLE_LINK1,
        _ => panic!("invalid party id"),
    };

    let layout = ValidMatchSettle::<MAX_BALANCES, MAX_ORDERS, MAX_FEES>::get_circuit_layout()
        .map_err(ProverError::Plonk)?;
    Ok(layout.get_group_layout(group_id))
}
