//! Helpers for linking proofs between circuits

use core::panic;

use ark_mpc::{network::PartyId, PARTY0, PARTY1};
use circuit_types::{
    errors::ProverError, traits::SingleProverCircuit, Fabric, MpcPlonkLinkProof,
    MpcProofLinkingHint, PlonkLinkProof, PlonkProof, ProofLinkingHint,
};
use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
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
    link_commitments_reblind::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>(
        reblind_link_hint,
        commitments_link_hint,
    )
}

/// Link a proof of VALID COMMITMENTS with a proof of VALID REBLIND
pub fn link_commitments_reblind<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    reblind_link_hint: &ProofLinkingHint,
    commitments_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Get the group layout for the reblind <-> commitments link group
    #[rustfmt::skip]
    let layout =
        get_reblind_commitments_group_layout::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>()?;
    let pk = ValidReblind::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>::proving_key();

    PlonkKzgSnark::link_proofs::<SolidityTranscript>(
        reblind_link_hint,
        commitments_link_hint,
        &layout,
        &pk.commit_key,
    )
    .map_err(ProverError::Plonk)
}

/// Validate a link between a proof of VALID REBLIND with a proof of VALID
/// COMMITMENTS using the system wide sizing constants
pub fn validate_sized_commitments_reblind_link(
    link_proof: &PlonkLinkProof,
    reblind_proof: &PlonkProof,
    commitments_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_commitments_reblind_link::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>(
        link_proof,
        reblind_proof,
        commitments_proof,
    )
}

/// Validate a link between a proof of VALID COMMITMENTS with a proof of VALID
/// REBLIND
pub fn validate_commitments_reblind_link<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>(
    link_proof: &PlonkLinkProof,
    reblind_proof: &PlonkProof,
    commitments_proof: &PlonkProof,
) -> Result<(), ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Get the group layout for the reblind <-> commitments link group
    #[rustfmt::skip]
    let layout =
        get_reblind_commitments_group_layout::<MAX_BALANCES, MAX_ORDERS,  MERKLE_HEIGHT>()?;
    let vk = ValidReblind::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>::verifying_key();

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
pub fn get_reblind_commitments_group_layout<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MERKLE_HEIGHT: usize,
>() -> Result<GroupLayout, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    let circuit_layout =
        ValidReblind::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>::get_circuit_layout()
            .map_err(ProverError::Plonk)?;
    Ok(circuit_layout.get_group_layout(VALID_REBLIND_COMMITMENTS_LINK))
}

// --------------------------------
// | Commitments <-> Match Proofs |
// --------------------------------

/// Link a proof of `VALID COMMITMENTS` with an atomic match settle proof
///
/// There are two atomic match settlement circuits:
/// - `VALID MATCH SETTLE ATOMIC`
/// - `VALID MALLEABLE MATCH SETTLE ATOMIC`
///
/// These circuits link to `VALID COMMITMENTS` using the same proof-linking
/// layout As the link between the first party's `VALID COMMITMENTS` and a
/// standard proof of `VALID MATCH SETTLE`, so we can reuse the helpers built
/// for the standard match settle link
pub fn link_sized_commitments_atomic_match_settle(
    commitments_link_hint: &ProofLinkingHint,
    atomic_settle_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_commitments_match_settle::<MAX_BALANCES, MAX_ORDERS>(
        PARTY0,
        commitments_link_hint,
        atomic_settle_link_hint,
    )
}

/// Link a proof of `VALID COMMITMENTS` into an atomic match settle proof,
/// with generics sizing constants
pub fn link_commitments_atomic_match_settle<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    commitments_link_hint: &ProofLinkingHint,
    atomic_settle_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    link_commitments_match_settle::<MAX_BALANCES, MAX_ORDERS>(
        PARTY0,
        commitments_link_hint,
        atomic_settle_link_hint,
    )
}

/// Verify a link between a proof of `VALID COMMITMENTS` and an atomic match
/// settle proof
///
/// See the doc comment above for `link_sized_commitments_atomic_match_settle`
/// for more details
pub fn validate_sized_commitments_atomic_match_settle_link(
    link_proof: &PlonkLinkProof,
    commitments_proof: &PlonkProof,
    atomic_settle_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_commitments_match_settle_link::<MAX_BALANCES, MAX_ORDERS>(
        PARTY0,
        link_proof,
        commitments_proof,
        atomic_settle_proof,
    )
}

/// Verify a link between a proof of `VALID COMMITMENTS` and an atomic match
/// settle proof, with generics sizing constants
pub fn validate_commitments_atomic_match_settle_link<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
>(
    link_proof: &PlonkLinkProof,
    commitments_proof: &PlonkProof,
    atomic_settle_proof: &PlonkProof,
) -> Result<(), ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    validate_commitments_match_settle_link::<MAX_BALANCES, MAX_ORDERS>(
        PARTY0,
        link_proof,
        commitments_proof,
        atomic_settle_proof,
    )
}

/// Link a proof of VALID COMMITMENTS with a proof of MATCH SETTLE using the
/// system wide sizing constants in a singleprover context
pub fn link_sized_commitments_match_settle(
    party_id: PartyId,
    commitments_link_hint: &ProofLinkingHint,
    match_settle_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError> {
    link_commitments_match_settle::<MAX_BALANCES, MAX_ORDERS>(
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
    link_commitments_match_settle_multiprover::<MAX_BALANCES, MAX_ORDERS>(
        party_id,
        commitments_link_hint,
        match_settle_link_hint,
        fabric,
    )
}

/// Link a proof of VALID COMMITMENTS with a proof of MATCH SETTLE in a
/// singleprover context
pub fn link_commitments_match_settle<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    party_id: PartyId,
    commitments_link_hint: &ProofLinkingHint,
    match_settle_link_hint: &ProofLinkingHint,
) -> Result<PlonkLinkProof, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Get the group layout for the match settle <-> commitments link group
    let layout = get_commitments_match_settle_group_layout::<MAX_BALANCES, MAX_ORDERS>(party_id)?;
    let pk = ValidMatchSettle::<MAX_BALANCES, MAX_ORDERS>::proving_key();

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
>(
    party_id: PartyId,
    commitments_link_hint: &MpcProofLinkingHint,
    match_settle_link_hint: &MpcProofLinkingHint,
    fabric: &Fabric,
) -> Result<MpcPlonkLinkProof, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Get the group layout for the match settle <-> commitments link group
    let layout = get_commitments_match_settle_group_layout::<MAX_BALANCES, MAX_ORDERS>(party_id)?;
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

/// Validate a link between a proof of VALID COMMITMENTS with a proof of MATCH
/// SETTLE using the system wide sizing constants
pub fn validate_sized_commitments_match_settle_link(
    party_id: PartyId,
    link_proof: &PlonkLinkProof,
    commitments_proof: &PlonkProof,
    match_settle_proof: &PlonkProof,
) -> Result<(), ProverError> {
    validate_commitments_match_settle_link::<MAX_BALANCES, MAX_ORDERS>(
        party_id,
        link_proof,
        commitments_proof,
        match_settle_proof,
    )
}

/// Validate a link between a proof of MATCH SETTLE with a proof of VALID
/// COMMITMENTS
pub fn validate_commitments_match_settle_link<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    party_id: PartyId,
    link_proof: &PlonkLinkProof,
    commitments_proof: &PlonkProof,
    match_settle_proof: &PlonkProof,
) -> Result<(), ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Get the group layout for the match settle <-> commitments link group
    let layout = get_commitments_match_settle_group_layout::<MAX_BALANCES, MAX_ORDERS>(party_id)?;
    let vk = ValidMatchSettle::<MAX_BALANCES, MAX_ORDERS>::verifying_key();

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
pub fn get_commitments_match_settle_group_layout<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
>(
    party_id: PartyId,
) -> Result<GroupLayout, ProverError>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // Match the group id by party id
    let group_id = match party_id {
        PARTY0 => VALID_COMMITMENTS_MATCH_SETTLE_LINK0,
        PARTY1 => VALID_COMMITMENTS_MATCH_SETTLE_LINK1,
        _ => panic!("invalid party id"),
    };

    let layout = ValidMatchSettle::<MAX_BALANCES, MAX_ORDERS>::get_circuit_layout()
        .map_err(ProverError::Plonk)?;
    Ok(layout.get_group_layout(group_id))
}

#[cfg(test)]
mod test {
    use ark_mpc::{network::PartyId, test_helpers::execute_mock_mpc, PARTY0, PARTY1};
    use circuit_types::{
        balance::Balance,
        errors::ProverError,
        fees::FeeTakeRate,
        fixed_point::FixedPoint,
        order::OrderSide,
        r#match::{BoundedMatchResult, ExternalMatchResult, MatchResult},
        traits::{BaseType, MpcBaseType, SingleProverCircuit},
        wallet::WalletShare,
        Address,
    };
    use constants::Scalar;
    use mpc_plonk::multiprover::proof_system::MpcLinkingHint;
    use rand::{distributions::uniform::SampleRange, thread_rng};
    use util::matching_engine::{compute_fee_obligation, settle_match_into_wallets};

    use crate::{
        multiprover_prove_with_hint, singleprover_prove_with_hint,
        zk_circuits::{
            proof_linking::link_commitments_match_settle,
            test_helpers::{
                create_wallet_shares, SizedWalletShare, INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS,
            },
            valid_commitments::{
                test_helpers::create_witness_and_statement_with_shares as commitments_witness_statement,
                ValidCommitments,
            },
            valid_malleable_match_settle_atomic::{
                ValidMalleableMatchSettleAtomic, ValidMalleableMatchSettleAtomicStatement,
                ValidMalleableMatchSettleAtomicWitness,
            },
            valid_match_settle::{
                test_helpers::dummy_witness_and_statement as match_settle_witness_statement,
                ValidMatchSettle,
            },
            valid_match_settle_atomic::{
                ValidMatchSettleAtomic, ValidMatchSettleAtomicStatement,
                ValidMatchSettleAtomicWitness,
            },
            valid_reblind::{
                test_helpers::construct_witness_statement as reblind_witness_statement,
                ValidReblind,
            },
        },
    };

    use super::{
        link_commitments_atomic_match_settle, link_commitments_match_settle_multiprover,
        link_commitments_reblind, validate_commitments_atomic_match_settle_link,
        validate_commitments_match_settle_link, validate_commitments_reblind_link,
    };

    /// The Merkle height used for testing
    const MERKLE_HEIGHT: usize = 3;
    /// Valid reblind with testing sizing
    type SizedValidReblind = ValidReblind<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>;
    /// Valid commitments with testing sizing
    type SizedValidCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS>;
    /// Valid match settle with testing sizing
    type SizedValidMatchSettle = ValidMatchSettle<MAX_BALANCES, MAX_ORDERS>;

    // -----------
    // | Helpers |
    // -----------

    /// Prove VALID COMMITMENTS and VALID REBLIND, then link the proofs and
    /// verify the link
    fn test_commitments_reblind_link(
        reblind_witness: <SizedValidReblind as SingleProverCircuit>::Witness,
        reblind_statement: <SizedValidReblind as SingleProverCircuit>::Statement,
        comm_witness: <SizedValidCommitments as SingleProverCircuit>::Witness,
        comm_statement: <SizedValidCommitments as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of VALID REBLIND and one of VALID COMMITMENTS
        let (reblind_proof, reblind_hint) =
            singleprover_prove_with_hint::<SizedValidReblind>(reblind_witness, reblind_statement)?;
        let (comm_proof, comm_hint) =
            singleprover_prove_with_hint::<SizedValidCommitments>(comm_witness, comm_statement)?;

        // Link the proofs and verify the link
        let proof = link_commitments_reblind::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>(
            &reblind_hint,
            &comm_hint,
        )?;
        validate_commitments_reblind_link::<MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT>(
            &proof,
            &reblind_proof,
            &comm_proof,
        )
    }

    /// Prove VALID COMMITMENTS and VALID MATCH SETTLE, then link the proofs and
    /// verify the link
    async fn test_commitments_match_settle_link(
        party_id: PartyId,
        comm_witness: <SizedValidCommitments as SingleProverCircuit>::Witness,
        comm_statement: <SizedValidCommitments as SingleProverCircuit>::Statement,
        match_settle_witness: <SizedValidMatchSettle as SingleProverCircuit>::Witness,
        match_settle_statement: <SizedValidMatchSettle as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Singleprover
        test_commitments_match_settle_singleprover(
            party_id,
            comm_witness.clone(),
            comm_statement,
            match_settle_witness.clone(),
            match_settle_statement.clone(),
        )?;

        // Multiprover
        test_commitments_match_settle_multiprover(
            party_id,
            comm_witness,
            comm_statement,
            match_settle_witness,
            match_settle_statement,
        )
        .await
    }

    /// Test the commitments <-> match-settle link in a singleprover context
    fn test_commitments_match_settle_singleprover(
        party_id: PartyId,
        comm_witness: <SizedValidCommitments as SingleProverCircuit>::Witness,
        comm_statement: <SizedValidCommitments as SingleProverCircuit>::Statement,
        match_settle_witness: <SizedValidMatchSettle as SingleProverCircuit>::Witness,
        match_settle_statement: <SizedValidMatchSettle as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of VALID COMMITMENTS and one of VALID MATCH SETTLE
        let (comm_proof, comm_hint) =
            singleprover_prove_with_hint::<SizedValidCommitments>(comm_witness, comm_statement)?;
        let (match_settle_proof, match_settle_hint) =
            singleprover_prove_with_hint::<SizedValidMatchSettle>(
                match_settle_witness,
                match_settle_statement,
            )?;

        let link_proof = link_commitments_match_settle::<MAX_BALANCES, MAX_ORDERS>(
            party_id,
            &comm_hint,
            &match_settle_hint,
        )?;

        // Validate the link proof
        validate_commitments_match_settle_link::<MAX_BALANCES, MAX_ORDERS>(
            party_id,
            &link_proof,
            &comm_proof,
            &match_settle_proof,
        )
    }

    /// Test the commitments <-> match-settle link in a multiprover context
    async fn test_commitments_match_settle_multiprover(
        party_id: PartyId,
        comm_witness: <SizedValidCommitments as SingleProverCircuit>::Witness,
        comm_statement: <SizedValidCommitments as SingleProverCircuit>::Statement,
        match_settle_witness: <SizedValidMatchSettle as SingleProverCircuit>::Witness,
        match_settle_statement: <SizedValidMatchSettle as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of VALID COMMITMENTS and one of VALID MATCH SETTLE
        let (comm_proof, comm_hint) =
            singleprover_prove_with_hint::<SizedValidCommitments>(comm_witness, comm_statement)?;

        // Link the proofs and verify the link
        let ((link_proof, match_settle_proof), _) = execute_mock_mpc(|fabric| {
            let match_settle_witness = match_settle_witness.clone();
            let match_settle_statement = match_settle_statement.clone();
            let comm_hint = comm_hint.clone();

            async move {
                // Prove the match settle circuit
                let witness = match_settle_witness.allocate(PARTY0, &fabric);
                let statement = match_settle_statement.allocate(PARTY0, &fabric);
                let (match_settle_proof, match_settle_hint) = multiprover_prove_with_hint::<
                    SizedValidMatchSettle,
                >(
                    witness, statement, fabric.clone()
                )
                .unwrap();

                // Allocate the valid commitments link hint
                let comm_hint = MpcLinkingHint::from_singleprover_hint(&comm_hint, PARTY0, &fabric);

                // Link the proofs
                let link_proof = link_commitments_match_settle_multiprover::<
                    MAX_BALANCES,
                    MAX_ORDERS,
                >(
                    party_id, &comm_hint, &match_settle_hint, &fabric
                )
                .unwrap();

                (
                    link_proof.open_authenticated().await.unwrap(),
                    match_settle_proof.open_authenticated().await.unwrap(),
                )
            }
        })
        .await;

        validate_commitments_match_settle_link::<MAX_BALANCES, MAX_ORDERS>(
            party_id,
            &link_proof,
            &comm_proof,
            &match_settle_proof,
        )
    }

    /// Test the commitments <-> match-settle atomic link in a singleprover
    /// context
    fn test_commitments_match_settle_atomic_singleprover(
        comm_witness: <SizedValidCommitments as SingleProverCircuit>::Witness,
        comm_statement: <SizedValidCommitments as SingleProverCircuit>::Statement,
        match_settle_witness: <ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::Witness,
        match_settle_statement: <ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of VALID COMMITMENTS and one of VALID MATCH SETTLE ATOMIC
        let (comm_proof, comm_hint) =
            singleprover_prove_with_hint::<SizedValidCommitments>(comm_witness, comm_statement)?;
        let (match_settle_proof, match_settle_hint) =
            singleprover_prove_with_hint::<ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>>(
                match_settle_witness,
                match_settle_statement,
            )?;

        let link_proof = link_commitments_atomic_match_settle::<MAX_BALANCES, MAX_ORDERS>(
            &comm_hint,
            &match_settle_hint,
        )?;

        // Validate the link proof
        validate_commitments_atomic_match_settle_link::<MAX_BALANCES, MAX_ORDERS>(
            &link_proof,
            &comm_proof,
            &match_settle_proof,
        )
    }

    /// Test the commitments <-> malleable match-settle atomic link in a
    /// singleprover context
    fn test_commitments_malleable_match_settle_atomic_singleprover(
        comm_witness: <SizedValidCommitments as SingleProverCircuit>::Witness,
        comm_statement: <SizedValidCommitments as SingleProverCircuit>::Statement,
        match_atomic_witness: <ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::Witness,
        match_atomic_statement: <ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::Statement,
    ) -> Result<(), ProverError> {
        // Create a proof of VALID COMMITMENTS and one of VALID MALLEABLE MATCH SETTLE
        // ATOMIC
        let (comm_proof, comm_hint) =
            singleprover_prove_with_hint::<SizedValidCommitments>(comm_witness, comm_statement)?;
        let (match_atomic_proof, match_atomic_hint) =
            singleprover_prove_with_hint::<
                ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>,
            >(match_atomic_witness, match_atomic_statement)?;

        let link_proof = link_commitments_atomic_match_settle::<MAX_BALANCES, MAX_ORDERS>(
            &comm_hint,
            &match_atomic_hint,
        )?;

        // Validate the link proof
        validate_commitments_atomic_match_settle_link::<MAX_BALANCES, MAX_ORDERS>(
            &link_proof,
            &comm_proof,
            &match_atomic_proof,
        )
    }

    /// Builds a commitments and match settle witness and statement around a
    /// random match
    ///
    /// This largely involves modifying the dummy witness and statements for
    /// each circuit to align with one another so that they may be linked
    fn build_commitments_match_settle_data(
        party_id: PartyId,
    ) -> (
        <SizedValidCommitments as SingleProverCircuit>::Witness,
        <SizedValidCommitments as SingleProverCircuit>::Statement,
        <SizedValidMatchSettle as SingleProverCircuit>::Witness,
        <SizedValidMatchSettle as SingleProverCircuit>::Statement,
    ) {
        // Macro to select one of two options based on party id
        macro_rules! sel {
            ($a:expr, $b:expr) => {
                if party_id == PARTY0 {
                    $a
                } else {
                    $b
                }
            };
        }

        // Zero the balances
        let mut wallet = INITIAL_WALLET.clone();
        wallet.balances.iter_mut().for_each(|b| *b = Balance::default());

        // Generate a match-settle witness and statement, this generates a random match
        // on random orders
        let (mut match_witness, mut match_statement) = match_settle_witness_statement();

        // Get a mutable reference to the indices for the given party
        let indices =
            sel!(&mut match_statement.party0_indices, &mut match_statement.party1_indices);
        indices.order = 0; // Use the first order

        // Modify the wallet to work with the randomized match then create new wallet
        // shares
        wallet.orders[indices.order] =
            sel!(match_witness.order0.clone(), match_witness.order1.clone());
        wallet.balances[indices.balance_send] =
            sel!(match_witness.balance0.clone(), match_witness.balance1.clone());
        wallet.balances[indices.balance_receive] =
            sel!(match_witness.balance_receive0.clone(), match_witness.balance_receive1.clone());

        // Modify the VALID MATCH SETTLE witness to use the shares from the test wallet
        let (private_share, public_share) = create_wallet_shares(&wallet);
        *sel!(&mut match_witness.party0_public_shares, &mut match_witness.party1_public_shares) =
            public_share.clone();

        // Settle the randomized match into the test wallet's shares
        let mut new_public_shares0 = public_share.clone();
        let mut new_public_shares1 = public_share.clone();

        let party0_fees = compute_fee_obligation(
            wallet.max_match_fee,
            match_witness.order0.side,
            &match_witness.match_res,
        );
        let party1_fees = compute_fee_obligation(
            wallet.max_match_fee,
            match_witness.order1.side,
            &match_witness.match_res,
        );

        settle_match_into_wallets(
            &mut new_public_shares0,
            &mut new_public_shares1,
            // Use the same indices, only the selected wallet shares need to be correctly settled
            party0_fees,
            party1_fees,
            *indices,
            *indices,
            &match_witness.match_res,
        );

        *sel!(
            &mut match_statement.party0_modified_shares,
            &mut match_statement.party1_modified_shares
        ) = sel!(new_public_shares0, new_public_shares1);

        // Generate a commitments witness and statement and set the appropriate fields
        // to match the match-settle witness
        let (comm_witness, mut comm_statement) =
            commitments_witness_statement(&wallet, &public_share, &private_share);
        comm_statement.indices = *indices;

        (comm_witness, comm_statement, match_witness, match_statement)
    }

    /// Builds a commitments and match settle atomic witness and statement
    ///
    /// Here, we just use the data for a regular match and treat party0 as the
    /// internal party
    fn build_commitments_match_settle_atomic_data() -> (
        <SizedValidCommitments as SingleProverCircuit>::Witness,
        <SizedValidCommitments as SingleProverCircuit>::Statement,
        <ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::Witness,
        <ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::Statement,
    ) {
        let (comm_witness, comm_statement, match_witness, match_statement) =
            build_commitments_match_settle_data(PARTY0);

        let match_atomic_witness = ValidMatchSettleAtomicWitness {
            internal_party_order: match_witness.order0,
            internal_party_balance: match_witness.balance0,
            internal_party_receive_balance: match_witness.balance_receive0,
            relayer_fee: match_witness.relayer_fee0,
            internal_party_public_shares: match_witness.party0_public_shares.clone(),
            price: match_witness.price0,
            internal_party_fees: match_witness.party0_fees,
        };

        let relayer_fee_address = Address::default();
        let match_result = build_external_match_result(match_witness.match_res);
        let match_atomic_statement = ValidMatchSettleAtomicStatement {
            match_result,
            external_party_fees: match_witness.party1_fees,
            internal_party_modified_shares: match_statement.party0_modified_shares,
            internal_party_indices: match_statement.party0_indices,
            protocol_fee: match_statement.protocol_fee,
            relayer_fee_address,
        };

        (comm_witness, comm_statement, match_atomic_witness, match_atomic_statement)
    }

    /// Build a commitments and malleable match
    fn build_commitments_malleable_match_settle_atomic_data() -> (
        <SizedValidCommitments as SingleProverCircuit>::Witness,
        <SizedValidCommitments as SingleProverCircuit>::Statement,
        <ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::Witness,
        <ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS> as SingleProverCircuit>::Statement,
    ){
        let fee_rates = FeeTakeRate {
            relayer_fee_rate: FixedPoint::from_f64_round_down(0.0004),
            protocol_fee_rate: FixedPoint::from_f64_round_down(0.0001),
        };

        let (comm_witness, comm_statement, match_witness, _match_statement) =
            build_commitments_match_settle_data(PARTY0);

        let match_atomic_witness = ValidMalleableMatchSettleAtomicWitness {
            internal_party_order: match_witness.order0,
            internal_party_balance: match_witness.balance0,
            internal_party_receive_balance: match_witness.balance_receive0,
            internal_party_relayer_fee: match_witness.relayer_fee0,
            internal_party_public_shares: match_witness.party0_public_shares.clone(),
        };

        let price = match_witness.price0;
        let match_atomic_statement = ValidMalleableMatchSettleAtomicStatement {
            bounded_match_result: build_bounded_match_result(match_witness.match_res, price),
            external_fee_rates: fee_rates,
            internal_fee_rates: fee_rates,
            internal_party_public_shares: match_witness.party0_public_shares.clone(),
            relayer_fee_address: Address::default(),
        };

        (comm_witness, comm_statement, match_atomic_witness, match_atomic_statement)
    }

    /// Build an `ExternalMatchResult` from a `MatchResult`
    fn build_external_match_result(match_res: MatchResult) -> ExternalMatchResult {
        ExternalMatchResult {
            quote_mint: match_res.quote_mint,
            base_mint: match_res.base_mint,
            quote_amount: match_res.quote_amount,
            base_amount: match_res.base_amount,
            direction: match_res.direction,
        }
    }

    /// Build a `BoundedMatchResult` from a `MatchResult`
    ///
    /// For simplicity, we set min and max to be a small range, these values
    /// are not checked in the proof linking relation anyways
    fn build_bounded_match_result(match_res: MatchResult, price: FixedPoint) -> BoundedMatchResult {
        BoundedMatchResult {
            quote_mint: match_res.quote_mint,
            base_mint: match_res.base_mint,
            price,
            min_base_amount: match_res.base_amount - 1,
            max_base_amount: match_res.base_amount,
            direction: match_res.direction,
        }
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests a valid link between a proof of VALID REBLIND and a proof of VALID
    /// COMMITMENTS
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_reblind_commitments_valid_link() {
        let mut wallet = INITIAL_WALLET.clone();
        let (reblind_witness, reblind_statement) = reblind_witness_statement(&wallet);

        let private_share = reblind_witness.reblinded_wallet_private_shares.clone();
        let public_share = reblind_witness.reblinded_wallet_public_shares.clone();
        wallet.blinder = public_share.blinder + private_share.blinder;
        let (comm_witness, comm_statement) =
            commitments_witness_statement(&wallet, &public_share, &private_share);

        test_commitments_reblind_link(
            reblind_witness,
            reblind_statement,
            comm_witness,
            comm_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID REBLIND and a proof of
    /// VALID COMMITMENTS
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    fn test_reblind_commitments_invalid_link() {
        let mut wallet = INITIAL_WALLET.clone();
        let (reblind_witness, reblind_statement) = reblind_witness_statement(&wallet);

        let private_share = reblind_witness.reblinded_wallet_private_shares.clone();
        let public_share = reblind_witness.reblinded_wallet_public_shares.clone();
        wallet.blinder = public_share.blinder + private_share.blinder;

        // Randomly modify a share, add to the public share and subtract from the
        // private so that the wallet stays the same (i.e. is a valid witness)
        let mut rng = rand::thread_rng();
        let modification_idx = (0..SizedWalletShare::num_scalars()).sample_single(&mut rng);
        let mut public_shares = public_share.to_scalars();
        let mut private_shares = private_share.to_scalars();

        let modification = Scalar::random(&mut rng);
        public_shares[modification_idx] += modification;
        private_shares[modification_idx] -= modification;

        let public_share = SizedWalletShare::from_scalars(&mut public_shares.into_iter());
        let private_share = SizedWalletShare::from_scalars(&mut private_shares.into_iter());

        let (comm_witness, comm_statement) =
            commitments_witness_statement(&wallet, &public_share, &private_share);

        test_commitments_reblind_link(
            reblind_witness,
            reblind_statement,
            comm_witness,
            comm_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of VALID COMMITMENTS and a proof of
    /// VALID MATCH SETTLE on the first party's side
    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    async fn test_commitments_match_settle_valid_party0() {
        let (comm_witness, comm_statement, match_settle_witness, match_settle_statement) =
            build_commitments_match_settle_data(PARTY0);

        test_commitments_match_settle_link(
            PARTY0,
            comm_witness,
            comm_statement,
            match_settle_witness,
            match_settle_statement,
        )
        .await
        .unwrap()
    }

    /// Tests a valid link between a proof of VALID COMMITMENTS and a proof of
    /// VALID MATCH SETTLE on the second party's side
    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    async fn test_commitments_match_settle_valid_party1() {
        let (comm_witness, comm_statement, match_settle_witness, match_settle_statement) =
            build_commitments_match_settle_data(PARTY1);

        test_commitments_match_settle_link(
            PARTY1,
            comm_witness,
            comm_statement,
            match_settle_witness,
            match_settle_statement,
        )
        .await
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a proof
    /// of VALID MATCH SETTLE wherein the shares are modified between the
    /// two proofs
    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    async fn test_commitments_match_settle_invalid_link__modified_shares() {
        let (comm_witness, comm_statement, mut match_settle_witness, mut match_settle_statement) =
            build_commitments_match_settle_data(PARTY0);

        // Modify the shares on the first party's side, but keep them consistent such
        // that they remain a valid witness
        let mut rng = thread_rng();
        let mut modified_shares = match_settle_witness.party0_public_shares.to_scalars();
        let mut result_shares = match_settle_statement.party0_modified_shares.to_scalars();
        let modification_idx = (0..modified_shares.len()).sample_single(&mut rng);

        let modification = Scalar::random(&mut rng);
        modified_shares[modification_idx] += modification;
        result_shares[modification_idx] += modification;
        match_settle_witness.party0_public_shares =
            WalletShare::from_scalars(&mut modified_shares.into_iter());
        match_settle_statement.party0_modified_shares =
            WalletShare::from_scalars(&mut result_shares.into_iter());

        test_commitments_match_settle_singleprover(
            PARTY0,
            comm_witness,
            comm_statement,
            match_settle_witness,
            match_settle_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a proof
    /// of VALID MATCH SETTLE wherein the party's balance is modified between
    /// the two proofs
    ///
    /// Test this modification on the second party's side in the VALID MATCH
    /// SETTLE circuit
    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    async fn test_commitments_match_settle_invalid_link__modified_balance() {
        let (comm_witness, comm_statement, mut match_settle_witness, match_settle_statement) =
            build_commitments_match_settle_data(PARTY1);

        // Malicious prover tries to increase their balance by 1
        match_settle_witness.balance0.amount += 1;

        test_commitments_match_settle_singleprover(
            PARTY0,
            comm_witness,
            comm_statement,
            match_settle_witness,
            match_settle_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a proof
    /// of VALID MATCH SETTLE wherein the party's order is modified between
    /// the two proofs
    ///
    /// Test this modification on the first party's side in the VALID MATCH
    /// SETTLE circuit
    #[cfg_attr(feature = "ci", ignore)]
    #[tokio::test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    async fn test_commitments_match_settle_invalid_link__modified_order() {
        let (comm_witness, comm_statement, mut match_settle_witness, match_settle_statement) =
            build_commitments_match_settle_data(PARTY0);

        // Malicious prover tries to modify the buy side worst case price
        let price = &mut match_settle_witness.order0.worst_case_price;
        if match_settle_witness.order0.side == OrderSide::Buy {
            *price = *price + Scalar::one();
        } else {
            *price = *price - Scalar::one();
        }

        test_commitments_match_settle_singleprover(
            PARTY0,
            comm_witness,
            comm_statement,
            match_settle_witness,
            match_settle_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of VALID COMMITMENTS and a proof of
    /// VALID MATCH SETTLE ATOMIC
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_commitments_match_settle_atomic_valid_link() {
        let (comm_witness, comm_statement, match_atomic_witness, match_atomic_statement) =
            build_commitments_match_settle_atomic_data();

        test_commitments_match_settle_atomic_singleprover(
            comm_witness,
            comm_statement,
            match_atomic_witness,
            match_atomic_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a proof
    /// of VALID MATCH SETTLE ATOMIC with modified shares
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    fn test_commitments_match_settle_atomic_invalid_link_modified_shares() {
        let (comm_witness, comm_statement, mut match_atomic_witness, mut match_atomic_statement) =
            build_commitments_match_settle_atomic_data();

        // Modify the shares, but keep them consistent so that the witness is
        // still valid, but the link will fail
        let mut rng = thread_rng();
        let mut modified_shares = match_atomic_witness.internal_party_public_shares.to_scalars();
        let mut result_shares = match_atomic_statement.internal_party_modified_shares.to_scalars();
        let modification_idx = (0..modified_shares.len()).sample_single(&mut rng);

        let modification = Scalar::random(&mut rng);
        modified_shares[modification_idx] += modification;
        result_shares[modification_idx] += modification;
        match_atomic_witness.internal_party_public_shares =
            WalletShare::from_scalars(&mut modified_shares.into_iter());
        match_atomic_statement.internal_party_modified_shares =
            WalletShare::from_scalars(&mut result_shares.into_iter());

        test_commitments_match_settle_atomic_singleprover(
            comm_witness,
            comm_statement,
            match_atomic_witness,
            match_atomic_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a proof
    /// of VALID MATCH SETTLE ATOMIC with a modified balance
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    fn test_commitments_match_settle_atomic_invalid_link_modified_balance() {
        let (comm_witness, comm_statement, mut match_atomic_witness, match_atomic_statement) =
            build_commitments_match_settle_atomic_data();

        // Modify the balance
        match_atomic_witness.internal_party_balance.amount += 1;
        test_commitments_match_settle_atomic_singleprover(
            comm_witness,
            comm_statement,
            match_atomic_witness,
            match_atomic_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a
    /// of VALID MATCH SETTLE ATOMIC with a modified order
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    fn test_commitments_match_settle_atomic_invalid_link_modified_order() {
        let (comm_witness, comm_statement, mut match_atomic_witness, match_atomic_statement) =
            build_commitments_match_settle_atomic_data();

        // Modify the order
        let price = &mut match_atomic_witness.internal_party_order.worst_case_price;
        if match_atomic_witness.internal_party_order.side == OrderSide::Buy {
            *price = *price + Scalar::one();
        } else {
            *price = *price - Scalar::one();
        }

        test_commitments_match_settle_atomic_singleprover(
            comm_witness,
            comm_statement,
            match_atomic_witness,
            match_atomic_statement,
        )
        .unwrap();
    }

    /// Tests a valid link between a proof of VALID COMMITMENTS and a proof of
    /// VALID MALLEABLE MATCH SETTLE ATOMIC
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    fn test_commitments_malleable_match_settle_atomic_valid_link() {
        let (comm_witness, comm_statement, match_atomic_witness, match_atomic_statement) =
            build_commitments_malleable_match_settle_atomic_data();

        test_commitments_malleable_match_settle_atomic_singleprover(
            comm_witness,
            comm_statement,
            match_atomic_witness,
            match_atomic_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a proof
    /// of VALID MALLEABLE MATCH SETTLE ATOMIC with a modified secret share
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_commitments_malleable_match_settle_atomic__invalid_link__modified_shares() {
        let (comm_witness, comm_statement, mut match_atomic_witness, mut match_atomic_statement) =
            build_commitments_malleable_match_settle_atomic_data();

        // Modify the shares
        let mut rng = thread_rng();
        let mut modified_shares = match_atomic_witness.internal_party_public_shares.to_scalars();
        let mut result_shares = match_atomic_statement.internal_party_public_shares.to_scalars();
        let modification_idx = (0..modified_shares.len()).sample_single(&mut rng);

        let modification = Scalar::random(&mut rng);
        modified_shares[modification_idx] += modification;
        result_shares[modification_idx] += modification;

        match_atomic_witness.internal_party_public_shares =
            WalletShare::from_scalars(&mut modified_shares.into_iter());
        match_atomic_statement.internal_party_public_shares =
            WalletShare::from_scalars(&mut result_shares.into_iter());

        test_commitments_malleable_match_settle_atomic_singleprover(
            comm_witness,
            comm_statement,
            match_atomic_witness,
            match_atomic_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a proof
    /// of VALID MALLEABLE MATCH SETTLE ATOMIC with a modified balance
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_commitments_malleable_match_settle_atomic__invalid_link__modified_balance() {
        let (comm_witness, comm_statement, mut match_atomic_witness, match_atomic_statement) =
            build_commitments_malleable_match_settle_atomic_data();

        // Modify the balance
        match_atomic_witness.internal_party_balance.amount += 1;
        test_commitments_malleable_match_settle_atomic_singleprover(
            comm_witness,
            comm_statement,
            match_atomic_witness,
            match_atomic_statement,
        )
        .unwrap();
    }

    /// Tests an invalid link between a proof of VALID COMMITMENTS and a proof
    /// of VALID MALLEABLE MATCH SETTLE ATOMIC with a modified order
    #[cfg_attr(feature = "ci", ignore)]
    #[test]
    #[should_panic(expected = "ProofLinkVerification")]
    #[allow(non_snake_case)]
    fn test_commitments_malleable_match_settle_atomic__invalid_link__modified_order() {
        let (comm_witness, comm_statement, mut match_atomic_witness, match_atomic_statement) =
            build_commitments_malleable_match_settle_atomic_data();

        // Modify the order
        let price = &mut match_atomic_witness.internal_party_order.worst_case_price;
        if match_atomic_witness.internal_party_order.side == OrderSide::Buy {
            *price = *price + Scalar::one();
        } else {
            *price = *price - Scalar::one();
        }

        test_commitments_malleable_match_settle_atomic_singleprover(
            comm_witness,
            comm_statement,
            match_atomic_witness,
            match_atomic_statement,
        )
        .unwrap();
    }
}
