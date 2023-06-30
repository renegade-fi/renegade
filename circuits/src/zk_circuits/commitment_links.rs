//! Groups helpers that validate commitment links between proofs
//!
//! When we wish to guarantee input consistency between two proofs; we share the
//! commitment to each consistent variable between the proofs. Checking that two
//! proofs are input consistent then amounts to checking that the relevant witness elements
//! use the same commitment between proofs

use circuit_types::{traits::CircuitBaseType, wallet::LinkableWalletShare};
use merlin::Transcript;
use mpc_bulletproof::{r1cs::Prover, PedersenGens};
use rand_core::OsRng;

use super::{
    valid_commitments::ValidCommitmentsWitnessCommitment,
    valid_match_mpc::ValidMatchMpcWitnessCommitment, valid_reblind::ValidReblindWitnessCommitment,
};

/// Verify that a proof of `VALID REBLIND` and a proof of `VALID COMMITMENTS` are linked properly
///
/// The linked elements are simply the reblinded secret shares of the wallet
#[rustfmt::skip]
pub fn verify_reblind_commitments_link<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    const MERKLE_HEIGHT: usize,
>(
    reblind_commitment: &ValidReblindWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES, MERKLE_HEIGHT>,
    commitments_commitment: &ValidCommitmentsWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
) -> bool
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    reblind_commitment.reblinded_wallet_private_shares == commitments_commitment.private_secret_shares &&
    reblind_commitment.reblinded_wallet_public_shares == commitments_commitment.public_secret_shares
}

/// Verify that a proof of `VALID COMMITMENTS` and a proof of `VALID MATCH MPC` are linked properly
///
/// The linked elements are the orders and balances used as input to the matching engine
pub fn verify_commitment_match_link<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    party0_commitments_commitment: &ValidCommitmentsWitnessCommitment<
        MAX_BALANCES,
        MAX_ORDERS,
        MAX_FEES,
    >,
    party1_commitments_commitment: &ValidCommitmentsWitnessCommitment<
        MAX_BALANCES,
        MAX_ORDERS,
        MAX_FEES,
    >,
    match_commitment: &ValidMatchMpcWitnessCommitment,
) -> bool
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    party0_commitments_commitment.balance_send == match_commitment.balance1
        && party0_commitments_commitment.order == match_commitment.order1
        && party1_commitments_commitment.balance_send == match_commitment.balance2
        && party1_commitments_commitment.order == match_commitment.order2
}

/// Verify that a given set of opened augmented public shares are the same as those in
/// the two parties' proofs of `VALID COMMITMENTS`
pub fn verify_augmented_shares_commitments<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    party0_augmented_shares: &LinkableWalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    party1_augmented_shares: &LinkableWalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    party0_validity_commitments: &ValidCommitmentsWitnessCommitment<
        MAX_BALANCES,
        MAX_ORDERS,
        MAX_FEES,
    >,
    party1_validity_commitments: &ValidCommitmentsWitnessCommitment<
        MAX_BALANCES,
        MAX_ORDERS,
        MAX_FEES,
    >,
) -> bool
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Create a dummy prover for simplicity
    // We can work around this and implement a more direct commitment if this
    // path becomes a bottleneck
    let pc_gens = PedersenGens::default();
    let mut transcript = Transcript::new(b"");
    let mut prover = Prover::new(&pc_gens, &mut transcript);

    // Commit to the linked augmented shares and verify that the commitments are the same
    // as the commitments in the validity proofs
    let mut rng = OsRng {};
    let (_, party0_shares_comm) = party0_augmented_shares.commit_witness(&mut rng, &mut prover);
    let (_, party1_shares_comm) = party1_augmented_shares.commit_witness(&mut rng, &mut prover);

    party0_shares_comm == party0_validity_commitments.augmented_public_shares
        && party1_shares_comm == party1_validity_commitments.augmented_public_shares
}
