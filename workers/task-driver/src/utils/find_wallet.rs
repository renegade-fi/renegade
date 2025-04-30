//! Helpers for finding wallets in the contract state

use std::iter;

use circuit_types::{traits::BaseType, SizedWallet, SizedWalletShare};
use constants::Scalar;
use darkpool_client::DarkpoolClient;
use itertools::Itertools;
use renegade_crypto::hash::PoseidonCSPRNG;

use super::ERR_WALLET_NOT_FOUND;

/// The wallet index at which to being the exponential phase of the search
const EXPONENTIAL_SEARCH_START_IDX: usize = 100;
/// The amount to exponentially increase the share index by in the first phase
/// of wallet search
const EXPONENTIAL_SEARCH_MULTIPLIER: usize = 2;

/// Get the i'th set of private shares for a wallet from the given share seed
///
/// The `idx` here is an index (in number of wallets) into the share CSPRNG
/// stream
pub(crate) fn gen_private_shares(
    idx: usize,
    share_seed: Scalar,
    private_blinder: Scalar,
) -> SizedWalletShare {
    // Subtract one from the number of scalars to account for the wallet blinder
    // private share, which is sampled from the blinder stream instead of the
    // share stream
    let shares_per_wallet = SizedWallet::NUM_SCALARS - 1;
    let mut share_csprng = PoseidonCSPRNG::new(share_seed);
    share_csprng.advance_by(idx * shares_per_wallet).unwrap();

    // Sample private secret shares for the wallet
    let mut new_private_shares =
        share_csprng.take(shares_per_wallet).chain(iter::once(private_blinder));
    SizedWalletShare::from_scalars(&mut new_private_shares)
}

/// Find the latest update of a wallet that has been submitted to the
/// contract. The update is represented as an index into the blinder stream
///
/// Returns a tuple: `(blinder_index, blinder, blinder_private_share)`
pub(crate) async fn find_latest_wallet_tx(
    blinder_seed: Scalar,
    darkpool_client: &DarkpoolClient,
) -> Result<(usize, Scalar, Scalar), String> {
    let (min_idx, max_idx) =
        find_wallet_share_index_phase_one(blinder_seed, darkpool_client).await?;
    let (idx, blinder, blinder_private) =
        find_wallet_share_index_phase_two(min_idx, max_idx, blinder_seed, darkpool_client).await?;

    // Check that the implied public blinder exists
    let public_blinder = blinder - blinder_private;
    match darkpool_client.get_public_blinder_tx(public_blinder).await.map_err(|e| e.to_string())? {
        None => Err(ERR_WALLET_NOT_FOUND.to_string()),
        Some(_) => Ok((idx, blinder, blinder_private)),
    }
}

/// The first phase of the find wallet process, exponentially increase the share
/// index until one is not seen on-chain
///
/// The first value not seen on-chain becomes the initial `max` for the binary
/// search phase
///
/// Returns the bounds for the binary search phase
async fn find_wallet_share_index_phase_one(
    blinder_seed: Scalar,
    darkpool_client: &DarkpoolClient,
) -> Result<(usize, usize), String> {
    let mut curr_min = 0;
    let mut curr_max = EXPONENTIAL_SEARCH_START_IDX;

    loop {
        let public_blinder = get_public_blinder_at_idx(curr_max, blinder_seed);

        // Check if the blinder has been seen on-chain
        match darkpool_client
            .get_public_blinder_tx(public_blinder)
            .await
            .map_err(|e| e.to_string())?
        {
            None => break,
            Some(_) => {
                curr_min = curr_max;
                curr_max *= EXPONENTIAL_SEARCH_MULTIPLIER;
            },
        }
    }

    Ok((curr_min, curr_max))
}

/// The second phase of the find wallet process, binary search the range of
/// indices [min_idx, max_idx) to find the latest update of the wallet
async fn find_wallet_share_index_phase_two(
    min_idx: usize,
    max_idx: usize,
    blinder_seed: Scalar,
    darkpool_client: &DarkpoolClient,
) -> Result<(usize, Scalar, Scalar), String> {
    let mut curr_min = min_idx;
    let mut curr_max = max_idx;
    let (mut curr_min_blinder, mut curr_min_blinder_private) =
        get_blinder_and_private_share_at_idx(curr_min, blinder_seed);

    loop {
        // Return condition
        if curr_max - curr_min <= 1 {
            return Ok((curr_min, curr_min_blinder, curr_min_blinder_private));
        }

        let curr_idx = (curr_min + curr_max) / 2;
        let idx_from_min = curr_idx - curr_min - 1;

        // Build the blinder relative to the min idx to avoid recomputing the stream up
        // to the min
        let (curr_blinder, curr_blinder_private) =
            get_blinder_and_private_share_at_idx(idx_from_min, curr_min_blinder_private);
        let curr_blinder_public = curr_blinder - curr_blinder_private;

        // Check if the blinder has been seen on-chain
        match darkpool_client
            .get_public_blinder_tx(curr_blinder_public)
            .await
            .map_err(|e| e.to_string())?
        {
            None => {
                curr_max = curr_idx;
            },
            Some(_) => {
                curr_min = curr_idx;
                curr_min_blinder = curr_blinder;
                curr_min_blinder_private = curr_blinder_private;
            },
        }
    }
}

/// Get the public blinder at index `idx` from the blinder stream at the given
/// seed
fn get_public_blinder_at_idx(idx: usize, blinder_seed: Scalar) -> Scalar {
    let (blinder, private_share) = get_blinder_and_private_share_at_idx(idx, blinder_seed);
    blinder - private_share
}

/// Get the blinder and private blinder share at index `idx` from the blinder
/// stream at the given seed
fn get_blinder_and_private_share_at_idx(idx: usize, blinder_seed: Scalar) -> (Scalar, Scalar) {
    let mut blinder_csprng = PoseidonCSPRNG::new(blinder_seed);

    // Advance the stream by 2 * idx; we draw two samples per blinder, the blinder
    // and the private share
    blinder_csprng.advance_by(idx * 2).unwrap();
    blinder_csprng.next_tuple().unwrap()
}
