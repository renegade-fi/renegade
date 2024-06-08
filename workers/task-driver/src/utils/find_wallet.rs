//! Helpers for finding wallets in the contract state

use std::iter;

use arbitrum_client::client::ArbitrumClient;
use circuit_types::{traits::BaseType, SizedWallet, SizedWalletShare};
use constants::Scalar;
use itertools::Itertools;
use renegade_crypto::hash::PoseidonCSPRNG;

use super::ERR_WALLET_NOT_FOUND;

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
    share_csprng.advance_by((idx - 1) * shares_per_wallet).unwrap();

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
    arbitrum_client: &ArbitrumClient,
) -> Result<(usize, Scalar, Scalar), String> {
    // Find the latest transaction updating the wallet, as indexed by the public
    // share of the blinders
    let mut blinder_csprng = PoseidonCSPRNG::new(blinder_seed);

    let mut blinder_index = 0;
    let mut curr_blinder = Scalar::zero();
    let mut curr_blinder_private_share = Scalar::zero();

    let mut updating_tx = None;

    while let (blinder, private_share) = blinder_csprng.next_tuple().unwrap()
        && let Some(tx) = arbitrum_client
            .get_public_blinder_tx(blinder - private_share)
            .await
            .map_err(|e| e.to_string())?
    {
        updating_tx = Some(tx);

        curr_blinder = blinder;
        curr_blinder_private_share = private_share;
        blinder_index += 1;
    }

    // Error if not found
    if updating_tx.is_none() {
        return Err(ERR_WALLET_NOT_FOUND.to_string());
    }

    Ok((blinder_index, curr_blinder, curr_blinder_private_share))
}
