//! Groups integration tests for circuit type operations

use std::iter::from_fn;

use circuit_types::{
    native_helpers::create_wallet_shares_with_randomness,
    wallet::{Wallet, WalletShare},
};
use curve25519_dalek::scalar::Scalar;
use rand_core::OsRng;

pub mod sharing;

/// Construct secret shares of a wallet for testing
pub fn create_wallet_shares<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>(
    wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
) -> (
    WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
)
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    // Sample a random secret share for the blinder
    let mut rng = OsRng {};
    let blinder_share = Scalar::random(&mut rng);

    let blinder = wallet.blinder;
    create_wallet_shares_with_randomness(
        wallet,
        blinder,
        blinder_share,
        from_fn(|| Some(Scalar::random(&mut rng))),
    )
}
