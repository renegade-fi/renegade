//! Groups integration tests around sharing values in an MPC fabric
use ark_mpc::PARTY0;
use circuit_types::{
    traits::{BaseType, MpcBaseType, MpcType, SecretShareType},
    wallet::Wallet,
};
use constants::{MAX_BALANCES, MAX_ORDERS};
use eyre::Result;
use test_helpers::{assert_eq_result, integration_test_async};

use crate::IntegrationTestArgs;

use super::create_wallet_shares;

/// A wallet with default generics
type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS>;

/// Tests sharing a value then opening it
async fn test_share_then_open(test_args: IntegrationTestArgs) -> Result<()> {
    let wallet = SizedWallet::default();
    let fabric = &test_args.mpc_fabric;

    let shared = wallet.allocate(PARTY0, fabric);
    let opened = shared.open().await?;

    assert_eq_result!(wallet, opened)
}

/// Tests sharing values in the cleartext over an MPC fabric
async fn test_share_public(test_args: IntegrationTestArgs) -> Result<()> {
    let fabric = test_args.mpc_fabric.clone();

    // Construct a set of wallet shares
    let wallet = SizedWallet::default();
    let (private_shares, blinded_public_shares) = create_wallet_shares(&wallet);

    // Share the public and private shares over the network
    let private = private_shares.share_public(PARTY0, &fabric).await;
    let public_blinded = blinded_public_shares.share_public(PARTY0, &fabric).await;

    // Recover the wallet
    let recovered_blinder = private.blinder + public_blinded.blinder;
    let public_shares = public_blinded.unblind_shares(recovered_blinder);
    let recovered_wallet = private.add_shares(&public_shares);

    assert_eq_result!(wallet, recovered_wallet)
}

integration_test_async!(test_share_then_open);
integration_test_async!(test_share_public);
