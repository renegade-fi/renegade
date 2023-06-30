//! Groups integration tests around sharing values in an MPC fabric
use circuit_types::{
    r#match::MatchResult,
    traits::{BaseType, LinkableBaseType, LinkableType, MpcBaseType, MpcType, SecretShareType},
    wallet::Wallet,
};
use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use integration_helpers::types::IntegrationTest;

use crate::{IntegrationTestArgs, TestWrapper};

use super::create_wallet_shares;

/// A wallet with default generics
type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// Tests sharing values in the cleartext over an MPC fabric
fn test_share_public(test_args: &IntegrationTestArgs) -> Result<(), String> {
    // Construct a linkable wallet share type
    let wallet = SizedWallet::default();
    let (private_shares, blinded_public_shares) = create_wallet_shares(wallet.clone());

    let linkable_private_share = private_shares.to_linkable();
    let linkable_public_share = blinded_public_shares.to_linkable();

    // Share the public and private shares over the network
    let fabric = test_args.mpc_fabric.clone();
    let private = linkable_private_share
        .share_public(0 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error sharing private shares: {:?}", err))?
        .to_base_type();
    let public_blinded = linkable_public_share
        .share_public(0 /* owning_party */, fabric)
        .map_err(|err| format!("Error sharing public shares: {:?}", err))?
        .to_base_type();

    // Recover the wallet
    let recovered_blinder = private.blinder + public_blinded.blinder;
    let public_shares = public_blinded.unblind_shares(recovered_blinder);
    let recovered_wallet = private.add_shares(public_shares);

    if recovered_wallet != wallet {
        return Err("Wallets do not match".to_string());
    }

    Ok(())
}

/// Tests opening an authenticated Match result that has been proof linked
fn test_open_linkable_match_res(test_args: &IntegrationTestArgs) -> Result<(), String> {
    let fabric = test_args.mpc_fabric.clone();
    let match_res = MatchResult::default()
        .allocate(0 /* owning_party */, fabric.clone())
        .map_err(|err| format!("Error allocating match result: {:?}", err))?;

    let linkable_match_res = match_res.link_commitments(fabric.clone());
    let opened = linkable_match_res
        .open_and_authenticate(fabric)
        .map_err(|err| format!("Error opening match result: {:?}", err))?;

    if opened.to_base_type() != MatchResult::default() {
        return Err("Match results do not match".to_string());
    }

    Ok(())
}

inventory::submit!(TestWrapper(IntegrationTest {
    name: "types::sharing::test_share_public",
    test_fn: test_share_public
}));

inventory::submit!(TestWrapper(IntegrationTest {
    name: "types::sharing::test_open_linkable_match_res",
    test_fn: test_open_linkable_match_res
}));
