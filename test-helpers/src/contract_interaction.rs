//! Helpers for interacting with contracts in tests
use circuit_types::{
    native_helpers::create_wallet_shares_from_private, traits::BaseType, SizedWalletShare,
};
use common::types::{
    proof_bundles::mocks::dummy_valid_wallet_create_bundle,
    wallet::{mocks::mock_empty_wallet, Wallet},
};
use constants::Scalar;
use darkpool_client::DarkpoolClient;
use eyre::Result;
use rand::thread_rng;
use renegade_crypto::hash::{evaluate_hash_chain, PoseidonCSPRNG};

// ---------------------
// | Wallet Allocation |
// ---------------------

/// Allocate a new empty wallet in the darkpool
///
/// Returns the `blinder_stream_seed` and `share_stream_seed` used to secret
/// share the wallet as well as the wallet itself
pub async fn new_wallet_in_darkpool(client: &DarkpoolClient) -> Result<(Wallet, Scalar, Scalar)> {
    let mut rng = thread_rng();
    let blinder_seed = Scalar::random(&mut rng);
    let share_seed = Scalar::random(&mut rng);

    let mut wallet = empty_wallet_from_seed(blinder_seed, share_seed);
    allocate_wallet_in_darkpool(&mut wallet, client).await?;

    Ok((wallet, blinder_seed, share_seed))
}

/// Create a wallet in the contract state and update the Merkle path on the
/// wallet
pub async fn allocate_wallet_in_darkpool(
    wallet: &mut Wallet,
    client: &DarkpoolClient,
) -> Result<()> {
    let share_comm = wallet.get_wallet_share_commitment();

    let mut proof = dummy_valid_wallet_create_bundle();
    proof.statement.public_wallet_shares = wallet.blinded_public_shares.clone();
    proof.statement.wallet_share_commitment = share_comm;

    client.new_wallet(&proof).await?;

    // Find the Merkle opening for the wallet
    attach_merkle_opening(wallet, client).await
}

/// Find the merkle path of the wallet and attach it
pub async fn attach_merkle_opening(wallet: &mut Wallet, client: &DarkpoolClient) -> Result<()> {
    let comm = wallet.get_wallet_share_commitment();
    let opening = client.find_merkle_authentication_path(comm).await?;

    wallet.merkle_proof = Some(opening);
    Ok(())
}

// --------------
// | Dummy Data |
// --------------

/// Create a mock wallet and secret share it with a given blinder seed
pub fn empty_wallet_from_seed(blinder_stream_seed: Scalar, secret_share_seed: Scalar) -> Wallet {
    // Create a blank wallet then modify the shares
    let mut wallet = mock_empty_wallet();
    setup_wallet_shares(blinder_stream_seed, secret_share_seed, &mut wallet);

    wallet
}

/// Create shares for a mock wallet given the seeds for the blinder and secret
/// share CSPRNG streams
///
/// Mutates the wallet in-place to set its shares and blinder
pub fn setup_wallet_shares(
    blinder_stream_seed: Scalar,
    secret_share_seed: Scalar,
    wallet: &mut Wallet,
) {
    // Sample the blinder and blinder private share
    let blinder_and_private_share = evaluate_hash_chain(blinder_stream_seed, 2 /* length */);
    let new_blinder = blinder_and_private_share[0];
    let new_blinder_private_share = blinder_and_private_share[1];

    // Sample new secret shares for the wallet
    let mut share_csprng = PoseidonCSPRNG::new(secret_share_seed);
    let mut private_shares = SizedWalletShare::from_scalars(&mut share_csprng);
    private_shares.blinder = new_blinder_private_share;

    // Create the public shares
    let (private_shares, blinded_public_shares) =
        create_wallet_shares_from_private(&wallet.clone().into(), &private_shares, new_blinder);

    wallet.blinded_public_shares = blinded_public_shares;
    wallet.private_shares = private_shares;
    wallet.blinder = new_blinder;
}
