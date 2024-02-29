//! Wallet helpers for modifying and manipulating a wallet's secret shares

use circuit_types::{
    native_helpers::{
        compute_wallet_private_share_commitment, compute_wallet_share_commitment,
        compute_wallet_share_nullifier, create_wallet_shares_from_private,
        wallet_from_blinded_shares,
    },
    traits::BaseType,
    wallet::{Nullifier, WalletShare, WalletShareStateCommitment},
    SizedWallet, SizedWalletShare,
};
use constants::Scalar;
use renegade_crypto::hash::evaluate_hash_chain;

use super::Wallet;

impl Wallet {
    // -----------
    // | Getters |
    // -----------

    /// Check that the wallet's shares correctly add to its contents
    pub fn check_wallet_shares(&self) -> bool {
        let circuit_wallet: SizedWallet = self.clone().into();
        let recovered_wallet =
            wallet_from_blinded_shares(&self.private_shares, &self.blinded_public_shares);

        circuit_wallet == recovered_wallet
    }

    /// Computes the commitment to the private shares of the wallet
    pub fn get_private_share_commitment(&self) -> WalletShareStateCommitment {
        compute_wallet_private_share_commitment(&self.private_shares)
    }

    /// Compute the commitment to the full wallet shares
    pub fn get_wallet_share_commitment(&self) -> WalletShareStateCommitment {
        compute_wallet_share_commitment(&self.blinded_public_shares, &self.private_shares)
    }

    /// Compute the wallet nullifier
    pub fn get_wallet_nullifier(&self) -> Nullifier {
        compute_wallet_share_nullifier(self.get_wallet_share_commitment(), self.blinder)
    }

    // -----------
    // | Setters |
    // -----------

    /// Reblind the wallet, consuming the next set of blinders and secret shares
    pub fn reblind_wallet(&mut self) {
        let private_shares_serialized: Vec<Scalar> = self.private_shares.to_scalars();

        // Sample a new blinder and private secret share
        let n_shares = private_shares_serialized.len();
        let blinder_and_private_share =
            evaluate_hash_chain(private_shares_serialized[n_shares - 1], 2 /* length */);
        let new_blinder = blinder_and_private_share[0];
        let new_blinder_private_share = blinder_and_private_share[1];

        // Sample new secret shares for the wallet
        let mut new_private_shares =
            evaluate_hash_chain(private_shares_serialized[n_shares - 2], n_shares - 1);
        new_private_shares.push(new_blinder_private_share);

        let (new_private_share, new_public_share) = create_wallet_shares_from_private(
            &self.clone().into(),
            &WalletShare::from_scalars(&mut new_private_shares.into_iter()),
            new_blinder,
        );

        self.private_shares = new_private_share;
        self.blinded_public_shares = new_public_share;
        self.blinder = new_blinder;
        self.invalidate_merkle_opening();
    }

    /// Update a wallet from a given set of private and (blinded) public secret
    /// shares
    pub fn update_from_shares(
        &mut self,
        private_shares: &SizedWalletShare,
        blinded_public_shares: &SizedWalletShare,
    ) {
        // Recover the wallet and update the balances, orders, fees
        let wallet = wallet_from_blinded_shares(private_shares, blinded_public_shares);

        self.blinder = wallet.blinder;
        self.balances = wallet.balances.into_iter().map(|b| (b.mint.clone(), b)).collect();

        // Preserve the order_ids, the indexmap should give a consistent ordering
        // between orders
        let order_ids = self.orders.keys().cloned();
        self.orders = order_ids.zip(wallet.orders).collect();

        // Update the wallet shares
        self.private_shares = private_shares.clone();
        self.blinded_public_shares = blinded_public_shares.clone();

        // The Merkle proof is now invalid
        self.invalidate_merkle_opening();
    }
}
