//! Helpers for the update wallet task

use circuit_types::SizedWallet as CircuitWallet;
use common::types::tasks::WalletUpdateType;
use common::types::wallet::Wallet;

use crate::tasks::update_wallet::UpdateWalletTask;

pub(crate) mod events;
pub(crate) mod witness_generation;

impl UpdateWalletTask {
    // --- General Helpers --- //

    /// Whether the wallet update requires an on-chain update
    ///
    /// Some wallet updates do not modify the on-chain state, e.g. marking an
    /// order as externally matchable. In these cases, we can skip the on-chain
    /// interaction and just update the local copy of the wallet
    ///
    /// Concretely, if an update doesn't change the circuit representation of
    /// the wallet, we can skip the on-chain update
    ///
    /// TODO: In the future we'll want to allow reblind-only updates, for which
    /// we can force an on-chain update
    pub(crate) fn requires_onchain_update(&self) -> bool {
        let old_circuit_wallet: CircuitWallet = self.old_wallet.clone().into();
        let mut new_circuit_wallet: CircuitWallet = self.new_wallet.clone().into();

        // The wallet blinders are allowed to be different, all other fields must
        // match exactly to skip the on-chain update
        new_circuit_wallet.blinder = self.old_wallet.blinder;
        new_circuit_wallet != old_circuit_wallet
    }

    /// Check that the wallet's blinder and private shares are the result of
    /// applying a reblind to the old wallet
    pub fn check_reblind_progression(old_wallet: &Wallet, new_wallet: &Wallet) -> bool {
        let mut old_wallet_clone = old_wallet.clone();
        old_wallet_clone.reblind_wallet();
        let expected_private_shares = old_wallet_clone.private_shares;
        let expected_blinder = old_wallet_clone.blinder;

        new_wallet.private_shares == expected_private_shares
            && new_wallet.blinder == expected_blinder
    }

    /// Whether the given wallet update requests a precomputed cancellation
    /// proof
    pub fn should_precompute_cancellation_proof(&self) -> bool {
        match &self.update_type {
            WalletUpdateType::PlaceOrder { precompute_cancellation_proof, .. } => {
                *precompute_cancellation_proof
            },
            _ => false,
        }
    }
}
