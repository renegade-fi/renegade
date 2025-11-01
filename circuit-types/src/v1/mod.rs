//! V1 circuit types

pub mod balance;
pub mod fees;
pub mod keychain;
pub mod r#match;
pub mod note;
pub mod order;
pub mod transfers;
pub mod wallet;

use constants::{MAX_BALANCES, MAX_ORDERS, MERKLE_HEIGHT};
use num_bigint::BigUint;

#[cfg(feature = "proof-system-types")]
use crate::wallet::WalletShare;
use crate::{merkle::MerkleOpening, wallet::Wallet};

// ----------------
// | Type Aliases |
// ----------------

/// A type alias for an on-chain address, we represent these as `BigUint`
pub type Address = BigUint;

/// A wallet with system-wide default generic parameters attached
pub type SizedWallet = Wallet<MAX_BALANCES, MAX_ORDERS>;
/// A wallet share with system-wide default generic parameters attached
#[cfg(feature = "proof-system-types")]
pub type SizedWalletShare = WalletShare<MAX_BALANCES, MAX_ORDERS>;
/// A type alias for the Merkle opening with system-wide default generics
/// attached
pub type SizedMerkleOpening = MerkleOpening<MERKLE_HEIGHT>;

// ------------------
// | Helper Methods |
// ------------------

/// Groups helpers that operate on native types; which correspond to circuitry
/// defined in this library
#[cfg(feature = "proof-system-types")]
pub mod native_helpers {
    use constants::{EmbeddedScalarField, Scalar};
    use itertools::Itertools;
    use renegade_crypto::hash::{compute_poseidon_hash, evaluate_hash_chain};

    use crate::{
        elgamal::{ElGamalCiphertext, EncryptionKey},
        native_helpers::elgamal_encrypt,
        note::{NOTE_CIPHERTEXT_SIZE, Note},
        traits::BaseType,
        wallet::{Nullifier, Wallet, WalletShare, WalletShareStateCommitment},
    };

    // -----------------
    // | Wallet Shares |
    // -----------------

    /// Recover a wallet from blinded secret shares
    pub fn wallet_from_blinded_shares<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
    ) -> Wallet<MAX_BALANCES, MAX_ORDERS> {
        let recovered_blinder = private_shares.blinder + public_shares.blinder;
        let unblinded_public_shares = public_shares.unblind_shares(recovered_blinder);
        private_shares.clone() + unblinded_public_shares
    }

    /// Compute a commitment to the shares of a wallet
    pub fn compute_wallet_share_commitment<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
    ) -> WalletShareStateCommitment {
        // Hash the private input, then append the public input and re-hash
        let private_input_commitment = compute_wallet_private_share_commitment(private_shares);
        let mut hash_input = vec![private_input_commitment];
        hash_input.append(&mut public_shares.to_scalars());

        compute_poseidon_hash(&hash_input)
    }

    /// Compute a commitment to a single share of a wallet
    pub fn compute_wallet_private_share_commitment<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        private_share: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
    ) -> Scalar {
        compute_poseidon_hash(&private_share.to_scalars())
    }

    /// Compute a commitment to the full shares of a wallet, given a commitment
    /// to only the private shares
    pub fn compute_wallet_commitment_from_private<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        public_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        private_share_comm: WalletShareStateCommitment,
    ) -> WalletShareStateCommitment {
        let mut hash_input = vec![private_share_comm];
        hash_input.append(&mut public_shares.to_scalars());
        compute_poseidon_hash(&hash_input)
    }

    /// Compute the nullifier of a set of wallet shares
    pub fn compute_wallet_share_nullifier(
        share_commitment: WalletShareStateCommitment,
        wallet_blinder: Scalar,
    ) -> Nullifier {
        compute_poseidon_hash(&[share_commitment, wallet_blinder])
    }

    /// Reblind a wallet given its secret shares
    ///
    /// Returns the reblinded private and public shares
    pub fn reblind_wallet<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        private_secret_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
    ) -> (WalletShare<MAX_BALANCES, MAX_ORDERS>, WalletShare<MAX_BALANCES, MAX_ORDERS>) {
        // Sample new wallet blinders from the `blinder` CSPRNG
        // See the comments in `valid_reblind.rs` for an explanation of the two CSPRNGs
        let mut blinder_samples = evaluate_hash_chain(
            private_secret_shares.blinder,
            2, // length
        );
        let mut blinder_drain = blinder_samples.drain(..);
        let new_blinder = blinder_drain.next().unwrap();
        let new_blinder_private_share = blinder_drain.next().unwrap();

        // Sample new secret shares for the wallet
        let shares_serialized: Vec<Scalar> = private_secret_shares.to_scalars();
        let serialized_len = shares_serialized.len();
        let mut secret_shares =
            evaluate_hash_chain(shares_serialized[serialized_len - 2], serialized_len - 1);
        secret_shares.push(new_blinder_private_share);

        create_wallet_shares_with_randomness(
            wallet,
            new_blinder,
            new_blinder_private_share,
            secret_shares,
        )
    }

    /// Construct public shares of a wallet given the private shares and blinder
    ///
    /// The return type is a tuple containing the private and public shares.
    /// Note that the private shares returned are exactly those passed in
    pub fn create_wallet_shares_from_private<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        private_shares: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        blinder: Scalar,
    ) -> (WalletShare<MAX_BALANCES, MAX_ORDERS>, WalletShare<MAX_BALANCES, MAX_ORDERS>) {
        // Serialize the wallet's private shares and use this as the secret share stream
        let private_shares_ser: Vec<Scalar> = private_shares.clone().to_scalars();
        create_wallet_shares_with_randomness(
            wallet,
            blinder,
            private_shares.blinder,
            private_shares_ser,
        )
    }

    /// Create a secret sharing of a wallet given the secret shares and blinders
    pub fn create_wallet_shares_with_randomness<
        T,
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        blinder: Scalar,
        private_blinder_share: Scalar,
        secret_shares: T,
    ) -> (WalletShare<MAX_BALANCES, MAX_ORDERS>, WalletShare<MAX_BALANCES, MAX_ORDERS>)
    where
        T: IntoIterator<Item = Scalar>,
    {
        let share_iter = secret_shares.into_iter();
        let wallet_scalars = wallet.to_scalars();
        let wallet_private_shares = share_iter.take(wallet_scalars.len()).collect_vec();
        let wallet_public_shares = wallet_scalars
            .iter()
            .zip_eq(wallet_private_shares.iter())
            .map(|(scalar, private_share)| scalar - private_share)
            .collect_vec();

        let mut private_shares = WalletShare::from_scalars(&mut wallet_private_shares.into_iter());
        let mut public_shares = WalletShare::from_scalars(&mut wallet_public_shares.into_iter());
        private_shares.blinder = private_blinder_share;
        public_shares.blinder = blinder - private_blinder_share;

        let blinded_public_shares = public_shares.blind_shares(blinder);

        (private_shares, blinded_public_shares)
    }

    // -------------------
    // | Note Operations |
    // -------------------

    /// Encrypt a note under the given key, returning both the ciphertext and
    /// the randomness
    pub fn encrypt_note(
        note: &Note,
        key: &EncryptionKey,
    ) -> (ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>, EmbeddedScalarField) {
        let plaintext = note.plaintext_elements();
        elgamal_encrypt::<NOTE_CIPHERTEXT_SIZE>(&plaintext, key)
    }

    /// Compute a commitment to a note
    pub fn note_commitment(note: &Note) -> Scalar {
        compute_poseidon_hash(&note.to_scalars())
    }

    /// Compute the nullifier for a note
    pub fn note_nullifier(note_comm: Scalar, note_blinder: Scalar) -> Scalar {
        compute_poseidon_hash(&[note_comm, note_blinder])
    }
}
