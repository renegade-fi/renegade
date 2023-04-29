//! Groups logic for computing wallet commitments and nullifiers inside of a circuit

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::R1CSError,
};

use crate::{
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{note::NoteVar, wallet::WalletSecretShareVar},
};

use super::poseidon::PoseidonHashGadget;

/// A gadget for computing the commitment to a secret share of a wallet
#[derive(Clone, Debug)]
pub struct WalletShareCommitGadget<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {}
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    WalletShareCommitGadget<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Compute the commitment to a wallet
    pub fn compute_commitment<CS: RandomizableConstraintSystem>(
        wallet_share: &WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Create a new hash gadget
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        // Serialize the wallet and hash it into the hasher's state
        let serialized_wallet: Vec<LinearCombination> = wallet_share.clone().into();
        hasher.batch_absorb(&serialized_wallet, cs)?;

        // Squeeze an element out of the state
        hasher.squeeze(cs)
    }
}

/// A gadget for computing note commitments
#[derive(Clone, Debug)]
pub struct NoteCommitmentGadget {}
impl NoteCommitmentGadget {
    /// Computes a commitment to a given note
    pub fn note_commit<CS: RandomizableConstraintSystem>(
        note: &NoteVar,
        recipient_pub_key: Variable,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Create a new hash gadget
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        hasher.batch_absorb(
            &[
                note.mint1,
                note.volume1,
                note.direction1,
                note.mint2,
                note.volume2,
                note.direction2,
                note.fee_mint,
                note.fee_volume,
                note.fee_direction,
                note.type_,
                note.randomness,
                recipient_pub_key,
            ],
            cs,
        )?;
        hasher.squeeze(cs)
    }
}

/// A gadget for computing the nullifier of a wallet
#[derive(Clone, Debug)]
pub struct NullifierGadget {}
impl NullifierGadget {
    /// Compute the spend nullifier of a wallet from a commitment to the wallet
    pub fn spend_nullifier<CS: RandomizableConstraintSystem>(
        wallet_randomness: Variable,
        wallet_commit: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hasher_params);

        hasher.batch_absorb(&[wallet_commit, wallet_randomness.into()], cs)?;
        hasher.squeeze(cs)
    }

    /// Compute the match nullifier of a wallet from a commitment to the wallet
    pub fn match_nullifier<CS: RandomizableConstraintSystem>(
        wallet_randomness: Variable,
        wallet_commit: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hasher_params);

        hasher.batch_absorb(&[wallet_commit, wallet_randomness + Scalar::one()], cs)?;
        hasher.squeeze(cs)
    }

    /// Compute the note redeem nullifier for a given note
    ///
    /// This is constructed as a Poseidon sponge hash of the note commitment
    /// with the settle key of the receiver concatenated
    pub fn note_redeem_nullifier<CS: RandomizableConstraintSystem>(
        pk_settle_receiver: Variable,
        note_commitment: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hasher_params);

        hasher.batch_absorb(&[note_commitment, pk_settle_receiver.into()], cs)?;
        hasher.squeeze(cs)
    }
}
