//! Groups logic for computing wallet commitments and nullifiers inside of a circuit

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::R1CSError,
};

use crate::{
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{
        note::NoteVar,
        wallet::{WalletSecretShareVar, WalletShareCommitment},
    },
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
    /// Compute the commitment to a wallet share
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

/// A gadget for computing the nullifier of a wallet
#[derive(Clone, Debug)]
pub struct NullifierGadget {}
impl NullifierGadget {
    /// Compute the nullifier of a set of secret shares given their commitment
    pub fn wallet_shares_nullifier<L, CS>(
        share_commitment: L,
        wallet_blinder: L,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // The nullifier is computed as H(C(w)||r)
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        hasher.batch_absorb(&[share_commitment, wallet_blinder], cs)?;
        hasher.squeeze(cs)
    }
}
