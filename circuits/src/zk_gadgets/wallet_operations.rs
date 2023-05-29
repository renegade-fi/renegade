//! Groups logic for computing wallet commitments and nullifiers inside of a circuit

use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem},
    r1cs_mpc::R1CSError,
};

use crate::{
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    traits::{CircuitVarType, LinearCombinationLike},
    types::wallet::WalletShareVar,
};

use super::poseidon::PoseidonHashGadget;

// ------------------------
// | Public State Gadgets |
// ------------------------

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
    /// Compute the commitment to the private wallet shares
    pub fn compute_private_commitment<
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    >(
        private_wallet_share: WalletShareVar<L, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Create a new hash gadget
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        // Serialize the wallet and hash it into the hasher's state
        let serialized_wallet: Vec<L> = private_wallet_share.to_vars();
        hasher.batch_absorb(&serialized_wallet, cs)?;

        // Squeeze an element out of the state
        hasher.squeeze(cs)
    }

    /// Compute the commitment to the full wallet given a commitment to the private shares
    pub fn compute_wallet_commitment_from_private<
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    >(
        blinded_public_wallet_share: WalletShareVar<L, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_commitment: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Create a new hash gadget
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        // The public shares are added directly to a sponge H(private_commit || public shares)
        let mut hash_input = vec![private_commitment];
        hash_input.append(
            &mut blinded_public_wallet_share
                .to_vars()
                .into_iter()
                .map(|var| var.into())
                .collect_vec(),
        );

        hasher.batch_absorb(&hash_input, cs)?;
        hasher.squeeze(cs)
    }

    /// Compute the full commitment of a wallet's shares given both the public and private shares
    pub fn compute_wallet_share_commitment<
        L: LinearCombinationLike,
        CS: RandomizableConstraintSystem,
    >(
        public_wallet_share: WalletShareVar<L, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_wallet_share: WalletShareVar<L, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // First compute the private half, then absorb in the public
        let private_comm = Self::compute_private_commitment(private_wallet_share, cs)?;
        Self::compute_wallet_commitment_from_private(public_wallet_share, private_comm, cs)
    }
}

/// A gadget for computing the nullifier of secret share to a wallet
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
