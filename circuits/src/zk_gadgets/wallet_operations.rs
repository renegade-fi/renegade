//! Groups logic for computing wallet commitments and nullifiers inside of a circuit

use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::R1CSError,
};

use crate::{
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{balance::BalanceVar, fee::FeeVar, order::OrderVar, wallet::WalletSecretShareVar},
};

use super::{comparators::EqVecGadget, poseidon::PoseidonHashGadget};

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
    pub fn compute_private_commitment<CS: RandomizableConstraintSystem>(
        private_wallet_share: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Create a new hash gadget
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        // Serialize the wallet and hash it into the hasher's state
        let serialized_wallet: Vec<LinearCombination> = private_wallet_share.into();
        hasher.batch_absorb(&serialized_wallet, cs)?;

        // Squeeze an element out of the state
        hasher.squeeze(cs)
    }

    /// Compute the commitment to the full wallet given a commitment to the private shares
    pub fn compute_wallet_commitment_from_private<CS: RandomizableConstraintSystem>(
        blinded_public_wallet_share: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_commitment: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Create a new hash gadget
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        // The public shares are added directly to a sponge H(private_commit || public shares)
        let mut hash_input = vec![private_commitment];
        hash_input.append(&mut blinded_public_wallet_share.into());

        hasher.batch_absorb(&hash_input, cs)?;
        hasher.squeeze(cs)
    }

    /// Compute the full commitment of a wallet's shares given both the public and private shares
    pub fn compute_wallet_share_commitment<CS: RandomizableConstraintSystem>(
        public_wallet_share: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        private_wallet_share: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
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

// -----------------------------
// | Wallet Comparison Gadgets |
// -----------------------------

/// Compares two balances
pub struct BalanceComparatorGadget;
impl BalanceComparatorGadget {
    /// Compare two balances returning 1 if they are equal, 0 otherwise
    pub fn compare_eq<L1, L2, CS>(b1: BalanceVar<L1>, b2: BalanceVar<L2>, cs: &mut CS) -> Variable
    where
        L1: Into<LinearCombination> + Clone,
        L2: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        EqVecGadget::eq_vec(
            &[b1.mint.into(), b1.amount.into()],
            &[b2.mint.into(), b2.amount.into()],
            cs,
        )
    }

    /// Constrain two balances to be equal
    pub fn constrain_eq<L, CS>(b1: BalanceVar<L>, b2: BalanceVar<L>, cs: &mut CS)
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        EqVecGadget::constrain_eq_vec(&[b1.mint, b1.amount], &[b2.mint, b2.amount], cs);
    }
}

/// Compares two orders
pub struct OrderComparatorGadget;
impl OrderComparatorGadget {
    /// Compare two orders, returning 1 if they are equal, 0 otherwise
    pub fn compare_eq<L1, L2, CS>(o1: OrderVar<L1>, o2: OrderVar<L2>, cs: &mut CS) -> Variable
    where
        L1: Into<LinearCombination>,
        L2: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        EqVecGadget::eq_vec(
            &[
                o1.quote_mint.into(),
                o1.base_mint.into(),
                o1.side.into(),
                o1.price.repr,
                o1.amount.into(),
                o1.timestamp.into(),
            ],
            &[
                o2.quote_mint.into(),
                o2.base_mint.into(),
                o2.side.into(),
                o2.price.repr,
                o2.amount.into(),
                o2.timestamp.into(),
            ],
            cs,
        )
    }

    /// Constrain two orders to equal one another
    pub fn constrain_eq<L, CS>(o1: OrderVar<L>, o2: OrderVar<L>, cs: &mut CS)
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        EqVecGadget::constrain_eq_vec(
            &[
                o1.quote_mint.into(),
                o1.base_mint.into(),
                o1.side.into(),
                o1.price.repr,
                o1.amount.into(),
                o1.timestamp.into(),
            ],
            &[
                o2.quote_mint.into(),
                o2.base_mint.into(),
                o2.side.into(),
                o2.price.repr,
                o2.amount.into(),
                o2.timestamp.into(),
            ],
            cs,
        )
    }
}

/// Compares two fees
pub struct FeeComparatorGadget;
impl FeeComparatorGadget {
    /// Compare two fees, returning 1 if they are equal, 0 otherwise
    pub fn compare_eq<L1, L2, CS>(f1: FeeVar<L1>, f2: FeeVar<L2>, cs: &mut CS) -> Variable
    where
        L1: Into<LinearCombination>,
        L2: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        EqVecGadget::eq_vec(
            &[
                f1.settle_key.into(),
                f1.gas_addr.into(),
                f1.gas_token_amount.into(),
                f1.percentage_fee.repr,
            ],
            &[
                f2.settle_key.into(),
                f2.gas_addr.into(),
                f2.gas_token_amount.into(),
                f2.percentage_fee.repr,
            ],
            cs,
        )
    }

    /// Constrain two fees to equal one another
    pub fn constrain_eq<L, CS>(f1: FeeVar<L>, f2: FeeVar<L>, cs: &mut CS)
    where
        L: Into<LinearCombination>,
        CS: RandomizableConstraintSystem,
    {
        EqVecGadget::constrain_eq_vec(
            &[
                f1.settle_key.into(),
                f1.gas_addr.into(),
                f1.gas_token_amount.into(),
                f1.percentage_fee.repr,
            ],
            &[
                f2.settle_key.into(),
                f2.gas_addr.into(),
                f2.gas_token_amount.into(),
                f2.percentage_fee.repr,
            ],
            cs,
        )
    }
}
