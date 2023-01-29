//! Groups logic for computing wallet commitments and nullifiers inside of a circuit

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::R1CSError,
};

use crate::{mpc_gadgets::poseidon::PoseidonSpongeParameters, types::wallet::WalletVar};

use super::poseidon::PoseidonHashGadget;

/// A gadget for computing wallet commitments
#[derive(Clone, Debug)]
pub struct WalletCommitGadget<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {}
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    WalletCommitGadget<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Compute the commitment to a wallet
    pub fn wallet_commit<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Create a new hash gadget
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        // Hash the balances into the state
        for balance in wallet.balances.iter() {
            hasher.batch_absorb(&[balance.mint, balance.amount], cs)?;
        }

        // Hash the orders into the state
        for order in wallet.orders.iter() {
            hasher.batch_absorb(
                &[
                    order.quote_mint.into(),
                    order.base_mint.into(),
                    order.side.into(),
                    order.price.repr.clone(),
                    order.amount.into(),
                ],
                cs,
            )?;
        }

        // Hash the fees into the state
        for fee in wallet.fees.iter() {
            hasher.batch_absorb(
                &[
                    fee.settle_key.into(),
                    fee.gas_addr.into(),
                    fee.gas_token_amount.into(),
                    fee.percentage_fee.repr.clone(),
                ],
                cs,
            )?;
        }

        // Hash the keys into the state
        hasher.batch_absorb(&wallet.keys, cs)?;

        // Hash the randomness into the state
        hasher.absorb(wallet.randomness, cs)?;

        // Squeeze an element out of the state
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
}
