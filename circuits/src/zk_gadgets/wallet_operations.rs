//! Groups logic for computing wallet commitments and nullifiers inside of a
//! circuit

use circuit_types::{
    fixed_point::FixedPointVar,
    merkle::MerkleOpeningVar,
    order::OrderVar,
    traits::{CircuitVarType, SecretShareVarType},
    wallet::{WalletShareVar, WalletVar},
    Fabric, MpcPlonkCircuit, PlonkCircuit, AMOUNT_BITS, FEE_BITS, PRICE_BITS,
};
use constants::ScalarField;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use super::{
    bits::{BitRangeGadget, MultiproverBitRangeGadget},
    merkle::PoseidonMerkleHashGadget,
    poseidon::{PoseidonCSPRNGGadget, PoseidonHashGadget},
    select::CondSelectGadget,
};

/// Gadget for operating on wallets and wallet shares
pub struct WalletGadget<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> WalletGadget<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    // ----------------
    // | State Update |
    // ----------------

    /// Validates the inclusion of the wallet in the state tree and the
    /// nullifier of the wallet from its shares
    ///
    /// Returns the reconstructed wallet for convenience in the caller
    pub fn validate_wallet_transition<const MERKLE_HEIGHT: usize, C: Circuit<ScalarField>>(
        blinded_public_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        private_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        merkle_opening: &MerkleOpeningVar<MERKLE_HEIGHT>,
        merkle_root: Variable,
        expected_nullifier: Variable,
        cs: &mut C,
    ) -> Result<(), CircuitError> {
        // Compute a commitment to the wallet
        let wallet_comm =
            Self::compute_wallet_share_commitment(blinded_public_share, private_share, cs)?;

        // Verify the opening of the wallet commitment to the root
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            wallet_comm,
            merkle_opening,
            merkle_root,
            cs,
        )?;

        // Compute the nullifier of the wallet
        let recovered_blinder = cs.add(blinded_public_share.blinder, private_share.blinder)?;
        let nullifier = Self::wallet_shares_nullifier(wallet_comm, recovered_blinder, cs)?;
        cs.enforce_equal(nullifier, expected_nullifier)?;

        Ok(())
    }

    /// Reconstruct a wallet from its secret shares
    pub fn wallet_from_shares<C: Circuit<ScalarField>>(
        blinded_public_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        private_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut C,
    ) -> Result<WalletVar<MAX_BALANCES, MAX_ORDERS>, CircuitError> {
        // Recover the blinder of the wallet
        let blinder = cs.add(blinded_public_share.blinder, private_share.blinder)?;
        let unblinded_public_shares = blinded_public_share.clone().unblind_shares(blinder, cs);

        // Add the public and private shares to get the full wallet
        Ok(private_share.add_shares(&unblinded_public_shares, cs))
    }

    // ---------------
    // | Commitments |
    // ---------------

    /// Compute the commitment to the private wallet shares
    pub fn compute_private_commitment<C: Circuit<ScalarField>>(
        private_wallet_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // Serialize the wallet and hash it into the hasher's state
        let serialized_wallet = private_wallet_share.to_vars();

        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.batch_absorb(&serialized_wallet, cs)?;

        hasher.squeeze(cs)
    }

    /// Compute the commitment to the full wallet given a commitment to the
    /// private shares
    pub fn compute_wallet_commitment_from_private<C: Circuit<ScalarField>>(
        blinded_public_wallet_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        private_commitment: Variable,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // The public shares are added directly to a sponge H(private_commit || public
        // shares), giving the full wallet commitment
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        hasher.absorb(private_commitment, cs)?;
        hasher.batch_absorb(&blinded_public_wallet_share.to_vars(), cs)?;

        hasher.squeeze(cs)
    }

    /// Compute the full commitment of a wallet's shares given both the public
    /// and private shares
    pub fn compute_wallet_share_commitment<C: Circuit<ScalarField>>(
        public_wallet_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        private_wallet_share: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // First compute the private half, then absorb in the public
        let private_comm = Self::compute_private_commitment(private_wallet_share, cs)?;
        Self::compute_wallet_commitment_from_private(public_wallet_share, private_comm, cs)
    }

    // --------------
    // | Nullifiers |
    // --------------

    /// Compute the nullifier of a set of secret shares given their commitment
    pub fn wallet_shares_nullifier<C: Circuit<ScalarField>>(
        share_commitment: Variable,
        wallet_blinder: Variable,
        cs: &mut C,
    ) -> Result<Variable, CircuitError> {
        // The nullifier is computed as H(C(w)||r)
        let mut hasher = PoseidonHashGadget::new(cs.zero());

        hasher.batch_absorb(&[share_commitment, wallet_blinder], cs)?;
        hasher.squeeze(cs)
    }

    // -----------
    // | Reblind |
    // -----------

    /// Sample a new set of private shares and blinder from the CSPRNG
    ///
    /// Returns the new private shares and blinder
    pub fn reblind<C: Circuit<ScalarField>>(
        private_shares: &WalletShareVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut C,
    ) -> Result<(WalletShareVar<MAX_BALANCES, MAX_ORDERS>, Variable), CircuitError> {
        // Sample a new blinder and private share for the blinder
        let blinder = private_shares.blinder;
        let mut blinder_samples = PoseidonCSPRNGGadget::sample(blinder, 2 /* num_vals */, cs)?;
        let new_blinder = blinder_samples.remove(0);
        let new_blinder_private_share = blinder_samples.remove(0);

        // Sample private secret shares for individual wallet elements, we sample for n
        // - 1 shares because the wallet serialization includes the wallet
        // blinder, which was resampled separately in the previous step
        //
        // As well, we seed the CSPRNG with the second to last share in the old wallet,
        // again because the wallet blinder comes from a separate stream of
        // randomness
        let shares_ser = private_shares.to_vars();
        let n_samples = shares_ser.len() - 1;
        let mut share_samples =
            PoseidonCSPRNGGadget::sample(shares_ser[n_samples - 1], n_samples, cs)?;

        // Add a dummy value to the end of the shares (in place of the private blinder
        // share), recover the wallet share type, then overwrite with the actual blinder
        // share
        share_samples.push(cs.zero());
        let mut new_shares = WalletShareVar::from_vars(&mut share_samples.into_iter(), cs);
        new_shares.blinder = new_blinder_private_share;

        Ok((new_shares, new_blinder))
    }
}

// ------------------------
// | Wallet Field Gadgets |
// ------------------------

/// A gadget for computing on orders
pub struct OrderGadget;
impl OrderGadget {
    /// Get the mint bought by the given order
    pub fn get_buy_mint(order: &OrderVar, cs: &mut PlonkCircuit) -> Result<Variable, CircuitError> {
        CondSelectGadget::select(&order.quote_mint, &order.base_mint, order.side, cs)
    }

    /// Get the mint sold by the given order
    pub fn get_sell_mint(
        order: &OrderVar,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        CondSelectGadget::select(&order.base_mint, &order.quote_mint, order.side, cs)
    }
}

/// Constrain a value to be a valid `Amount`, i.e. a non-negative `Scalar`
/// representable in at most `AMOUNT_BITS` bits
pub struct AmountGadget;
impl AmountGadget {
    /// Constrain an value to be a valid `Amount`
    pub fn constrain_valid_amount(
        amount: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        BitRangeGadget::<AMOUNT_BITS>::constrain_bit_range(amount, cs)
    }
}

/// Constrain a value to be a valid `Amount` in a multiprover context
pub struct MultiproverAmountGadget;
impl MultiproverAmountGadget {
    /// Constrain an value to be a valid `Amount`
    pub fn constrain_valid_amount(
        amount: Variable,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        MultiproverBitRangeGadget::<AMOUNT_BITS>::constrain_bit_range(amount, fabric, cs)
    }
}

/// Constrain a fee to be in the range of valid take rates
///
/// This is [0, 2^FEE_BITS-1]
pub struct FeeGadget;
impl FeeGadget {
    /// Constrain a value to be a valid fee
    pub fn constrain_valid_fee(
        fee: FixedPointVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        BitRangeGadget::<FEE_BITS>::constrain_bit_range(fee.repr, cs)
    }
}

/// Constrain a `FixedPoint` value to be a valid price, i.e. with a non-negative
/// `Scalar` repr representable in at most `PRICE_BITS` bits
pub struct PriceGadget;
impl PriceGadget {
    /// Constrain a value to be a valid `FixedPoint` price
    pub fn constrain_valid_price(
        price: FixedPointVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        BitRangeGadget::<PRICE_BITS>::constrain_bit_range(price.repr, cs)
    }
}

/// Constrain a `FixedPoint` value to be a valid price in a multiprover context
pub struct MultiproverPriceGadget;
impl MultiproverPriceGadget {
    /// Constrain a value to be a valid `FixedPoint` price
    pub fn constrain_valid_price(
        price: FixedPointVar,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        MultiproverBitRangeGadget::<PRICE_BITS>::constrain_bit_range(price.repr, fabric, cs)
    }
}

#[cfg(test)]
mod test {
    use std::iter;

    use circuit_types::{
        fixed_point::FixedPoint,
        native_helpers::{
            compute_wallet_commitment_from_private, compute_wallet_private_share_commitment,
            compute_wallet_share_commitment, compute_wallet_share_nullifier,
        },
        traits::{BaseType, CircuitBaseType},
        PlonkCircuit, SizedWalletShare, AMOUNT_BITS, FEE_BITS, PRICE_BITS,
    };
    use constants::{Scalar, MAX_BALANCES, MAX_ORDERS};
    use itertools::Itertools;
    use mpc_relation::traits::Circuit;
    use rand::{thread_rng, Rng};
    use std::ops::Neg;

    use crate::zk_gadgets::wallet_operations::{FeeGadget, PriceGadget, WalletGadget};

    use super::AmountGadget;

    // -----------
    // | Helpers |
    // -----------

    /// Generate random wallet shares
    fn random_wallet_shares() -> (SizedWalletShare, SizedWalletShare) {
        let mut rng = thread_rng();
        let mut share_iter = iter::from_fn(|| Some(Scalar::random(&mut rng)));

        (
            SizedWalletShare::from_scalars(&mut share_iter),
            SizedWalletShare::from_scalars(&mut share_iter),
        )
    }

    /// Generate a scalar representation of 2^N
    fn scalar_2_pow_n(n: usize) -> Scalar {
        Scalar::from(2u8).pow(n as u64)
    }

    /// Generate a random scalar under the specified bit amount
    fn random_bitlength_scalar(bit_length: usize) -> Scalar {
        let mut rng = thread_rng();

        let bits = (0..bit_length).map(|_| rng.gen_bool(0.5)).collect_vec();
        let mut res = Scalar::zero();

        for bit in bits.into_iter() {
            res *= Scalar::from(2u8);
            if bit {
                res += Scalar::one();
            }
        }

        res
    }

    /// Check whether the constraints of a constraint system are satisfied
    fn check_satisfaction(cs: &PlonkCircuit) -> bool {
        cs.check_circuit_satisfiability(&[]).is_ok()
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests the wallet commitment share gadget
    #[test]
    fn test_wallet_share_commitments() {
        let (private_shares, public_shares) = random_wallet_shares();

        let mut cs = PlonkCircuit::new_turbo_plonk();
        let private_share_var = private_shares.create_witness(&mut cs);
        let public_share_var = public_shares.create_witness(&mut cs);

        // Private share commitment
        let expected_private = compute_wallet_private_share_commitment(&private_shares);
        let expected_var = expected_private.create_public_var(&mut cs);

        let priv_comm =
            WalletGadget::compute_private_commitment(&private_share_var, &mut cs).unwrap();

        cs.enforce_equal(priv_comm, expected_var).unwrap();

        // Public share commitment
        let expected_pub = compute_wallet_commitment_from_private(&public_shares, expected_private);
        let expected_var = expected_pub.create_public_var(&mut cs);

        let pub_comm = WalletGadget::compute_wallet_commitment_from_private(
            &public_share_var,
            priv_comm,
            &mut cs,
        )
        .unwrap();

        cs.enforce_equal(pub_comm, expected_var).unwrap();

        // Full wallet commitment
        let expected_full = compute_wallet_share_commitment(&public_shares, &private_shares);
        let expected_var = expected_full.create_public_var(&mut cs);

        let full_comm = WalletGadget::compute_wallet_share_commitment(
            &public_share_var,
            &private_share_var,
            &mut cs,
        );

        cs.enforce_equal(full_comm.unwrap(), expected_var).unwrap();

        // Verify that all constraints are satisfied
        assert!(cs
            .check_circuit_satisfiability(&[
                expected_private.inner(),
                expected_pub.inner(),
                expected_full.inner()
            ])
            .is_ok())
    }

    /// Tests the nullifier gadget
    #[test]
    fn test_nullifier_gadget() {
        let mut rng = thread_rng();
        let share_commitment = Scalar::random(&mut rng);
        let wallet_blinder = Scalar::random(&mut rng);

        let expected = compute_wallet_share_nullifier(share_commitment, wallet_blinder);

        // Check against the gadget
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let comm_var = share_commitment.create_witness(&mut cs);
        let blinder_var = wallet_blinder.create_witness(&mut cs);

        let expected_var = expected.create_public_var(&mut cs);

        let nullifier = WalletGadget::<MAX_BALANCES, MAX_ORDERS>::wallet_shares_nullifier(
            comm_var,
            blinder_var,
            &mut cs,
        )
        .unwrap();

        cs.enforce_equal(nullifier, expected_var).unwrap();

        // Verify that all constraints are satisfied
        assert!(cs.check_circuit_satisfiability(&[expected.inner()]).is_ok())
    }

    /// Tests the amount gadget
    #[test]
    fn test_amount_gadget() {
        // Test a valid amount
        let amount = random_bitlength_scalar(AMOUNT_BITS);
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let amt_var = amount.create_witness(&mut cs);
        AmountGadget::constrain_valid_amount(amt_var, &mut cs).unwrap();

        assert!(check_satisfaction(&cs));

        // Test zero
        let amount = Scalar::zero();
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let amt_var = amount.create_witness(&mut cs);
        AmountGadget::constrain_valid_amount(amt_var, &mut cs).unwrap();

        assert!(check_satisfaction(&cs));

        // Test negative one
        let amount = Scalar::one().neg();
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let amt_var = amount.create_witness(&mut cs);
        AmountGadget::constrain_valid_amount(amt_var, &mut cs).unwrap();

        assert!(!check_satisfaction(&cs));

        // Test 2^AMOUNT_BITS
        let amount = scalar_2_pow_n(AMOUNT_BITS);
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let amt_var = amount.create_witness(&mut cs);
        AmountGadget::constrain_valid_amount(amt_var, &mut cs).unwrap();

        assert!(!check_satisfaction(&cs));
    }

    /// Test the price gadget
    #[test]
    fn test_price_gadget() {
        // Test a valid price
        let price_repr = random_bitlength_scalar(PRICE_BITS);
        let price = FixedPoint { repr: price_repr };
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let price_var = price.create_witness(&mut cs);
        PriceGadget::constrain_valid_price(price_var, &mut cs).unwrap();

        assert!(check_satisfaction(&cs));

        // Test zero
        let price = FixedPoint { repr: Scalar::zero() };
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let price_var = price.create_witness(&mut cs);
        PriceGadget::constrain_valid_price(price_var, &mut cs).unwrap();

        assert!(check_satisfaction(&cs));

        // Test negative one
        let price = FixedPoint { repr: Scalar::one().neg() };
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let price_var = price.create_witness(&mut cs);
        PriceGadget::constrain_valid_price(price_var, &mut cs).unwrap();

        assert!(!check_satisfaction(&cs));

        // Test 2^PRICE_BITS
        let price_repr = scalar_2_pow_n(PRICE_BITS);
        let price = FixedPoint { repr: price_repr };
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let price_var = price.create_witness(&mut cs);
        PriceGadget::constrain_valid_price(price_var, &mut cs).unwrap();

        assert!(!check_satisfaction(&cs));
    }

    /// Test the fee gadget
    #[test]
    fn test_fee_gadget() {
        // Test a valid fee
        let fee_repr = random_bitlength_scalar(FEE_BITS);
        let fee = FixedPoint { repr: fee_repr };
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fee_var = fee.create_witness(&mut cs);
        FeeGadget::constrain_valid_fee(fee_var, &mut cs).unwrap();

        assert!(check_satisfaction(&cs));

        // Test zero
        let fee = FixedPoint { repr: Scalar::zero() };
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fee_var = fee.create_witness(&mut cs);
        FeeGadget::constrain_valid_fee(fee_var, &mut cs).unwrap();

        assert!(check_satisfaction(&cs));

        // Test negative one
        let fee = FixedPoint { repr: Scalar::one().neg() };
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fee_var = fee.create_witness(&mut cs);
        FeeGadget::constrain_valid_fee(fee_var, &mut cs).unwrap();

        assert!(!check_satisfaction(&cs));

        // Test 2^FEE_BITS
        let fee_repr = scalar_2_pow_n(FEE_BITS);
        let fee = FixedPoint { repr: fee_repr };
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let fee_var = fee.create_witness(&mut cs);
        FeeGadget::constrain_valid_fee(fee_var, &mut cs).unwrap();

        assert!(!check_satisfaction(&cs));
    }
}
