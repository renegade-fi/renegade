//! Defines the `VALID WALLET UPDATE` circuit
//!
//! This circuit proves that a user-generated update to a wallet is valid, and that
//! the state nullification/creation is computed correctly

// ----------------------
// | Circuit Definition |
// ----------------------

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        keychain::PublicSigningKey,
        order::OrderVar,
        transfers::{ExternalTransfer, ExternalTransferVar},
        wallet::{
            Nullifier, WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar,
            WalletShareCommitment, WalletVar,
        },
    },
    zk_gadgets::{
        commitments::{NullifierGadget, WalletShareCommitGadget},
        comparators::{
            EqGadget, EqVecGadget, EqZeroGadget, GreaterThanEqZeroGadget, NotEqualGadget,
        },
        fixed_point::FixedPointVar,
        gates::{AndGate, ConstrainBinaryGadget, NotGate, OrGate},
        merkle::{
            MerkleOpening, MerkleOpeningCommitment, MerkleOpeningVar, MerkleRoot,
            PoseidonMerkleHashGadget,
        },
        nonnative::NonNativeElementVar,
        select::CondSelectGadget,
    },
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit,
};

/// The `VALID WALLET UPDATE` circuit
pub struct ValidWalletUpdate<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit<CS: RandomizableConstraintSystem>(
        mut statement: ValidWalletUpdateStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        mut witness: ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // -- State Validity -- //

        // Verify the opening of the old wallet's private secret shares
        let old_private_shares_comm =
            WalletShareCommitGadget::compute_commitment(&witness.old_wallet_private_shares, cs)?;
        let computed_root = PoseidonMerkleHashGadget::compute_root_prehashed(
            old_private_shares_comm.clone(),
            witness.private_shares_opening,
            cs,
        )?;
        cs.constrain(statement.merkle_root - computed_root);

        // Verify the opening of the old wallet's public secret shares
        let old_public_shares_comm =
            WalletShareCommitGadget::compute_commitment(&witness.old_wallet_public_shares, cs)?;
        let computed_root = PoseidonMerkleHashGadget::compute_root_prehashed(
            old_public_shares_comm.clone(),
            witness.public_shares_opening,
            cs,
        )?;
        cs.constrain(statement.merkle_root - computed_root);

        // Reconstruct the wallet from secret shares
        let recovered_blinder = witness.old_wallet_private_shares.blinder.clone()
            + witness.old_wallet_public_shares.blinder.clone();
        witness.old_wallet_public_shares.unblind(recovered_blinder);

        let old_wallet = witness.old_wallet_private_shares + witness.old_wallet_public_shares;

        // Verify that the nullifiers of the two secret shares are correctly computed
        let public_nullifier = NullifierGadget::wallet_shares_nullifier(
            old_public_shares_comm,
            old_wallet.blinder.clone(),
            cs,
        )?;
        cs.constrain(public_nullifier - statement.old_public_shares_nullifier);

        let private_nullifier = NullifierGadget::wallet_shares_nullifier(
            old_private_shares_comm,
            old_wallet.blinder.clone(),
            cs,
        )?;
        cs.constrain(private_nullifier - statement.old_private_shares_nullifier);

        // Validate the commitment to the new wallet shares
        let new_wallet_private_commitment =
            WalletShareCommitGadget::compute_commitment(&witness.new_wallet_private_shares, cs)?;
        cs.constrain(statement.new_private_shares_commitment - new_wallet_private_commitment);

        // -- Authorization -- //

        // Check pk_root in the statement corresponds to pk_root in the wallet
        NonNativeElementVar::constrain_equal(&statement.old_pk_root, &old_wallet.keys.pk_root, cs);

        // -- State transition validity -- //

        // Reconstruct the new wallet from shares
        let recovered_blinder = witness.new_wallet_private_shares.blinder.clone()
            + statement.new_public_shares.blinder.clone();
        statement.new_public_shares.unblind(recovered_blinder);

        let new_wallet = statement.new_public_shares + witness.new_wallet_private_shares;

        Self::verify_wallet_transition(
            old_wallet,
            new_wallet,
            statement.external_transfer,
            statement.timestamp,
            cs,
        );

        Ok(())
    }

    /// Verify a state transition between two wallets
    fn verify_wallet_transition<CS: RandomizableConstraintSystem>(
        old_wallet: WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        new_wallet: WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        external_transfer: ExternalTransferVar,
        update_timestamp: Variable,
        cs: &mut CS,
    ) {
        // External transfer must have binary direction
        ConstrainBinaryGadget::constrain_binary(external_transfer.direction, cs);

        // Validate updates to the orders within the wallet
        Self::validate_order_updates(&old_wallet, &new_wallet, update_timestamp, cs);

        // Validate updates to the balances within the wallet
        Self::validate_balance_updates(&old_wallet, &new_wallet, external_transfer, cs);
    }

    // ------------
    // | Balances |
    // ------------

    /// Validates the balance updates in the wallet
    fn validate_balance_updates<CS: RandomizableConstraintSystem>(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        external_transfer: ExternalTransferVar,
        cs: &mut CS,
    ) {
        // Ensure that all mints in the updated balances are unique
        Self::constrain_unique_balance_mints(new_wallet, cs);
        // Validate that the external transfer has been correctly applied
        Self::validate_external_transfer(old_wallet, new_wallet, external_transfer, cs);
    }

    /// Validates the application of the external transfer to the balance state
    /// Verifies that:
    ///     1. The external transfer is applied properly and results
    ///        in non-negative balances
    ///     2. The user has the funds to cover the transfers
    pub(crate) fn validate_external_transfer<CS: RandomizableConstraintSystem>(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        external_transfer: ExternalTransferVar,
        cs: &mut CS,
    ) {
        // Zero out the external transfer amount if its mint is zero
        let external_transfer_zero = EqZeroGadget::eq_zero(external_transfer.mint, cs);
        let external_transfer_not_zero = NotGate::not(external_transfer_zero, cs);
        let (_, _, transfer_amount) =
            cs.multiply(external_transfer.amount.into(), external_transfer_not_zero);

        // The term added to any balance matching the external transfer mint
        let external_transfer_term = CondSelectGadget::select(
            -transfer_amount,
            transfer_amount.into(),
            external_transfer.direction.into(),
            cs,
        );

        // Stores a boolean indicating whether the external transfer appeared in the new balances
        // it must be applied to at least one balance
        let mut external_transfer_applied: LinearCombination = Variable::Zero().into();

        // Check the balance state transition for each balance
        for (old_balance, new_balance) in old_wallet.balances.iter().zip(new_wallet.balances.iter())
        {
            // The initial balance before updates
            let mut expected_balance = old_balance.amount.clone();

            // Add in the external transfer information term if applicable
            let equals_external_transfer_mint =
                EqGadget::eq(new_balance.mint.clone(), external_transfer.mint.into(), cs);
            let (_, _, external_transfer_term) = cs.multiply(
                equals_external_transfer_mint.into(),
                external_transfer_term.clone(),
            );

            external_transfer_applied += equals_external_transfer_mint;
            expected_balance += external_transfer_term;

            // Constrain the updated balance to be non-negative and correctly updated
            cs.constrain(new_balance.amount.clone() - expected_balance);
            GreaterThanEqZeroGadget::<64 /* bitwidth */>::constrain_greater_than_zero(
                new_balance.amount.clone(),
                cs,
            );

            // Constrain the mints to be set correctly. A valid mint is one of:
            //  1. The same mint as in the old wallet, if the balance previously existed and was not zero'd
            //  2. The mint of the transfer if the balance was previously zero; balances are constrained
            //     to be unique elsewhere in the circuit
            //  3. The zero mint, if the balance is zero
            let mints_equal = EqGadget::eq(old_balance.mint.clone(), new_balance.mint.clone(), cs);
            let equals_transfer_mint =
                EqGadget::eq(new_balance.mint.clone(), external_transfer.mint.into(), cs);
            let mint_is_zero = EqZeroGadget::eq_zero(new_balance.mint.clone(), cs);
            let new_balance_zero = EqZeroGadget::eq_zero(new_balance.amount.clone(), cs);
            let prev_balance_zero = EqZeroGadget::eq_zero(old_balance.amount.clone(), cs);

            // Condition 1 -- same mint as old wallet, balance not zero'd
            let valid_mint1 = AndGate::multi_and(
                &[
                    mints_equal.into(),
                    NotGate::not(prev_balance_zero, cs),
                    NotGate::not(new_balance_zero, cs),
                ],
                cs,
            );

            // Condition 2 -- new mint added to wallet
            let valid_mint2 = AndGate::multi_and(
                &[
                    equals_transfer_mint.into(),
                    prev_balance_zero.into(),
                    NotGate::not(new_balance_zero, cs),
                ],
                cs,
            );

            // Condition 3 -- withdrawal of entire balance, mint is now zero
            let valid_mint3 = AndGate::multi_and(&[mint_is_zero, new_balance_zero], cs);

            // Constrain one of the thee mint conditions to hold
            let valid_mint = OrGate::multi_or(&[valid_mint1, valid_mint2, valid_mint3], cs);
            cs.constrain(Variable::One() - valid_mint);
        }

        // Validate that the external transfer's mint did show up in exactly one of the balances
        let transfer_applied = EqGadget::eq(external_transfer_applied, Variable::One().into(), cs);
        let transfer_applied_or_zero = OrGate::or(transfer_applied, external_transfer_zero, cs);
        cs.constrain(transfer_applied_or_zero - Variable::One());
    }

    /// Constrains all balance mints to be unique or zero
    fn constrain_unique_balance_mints<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        cs: &mut CS,
    ) {
        for i in 0..wallet.balances.len() {
            for j in (i + 1)..wallet.balances.len() {
                // Check whether balance[i] != balance[j]
                let ij_unique = NotEqualGadget::not_equal(
                    wallet.balances[i].mint.clone(),
                    wallet.balances[j].mint.clone(),
                    cs,
                );

                // Evaluate the polynomial mint * (1 - ij_unique) which is 0 iff
                // the mint is zero, or balance[i] != balance[j]
                let (_, _, constraint_poly) =
                    cs.multiply(wallet.balances[i].mint.clone(), Variable::One() - ij_unique);
                cs.constrain(constraint_poly.into());
            }
        }
    }

    // ----------
    // | Orders |
    // ----------

    /// Validates the orders of the new wallet
    fn validate_order_updates<CS: RandomizableConstraintSystem>(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        new_timestamp: Variable,
        cs: &mut CS,
    ) {
        // Ensure that all order's assert pairs are unique
        Self::constrain_unique_order_pairs(new_wallet, cs);

        // Ensure that the timestamps for all orders are properly set
        Self::constrain_updated_order_timestamps(old_wallet, new_wallet, new_timestamp, cs);
    }

    /// Constrain the timestamps to be properly updated
    /// For each order, if the order is unchanged from the previous wallet, no constraint is
    /// made. Otherwise, the timestamp should be updated to the current timestamp passed as
    /// a public variable
    fn constrain_updated_order_timestamps<CS: RandomizableConstraintSystem>(
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        new_timestamp: Variable,
        cs: &mut CS,
    ) {
        for (i, order) in new_wallet.orders.iter().enumerate() {
            let order_is_zero = Self::order_is_zero(order, cs);
            let equals_old_order =
                Self::orders_equal_except_timestamp(order, &old_wallet.orders[i], cs);

            let timestamp_not_updated = EqGadget::eq(
                order.timestamp.clone(),
                old_wallet.orders[i].timestamp.clone(),
                cs,
            );
            let timestamp_updated = EqGadget::eq(order.timestamp.clone(), new_timestamp.into(), cs);

            // Either the orders are equal and the timestamp is not updated, or the timestamp has
            // been updated to the new timestamp
            let equal_and_not_updated = AndGate::and(equals_old_order, timestamp_not_updated, cs);
            let not_equal_and_updated = AndGate::and(
                Variable::One() - equals_old_order,
                timestamp_updated.into(),
                cs,
            );

            // Validate that if the order is in one of the following states:
            //  1. Updated order with updated timestamp
            //  2. Non-updated order with non-updated timestamp
            //  3. Cancelled order
            let or1 = OrGate::or(not_equal_and_updated, equal_and_not_updated, cs);
            let or2 = OrGate::or(or1, order_is_zero.into(), cs);
            cs.constrain(Variable::One() - or2);
        }
    }

    /// Assert that all order pairs in a wallet have unique asset pairs
    fn constrain_unique_order_pairs<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        cs: &mut CS,
    ) {
        // Validate that all mints pairs are zero or unique
        for i in 0..wallet.orders.len() {
            let order_zero = Self::order_is_zero(&wallet.orders[i], cs);

            for j in (i + 1)..wallet.orders.len() {
                // Check if the ith order is unique
                let mints_equal = EqVecGadget::eq_vec(
                    &[
                        wallet.orders[i].quote_mint.clone(),
                        wallet.orders[i].base_mint.clone(),
                    ],
                    &[
                        wallet.orders[j].quote_mint.clone(),
                        wallet.orders[j].base_mint.clone(),
                    ],
                    cs,
                );

                // Constrain the polynomial (1 - order_zero) * mints_equal; this is satisfied iff
                // the mints are not equal (the order is unique)
                let (_, _, constraint_poly) =
                    cs.multiply(mints_equal.into(), Variable::One() - order_zero);
                cs.constrain(constraint_poly.into());
            }
        }
    }

    /// Returns 1 if the order is a zero'd order, otherwise 0
    fn order_is_zero<CS: RandomizableConstraintSystem>(
        order: &OrderVar<LinearCombination>,
        cs: &mut CS,
    ) -> Variable {
        Self::orders_equal_except_timestamp(
            order,
            &OrderVar {
                quote_mint: Variable::Zero().into(),
                base_mint: Variable::Zero().into(),
                side: Variable::Zero().into(),
                amount: Variable::Zero().into(),
                price: FixedPointVar {
                    repr: Variable::Zero().into(),
                },
                timestamp: Variable::Zero().into(),
            },
            cs,
        )
    }

    /// Returns 1 if the orders are equal (except the timestamp) and 0 otherwise
    fn orders_equal_except_timestamp<CS: RandomizableConstraintSystem>(
        order1: &OrderVar<LinearCombination>,
        order2: &OrderVar<LinearCombination>,
        cs: &mut CS,
    ) -> Variable {
        EqVecGadget::eq_vec(
            &[
                order1.quote_mint.clone(),
                order1.base_mint.clone(),
                order1.side.clone(),
                order1.amount.clone(),
                order1.price.repr.clone(),
            ],
            &[
                order2.quote_mint.clone(),
                order2.base_mint.clone(),
                order2.side.clone(),
                order2.amount.clone(),
                order2.price.repr.clone(),
            ],
            cs,
        )
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID WALLET UPDATE`
#[derive(Clone, Debug)]
pub struct ValidWalletUpdateWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the existing wallet
    pub old_wallet_private_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the existing wallet
    pub old_wallet_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The Merkle opening of the old wallet's private secret shares
    pub private_shares_opening: MerkleOpening,
    /// The Merkle opening of the old wallet's public secret shares
    pub public_shares_opening: MerkleOpening,
    /// The new wallet's private secret shares
    pub new_wallet_private_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// The witness type for `VALID WALLET UPDATE` allocated in a constraint system
#[derive(Clone)]
pub struct ValidWalletUpdateWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the existing wallet
    pub old_wallet_private_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the existing wallet
    pub old_wallet_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The Merkle opening of the old wallet's private secret shares
    pub private_shares_opening: MerkleOpeningVar,
    /// The Merkle opening of the old wallet's public secret shares
    pub public_shares_opening: MerkleOpeningVar,
    /// The new wallet's private secret shares
    pub new_wallet_private_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// A commitment to the witness type of `VALID WALLET UPDATE` that has been
/// allocated in a constraint system
#[derive(Clone)]
pub struct ValidWalletUpdateWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the existing wallet
    pub old_wallet_private_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the existing wallet
    pub old_wallet_public_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The Merkle opening of the old wallet's private secret shares
    pub private_shares_opening: MerkleOpeningCommitment,
    /// The Merkle opening of the old wallet's public secret shares
    pub public_shares_opening: MerkleOpeningCommitment,
    /// The new wallet's private secret shares
    pub new_wallet_private_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidWalletUpdateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        // Old wallet state
        let (old_private_share_vars, old_private_share_comms) = self
            .old_wallet_private_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (old_public_share_vars, old_public_share_comms) = self
            .old_wallet_public_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (private_opening_vars, private_opening_comms) = self
            .private_shares_opening
            .commit_witness(rng, prover)
            .unwrap();
        let (public_opening_vars, public_opening_comms) = self
            .public_shares_opening
            .commit_witness(rng, prover)
            .unwrap();

        // New wallet state
        let (new_private_share_vars, new_private_share_comms) = self
            .new_wallet_private_shares
            .commit_witness(rng, prover)
            .unwrap();

        Ok((
            ValidWalletUpdateWitnessVar {
                old_wallet_private_shares: old_private_share_vars,
                old_wallet_public_shares: old_public_share_vars,
                private_shares_opening: private_opening_vars,
                public_shares_opening: public_opening_vars,
                new_wallet_private_shares: new_private_share_vars,
            },
            ValidWalletUpdateWitnessCommitment {
                old_wallet_private_shares: old_private_share_comms,
                old_wallet_public_shares: old_public_share_comms,
                private_shares_opening: private_opening_comms,
                public_shares_opening: public_opening_comms,
                new_wallet_private_shares: new_private_share_comms,
            },
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for ValidWalletUpdateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let old_private_share_vars = self
            .old_wallet_private_shares
            .commit_verifier(verifier)
            .unwrap();
        let old_public_share_vars = self
            .old_wallet_public_shares
            .commit_verifier(verifier)
            .unwrap();
        let private_opening_vars = self
            .private_shares_opening
            .commit_verifier(verifier)
            .unwrap();
        let public_opening_vars = self
            .public_shares_opening
            .commit_verifier(verifier)
            .unwrap();
        let new_private_share_vars = self
            .new_wallet_private_shares
            .commit_verifier(verifier)
            .unwrap();

        Ok(ValidWalletUpdateWitnessVar {
            old_wallet_private_shares: old_private_share_vars,
            old_wallet_public_shares: old_public_share_vars,
            private_shares_opening: private_opening_vars,
            public_shares_opening: public_opening_vars,
            new_wallet_private_shares: new_private_share_vars,
        })
    }
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID WALLET UPDATE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletUpdateStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The nullifier of the old wallet's private secret shares
    pub old_private_shares_nullifier: Nullifier,
    /// The nullifier of the old wallet's public secret shares
    pub old_public_shares_nullifier: Nullifier,
    /// A commitment to the new wallet's private secret shares
    pub new_private_shares_commitment: WalletShareCommitment,
    /// The public secret shares of the new wallet
    pub new_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The global Merkle root that the wallet share proofs open to
    pub merkle_root: MerkleRoot,
    /// The external transfer tuple
    pub external_transfer: ExternalTransfer,
    /// The public root key of the old wallet, rotated out after update
    pub old_pk_root: PublicSigningKey,
    /// The timestamp this update is at
    pub timestamp: u64,
}

/// The statement type for `VALID WALLET UPDATE` allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidWalletUpdateStatementVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The nullifier of the old wallet's private secret shares
    pub old_private_shares_nullifier: Variable,
    /// The nullifier of the old wallet's public secret shares
    pub old_public_shares_nullifier: Variable,
    /// A commitment to the new wallet's private secret shares
    pub new_private_shares_commitment: Variable,
    /// The public secret shares of the new wallet
    pub new_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The global Merkle root that the wallet share proofs open to
    pub merkle_root: Variable,
    /// The external transfer tuple
    pub external_transfer: ExternalTransferVar,
    /// The public root key of the old wallet, rotated out after update
    pub old_pk_root: NonNativeElementVar,
    /// The timestamp this update is at
    pub timestamp: Variable,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitPublic
    for ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidWalletUpdateStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let old_private_nullifier_var =
            self.old_private_shares_nullifier.commit_public(cs).unwrap();
        let old_public_nullifier_var = self.old_public_shares_nullifier.commit_public(cs).unwrap();
        let new_private_commitment_var = self
            .new_private_shares_commitment
            .commit_public(cs)
            .unwrap();
        let new_public_share_vars = self.new_public_shares.commit_public(cs).unwrap();

        let merkle_root_var = self.merkle_root.commit_public(cs).unwrap();
        let external_transfer_var = self.external_transfer.commit_public(cs).unwrap();
        let pk_root_var = self.old_pk_root.commit_public(cs).unwrap();
        let timestamp_var = Scalar::from(self.timestamp).commit_public(cs).unwrap();

        Ok(ValidWalletUpdateStatementVar {
            old_private_shares_nullifier: old_private_nullifier_var,
            old_public_shares_nullifier: old_public_nullifier_var,
            new_private_shares_commitment: new_private_commitment_var,
            new_public_shares: new_public_share_vars,
            merkle_root: merkle_root_var,
            external_transfer: external_transfer_var,
            old_pk_root: pk_root_var,
            timestamp: timestamp_var,
        })
    }
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidWalletUpdateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 2048;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Allocate the witness and statement in the constraint system
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        // Apply the constraints
        Self::circuit(statement_var, witness_var, &mut prover).map_err(ProverError::R1CS)?;

        // Prove the circuit
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::R1CS)?;

        Ok((witness_comm, proof))
    }

    fn verify(
        witness_commitment: Self::WitnessCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Allocate the witness and statement in the constraint system
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();
        let statement_var = statement.commit_public(&mut verifier).unwrap();

        // Apply the constraints
        Self::circuit(statement_var, witness_var, &mut verifier).map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    #![allow(non_snake_case)]

    use merlin::Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use num_bigint::BigUint;
    use rand_core::OsRng;

    use crate::{
        native_helpers::{compute_wallet_share_commitment, compute_wallet_share_nullifier},
        types::{
            balance::Balance,
            order::Order,
            transfers::{ExternalTransfer, ExternalTransferDirection},
        },
        zk_circuits::test_helpers::{
            create_multi_opening, create_wallet_shares, SizedWallet, INITIAL_WALLET, MAX_BALANCES,
            MAX_FEES, MAX_ORDERS, TIMESTAMP,
        },
        zk_gadgets::fixed_point::FixedPoint,
        CommitPublic, CommitWitness,
    };

    use super::{ValidWalletUpdate, ValidWalletUpdateStatement, ValidWalletUpdateWitness};

    /// The witness type with default size parameters attached
    type SizedWitness = ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    /// The statement type with default size parameters attached
    type SizedStatement = ValidWalletUpdateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 3;
    /// The timestamp of update
    const NEW_TIMESTAMP: u64 = TIMESTAMP + 1;

    // -----------
    // | Helpers |
    // -----------

    /// Returns true if the circuit constraints are satisfied on the given parameters
    fn constraints_satisfied_on_wallets(
        old_wallet: SizedWallet,
        new_wallet: SizedWallet,
        transfer: ExternalTransfer,
    ) -> bool {
        let (witness, statement) = construct_witness_statement(old_wallet, new_wallet, transfer);
        constraints_satisfied(statement, witness)
    }

    /// Construct a witness and statement
    fn construct_witness_statement(
        old_wallet: SizedWallet,
        new_wallet: SizedWallet,
        external_transfer: ExternalTransfer,
    ) -> (SizedWitness, SizedStatement) {
        let mut rng = OsRng {};

        // Construct secret shares of the wallets
        let (old_wallet_private_shares, old_wallet_public_shares) =
            create_wallet_shares(&old_wallet);
        let (new_wallet_private_shares, new_wallet_public_shares) =
            create_wallet_shares(&new_wallet);

        // Create dummy openings for the old shares
        let old_private_commitment =
            compute_wallet_share_commitment(old_wallet_private_shares.clone());
        let old_public_commitment =
            compute_wallet_share_commitment(old_wallet_public_shares.clone());
        let (merkle_root, mut openings) = create_multi_opening(
            &[old_private_commitment, old_public_commitment],
            MERKLE_HEIGHT,
            &mut rng,
        );

        // Compute nullifiers for the old state
        let old_private_nullifier =
            compute_wallet_share_nullifier(old_private_commitment, old_wallet.blinder);
        let old_public_nullifier =
            compute_wallet_share_nullifier(old_public_commitment, old_wallet.blinder);

        // Commit to the new private shares
        let new_private_shares_commitment =
            compute_wallet_share_commitment(new_wallet_private_shares.clone());

        let witness = SizedWitness {
            old_wallet_private_shares,
            old_wallet_public_shares,
            new_wallet_private_shares,
            private_shares_opening: openings.remove(0),
            public_shares_opening: openings.remove(0),
        };
        let statement = SizedStatement {
            old_private_shares_nullifier: old_private_nullifier,
            old_public_shares_nullifier: old_public_nullifier,
            old_pk_root: old_wallet.keys.pk_root,
            new_private_shares_commitment,
            new_public_shares: new_wallet_public_shares,
            merkle_root,
            external_transfer,
            timestamp: NEW_TIMESTAMP,
        };

        (witness, statement)
    }

    /// Return true if the circuit constraints are satisfied on a given
    /// statement, witness pair
    fn constraints_satisfied(statement: SizedStatement, witness: SizedWitness) -> bool {
        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Allocate the witness and statement in the constraint system
        let mut rng = OsRng {};
        let statement_var = statement.commit_public(&mut prover).unwrap();
        let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover).unwrap();

        // Apply the constraints
        ValidWalletUpdate::circuit(statement_var, witness_var, &mut prover).unwrap();
        prover.constraints_satisfied()
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests a valid witness and statement for placing an order
    #[test]
    fn test_place_order__valid() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        new_wallet.orders[0].timestamp = NEW_TIMESTAMP;

        // Remove an order from the initial wallet
        old_wallet.orders[0] = Order::default();

        assert!(constraints_satisfied_on_wallets(
            old_wallet,
            new_wallet,
            ExternalTransfer::default()
        ));
    }

    /// Tests order cancellation
    #[test]
    fn test_order_cancellation() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        new_wallet.orders[0] = Order::default();

        assert!(constraints_satisfied_on_wallets(
            old_wallet,
            new_wallet,
            ExternalTransfer::default()
        ))
    }

    /// Tests placing an order without updating the timestamp
    #[test]
    fn test_place_order__invalid_timestamp() {
        let mut old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        new_wallet.orders[0].timestamp = TIMESTAMP; // old timestamp

        // Remove an order from the initial wallet
        old_wallet.orders[0] = Order::default();

        assert!(!constraints_satisfied_on_wallets(
            old_wallet,
            new_wallet,
            ExternalTransfer::default()
        ));
    }

    /// Tests modifying the timestamp of an existing order
    #[test]
    fn test_place_order__invalid_timestamp_update() {
        // No update to the orders, but the timestamp is incorrect
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();
        new_wallet.orders[0].timestamp = NEW_TIMESTAMP;

        assert!(!constraints_satisfied_on_wallets(
            old_wallet,
            new_wallet,
            ExternalTransfer::default()
        ));
    }

    /// Tests that orders with duplicate asset pairs will fail
    #[test]
    fn test_place_order__duplicate_mint() {
        // No update to the orders, but the timestamp is incorrect
        let mut old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Create the wallet's second order as a duplicate of the first
        new_wallet.orders[1] = new_wallet.orders[0].clone();
        new_wallet.orders[1].price = new_wallet.orders[1].price + FixedPoint::from_integer(10u64);
        new_wallet.orders[1].timestamp = NEW_TIMESTAMP;

        // Remove the order from the original wallet to simulate order placement
        old_wallet.orders[1] = Order::default();

        assert!(!constraints_satisfied_on_wallets(
            old_wallet,
            new_wallet,
            ExternalTransfer::default()
        ));
    }

    /// Tests the case in which a duplicate balance is given
    #[test]
    fn test_duplicate_balance() {
        // No update to the orders, but the timestamp is incorrect
        let mut old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Create the wallet's second balance as a duplicate of the first
        new_wallet.balances[1] = new_wallet.balances[0].clone();
        new_wallet.balances[1].amount += 10;

        // Remove the duplicated balance from the old wallet
        old_wallet.balances[1] = Balance::default();

        assert!(!constraints_satisfied_on_wallets(
            old_wallet,
            new_wallet,
            ExternalTransfer::default()
        ));
    }

    /// Tests a valid external transfer that withdraws a balance
    #[test]
    fn test_external_transfer__valid_withdrawal() {
        let old_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = INITIAL_WALLET.clone();

        // Withdraw all of the first balance from the new wallet
        new_wallet.balances[0] = Balance::default();
        let transfer = ExternalTransfer {
            mint: old_wallet.balances[0].mint.clone(),
            amount: BigUint::from(old_wallet.balances[0].amount),
            direction: ExternalTransferDirection::Withdrawal,
            account_addr: BigUint::from(0u8),
        };

        assert!(constraints_satisfied_on_wallets(
            old_wallet, new_wallet, transfer
        ));
    }
}
