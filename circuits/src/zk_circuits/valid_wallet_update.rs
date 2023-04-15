//! Defines the VALID WALLET UPDATE circuit which proves that a valid
//! transition exists between a pair of wallets, and nullifies the old
//! wallet.
//!
//! The user proves this statement to create new orders, deposit and withdraw
//! funds, and transfer funds internally.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.2
//! for a formal specification

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Variable, Verifier,
    },
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        keychain::PublicSigningKey,
        order::OrderVar,
        transfers::{
            ExternalTransfer, ExternalTransferVar, InternalTransfer, InternalTransferCommitment,
            InternalTransferVar,
        },
        wallet::{CommittedWallet, Wallet, WalletVar},
    },
    zk_gadgets::{
        commitments::{NullifierGadget, WalletCommitGadget},
        comparators::{
            EqGadget, EqVecGadget, EqZeroGadget, GreaterThanEqZeroGadget, NotEqualGadget,
        },
        fixed_point::FixedPointVar,
        gates::{AndGate, ConstrainBinaryGadget, OrGate},
        merkle::{
            MerkleOpening, MerkleOpeningCommitment, MerkleOpeningVar, PoseidonMerkleHashGadget,
        },
        nonnative::NonNativeElementVar,
        select::CondSelectGadget,
    },
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit,
};

// -----------------------
/// | Circuit Definition |
// -----------------------

/// The circuitry for the VALID WALLET UPDATE statement
///
/// TODO: bounds checks everywhere
#[derive(Clone, Debug)]
pub struct ValidWalletUpdate<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized, {}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Applies the constraints of the VALID WALLET UPDATE statement
    ///
    /// TODO: Some of the uniqueness checks might be able to be done with a randomized challenge scalar
    #[allow(clippy::too_many_arguments)]
    pub fn circuit<CS: RandomizableConstraintSystem>(
        witness: ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        statement: ValidWalletUpdateStatementVar,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Commit to the new wallet and constrain it to equal the public variable
        let new_wallet_commit_res = Self::wallet_commit(&witness.wallet2, cs)?;
        cs.constrain(statement.new_wallet_commitment - new_wallet_commit_res);

        // Commit to the old wallet, use this as a leaf in the Merkle opening
        let old_wallet_commit = Self::wallet_commit(&witness.wallet1, cs)?;
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            old_wallet_commit.clone(),
            witness.wallet1_opening,
            statement.merkle_root.into(),
            cs,
        )?;

        // Verify that the nullifiers are properly computed
        let spend_nullifier_res =
            Self::compute_spend_nullifier(&witness.wallet1, old_wallet_commit.clone(), cs)?;
        let match_nullifier_res =
            Self::compute_match_nullifier(&witness.wallet1, old_wallet_commit, cs)?;

        cs.constrain(statement.spend_nullifier - spend_nullifier_res);
        cs.constrain(statement.match_nullifier - match_nullifier_res);

        // Verify that the given pk_root key is the same as the wallet
        NonNativeElementVar::constrain_equal(&statement.pk_root, &witness.wallet1.keys.pk_root, cs);

        // Verify that the keys are unchanged between the two wallets
        Self::constrain_keys_equal(&witness.wallet1, &witness.wallet2, cs);

        // The randomness of the new wallet should equal the randomness of the old wallet, twice incremented
        cs.constrain(witness.wallet1.randomness + Scalar::from(2u64) - witness.wallet2.randomness);

        // Verify that the external transfer direction is binary
        ConstrainBinaryGadget::constrain_binary(statement.external_transfer.direction, cs);

        // Validate the balances of the new wallet
        Self::validate_transfers(
            &witness.wallet2,
            &witness.wallet1,
            witness.internal_transfer,
            statement.external_transfer,
            cs,
        );

        Self::validate_wallet_orders(&witness.wallet2, &witness.wallet1, statement.timestamp, cs);
        Ok(())
    }

    /// Compute the commitment to a wallet
    fn wallet_commit<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        WalletCommitGadget::wallet_commit(wallet, cs)
    }

    /// Compute the wallet spend nullifier, defined as the poseidon hash:
    ///     H(C(W) || r)
    fn compute_spend_nullifier<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        wallet_commit: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        NullifierGadget::spend_nullifier(wallet.randomness, wallet_commit, cs)
    }

    /// Compute the wallet match nullifier, defined as the poseidon hash:
    ///     H(C(W) || r + 1)
    fn compute_match_nullifier<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        wallet_commit: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        NullifierGadget::match_nullifier(wallet.randomness, wallet_commit, cs)
    }

    /// Constrain the keys of two wallets to be equal
    fn constrain_keys_equal<CS: RandomizableConstraintSystem>(
        wallet1: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        wallet2: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        NonNativeElementVar::constrain_equal(&wallet1.keys.pk_root, &wallet2.keys.pk_root, cs);
        cs.constrain(wallet1.keys.pk_match - wallet2.keys.pk_match);
        cs.constrain(wallet1.keys.pk_settle - wallet2.keys.pk_settle);
        cs.constrain(wallet1.keys.pk_view - wallet2.keys.pk_view);
    }

    /// Validates the application of the transfers to the balance state
    /// Verifies that:
    ///     1. All balance mints are unique after update
    ///     2. The internal and external transfers are applied properly and result
    ///        in non-negative balances
    ///     3. The user has the funds to cover the transfers
    pub(crate) fn validate_transfers<CS: RandomizableConstraintSystem>(
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        internal_transfer: InternalTransferVar,
        external_transfer: ExternalTransferVar,
        cs: &mut CS,
    ) {
        // Enforce all balance mints to be unique or 0
        Self::constrain_unique_balance_mints(new_wallet, cs);

        // Apply the transfers to the old balances, ensure that the new balances are properly computed

        // The external transfer term; negate the amount if the direction is 1 (withdraw)
        // otherwise keep the amount as positive
        let external_transfer_term = CondSelectGadget::select(
            -external_transfer.amount,
            external_transfer.amount.into(),
            external_transfer.direction.into(),
            cs,
        );

        // Stores the sum of the mints_eq gadgets; the internal/external transfers should either be
        // zero'd, or equal to a non-zero mint in the balances
        let mut external_transfer_mint_present: LinearCombination = Variable::Zero().into();
        let mut internal_transfer_mint_present: LinearCombination = Variable::Zero().into();

        for new_balance in new_wallet.balances.iter() {
            let mut expected_amount: LinearCombination = Variable::Zero().into();

            // Match amounts in the old wallet, before transfers
            for old_balance in old_wallet.balances.iter() {
                let mints_eq = EqZeroGadget::eq_zero(new_balance.mint - old_balance.mint, cs);
                let (_, _, masked_amount) = cs.multiply(mints_eq.into(), old_balance.amount.into());
                expected_amount += masked_amount;
            }

            // Add in the external transfer information
            let equals_external_transfer_mint =
                EqZeroGadget::eq_zero(new_balance.mint - external_transfer.mint, cs);
            let (_, _, external_transfer_term) = cs.multiply(
                equals_external_transfer_mint.into(),
                external_transfer_term.clone(),
            );

            external_transfer_mint_present += equals_external_transfer_mint;
            expected_amount += external_transfer_term;

            // Add in the internal transfer information
            let equals_internal_transfer_mint =
                EqZeroGadget::eq_zero(new_balance.mint - internal_transfer.mint, cs);
            let (_, _, internal_transfer_term) = cs.multiply(
                equals_internal_transfer_mint.into(),
                internal_transfer.amount.into(),
            );

            internal_transfer_mint_present += equals_internal_transfer_mint;
            expected_amount -= internal_transfer_term;

            // Constrain the expected amount to equal the amount in the new wallet
            cs.constrain(new_balance.amount - expected_amount);
            GreaterThanEqZeroGadget::<64 /* bitwidth */>::constrain_greater_than_zero(
                new_balance.amount,
                cs,
            );
        }

        // Lastly, for the internal transfer (and the external transfer if it is a withdraw)
        // we must ensure that the user had a balance of this mint in the previous wallet.
        // The constraints above constrain this balance to have sufficient value if it exists
        let internal_transfer_equals_zero = EqZeroGadget::eq_zero(internal_transfer.mint, cs);
        let internal_zero_or_valid_balance = OrGate::or(
            internal_transfer_equals_zero.into(),
            internal_transfer_mint_present,
            cs,
        );
        cs.constrain(Variable::One() - internal_zero_or_valid_balance);

        let external_transfer_is_deposit =
            EqGadget::eq(external_transfer.direction, Variable::Zero(), cs);
        let external_deposit_or_valid_balance = OrGate::or(
            external_transfer_is_deposit.into(),
            external_transfer_mint_present,
            cs,
        );
        cs.constrain(Variable::One() - external_deposit_or_valid_balance);
    }

    /// Constrains all balance mints to be unique or zero
    fn constrain_unique_balance_mints<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        for i in 0..wallet.balances.len() {
            for j in (i + 1)..wallet.balances.len() {
                // Check whether balance[i] != balance[j]
                let ij_unique =
                    NotEqualGadget::not_equal(wallet.balances[i].mint, wallet.balances[j].mint, cs);

                // Evaluate the polynomial mint * (1 - ij_unique) which is 0 iff
                // the mint is zero, or balance[i] != balance[j]
                let (_, _, constraint_poly) =
                    cs.multiply(wallet.balances[i].mint.into(), Variable::One() - ij_unique);
                cs.constrain(constraint_poly.into());
            }
        }
    }

    /// Validates the orders of the new wallet
    ///
    /// TODO: Optimize this to use a tree-structured multi-OR gate
    fn validate_wallet_orders<CS: RandomizableConstraintSystem>(
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        new_timestamp: Variable,
        cs: &mut CS,
    ) {
        // Ensure that all order's assert pairs are unique
        Self::constrain_unique_order_pairs(new_wallet, cs);

        // Ensure that the timestamps for all orders are properly set
        Self::constrain_updated_order_timestamps(new_wallet, old_wallet, new_timestamp, cs);
    }

    /// Constrains all order pairs in the wallet to have unique mints
    fn constrain_unique_order_pairs<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // Validate that all mints pairs are zero or unique
        for i in 0..wallet.orders.len() {
            let order_zero = Self::order_is_zero(&wallet.orders[i], cs);

            for j in (i + 1)..wallet.orders.len() {
                // Check if the ith order is unique
                let mints_equal = EqVecGadget::eq_vec(
                    &[wallet.orders[i].quote_mint, wallet.orders[i].base_mint],
                    &[wallet.orders[j].quote_mint, wallet.orders[j].base_mint],
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

    /// Constrain the timestamps to be properly updated
    /// For each order, if the order is unchanged from the previous wallet, no constraint is
    /// made. Otherwise, the timestamp should be updated to the current timestamp passed as
    /// a public variable
    fn constrain_updated_order_timestamps<CS: RandomizableConstraintSystem>(
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        new_timestamp: Variable,
        cs: &mut CS,
    ) {
        for (i, order) in new_wallet.orders.iter().enumerate() {
            let equals_old_order =
                Self::orders_equal_except_timestamp(order, &old_wallet.orders[i], cs);

            let timestamp_not_updated =
                EqGadget::eq(order.timestamp, old_wallet.orders[i].timestamp, cs);
            let timestamp_updated = EqGadget::eq(order.timestamp, new_timestamp, cs);

            // Either the orders are equal and the timestamp is not updated, or the timestamp has
            // been updated to the new timestamp
            let equal_and_not_updated = AndGate::and(equals_old_order, timestamp_not_updated, cs);
            let not_equal_and_updated = AndGate::and(
                Variable::One() - equals_old_order,
                timestamp_updated.into(),
                cs,
            );

            let constraint = OrGate::or(not_equal_and_updated, equal_and_not_updated, cs);
            cs.constrain(Variable::One() - constraint);
        }
    }

    /// Returns 1 if the order is a zero'd order, otherwise 0
    fn order_is_zero<CS: RandomizableConstraintSystem>(order: &OrderVar, cs: &mut CS) -> Variable {
        Self::orders_equal_except_timestamp(
            order,
            &OrderVar {
                quote_mint: Variable::Zero(),
                base_mint: Variable::Zero(),
                side: Variable::Zero(),
                amount: Variable::Zero(),
                price: FixedPointVar {
                    repr: Variable::Zero().into(),
                },
                timestamp: Variable::Zero(),
            },
            cs,
        )
    }

    /// Returns 1 if the orders are equal (except the timestamp) and 0 otherwise
    fn orders_equal_except_timestamp<CS: RandomizableConstraintSystem>(
        order1: &OrderVar,
        order2: &OrderVar,
        cs: &mut CS,
    ) -> Variable {
        EqVecGadget::eq_vec(
            &[
                order1.quote_mint.into(),
                order1.base_mint.into(),
                order1.side.into(),
                order1.amount.into(),
                order1.price.repr.clone(),
            ],
            &[
                order2.quote_mint.into(),
                order2.base_mint.into(),
                order2.side.into(),
                order2.amount.into(),
                order2.price.repr.clone(),
            ],
            cs,
        )
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for VALID WALLET UPDATE
#[derive(Clone, Debug)]
pub struct ValidWalletUpdateWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The old wallet; that being updated
    pub wallet1: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The new wallet; after the update is complete
    pub wallet2: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The opening from the old wallet's commitment to the global
    /// Merkle root
    pub wallet1_opening: MerkleOpening,
    /// The internal transfer tuple, a pair of (mint, volume); used to transfer
    /// funds out of a wallet to a settle-able note
    pub internal_transfer: InternalTransfer,
}

/// The witness type for VALID WALLET UPDATE that has been allocated
/// in a constraint system
#[derive(Clone, Debug)]
pub struct ValidWalletUpdateWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The old wallet; that being updated
    pub wallet1: WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The new wallet; after the update is complete
    pub wallet2: WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The opening from the old wallet's commitment to the global
    /// Merkle root
    pub wallet1_opening: MerkleOpeningVar,
    /// The internal transfer tuple, a pair of (mint, volume); used to transfer
    /// funds out of a wallet to a settle-able note
    pub internal_transfer: InternalTransferVar,
}

/// A commitment to the witness of VALID WALLET UPDATE
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletUpdateWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The old wallet; that being updated
    pub wallet1: CommittedWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The new wallet; after the update is complete
    pub wallet2: CommittedWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The opening from the old wallet's commitment to the global
    /// Merkle root
    pub wallet1_opening: MerkleOpeningCommitment,
    /// The internal transfer tuple, a pair of (mint, volume); used to transfer
    /// funds out of a wallet to a settle-able note
    pub internal_transfer: InternalTransferCommitment,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidWalletUpdateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (wallet1_var, wallet1_comm) = self.wallet1.commit_witness(rng, prover).unwrap();
        let (wallet2_var, wallet2_comm) = self.wallet2.commit_witness(rng, prover).unwrap();
        let (wallet1_opening_var, wallet1_opening_comm) =
            self.wallet1_opening.commit_witness(rng, prover).unwrap();
        let (internal_transfer_var, internal_transfer_comm) =
            self.internal_transfer.commit_witness(rng, prover).unwrap();

        Ok((
            ValidWalletUpdateWitnessVar {
                wallet1: wallet1_var,
                wallet2: wallet2_var,
                wallet1_opening: wallet1_opening_var,
                internal_transfer: internal_transfer_var,
            },
            ValidWalletUpdateWitnessCommitment {
                wallet1: wallet1_comm,
                wallet2: wallet2_comm,
                wallet1_opening: wallet1_opening_comm,
                internal_transfer: internal_transfer_comm,
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
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let wallet1_var = self.wallet1.commit_verifier(verifier).unwrap();
        let wallet2_var = self.wallet2.commit_verifier(verifier).unwrap();
        let wallet1_opening_var = self.wallet1_opening.commit_verifier(verifier).unwrap();
        let internal_transfer_var = self.internal_transfer.commit_verifier(verifier).unwrap();

        Ok(ValidWalletUpdateWitnessVar {
            wallet1: wallet1_var,
            wallet2: wallet2_var,
            wallet1_opening: wallet1_opening_var,
            internal_transfer: internal_transfer_var,
        })
    }
}

// ------------------------------
// | Statement Type Definitions |
// ------------------------------

/// The statement type for VALID WALLET UPDATE
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletUpdateStatement {
    /// The timestamp (user set) of the request, used for order timestamping
    pub timestamp: Scalar,
    /// The root public key of the wallet being updated
    pub pk_root: PublicSigningKey,
    /// The commitment to the new wallet
    pub new_wallet_commitment: Scalar,
    /// The wallet spend nullifier of the old wallet
    pub spend_nullifier: Scalar,
    /// The wallet match nullifier of the old wallet
    pub match_nullifier: Scalar,
    /// The global state tree root used to prove opening
    pub merkle_root: Scalar,
    /// The external transfer tuple, used to deposit or withdraw funds
    /// of the form (mint, volume, direction)
    pub external_transfer: ExternalTransfer,
}

/// The statement type for VALID WALLET UPDATE, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidWalletUpdateStatementVar {
    /// The timestamp (user set) of the request, used for order timestamping
    pub timestamp: Variable,
    /// The root public key of the wallet being updated
    pub pk_root: NonNativeElementVar,
    /// The commitment to the new wallet
    pub new_wallet_commitment: Variable,
    /// The wallet spend nullifier of the old wallet
    pub spend_nullifier: Variable,
    /// The wallet match nullifier of the old wallet
    pub match_nullifier: Variable,
    /// The global state tree root used to prove opening
    pub merkle_root: Variable,
    /// The external transfer tuple, used to deposit or withdraw funds
    /// of the form (mint, volume, direction)
    pub external_transfer: ExternalTransferVar,
}

impl CommitWitness for ValidWalletUpdateStatement {
    type VarType = ValidWalletUpdateStatementVar;
    type CommitType = ();
    type ErrorType = (); // Does not error

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        _rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let timestamp_var = prover.commit_public(self.timestamp);
        let pk_root_var = self.pk_root.commit_public(prover).unwrap();
        let new_wallet_commitment_var = prover.commit_public(self.new_wallet_commitment);
        let spend_nullifier_var = prover.commit_public(self.spend_nullifier);
        let match_nullifier_var = prover.commit_public(self.match_nullifier);
        let merkle_root_var = prover.commit_public(self.merkle_root);
        let external_transfer_var = self.external_transfer.commit_public(prover);

        Ok((
            ValidWalletUpdateStatementVar {
                timestamp: timestamp_var,
                pk_root: pk_root_var,
                new_wallet_commitment: new_wallet_commitment_var,
                match_nullifier: match_nullifier_var,
                spend_nullifier: spend_nullifier_var,
                merkle_root: merkle_root_var,
                external_transfer: external_transfer_var,
            },
            (),
        ))
    }
}

impl CommitVerifier for ValidWalletUpdateStatement {
    type VarType = ValidWalletUpdateStatementVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let timestamp_var = verifier.commit_public(self.timestamp);
        let pk_root_var = self.pk_root.commit_public(verifier).unwrap();
        let new_wallet_commitment_var = verifier.commit_public(self.new_wallet_commitment);
        let spend_nullifier_var = verifier.commit_public(self.spend_nullifier);
        let match_nullifier_var = verifier.commit_public(self.match_nullifier);
        let merkle_root_var = verifier.commit_public(self.merkle_root);
        let external_transfer_var = self.external_transfer.commit_public(verifier);

        Ok(ValidWalletUpdateStatementVar {
            timestamp: timestamp_var,
            pk_root: pk_root_var,
            new_wallet_commitment: new_wallet_commitment_var,
            match_nullifier: match_nullifier_var,
            spend_nullifier: spend_nullifier_var,
            merkle_root: merkle_root_var,
            external_transfer: external_transfer_var,
        })
    }
}

// ----------------------
// | Prove/Verify Flow |
// ----------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidWalletUpdateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidWalletUpdateStatement;

    const BP_GENS_CAPACITY: usize = 32768;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();

        // Commit to the statement
        let (statement_var, _) = statement.commit_witness(&mut rng, &mut prover).unwrap();

        // Apply the constraints
        Self::circuit(witness_var, statement_var, &mut prover).map_err(ProverError::R1CS)?;

        // Prove the statement
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
        // Commit to the witness
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

        // Commit to the statement
        let statement_var = statement.commit_verifier(&mut verifier).unwrap();

        // Apply the constraints
        Self::circuit(witness_var, statement_var, &mut verifier).map_err(VerifierError::R1CS)?;

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
mod valid_wallet_update_tests {
    use std::ops::Neg;

    use crypto::fields::prime_field_to_scalar;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{ConstraintSystem, Prover},
        PedersenGens,
    };
    use num_bigint::BigUint;
    use rand_core::{OsRng, RngCore};

    use crate::{
        native_helpers::{
            compute_wallet_commitment, compute_wallet_match_nullifier,
            compute_wallet_spend_nullifier,
        },
        test_helpers::bulletproof_prove_and_verify,
        types::{
            order::{Order, OrderSide},
            transfers::{ExternalTransfer, ExternalTransferDirection, InternalTransfer},
        },
        zk_circuits::test_helpers::{create_wallet_opening, INITIAL_WALLET},
        zk_gadgets::{fixed_point::FixedPoint, merkle::MerkleOpening},
        CommitWitness,
    };

    use super::{ValidWalletUpdate, ValidWalletUpdateStatement, ValidWalletUpdateWitness};

    // -------------
    // | Constants |
    // -------------

    /// The maximum number of balances allowed in a wallet for tests
    const MAX_BALANCES: usize = 2;
    /// The maximum number of orders allowed in a wallet for tests
    const MAX_ORDERS: usize = 2;
    /// The maximum number of fees allowed in a wallet for tests
    const MAX_FEES: usize = 1;
    /// The initial timestamp used in testing
    const TIMESTAMP: u64 = 3; // dummy value
    /// The height of the Merkle state tree
    const MERKLE_HEIGHT: usize = 3;

    /// Applies the constraints to a constraint system and verifies that they are
    /// all satisfied
    ///
    /// Importantly, this method does not prove or verify the statement, it is simply
    /// used to validate the constraints without actually generating a proof for efficiency
    fn constraints_satisfied(
        witness: ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        statement: ValidWalletUpdateStatement,
    ) -> bool {
        // Build a constraint system and allocate the witness and statement
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        // Allocate the witness and statement in the constraint system
        let mut rng = OsRng {};
        let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_witness(&mut rng, &mut prover).unwrap();

        ValidWalletUpdate::circuit(witness_var, statement_var, &mut prover).unwrap();
        prover.constraints_satisfied()
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests that updating a wallet with a valid witness/statement pair
    ///
    /// TODO: Add more tests in follow up
    #[test]
    fn test_place_order() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order {
            quote_mint: 1u8.into(),
            base_mint: 3u8.into(),
            side: OrderSide::Sell,
            price: FixedPoint::from(20.),
            amount: 10,
            timestamp: TIMESTAMP,
        };

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        let res = bulletproof_prove_and_verify::<
            ValidWalletUpdate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement);
        assert!(res.is_ok());
    }

    /// Tests placing an invalid order on a variety of cases
    #[test]
    fn test_place_order_invalid_timestamp() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = TIMESTAMP;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests that the circuit constrains an existing order's timestamp to have not changed
    #[test]
    fn test_place_order_invalid_timestamp2() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        new_wallet.orders[0].timestamp = timestamp; // invalid, old orders should remain unchanged
        initial_wallet.orders[1] = Order::default();

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests that two orders with the same mint pair fail
    #[test]
    fn test_duplicate_order_mint() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);

        // Invalid, cannot have two orders of the same pair
        new_wallet.orders[0].timestamp = timestamp;
        new_wallet.orders[0].quote_mint = new_wallet.orders[1].quote_mint.clone();
        new_wallet.orders[0].base_mint = new_wallet.orders[1].base_mint.clone();

        initial_wallet.orders[1] = Order::default();

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests the case in which a duplicate balance mint is used
    #[test]
    fn test_duplicate_balance_mint() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Invalid, multiple balances of the same mint
        new_wallet.balances[0].mint = new_wallet.balances[1].mint.clone();

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests a valid internal transfer
    #[test]
    fn test_internal_transfer_valid() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Modify the balance in balances[1] to deduct an amount for the internal transfer
        let internal_transfer_mint = new_wallet.balances[1].mint.clone();
        let internal_transfer_volume = new_wallet.balances[1].amount - 1; // all but 1 unit
        new_wallet.balances[1].amount -= internal_transfer_volume;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer {
                recipient_key: BigUint::default(),
                mint: internal_transfer_mint,
                amount: internal_transfer_volume.into(),
            },
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        assert!(constraints_satisfied(witness, statement));
    }

    /// Tests an internal transfer that incorrectly updates the balance
    #[test]
    fn test_internal_transfer_wrong_balance() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Modify the balance in balances[1] to deduct an amount for the internal transfer
        let internal_transfer_mint = new_wallet.balances[1].mint.clone();
        let internal_transfer_volume = new_wallet.balances[1].amount - 1; // all but 1 unit

        // Invalid, prover tries to decrease their balance by a smaller amount than transferred
        new_wallet.balances[1].amount -= internal_transfer_volume - 2;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer {
                recipient_key: BigUint::default(),
                mint: internal_transfer_mint,
                amount: internal_transfer_volume.into(),
            },
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test a valid external transfer
    #[test]
    fn test_valid_external_transfer_withdraw() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Modify the balance in balances[1] to deduct an amount for the internal transfer
        let external_transfer_mint = new_wallet.balances[1].mint.clone();
        let external_transfer_volume = new_wallet.balances[1].amount - 1; // all but 1 unit
        let external_transfer_direction = ExternalTransferDirection::Withdrawal;

        new_wallet.balances[1].amount -= external_transfer_volume;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer {
                account_addr: BigUint::default(),
                mint: external_transfer_mint,
                amount: external_transfer_volume.into(),
                direction: external_transfer_direction,
            },
        };

        assert!(constraints_satisfied(witness, statement));
    }

    /// Test a valid external transfer
    #[test]
    fn test_valid_external_transfer_deposit() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Modify the balance in balances[1] to deduct an amount for the internal transfer
        let external_transfer_mint = new_wallet.balances[1].mint.clone();
        let external_transfer_volume = new_wallet.balances[1].amount - 1; // all but 1 unit
        let external_transfer_direction = ExternalTransferDirection::Deposit;

        new_wallet.balances[1].amount += external_transfer_volume;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer {
                account_addr: BigUint::default(),
                mint: external_transfer_mint,
                amount: external_transfer_volume.into(),
                direction: external_transfer_direction,
            },
        };

        assert!(constraints_satisfied(witness, statement));
    }

    /// Tests the case in which the user withdraws, but updates their balance incorrectly
    #[test]
    fn test_invalid_external_transfer_withdraw() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Modify the balance in balances[1] to deduct an amount for the internal transfer
        let external_transfer_mint = new_wallet.balances[1].mint.clone();
        let external_transfer_volume = new_wallet.balances[1].amount - 1; // all but 1 unit
        let external_transfer_direction = ExternalTransferDirection::Withdrawal;

        // Invalid, prover tries to deduct too small of an amount from balance
        new_wallet.balances[1].amount -= external_transfer_volume - 1;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer {
                account_addr: BigUint::default(),
                mint: external_transfer_mint,
                amount: external_transfer_volume.into(),
                direction: external_transfer_direction,
            },
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests the case in which the user withdraws, but updates their balance incorrectly
    #[test]
    fn test_invalid_external_transfer_deposit() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Modify the balance in balances[1] to deduct an amount for the internal transfer
        let external_transfer_mint = new_wallet.balances[1].mint.clone();
        let external_transfer_volume = new_wallet.balances[1].amount - 1; // all but 1 unit
        let external_transfer_direction = ExternalTransferDirection::Deposit;

        // Invalid, prover tries to add too large of an amount to balance
        new_wallet.balances[1].amount += external_transfer_volume + 1;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer {
                account_addr: BigUint::default(),
                mint: external_transfer_mint,
                amount: external_transfer_volume.into(),
                direction: external_transfer_direction,
            },
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests the case in which the prover spuriously increases a balance
    #[test]
    fn test_invalid_balance_increase() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Invalid, prover tries to add too large of an amount to balance
        new_wallet.balances[1].amount += 1;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests the case in which an internal transfer is registered for a balance that does not exist
    #[test]
    fn test_invalid_internal_transfer_no_balance() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Invalid, the user does not have a balance for this mint
        let internal_transfer_mint = 1729u64;
        let internal_transfer_volume = new_wallet.balances[1].amount - 1; // all but 1 unit

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer {
                recipient_key: BigUint::default(),
                mint: internal_transfer_mint.into(),
                amount: internal_transfer_volume.into(),
            },
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer::default(),
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests the case in which an internal transfer is registered for a balance that does not exist
    #[test]
    fn test_invalid_external_transfer_no_balance() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Invalid, the user does not have an existing balance for the withdraw mint
        let external_transfer_mint = 1729u64;
        let external_transfer_volume = new_wallet.balances[1].amount - 1; // all but 1 unit
        let external_transfer_direction = ExternalTransferDirection::Withdrawal;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer {
                account_addr: BigUint::default(),
                mint: external_transfer_mint.into(),
                amount: external_transfer_volume.into(),
                direction: external_transfer_direction,
            },
        };

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests bounds checks on withdraw
    #[test]
    fn test_invalid_balance_negative_balance() {
        let mut rng = OsRng {};

        // Setup the initial wallet to have a single order, the updated wallet with a
        // new order
        let timestamp = TIMESTAMP + 1;
        let mut initial_wallet = INITIAL_WALLET.clone();
        let mut new_wallet = initial_wallet.clone();

        // Make changes to the initial and new wallet
        new_wallet.orders[1].timestamp = timestamp;
        new_wallet.randomness = initial_wallet.randomness + Scalar::from(2u32);
        initial_wallet.orders[1] = Order::default();

        // Invalid, the user does not have the withdrawn balance present
        // We do not modify the balance here, because we cannot underflow a u64; below we
        // replace the balance in the witness with an underflowed scalar
        let external_transfer_mint = new_wallet.balances[1].mint.clone();
        let external_transfer_volume = new_wallet.balances[1].amount + 1; // overdraw
        let external_transfer_direction = ExternalTransferDirection::Withdrawal;

        // Create a mock Merkle opening for the old wallet
        let random_index = rng.next_u32() % (2u32.pow(MERKLE_HEIGHT.try_into().unwrap()));
        let (mock_root, mock_opening, mock_opening_indices) = create_wallet_opening(
            &initial_wallet,
            MERKLE_HEIGHT,
            random_index as usize,
            &mut rng,
        );

        let witness = ValidWalletUpdateWitness {
            wallet1: initial_wallet.clone(),
            wallet2: new_wallet.clone(),
            wallet1_opening: MerkleOpening {
                elems: mock_opening,
                indices: mock_opening_indices,
            },
            internal_transfer: InternalTransfer::default(),
        };

        let new_wallet_commit = compute_wallet_commitment(&new_wallet);
        let old_wallet_commit = compute_wallet_commitment(&initial_wallet);

        let old_wallet_spend_nullifier =
            compute_wallet_spend_nullifier(&initial_wallet, old_wallet_commit);
        let old_wallet_match_nullifier =
            compute_wallet_match_nullifier(&initial_wallet, old_wallet_commit);

        let statement = ValidWalletUpdateStatement {
            timestamp: Scalar::from(timestamp),
            pk_root: new_wallet.keys.pk_root,
            new_wallet_commitment: prime_field_to_scalar(&new_wallet_commit),
            spend_nullifier: prime_field_to_scalar(&old_wallet_spend_nullifier),
            match_nullifier: prime_field_to_scalar(&old_wallet_match_nullifier),
            merkle_root: mock_root,
            external_transfer: ExternalTransfer {
                account_addr: BigUint::default(),
                mint: external_transfer_mint,
                amount: external_transfer_volume.into(),
                direction: external_transfer_direction,
            },
        };

        // Commit to the statement and witness
        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        let (mut witness_var, _) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_witness(&mut rng, &mut prover).unwrap();

        // Modify the second balance to explicitly underflow
        let negative_one = prover.commit_public(Scalar::one().neg());
        witness_var.wallet2.balances[1].amount = negative_one;

        // Validate the transfers directly; that way we don't have to go through the hassle of
        // updating commitments and nullifiers
        ValidWalletUpdate::validate_transfers(
            &witness_var.wallet2,
            &witness_var.wallet1,
            witness_var.internal_transfer,
            statement_var.external_transfer,
            &mut prover,
        );

        assert!(!prover.constraints_satisfied());
    }
}
