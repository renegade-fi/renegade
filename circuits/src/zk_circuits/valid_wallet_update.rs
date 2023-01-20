//! Defines the VALID WALLET UPDATE circuit which proves that a valid
//! transition exists between a pair of wallets, and nullifies the old
//! wallet.
//!
//! The user proves this statement to create new orders, deposit and withdraw
//! funds, and transfer funds internally.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.2
//! for a formal specification

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{
        ConstraintSystem, LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem,
        Variable, Verifier,
    },
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{
        order::OrderVar,
        wallet::{CommittedWallet, Wallet, WalletVar},
    },
    zk_gadgets::{
        comparators::{EqGadget, EqVecGadget, EqZeroGadget, NotEqualGadget},
        gates::{AndGate, OrGate},
        merkle::PoseidonMerkleHashGadget,
        poseidon::PoseidonHashGadget,
        select::CondSelectGadget,
    },
    CommitProver, CommitVerifier, SingleProverCircuit,
};

/// The circuitry for the VALID WALLET UPDATE statement
#[derive(Clone, Debug)]
pub struct ValidWalletUpdate<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized, {}

#[allow(unused)]
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
        timestamp: Variable,
        pk_root: Variable,
        merkle_root: Variable,
        match_nullifier: Variable,
        spend_nullifier: Variable,
        new_wallet_commit: Variable,
        external_transfer: (Variable, Variable, Variable),
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Commit to the new wallet and constrain it to equal the public variable
        let new_wallet_commit_res = Self::wallet_commit(&witness.wallet2, cs)?;
        cs.constrain(new_wallet_commit - new_wallet_commit_res);

        // Commit to the old wallet, use this as a leaf in the Merkle opening
        let old_wallet_commit = Self::wallet_commit(&witness.wallet1, cs)?;
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            cs,
            old_wallet_commit.clone(),
            witness.wallet1_opening,
            witness.wallet1_opening_indices,
            merkle_root.into(),
        )?;

        // Verify that the nullifiers are properly computed
        let spend_nullifier_res =
            Self::compute_spend_nullifier(&witness.wallet1, old_wallet_commit.clone(), cs)?;
        let match_nullifier_res =
            Self::compute_match_nullifier(&witness.wallet1, old_wallet_commit, cs)?;

        cs.constrain(spend_nullifier - spend_nullifier_res);
        cs.constrain(match_nullifier - match_nullifier_res);

        // Verify that the given pk_root key is the same as the wallet
        cs.constrain(pk_root - witness.wallet1.keys[0]);

        // Verify that the keys are unchanged between the two wallets
        Self::constrain_keys_equal(&witness.wallet1, &witness.wallet2, cs);

        // The randomness of the new wallet should equal the randomness of the old wallet, twice incremented
        cs.constrain(witness.wallet1.randomness + Scalar::from(2u64) - witness.wallet2.randomness);

        // Verify that the external transfer direction is binary
        let (_, _, external_transfer_binary) = cs.multiply(
            external_transfer.2.into(),
            Variable::One() - external_transfer.2,
        );
        cs.constrain(external_transfer_binary.into());

        // Validate the balances of the new wallet
        Self::validate_wallet_balances(
            &witness.wallet2,
            &witness.wallet1,
            witness.internal_transfer,
            external_transfer,
            cs,
        );

        Self::validate_wallet_orders(&witness.wallet2, &witness.wallet1, timestamp, cs);

        Ok(())
    }

    /// Compute the commitment to a wallet
    fn wallet_commit<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        // Create a new hash gadget
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);

        // Hash the balances into the state
        for balance in wallet.balances.iter() {
            hasher.batch_absorb(cs, &[balance.mint, balance.amount])?;
        }

        // Hash the orders into the state
        for order in wallet.orders.iter() {
            hasher.batch_absorb(
                cs,
                &[
                    order.quote_mint,
                    order.base_mint,
                    order.side,
                    order.price,
                    order.amount,
                ],
            )?;
        }

        // Hash the fees into the state
        for fee in wallet.fees.iter() {
            hasher.batch_absorb(
                cs,
                &[
                    fee.settle_key,
                    fee.gas_addr,
                    fee.gas_token_amount,
                    fee.percentage_fee,
                ],
            )?;
        }

        // Hash the keys into the state
        hasher.batch_absorb(cs, &wallet.keys)?;

        // Squeeze an element out of the state
        hasher.squeeze(cs)
    }

    /// Compute the wallet spend nullifier, defined as the poseidon hash:
    ///     H(C(W) || r)
    fn compute_spend_nullifier<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        wallet_commit: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hasher_params);

        hasher.batch_absorb(cs, &[wallet_commit, wallet.randomness.into()])?;
        hasher.squeeze(cs)
    }

    /// Compute the wallet match nullifier, defined as the poseidon hash:
    ///     H(C(W) || r + 1)
    fn compute_match_nullifier<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        wallet_commit: LinearCombination,
        cs: &mut CS,
    ) -> Result<LinearCombination, R1CSError> {
        let hasher_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hasher_params);

        hasher.batch_absorb(cs, &[wallet_commit, wallet.randomness + Scalar::one()])?;
        hasher.squeeze(cs)
    }

    /// Constrain the keys of two wallets to be equal
    fn constrain_keys_equal<CS: RandomizableConstraintSystem>(
        wallet1: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        wallet2: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        for (key1, key2) in wallet1.keys.iter().zip(wallet2.keys.iter()) {
            cs.constrain(*key1 - *key2);
        }
    }

    /// Validate the balances of the new wallet
    fn validate_wallet_balances<CS: RandomizableConstraintSystem>(
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        internal_transfer: (Variable, Variable),
        external_transfer: (Variable, Variable, Variable),
        cs: &mut CS,
    ) {
        // All balances of the new order should have unique mint or mint zero
        Self::constrain_unique_balance_mints(new_wallet, cs);

        // Constrain the amounts in each balance to either be unchanged, or correspond to
        // a deposit/withdraw
        Self::validate_balance_amounts(
            new_wallet,
            old_wallet,
            internal_transfer,
            external_transfer,
            cs,
        );
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

    /// Validate the amounts in the balances given internal and external transfer information
    fn validate_balance_amounts<CS: RandomizableConstraintSystem>(
        new_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        old_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        internal_transfer: (Variable, Variable),
        external_transfer: (Variable, Variable, Variable),
        cs: &mut CS,
    ) {
        // The external transfer term; negate the amount if the direction is 1 (withdraw)
        // otherwise keep the amount as positive
        let external_transfer_term = CondSelectGadget::select(
            cs,
            external_transfer.1.into(),
            Variable::Zero() - external_transfer.1,
            external_transfer.2.into(),
        );

        for new_balance in new_wallet.balances.iter() {
            let mut expected_amount: LinearCombination = Variable::Zero().into();

            // Match amounts in the old wallet, before transfers
            for old_balance in old_wallet.balances.iter() {
                let mints_eq = EqZeroGadget::eq_zero(cs, new_balance.mint - old_balance.mint);
                let (_, _, masked_amount) = cs.multiply(mints_eq.into(), old_balance.amount.into());
                expected_amount += masked_amount;
            }

            // Add in the external transfer information
            let equals_external_transfer_mint =
                EqZeroGadget::eq_zero(cs, new_balance.mint - external_transfer.0);
            let (_, _, external_transfer_term) = cs.multiply(
                equals_external_transfer_mint.into(),
                external_transfer_term.clone(),
            );

            expected_amount += external_transfer_term;

            // Add in the internal transfer information
            let equals_internal_transfer_mint =
                EqZeroGadget::eq_zero(cs, new_balance.mint - internal_transfer.0);
            let (_, _, internal_transfer_term) = cs.multiply(
                equals_internal_transfer_mint.into(),
                internal_transfer.1.into(),
            );

            expected_amount += internal_transfer_term;

            // Constrain the expected amount to equal the amount in the new wallet
            cs.constrain(new_balance.amount - expected_amount);
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
    }

    /// Constrains all order pairs in the wallet to have unique mints
    fn constrain_unique_order_pairs<CS: RandomizableConstraintSystem>(
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // Validate that all mints pairs are zero or unique
        for i in 0..wallet.orders.len() {
            let order_zero = Self::order_is_zero(&wallet.orders[i], cs);

            for j in i..wallet.orders.len() {
                // Check if the ith order is unique
                let mints_equal = EqVecGadget::eq_vec(
                    &[wallet.orders[i].quote_mint, wallet.orders[i].base_mint],
                    &[wallet.orders[j].quote_mint, wallet.orders[j].base_mint],
                    cs,
                );

                // Constrain the polynomial order_zero * (1 - mints_equal); this is satisfied iff
                // the mints are not equal (the order is unique)
                let (_, _, constraint_poly) = cs.multiply(mints_equal.into(), order_zero.into());
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
            let constraint = OrGate::or(timestamp_updated, equal_and_not_updated, cs);

            cs.constrain(constraint);
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
                price: Variable::Zero(),
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
                order1.quote_mint,
                order1.base_mint,
                order1.side,
                order1.amount,
                order1.price,
            ],
            &[
                order2.quote_mint,
                order2.base_mint,
                order2.side,
                order2.amount,
                order2.price,
            ],
            cs,
        )
    }
}

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
    pub wallet1_opening: Vec<Scalar>,
    /// The indices of the opening, i.e. 0 indicating that the next index in
    /// the opening is a left node, 1 indicating that it's a right hand node
    pub wallet1_opening_indices: Vec<Scalar>,
    /// The internal transfer tuple, a pair of (mint, volume); used to transfer
    /// funds out of a wallet to a settle-able note
    pub internal_transfer: (Scalar, Scalar),
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
    pub wallet1_opening: Vec<Variable>,
    /// The indices of the opening, i.e. 0 indicating that the next index in
    /// the opening is a left node, 1 indicating that it's a right hand node
    pub wallet1_opening_indices: Vec<Variable>,
    /// The internal transfer tuple, a pair of (mint, volume); used to transfer
    /// funds out of a wallet to a settle-able note
    pub internal_transfer: (Variable, Variable),
}

/// A commitment to the witness of VALID WALLET UPDATE
#[derive(Clone, Debug)]
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
    pub wallet1_opening: Vec<CompressedRistretto>,
    /// The indices of the opening, i.e. 0 indicating that the next index in
    /// the opening is a left node, 1 indicating that it's a right hand node
    pub wallet1_opening_indices: Vec<CompressedRistretto>,
    /// The internal transfer tuple, a pair of (mint, volume); used to transfer
    /// funds out of a wallet to a settle-able note
    pub internal_transfer: (CompressedRistretto, CompressedRistretto),
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitProver
    for ValidWalletUpdateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidWalletUpdateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (wallet1_var, wallet1_comm) = self.wallet1.commit_prover(rng, prover).unwrap();
        let (wallet2_var, wallet2_comm) = self.wallet2.commit_prover(rng, prover).unwrap();

        let (opening_comms, opening_vars): (Vec<CompressedRistretto>, Vec<Variable>) = self
            .wallet1_opening
            .iter()
            .map(|opening_elem| prover.commit(*opening_elem, Scalar::random(rng)))
            .unzip();
        let (opening_index_comms, opening_index_vars): (Vec<CompressedRistretto>, Vec<Variable>) =
            self.wallet1_opening_indices
                .iter()
                .map(|opening_index| prover.commit(*opening_index, Scalar::random(rng)))
                .unzip();

        let (internal_transfer_mint_comm, internal_transfer_mint_var) =
            prover.commit(self.internal_transfer.0, Scalar::random(rng));
        let (internal_transfer_volume_comm, internal_transfer_volume_var) =
            prover.commit(self.internal_transfer.1, Scalar::random(rng));

        Ok((
            ValidWalletUpdateWitnessVar {
                wallet1: wallet1_var,
                wallet2: wallet2_var,
                wallet1_opening: opening_vars,
                wallet1_opening_indices: opening_index_vars,
                internal_transfer: (internal_transfer_mint_var, internal_transfer_volume_var),
            },
            ValidWalletUpdateWitnessCommitment {
                wallet1: wallet1_comm,
                wallet2: wallet2_comm,
                wallet1_opening: opening_comms,
                wallet1_opening_indices: opening_index_comms,
                internal_transfer: (internal_transfer_mint_comm, internal_transfer_volume_comm),
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

        let opening_vars = self
            .wallet1_opening
            .iter()
            .map(|opening_elem| verifier.commit(*opening_elem))
            .collect_vec();
        let opening_index_vars = self
            .wallet1_opening_indices
            .iter()
            .map(|opening_index| verifier.commit(*opening_index))
            .collect_vec();

        let internal_transfer_mint = verifier.commit(self.internal_transfer.0);
        let internal_transfer_volume = verifier.commit(self.internal_transfer.1);

        Ok(ValidWalletUpdateWitnessVar {
            wallet1: wallet1_var,
            wallet2: wallet2_var,
            wallet1_opening: opening_vars,
            wallet1_opening_indices: opening_index_vars,
            internal_transfer: (internal_transfer_mint, internal_transfer_volume),
        })
    }
}

/// The statement type for VALID WALLET UPDATE
#[derive(Clone, Debug)]
pub struct ValidWalletUpdateStatement {
    /// The timestamp (user set) of the request, used for order timestamping
    pub timestamp: Scalar,
    /// The root public key of the wallet being updated
    pub pk_root: Scalar,
    /// The commitment to the new wallet
    pub new_wallet_commitment: Scalar,
    /// The wallet spend nullifier of the old wallet
    pub wallet_spend_nullifier: Scalar,
    /// The wallet match nullifier of the old wallet
    pub wallet_match_nullifier: Scalar,
    /// The global state tree root used to prove opening
    pub merkle_root: Scalar,
    /// The external transfer tuple, used to deposit or withdraw funds
    /// of the form (mint, volume, direction)
    pub external_transfer: (Scalar, Scalar, Scalar),
}

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
        let (witness_var, witness_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

        // Commit to the statement
        let timestamp_var = prover.commit_public(statement.timestamp);
        let pk_root_var = prover.commit_public(statement.pk_root);
        let new_wallet_commit_var = prover.commit_public(statement.new_wallet_commitment);
        let match_nullifier_var = prover.commit_public(statement.wallet_match_nullifier);
        let spend_nullifier_var = prover.commit_public(statement.wallet_spend_nullifier);
        let merkle_root_var = prover.commit_public(statement.merkle_root);
        let external_transfer_mint = prover.commit_public(statement.external_transfer.0);
        let external_transfer_volume = prover.commit_public(statement.external_transfer.1);
        let external_transfer_direction = prover.commit_public(statement.external_transfer.2);

        // Apply the constraints
        Self::circuit(
            witness_var,
            timestamp_var,
            pk_root_var,
            merkle_root_var,
            match_nullifier_var,
            spend_nullifier_var,
            new_wallet_commit_var,
            (
                external_transfer_mint,
                external_transfer_volume,
                external_transfer_direction,
            ),
            &mut prover,
        )
        .map_err(ProverError::R1CS)?;

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
        let timestamp_var = verifier.commit_public(statement.timestamp);
        let pk_root_var = verifier.commit_public(statement.pk_root);
        let new_wallet_commit_var = verifier.commit_public(statement.new_wallet_commitment);
        let match_nullifier_var = verifier.commit_public(statement.wallet_match_nullifier);
        let spend_nullifier_var = verifier.commit_public(statement.wallet_spend_nullifier);
        let merkle_root_var = verifier.commit_public(statement.merkle_root);
        let external_transfer_mint = verifier.commit_public(statement.external_transfer.0);
        let external_transfer_volume = verifier.commit_public(statement.external_transfer.1);
        let external_transfer_direction = verifier.commit_public(statement.external_transfer.2);

        // Apply the constraints
        Self::circuit(
            witness_var,
            timestamp_var,
            pk_root_var,
            merkle_root_var,
            match_nullifier_var,
            spend_nullifier_var,
            new_wallet_commit_var,
            (
                external_transfer_mint,
                external_transfer_volume,
                external_transfer_direction,
            ),
            &mut verifier,
        )
        .map_err(VerifierError::R1CS)?;

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
