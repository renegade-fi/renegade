//! Defines the VALID SETTLE circuit which proves that a given note is a valid, unspent
//! state entry; updates a wallet with the note, and proves that the updated wallet has
//! been correctly computed.
//!  
//! Either a node in the network or an individual async user may prove this statement, it
//! is gated by knowledge of sk_settle.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.8
//! for a formal specification

use std::ops::Neg;

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
    types::{
        note::{CommittedNote, Note, NoteType, NoteVar},
        order::OrderVar,
        wallet::{CommittedWallet, Wallet, WalletVar},
    },
    zk_gadgets::{
        commitments::{NoteCommitmentGadget, NullifierGadget, WalletCommitGadget},
        comparators::{EqGadget, EqVecGadget, EqZeroGadget, NotEqualGadget},
        elgamal::{ElGamalCiphertext, ElGamalCiphertextVar},
        gates::OrGate,
        merkle::PoseidonMerkleHashGadget,
        select::CondSelectGadget,
    },
    CommitProver, CommitVerifier, SingleProverCircuit,
};

/// Represents the circuit definition of VALID SETTLE
#[derive(Clone, Debug)]
pub struct ValidSettle<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized, {}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    [(); 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5]: Sized,
{
    /// Implements the circuitry for VALID SETTLE
    #[allow(unused)]
    pub fn circuit<CS: RandomizableConstraintSystem>(
        witness: ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        statement: ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Validate all state entries and state primitives that are constructed from the witness
        Self::validate_state_primitives(&witness, &statement, cs)?;

        // Validate that all the keys have remained the same
        cs.constrain(witness.pre_wallet.keys.pk_root - witness.post_wallet.keys.pk_root);
        cs.constrain(witness.pre_wallet.keys.pk_match - witness.post_wallet.keys.pk_match);
        cs.constrain(witness.pre_wallet.keys.pk_settle - witness.post_wallet.keys.pk_settle);
        cs.constrain(witness.pre_wallet.keys.pk_view - witness.post_wallet.keys.pk_view);

        // Validate that the randomness has been properly updated in the new wallet
        cs.constrain(
            witness.pre_wallet.randomness + Scalar::from(2u64) * Variable::One()
                - witness.post_wallet.randomness,
        );

        // Validate that the note type reported in the public variables is the same type as the note
        // in the witness
        cs.constrain(statement.type_ - witness.note.type_);

        Self::validate_new_balances(&witness, cs);
        Self::validate_order_updates(&witness, cs);
        Ok(())
    }

    /// Validates the state primitives for the contract are correctly constructed
    /// This means nullifiers, merkle openings, commitments, etc
    fn validate_state_primitives<CS: RandomizableConstraintSystem>(
        witness: &ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        statement: &ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Compute the commitment to the pre-wallet
        let pre_wallet_commit_res = WalletCommitGadget::wallet_commit(&witness.pre_wallet, cs)?;

        // Validate that this wallet commitment is a leaf in the state tree
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            pre_wallet_commit_res.clone(),
            witness.pre_wallet_opening.clone(),
            witness.pre_wallet_opening_indices.clone(),
            statement.merkle_root.into(),
            cs,
        )?;

        // Compute the commitment to the note
        let note_commitment_res = NoteCommitmentGadget::note_commit(&witness.note, cs)?;

        // Validate that this note commitment is a leaf in the state tree
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            note_commitment_res.clone(),
            witness.note_opening.clone(),
            witness.note_opening_indices.clone(),
            statement.merkle_root.into(),
            cs,
        )?;

        // Compute the commitment to the new wallet and verify that it is the same given in the statement
        let post_wallet_commit_res = WalletCommitGadget::wallet_commit(&witness.post_wallet, cs)?;
        cs.constrain(statement.post_wallet_commit - post_wallet_commit_res);

        // Validate that all three nullifiers (wallet spend, wallet match, note redeem) are correctly computed from witness
        let pre_wallet_spend_nullifier = NullifierGadget::spend_nullifier(
            witness.pre_wallet.randomness,
            pre_wallet_commit_res.clone(),
            cs,
        )?;
        cs.constrain(statement.wallet_spend_nullifier - pre_wallet_spend_nullifier);

        let pre_wallet_match_nullifier = NullifierGadget::match_nullifier(
            witness.pre_wallet.randomness,
            pre_wallet_commit_res,
            cs,
        )?;
        cs.constrain(statement.wallet_match_nullifier - pre_wallet_match_nullifier);

        let note_redeem_nullifier_res = NullifierGadget::note_redeem_nullifier(
            witness.pre_wallet.keys.pk_settle,
            note_commitment_res,
            cs,
        )?;
        cs.constrain(statement.note_redeem_nullifier - note_redeem_nullifier_res);

        Ok(())
    }

    /// Validates the balances of the new wallet given the old wallet and the note
    fn validate_new_balances<CS: RandomizableConstraintSystem>(
        witness: &ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // Validate that the mint of each balance is zero or unique
        Self::validate_balance_mints_unique(witness, cs);
        // Validate that the updates to the balances are correctly computed from the note
        Self::validate_balance_updates(witness, cs);
    }

    /// Validates that a given list of mints is unique except for zero; which may be
    /// repeated arbitrarily many times
    fn validate_balance_mints_unique<CS: RandomizableConstraintSystem>(
        witness: &ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        let n_balances = witness.post_wallet.balances.len();
        for i in 0..n_balances {
            let balance_mint_i = witness.post_wallet.balances[i].mint;
            let balance_mint_i_eq_zero = EqZeroGadget::eq_zero(balance_mint_i, cs);

            for j in (i + 1)..n_balances {
                // Assert that either mint_i != mint_j or mint_i == 0
                let balance_mint_j = witness.post_wallet.balances[j].mint;
                let ne = NotEqualGadget::not_equal(balance_mint_i, balance_mint_j, cs);
                let ne_or_mint_zero = OrGate::or(ne, balance_mint_i_eq_zero.into(), cs);

                cs.constrain(Variable::One() - ne_or_mint_zero);
            }
        }
    }

    /// Validates that the note is properly applied to the balances of the old wallet to
    /// give the new wallet balances
    fn validate_balance_updates<CS: RandomizableConstraintSystem>(
        witness: &ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // Select positive or negative depending on the direction of each value in the note
        let scalar_neg_one = Scalar::one().neg();
        let note_term1 = CondSelectGadget::select(
            scalar_neg_one * witness.note.volume1,
            witness.note.volume1.into(),
            witness.note.direction1.into(),
            cs,
        );

        let note_term2 = CondSelectGadget::select(
            scalar_neg_one * witness.note.volume2,
            witness.note.volume2.into(),
            witness.note.direction2.into(),
            cs,
        );

        let note_term3 = CondSelectGadget::select(
            scalar_neg_one * witness.note.fee_volume,
            witness.note.fee_volume.into(),
            witness.note.fee_direction.into(),
            cs,
        );

        // Loop over the balances in the new wallet and insure they're properly computed
        for new_balance in witness.post_wallet.balances.iter() {
            let mut expected_bal: LinearCombination = Variable::Zero().into();
            // Add any balances that existed before the note update
            for old_balance in witness.pre_wallet.balances.iter() {
                let mints_equal = EqGadget::eq(old_balance.mint, new_balance.mint, cs);
                let (_, _, equal_mints_term) =
                    cs.multiply(mints_equal.into(), old_balance.amount.into());

                expected_bal += equal_mints_term;
            }

            // Add in the terms from the note
            let mints_equal_note_term1 = EqGadget::eq(new_balance.mint, witness.note.mint1, cs);
            let (_, _, note_term1_masked) =
                cs.multiply(mints_equal_note_term1.into(), note_term1.clone());
            expected_bal += note_term1_masked;

            let mints_equal_note_term2 = EqGadget::eq(new_balance.mint, witness.note.mint2, cs);
            let (_, _, note_term2_masked) =
                cs.multiply(mints_equal_note_term2.into(), note_term2.clone());
            expected_bal += note_term2_masked;

            let mints_equal_note_term3 = EqGadget::eq(new_balance.mint, witness.note.fee_mint, cs);
            let (_, _, note_term3_masked) =
                cs.multiply(mints_equal_note_term3.into(), note_term3.clone());
            expected_bal += note_term3_masked;

            // Constrain the expected balance and the updated balance to be equal
            cs.constrain(new_balance.amount - expected_bal);
        }
    }

    /// Validates the updates to the wallet orders after the note has been applied
    ///
    /// Each order should either be equal to its previous order
    pub fn validate_order_updates<CS: RandomizableConstraintSystem>(
        witness: &ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // The subtracted term for the note; if this note was generated by an internal
        // transfer, the note term is zero; i.e. we don't update any orders
        let note_term = CondSelectGadget::select(
            witness.note.volume1,
            Variable::Zero(),
            witness.note.type_,
            cs,
        );

        for (old_order, new_order) in witness
            .pre_wallet
            .orders
            .iter()
            .zip(witness.post_wallet.orders.iter())
        {
            // Validate that the orders are equal up to their amount
            Self::validate_orders_equal_except_amount(old_order, new_order, cs);

            // Mask and apply the note term, validate that the resulting balance is as expected
            let mut expected_result: LinearCombination = old_order.amount.into();
            let mint_pair_equal = EqVecGadget::eq_vec(
                &[witness.note.mint1, witness.note.mint2],
                &[old_order.base_mint, old_order.quote_mint],
                cs,
            );

            let (_, _, masked_note_term) = cs.multiply(mint_pair_equal.into(), note_term.clone());
            expected_result -= masked_note_term;

            cs.constrain(expected_result - new_order.amount)
        }
    }

    /// Validate that two orders are equal
    pub fn validate_orders_equal_except_amount<CS: RandomizableConstraintSystem>(
        o1: &OrderVar,
        o2: &OrderVar,
        cs: &mut CS,
    ) {
        EqVecGadget::constrain_eq_vec(
            &[
                o1.base_mint.into(),
                o1.quote_mint.into(),
                o1.side.into(),
                o1.price.repr.clone(),
                o1.timestamp.into(),
            ],
            &[
                o2.base_mint.into(),
                o2.quote_mint.into(),
                o2.side.into(),
                o2.price.repr.clone(),
                o2.timestamp.into(),
            ],
            cs,
        );
    }
}

/// The witness type for the VALID SETTLE circuit
#[derive(Clone, Debug)]
pub struct ValidSettleWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The wallet before the note is applied to it
    pub pre_wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The opening of the original wallet to the state root
    pub pre_wallet_opening: Vec<Scalar>,
    /// The opening indices of the original wallet to the state root
    pub pre_wallet_opening_indices: Vec<Scalar>,
    /// The wallet after the note is applied to it
    pub post_wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The note applied to the pre-wallet
    pub note: Note,
    /// The note commitment, should be entered into the state tree as a leaf
    pub note_commitment: Scalar,
    /// The opening from the note commitment to the state root
    pub note_opening: Vec<Scalar>,
    /// The indices of the merkle inclusion proof
    pub note_opening_indices: Vec<Scalar>,
}

/// The witness type for VALID SETTLE, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidSettleWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The wallet before the note is applied to it
    pub pre_wallet: WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The opening of the original wallet to the state root
    pub pre_wallet_opening: Vec<Variable>,
    /// The opening indices of the original wallet to the state root
    pub pre_wallet_opening_indices: Vec<Variable>,
    /// The wallet after the note is applied to it
    pub post_wallet: WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The note applied to the pre-wallet
    pub note: NoteVar,
    /// The note commitment, should be entered into the state tree as a leaf
    pub note_commitment: Variable,
    /// The opening from the note commitment to the state root
    pub note_opening: Vec<Variable>,
    /// The indices of the merkle inclusion proof
    pub note_opening_indices: Vec<Variable>,
}

/// A commitment to the witness type for VALID SETTLE
#[derive(Clone, Debug)]
pub struct ValidSettleWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The wallet before the note is applied to it
    pub pre_wallet: CommittedWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The opening of the original wallet to the state root
    pub pre_wallet_opening: Vec<CompressedRistretto>,
    /// The opening indices of the original wallet to the state root
    pub pre_wallet_opening_indices: Vec<CompressedRistretto>,
    /// The wallet after the note is applied to it
    pub post_wallet: CommittedWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The note applied to the pre-wallet
    pub note: CommittedNote,
    /// The note commitment, should be entered into the state tree as a leaf
    pub note_commitment: CompressedRistretto,
    /// The opening from the note commitment to the state root
    pub note_opening: Vec<CompressedRistretto>,
    /// The indices of the merkle inclusion proof
    pub note_opening_indices: Vec<CompressedRistretto>,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitProver
    for ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        // Commit to the wallets
        let (pre_wallet_var, pre_wallet_comm) = self.pre_wallet.commit_prover(rng, prover).unwrap();
        let (pre_wallet_opening_comms, pre_wallet_opening_vars): (
            Vec<CompressedRistretto>,
            Vec<Variable>,
        ) = self
            .pre_wallet_opening
            .iter()
            .map(|opening| prover.commit(*opening, Scalar::random(rng)))
            .unzip();
        let (pre_wallet_index_comms, pre_wallet_index_vars): (
            Vec<CompressedRistretto>,
            Vec<Variable>,
        ) = self
            .pre_wallet_opening_indices
            .iter()
            .map(|index| prover.commit(*index, Scalar::random(rng)))
            .unzip();

        let (post_wallet_var, post_wallet_comm) =
            self.post_wallet.commit_prover(rng, prover).unwrap();

        // Commit to the note and its opening
        let (note_var, note_comm) = self.note.commit_prover(rng, prover).unwrap();
        let (note_commitment_comm, note_commitment_var) =
            prover.commit(self.note_commitment, Scalar::random(rng));
        let (note_opening_comms, note_opening_vars): (Vec<CompressedRistretto>, Vec<Variable>) =
            self.note_opening
                .iter()
                .map(|opening_elem| prover.commit(*opening_elem, Scalar::random(rng)))
                .unzip();
        let (note_indices_comms, note_indices_vars): (Vec<CompressedRistretto>, Vec<Variable>) =
            self.note_opening_indices
                .iter()
                .map(|index| prover.commit(*index, Scalar::random(rng)))
                .unzip();

        Ok((
            ValidSettleWitnessVar {
                pre_wallet: pre_wallet_var,
                pre_wallet_opening: pre_wallet_opening_vars,
                pre_wallet_opening_indices: pre_wallet_index_vars,
                post_wallet: post_wallet_var,
                note: note_var,
                note_commitment: note_commitment_var,
                note_opening: note_opening_vars,
                note_opening_indices: note_indices_vars,
            },
            ValidSettleWitnessCommitment {
                pre_wallet: pre_wallet_comm,
                pre_wallet_opening: pre_wallet_opening_comms,
                pre_wallet_opening_indices: pre_wallet_index_comms,
                post_wallet: post_wallet_comm,
                note: note_comm,
                note_commitment: note_commitment_comm,
                note_opening: note_opening_comms,
                note_opening_indices: note_indices_comms,
            },
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let pre_wallet_var = self.pre_wallet.commit_verifier(verifier).unwrap();
        let pre_wallet_opening_vars = self
            .pre_wallet_opening
            .iter()
            .map(|opening| verifier.commit(*opening))
            .collect_vec();
        let pre_wallet_index_vars = self
            .pre_wallet_opening_indices
            .iter()
            .map(|index| verifier.commit(*index))
            .collect_vec();

        let post_wallet_var = self.post_wallet.commit_verifier(verifier).unwrap();
        let note_var = self.note.commit_verifier(verifier).unwrap();
        let note_commitment_var = verifier.commit(self.note_commitment);
        let note_opening_vars = self
            .note_opening
            .iter()
            .map(|opening| verifier.commit(*opening))
            .collect_vec();
        let note_indices_vars = self
            .note_opening_indices
            .iter()
            .map(|index| verifier.commit(*index))
            .collect_vec();

        Ok(ValidSettleWitnessVar {
            pre_wallet: pre_wallet_var,
            pre_wallet_opening: pre_wallet_opening_vars,
            pre_wallet_opening_indices: pre_wallet_index_vars,
            post_wallet: post_wallet_var,
            note: note_var,
            note_commitment: note_commitment_var,
            note_opening: note_opening_vars,
            note_opening_indices: note_indices_vars,
        })
    }
}

/// The statement type for VALID SETTLE
#[derive(Clone, Debug)]
pub struct ValidSettleStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    [(); 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5]: Sized,
{
    /// The commitment to the updated wallet
    pub post_wallet_commit: Scalar,
    /// The encryption of the updated wallet
    pub post_wallet_ciphertext:
        [ElGamalCiphertext; 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5],
    /// The wallet spend nullifier of the pre-wallet
    pub wallet_spend_nullifier: Scalar,
    /// The wallet match nullifier of the pre-wallet
    pub wallet_match_nullifier: Scalar,
    /// The note-redeem nullifier of the spent note
    pub note_redeem_nullifier: Scalar,
    /// The global Merkle root used in the opening proof
    pub merkle_root: Scalar,
    /// The type of the note being redeemed; internal transfer or match
    pub type_: NoteType,
}

/// The statement type for VALID SETTLE
#[derive(Clone, Debug)]
pub struct ValidSettleStatementVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    [(); 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5]: Sized,
{
    /// The commitment to the updated wallet
    pub post_wallet_commit: Variable,
    /// The encryption of the updated wallet
    pub post_wallet_ciphertext:
        [ElGamalCiphertextVar; 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5],
    /// The wallet spend nullifier of the pre-wallet
    pub wallet_spend_nullifier: Variable,
    /// The wallet match nullifier of the pre-wallet
    pub wallet_match_nullifier: Variable,
    /// The note-redeem nullifier of the spent note
    pub note_redeem_nullifier: Variable,
    /// The global Merkle root used in the opening proof
    pub merkle_root: Variable,
    /// The type of the note being redeemed; internal transfer or match
    pub type_: Variable,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitProver
    for ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    [(); 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5]: Sized,
{
    type VarType = ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ();
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        _: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let post_wallet_commit_var = prover.commit_public(self.post_wallet_commit);
        let post_wallet_ciphertext_vars = self
            .post_wallet_ciphertext
            .iter()
            .map(|ciphertext| ciphertext.commit_public(prover))
            .collect_vec();
        let wallet_spend_nullifier_var = prover.commit_public(self.wallet_spend_nullifier);
        let wallet_match_nullifier_var = prover.commit_public(self.wallet_match_nullifier);
        let note_redeem_nullifier_var = prover.commit_public(self.note_redeem_nullifier);
        let merkle_root_var = prover.commit_public(self.merkle_root);
        let type_var = prover.commit_public(match self.type_ {
            NoteType::InternalTransfer => Scalar::zero(),
            NoteType::Match => Scalar::one(),
        });

        Ok((
            ValidSettleStatementVar {
                post_wallet_commit: post_wallet_commit_var,
                post_wallet_ciphertext: post_wallet_ciphertext_vars.try_into().unwrap(),
                wallet_spend_nullifier: wallet_spend_nullifier_var,
                wallet_match_nullifier: wallet_match_nullifier_var,
                note_redeem_nullifier: note_redeem_nullifier_var,
                merkle_root: merkle_root_var,
                type_: type_var,
            },
            (),
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    [(); 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5]: Sized,
{
    type VarType = ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let post_wallet_commit_var = verifier.commit_public(self.post_wallet_commit);
        let post_wallet_ciphertext_vars = self
            .post_wallet_ciphertext
            .iter()
            .map(|ciphertext| ciphertext.commit_public(verifier))
            .collect_vec();
        let wallet_spend_nullifier_var = verifier.commit_public(self.wallet_spend_nullifier);
        let wallet_match_nullifier_var = verifier.commit_public(self.wallet_match_nullifier);
        let note_redeem_nullifier_var = verifier.commit_public(self.note_redeem_nullifier);
        let merkle_root_var = verifier.commit_public(self.merkle_root);
        let type_var = verifier.commit_public(match self.type_ {
            NoteType::InternalTransfer => Scalar::zero(),
            NoteType::Match => Scalar::one(),
        });

        Ok(ValidSettleStatementVar {
            post_wallet_commit: post_wallet_commit_var,
            post_wallet_ciphertext: post_wallet_ciphertext_vars.try_into().unwrap(),
            wallet_spend_nullifier: wallet_spend_nullifier_var,
            wallet_match_nullifier: wallet_match_nullifier_var,
            note_redeem_nullifier: note_redeem_nullifier_var,
            merkle_root: merkle_root_var,
            type_: type_var,
        })
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    [(); 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5]: Sized,
{
    type Witness = ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 32768;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness and statement
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

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
        // Commit to the witness and statement
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();
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

#[cfg(test)]
mod valid_settle_tests {
    use crypto::fields::{prime_field_to_scalar, scalar_to_prime_field};
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use merlin::Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use rand_core::OsRng;

    use crate::{
        test_helpers::bulletproof_prove_and_verify,
        types::{
            note::{Note, NoteType},
            order::OrderSide,
        },
        zk_circuits::test_helpers::{
            compute_note_commitment, compute_note_redeem_nullifier, compute_wallet_commitment,
            compute_wallet_match_nullifier, compute_wallet_spend_nullifier, create_multi_opening,
            SizedWallet, INITIAL_WALLET, MAX_BALANCES, MAX_FEES, MAX_ORDERS,
        },
        zk_gadgets::elgamal::ElGamalCiphertext,
        CommitProver,
    };

    use super::{ValidSettle, ValidSettleStatement, ValidSettleWitness};

    const MERKLE_HEIGHT: usize = 3;
    const TOTAL_ENCRYPTIONS: usize = 2 * MAX_BALANCES + 8 * MAX_ORDERS + 4 * MAX_FEES + 5;

    // --------------
    // | Dummy Data |
    // --------------
    lazy_static! {
        /// A dummy note resulting from a match of quote mint 1, base mint 2
        /// in which the local party sold the quote to buy the base
        ///
        /// Fees for the match were paid in token 2
        static ref DUMMY_MATCH_NOTE: Note = Note {
            mint1: 2,
            volume1: 1,
            direction1: OrderSide::Buy,
            mint2: 1,
            volume2: 4,
            direction2: OrderSide::Sell,
            fee_mint: 2,
            fee_volume: 3,
            fee_direction: OrderSide::Sell,
            type_: NoteType::Match,
            randomness: 1729,
        };
    }

    // -----------
    // | Helpers |
    // -----------

    /// Applies a note to the given wallet and returns the wallet that results
    fn apply_note_to_wallet(note: &Note, wallet: &SizedWallet) -> SizedWallet {
        let mut result_wallet = wallet.clone();
        result_wallet.randomness += Scalar::from(2u8);

        // Update the balances according to the note
        for balance in result_wallet.balances.iter_mut() {
            if balance.mint == 0 {
                continue;
            }
            if balance.mint == note.mint1 {
                balance.amount =
                    update_balance_by_order_side(balance.amount, note.volume1, note.direction1);
            }
            if balance.mint == note.mint2 {
                balance.amount =
                    update_balance_by_order_side(balance.amount, note.volume2, note.direction2);
            }
            if balance.mint == note.fee_mint {
                balance.amount = update_balance_by_order_side(
                    balance.amount,
                    note.fee_volume,
                    note.fee_direction,
                );
            }
        }

        // Update the orders according to the note
        if note.type_ == NoteType::Match {
            for order in result_wallet.orders.iter_mut() {
                if order.base_mint == note.mint1 && order.quote_mint == note.mint2 {
                    order.amount -= note.volume1;
                }
            }
        }

        result_wallet
    }

    /// Helper to mux between buy and sell side note updates
    ///
    /// Returns the new balance after the update
    fn update_balance_by_order_side(
        initial_balance: u64,
        note_volume: u64,
        transfer_side: OrderSide,
    ) -> u64 {
        match transfer_side {
            OrderSide::Buy => initial_balance + note_volume,
            OrderSide::Sell => initial_balance - note_volume,
        }
    }

    /// Compute a witness and statement from a given wallet, note, and updated wallet
    fn compute_witness_and_statement(
        pre_wallet: SizedWallet,
        post_wallet: SizedWallet,
        note: Note,
    ) -> (
        ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) {
        let mut rng = OsRng {};

        let pre_wallet_commit = compute_wallet_commitment(&pre_wallet);
        let post_wallet_commit = compute_wallet_commitment(&post_wallet);
        let note_commit = compute_note_commitment(&note);

        let wallet_spend_nullifier = compute_wallet_spend_nullifier(&pre_wallet, pre_wallet_commit);
        let wallet_match_nullifier = compute_wallet_match_nullifier(&pre_wallet, pre_wallet_commit);
        let note_redeem_nullifier = compute_note_redeem_nullifier(
            note_commit,
            scalar_to_prime_field(&pre_wallet.keys.pk_settle),
        );

        let (merkle_root, openings, openings_indices) = create_multi_opening(
            &[
                prime_field_to_scalar(&pre_wallet_commit),
                prime_field_to_scalar(&note_commit),
            ],
            MERKLE_HEIGHT,
            &mut rng,
        );

        let elgamal_ciphertexts = (0..TOTAL_ENCRYPTIONS)
            .map(|_| ElGamalCiphertext {
                partial_shared_secret: Scalar::random(&mut rng),
                encrypted_message: Scalar::random(&mut rng),
            })
            .collect_vec();

        (
            ValidSettleWitness {
                pre_wallet,
                pre_wallet_opening: openings[0].to_owned(),
                pre_wallet_opening_indices: openings_indices[0].to_owned(),
                post_wallet,
                note: note.clone(),
                note_commitment: prime_field_to_scalar(&note_commit),
                note_opening: openings[1].to_owned(),
                note_opening_indices: openings_indices[1].to_owned(),
            },
            ValidSettleStatement {
                post_wallet_commit: prime_field_to_scalar(&post_wallet_commit),
                post_wallet_ciphertext: elgamal_ciphertexts.try_into().unwrap(),
                wallet_match_nullifier: prime_field_to_scalar(&wallet_match_nullifier),
                wallet_spend_nullifier: prime_field_to_scalar(&wallet_spend_nullifier),
                note_redeem_nullifier: prime_field_to_scalar(&note_redeem_nullifier),
                merkle_root,
                type_: note.type_,
            },
        )
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests the case in which a valid witness is given
    #[test]
    fn test_valid_settle() {
        let initial_wallet = INITIAL_WALLET.clone();
        let note = DUMMY_MATCH_NOTE.clone();
        let post_wallet = apply_note_to_wallet(&note, &initial_wallet);

        let (witness, statement) = compute_witness_and_statement(initial_wallet, post_wallet, note);
        let res = bulletproof_prove_and_verify::<ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>(
            witness, statement,
        );
        assert!(res.is_ok())
    }

    /// Tests the case that a note is settled from an internal transfer
    #[test]
    fn test_valid_internal_transfer_settle() {
        let mut rng = OsRng {};

        let initial_wallet = INITIAL_WALLET.clone();
        let mut note = DUMMY_MATCH_NOTE.clone();

        // Modify the note to be a transfer note
        note.mint2 = 0;
        note.volume2 = 0;
        note.direction2 = OrderSide::Buy;
        note.fee_mint = 0;
        note.fee_volume = 0;
        note.fee_direction = OrderSide::Buy;

        // Compute the wallet after transfer
        let mut post_wallet = apply_note_to_wallet(&note, &initial_wallet);

        // Modify the post wallet to have no order updates
        post_wallet.orders = initial_wallet.orders.clone();

        let (witness, statement) = compute_witness_and_statement(initial_wallet, post_wallet, note);

        // Build a prover
        let mut transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let (witness_var, _) = witness.commit_prover(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

        // Apply the constraints and verify that they are not satisfied
        ValidSettle::circuit(witness_var, statement_var, &mut prover).unwrap();
        assert!(prover.constraints_satisfied());
    }

    /// Tests the case in which a balance is spuriously added
    #[test]
    fn test_invalid_unexpected_mint() {
        let mut rng = OsRng {};

        let initial_wallet = INITIAL_WALLET.clone();
        let note = DUMMY_MATCH_NOTE.clone();
        let mut post_wallet = apply_note_to_wallet(&note, &initial_wallet);
        post_wallet.balances[0].mint = 42;

        let (witness, statement) = compute_witness_and_statement(initial_wallet, post_wallet, note);

        // Build a prover
        let mut transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let (witness_var, _) = witness.commit_prover(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

        // Apply the constraints and verify that they are not satisfied
        ValidSettle::circuit(witness_var, statement_var, &mut prover).unwrap();
        assert!(!prover.constraints_satisfied());
    }

    /// Tests the case in which a balance is not properly updated
    #[test]
    fn test_invalid_balance_update_buy_too_much() {
        let mut rng = OsRng {};

        let initial_wallet = INITIAL_WALLET.clone();
        let note = DUMMY_MATCH_NOTE.clone();
        let mut post_wallet = apply_note_to_wallet(&note, &initial_wallet);

        // Prover attempts to increase their balance of the base mint by more than the note allocated
        post_wallet.balances[1].amount += 2;

        let (witness, statement) = compute_witness_and_statement(initial_wallet, post_wallet, note);

        // Build a prover
        let mut transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let (witness_var, _) = witness.commit_prover(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

        // Apply the constraints and verify that they are not satisfied
        ValidSettle::circuit(witness_var, statement_var, &mut prover).unwrap();
        assert!(!prover.constraints_satisfied());
    }

    /// Tests the case in which the prover tries to sell less of the quote token than
    /// the note allocates
    #[test]
    fn test_invalid_balance_update_sell_too_little() {
        let mut rng = OsRng {};

        let initial_wallet = INITIAL_WALLET.clone();
        let note = DUMMY_MATCH_NOTE.clone();
        let mut post_wallet = apply_note_to_wallet(&note, &initial_wallet);

        // Prover attempts to increase their balance of the base mint by more than the note allocated
        post_wallet.balances[0].amount += 1;

        let (witness, statement) = compute_witness_and_statement(initial_wallet, post_wallet, note);

        // Build a prover
        let mut transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let (witness_var, _) = witness.commit_prover(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

        // Apply the constraints and verify that they are not satisfied
        ValidSettle::circuit(witness_var, statement_var, &mut prover).unwrap();
        assert!(!prover.constraints_satisfied());
    }

    /// Tests the case in which the prover attempts to not pay the full fee
    #[test]
    fn test_invalid_balance_update_no_fees() {
        let mut rng = OsRng {};

        let initial_wallet = INITIAL_WALLET.clone();
        let mut note = DUMMY_MATCH_NOTE.clone();
        let post_wallet = apply_note_to_wallet(&note, &initial_wallet);

        // Prover attempts to increase their balance of the base mint by more than the note allocated
        note.fee_volume += 1;

        let (witness, statement) = compute_witness_and_statement(initial_wallet, post_wallet, note);

        // Build a prover
        let mut transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let (witness_var, _) = witness.commit_prover(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

        // Apply the constraints and verify that they are not satisfied
        ValidSettle::circuit(witness_var, statement_var, &mut prover).unwrap();
        assert!(!prover.constraints_satisfied());
    }

    /// Tests the case in which the prover does not properly update the order that was
    /// matched into the note
    #[test]
    fn test_invalid_order_update_no_update() {
        let mut rng = OsRng {};

        let initial_wallet = INITIAL_WALLET.clone();
        let note = DUMMY_MATCH_NOTE.clone();
        let mut post_wallet = apply_note_to_wallet(&note, &initial_wallet);

        // Invalid, the prover attempts to not update the order that matched
        post_wallet.orders = initial_wallet.orders.clone();

        let (witness, statement) = compute_witness_and_statement(initial_wallet, post_wallet, note);

        // Build a prover
        let mut transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let (witness_var, _) = witness.commit_prover(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

        // Apply the constraints and verify that they are not satisfied
        ValidSettle::circuit(witness_var, statement_var, &mut prover).unwrap();
        assert!(!prover.constraints_satisfied());
    }

    /// Tests various cases in which the orders list is otherwise modified, other than
    /// the order volume, this should not be the case in a VALID SETTLE proof
    #[test]
    fn test_invalid_order_malleability() {
        let mut rng = OsRng {};

        let initial_wallet = INITIAL_WALLET.clone();
        let note = DUMMY_MATCH_NOTE.clone();
        let post_wallet = apply_note_to_wallet(&note, &initial_wallet);

        let mut bad_post_wallets = Vec::new();

        // Try changing the base mint
        let mut bad_post_wallet1 = post_wallet.clone();
        bad_post_wallet1.orders[1].base_mint += 1;
        bad_post_wallets.push(bad_post_wallet1);

        // Try changing the quote mint
        let mut bad_post_wallet2 = post_wallet.clone();
        bad_post_wallet2.orders[1].quote_mint += 1;
        bad_post_wallets.push(bad_post_wallet2);

        // Try changing the direction
        let mut bad_post_wallet3 = post_wallet.clone();
        bad_post_wallet3.orders[1].side = OrderSide::Buy;
        bad_post_wallets.push(bad_post_wallet3);

        // Try changing the price
        let mut bad_post_wallet4 = post_wallet.clone();
        bad_post_wallet4.orders[1].price = bad_post_wallet4.orders[1].price + Scalar::one();
        bad_post_wallets.push(bad_post_wallet4);

        // Try changing the timestamp
        let mut bad_post_wallet5 = post_wallet;
        bad_post_wallet5.orders[1].timestamp += 1;
        bad_post_wallets.push(bad_post_wallet5);

        for post_wallet in bad_post_wallets.into_iter() {
            let (witness, statement) =
                compute_witness_and_statement(initial_wallet.clone(), post_wallet, note.clone());

            // Build a prover
            let mut transcript = Transcript::new("test".as_bytes());
            let pc_gens = PedersenGens::default();
            let mut prover = Prover::new(&pc_gens, &mut transcript);

            let (witness_var, _) = witness.commit_prover(&mut rng, &mut prover).unwrap();
            let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

            // Apply the constraints and verify that they are not satisfied
            ValidSettle::circuit(witness_var, statement_var, &mut prover).unwrap();
            assert!(!prover.constraints_satisfied());
        }
    }
}
