//! Defines the VALID SETTLE circuit which proves that a given note is a valid, unspent
//! state entry; updates a wallet with the note, and proves that the updated wallet has
//! been correctly computed.
//!  
//! Either a node in the network or an individual async user may prove this statement, it
//! is gated by knowledge of sk_settle.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.8
//! for a formal specification

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{ConstraintSystem, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        note::{CommittedNote, Note, NoteType, NoteVar},
        wallet::{CommittedWallet, Wallet, WalletVar},
    },
    zk_gadgets::{
        commitments::{NoteCommitmentGadget, NullifierGadget, WalletCommitGadget},
        elgamal::{ElGamalCiphertext, ElGamalCiphertextVar},
        merkle::PoseidonMerkleHashGadget,
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
        cs.constrain(witness.pre_wallet.keys[0] - witness.post_wallet.keys[0]);
        cs.constrain(witness.pre_wallet.keys[1] - witness.post_wallet.keys[1]);
        cs.constrain(witness.pre_wallet.keys[2] - witness.post_wallet.keys[2]);
        cs.constrain(witness.pre_wallet.keys[3] - witness.post_wallet.keys[3]);

        // Validate that the randomness has been properly updated in the new wallet
        cs.constrain(
            witness.pre_wallet.randomness + Scalar::from(2u64) * Variable::One()
                - witness.post_wallet.randomness,
        );

        // TODO: Balance verification and authentication
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
            witness.pre_wallet.keys[2],
            note_commitment_res,
            cs,
        )?;
        cs.constrain(statement.note_redeem_nullifier - note_redeem_nullifier_res);

        Ok(())
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

    const BP_GENS_CAPACITY: usize = 1024;

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
