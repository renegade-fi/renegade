//! Defines the VALID MATCH ENCRYPTION circuit which proves that a completed
//! match has been encrypted properly for both parties to settle it
//!  
//! A node in the relayer network proves this statement after successfully completing
//! a match. This proof is essentially one of data availability, ensuring that a
//! user can decrypt and settle a match even if the relayers that manage her
//! wallet act maliciously.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.7
//! for a formal specification

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{ConstraintSystem, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        note::{CommittedNote, Note, NoteVar},
        r#match::{CommittedMatchResult, MatchResult, MatchResultVar},
    },
    CommitProver, CommitVerifier, SingleProverCircuit,
};

/// Represents the circuit definition of VALID MATCH ENCRYPTION
#[derive(Clone, Debug)]
pub struct ValidMatchEncryption {}
impl ValidMatchEncryption {
    /// Implements the circuitry for the VALID MATCH ENCRYPTION circuit
    #[allow(unused)]
    pub fn circuit<CS: RandomizableConstraintSystem>(
        witness: ValidMatchEncryptionWitnessVar,
        statement: ValidMatchEncryptionStatementVar,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        Ok(())
    }
}

/// The witness type for the VALID MATCH ENCRYPTION circuit
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionWitness {
    /// The result of the match process; a completed match
    pub match_res: MatchResult,
    /// The note of exchange for the first party
    pub party0_note: Note,
    /// The note of exchange for the second party
    pub party1_note: Note,
    /// The transfer note for the first relayer's fee
    pub relayer0_note: Note,
    /// The transfer note for the second relayer's fee
    pub relayer1_note: Note,
    /// The transfer note for the protocol fee
    pub protocol_note: Note,
}

/// A witness for VALID MATCH ENCRYPTION that has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionWitnessVar {
    /// The result of the match process; a completed match
    pub match_res: MatchResultVar,
    /// The note of exchange for the first party
    pub party0_note: NoteVar,
    /// The note of exchange for the second party
    pub party1_note: NoteVar,
    /// The transfer note for the first relayer's fee
    pub relayer0_note: NoteVar,
    /// The transfer note for the second relayer's fee
    pub relayer1_note: NoteVar,
    /// The transfer note for the protocol fee
    pub protocol_note: NoteVar,
}

/// A commitment to the witness type for the VALID MATCH ENCRYPTION circuit
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionWitnessCommitment {
    /// The result of the match process; a completed match
    pub match_res: CommittedMatchResult,
    /// The note of exchange for the first party
    pub party0_note: CommittedNote,
    /// The note of exchange for the second party
    pub party1_note: CommittedNote,
    /// The transfer note for the first relayer's fee
    pub relayer0_note: CommittedNote,
    /// The transfer note for the second relayer's fee
    pub relayer1_note: CommittedNote,
    /// The transfer note for the protocol fee
    pub protocol_note: CommittedNote,
}

impl CommitProver for ValidMatchEncryptionWitness {
    type VarType = ValidMatchEncryptionWitnessVar;
    type CommitType = ValidMatchEncryptionWitnessCommitment;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (match_res_var, match_res_comm) = self.match_res.commit_prover(rng, prover).unwrap();
        let (party0_note_var, party0_note_comm) =
            self.party0_note.commit_prover(rng, prover).unwrap();
        let (party1_note_var, party1_note_comm) =
            self.party1_note.commit_prover(rng, prover).unwrap();
        let (relayer0_note_var, relayer0_note_comm) =
            self.relayer0_note.commit_prover(rng, prover).unwrap();
        let (relayer1_note_var, relayer1_note_comm) =
            self.relayer1_note.commit_prover(rng, prover).unwrap();
        let (protocol_note_var, protocol_note_comm) =
            self.protocol_note.commit_prover(rng, prover).unwrap();

        Ok((
            ValidMatchEncryptionWitnessVar {
                match_res: match_res_var,
                party0_note: party0_note_var,
                party1_note: party1_note_var,
                relayer0_note: relayer0_note_var,
                relayer1_note: relayer1_note_var,
                protocol_note: protocol_note_var,
            },
            ValidMatchEncryptionWitnessCommitment {
                match_res: match_res_comm,
                party0_note: party0_note_comm,
                party1_note: party1_note_comm,
                relayer0_note: relayer0_note_comm,
                relayer1_note: relayer1_note_comm,
                protocol_note: protocol_note_comm,
            },
        ))
    }
}

impl CommitVerifier for ValidMatchEncryptionWitnessCommitment {
    type VarType = ValidMatchEncryptionWitnessVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let match_res_var = self.match_res.commit_verifier(verifier).unwrap();
        let party0_note_var = self.party0_note.commit_verifier(verifier).unwrap();
        let party1_note_var = self.party1_note.commit_verifier(verifier).unwrap();
        let relayer0_note_var = self.relayer0_note.commit_verifier(verifier).unwrap();
        let relayer1_note_var = self.relayer1_note.commit_verifier(verifier).unwrap();
        let protocol_note_var = self.protocol_note.commit_verifier(verifier).unwrap();

        Ok(ValidMatchEncryptionWitnessVar {
            match_res: match_res_var,
            party0_note: party0_note_var,
            party1_note: party1_note_var,
            relayer0_note: relayer0_note_var,
            relayer1_note: relayer1_note_var,
            protocol_note: protocol_note_var,
        })
    }
}

/// The statement type for the VALID MATCH ENCRYPTION circuit
///
/// Note that the statement does not include encryptions of all
/// note values. For efficiency, some of these values may be pre-encrypted
/// and have their ciphertext signed by an actor that holds sk_root. This gives
/// us the ability to drastically limit the amount of in-circuit encryption
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionStatement {
    /// The public settle key of the first party's wallet
    pub pk_settle1: Scalar,
    /// The public settle key of the second party's wallet
    pub pk_settle2: Scalar,
    /// The public settle key of the protocol
    pub pk_settle_protocol: Scalar,
    /// The global protocol fee
    pub protocol_fee: Scalar,
    /// Encryption of the exchanged volume of mint1 under the first party's key
    pub volume1_ciphertext1: Scalar,
    /// Encryption of the exchanged volume of mint2 under the first party's key
    pub volume2_ciphertext1: Scalar,
    /// Encryption of the exchanged volume of mint1 under the second party's key
    pub volume1_ciphertext2: Scalar,
    /// Encryption of the exchanged volume of mint2 under the second party's key
    pub volume2_ciphertext2: Scalar,
    /// Encryption of the first mint under the protocol's public key
    pub mint1_protocol_ciphertext: Scalar,
    /// Encryption of the first mint's exchanged volume under the protocol's key
    pub volume1_protocol_ciphertext: Scalar,
    /// Encryption of the second mint under the protocol's public key
    pub mint2_protocol_ciphertext: Scalar,
    /// Encryption of the second mint's exchanged volume under the protocol's key
    pub volume2_protocol_ciphertext: Scalar,
    /// Encryption of the protocol note's randomness under the protocol's key
    pub randomness_protocol_ciphertext: Scalar,
}

/// The statement type for the VALID MATCH ENCRYPTION circuit
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionStatementVar {
    /// The public settle key of the first party's wallet
    pub pk_settle1: Variable,
    /// The public settle key of the second party's wallet
    pub pk_settle2: Variable,
    /// The public settle key of the protocol
    pub pk_settle_protocol: Variable,
    /// The global protocol fee
    pub protocol_fee: Variable,
    /// Encryption of the exchanged volume of mint1 under the first party's key
    pub volume1_ciphertext1: Variable,
    /// Encryption of the exchanged volume of mint2 under the first party's key
    pub volume2_ciphertext1: Variable,
    /// Encryption of the exchanged volume of mint1 under the second party's key
    pub volume1_ciphertext2: Variable,
    /// Encryption of the exchanged volume of mint2 under the second party's key
    pub volume2_ciphertext2: Variable,
    /// Encryption of the first mint under the protocol's public key
    pub mint1_protocol_ciphertext: Variable,
    /// Encryption of the first mint's exchanged volume under the protocol's key
    pub volume1_protocol_ciphertext: Variable,
    /// Encryption of the second mint under the protocol's public key
    pub mint2_protocol_ciphertext: Variable,
    /// Encryption of the second mint's exchanged volume under the protocol's key
    pub volume2_protocol_ciphertext: Variable,
    /// Encryption of the protocol note's randomness under the protocol's key
    pub randomness_protocol_ciphertext: Variable,
}

impl CommitProver for ValidMatchEncryptionStatement {
    type VarType = ValidMatchEncryptionStatementVar;
    type CommitType = (); // Statement variables need no commitment
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        _: &mut R,
        prover: &mut mpc_bulletproof::r1cs::Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let pk_settle1_var = prover.commit_public(self.pk_settle1);
        let pk_settle2_var = prover.commit_public(self.pk_settle2);
        let pk_settle_protocol_var = prover.commit_public(self.pk_settle_protocol);
        let protocol_fee_var = prover.commit_public(self.protocol_fee);
        let volume1_ciphertext1_var = prover.commit_public(self.volume1_ciphertext1);
        let volume2_ciphertext1_var = prover.commit_public(self.volume2_ciphertext1);
        let volume1_ciphertext2_var = prover.commit_public(self.volume1_ciphertext2);
        let volume2_ciphertext2_var = prover.commit_public(self.volume2_ciphertext2);
        let mint1_protocol_ciphertext_var = prover.commit_public(self.mint1_protocol_ciphertext);
        let volume1_protocol_ciphertext_var =
            prover.commit_public(self.volume1_protocol_ciphertext);
        let mint2_protocol_ciphertext_var = prover.commit_public(self.mint2_protocol_ciphertext);
        let volume2_protocol_ciphertext_var =
            prover.commit_public(self.volume2_protocol_ciphertext);
        let randomness_protocol_ciphertext_var =
            prover.commit_public(self.randomness_protocol_ciphertext);

        Ok((
            ValidMatchEncryptionStatementVar {
                pk_settle1: pk_settle1_var,
                pk_settle2: pk_settle2_var,
                pk_settle_protocol: pk_settle_protocol_var,
                protocol_fee: protocol_fee_var,
                volume1_ciphertext1: volume1_ciphertext1_var,
                volume2_ciphertext1: volume2_ciphertext1_var,
                volume1_ciphertext2: volume1_ciphertext2_var,
                volume2_ciphertext2: volume2_ciphertext2_var,
                mint1_protocol_ciphertext: mint1_protocol_ciphertext_var,
                volume1_protocol_ciphertext: volume1_protocol_ciphertext_var,
                mint2_protocol_ciphertext: mint2_protocol_ciphertext_var,
                volume2_protocol_ciphertext: volume2_protocol_ciphertext_var,
                randomness_protocol_ciphertext: randomness_protocol_ciphertext_var,
            },
            (),
        ))
    }
}

impl CommitVerifier for ValidMatchEncryptionStatement {
    type VarType = ValidMatchEncryptionStatementVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let pk_settle1_var = verifier.commit_public(self.pk_settle1);
        let pk_settle2_var = verifier.commit_public(self.pk_settle2);
        let pk_settle_protocol_var = verifier.commit_public(self.pk_settle_protocol);
        let protocol_fee_var = verifier.commit_public(self.protocol_fee);
        let volume1_ciphertext1_var = verifier.commit_public(self.volume1_ciphertext1);
        let volume2_ciphertext1_var = verifier.commit_public(self.volume2_ciphertext1);
        let volume1_ciphertext2_var = verifier.commit_public(self.volume1_ciphertext2);
        let volume2_ciphertext2_var = verifier.commit_public(self.volume2_ciphertext2);
        let mint1_protocol_ciphertext_var = verifier.commit_public(self.mint1_protocol_ciphertext);
        let volume1_protocol_ciphertext_var =
            verifier.commit_public(self.volume1_protocol_ciphertext);
        let mint2_protocol_ciphertext_var = verifier.commit_public(self.mint2_protocol_ciphertext);
        let volume2_protocol_ciphertext_var =
            verifier.commit_public(self.volume2_protocol_ciphertext);
        let randomness_protocol_ciphertext_var =
            verifier.commit_public(self.randomness_protocol_ciphertext);

        Ok(ValidMatchEncryptionStatementVar {
            pk_settle1: pk_settle1_var,
            pk_settle2: pk_settle2_var,
            pk_settle_protocol: pk_settle_protocol_var,
            protocol_fee: protocol_fee_var,
            volume1_ciphertext1: volume1_ciphertext1_var,
            volume2_ciphertext1: volume2_ciphertext1_var,
            volume1_ciphertext2: volume1_ciphertext2_var,
            volume2_ciphertext2: volume2_ciphertext2_var,
            mint1_protocol_ciphertext: mint1_protocol_ciphertext_var,
            volume1_protocol_ciphertext: volume1_protocol_ciphertext_var,
            mint2_protocol_ciphertext: mint2_protocol_ciphertext_var,
            volume2_protocol_ciphertext: volume2_protocol_ciphertext_var,
            randomness_protocol_ciphertext: randomness_protocol_ciphertext_var,
        })
    }
}

impl SingleProverCircuit for ValidMatchEncryption {
    type Witness = ValidMatchEncryptionWitness;
    type WitnessCommitment = ValidMatchEncryptionWitnessCommitment;
    type Statement = ValidMatchEncryptionStatement;

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
