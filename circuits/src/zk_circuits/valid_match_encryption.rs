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
        fee::{CommittedFee, Fee, FeeVar},
        note::{CommittedNote, Note, NoteVar},
        r#match::{CommittedMatchResult, MatchResult, MatchResultVar},
    },
    zk_gadgets::{
        comparators::EqGadget,
        elgamal::{
            ElGamalCiphertext, ElGamalCiphertextVar, ElGamalGadget, DEFAULT_ELGAMAL_GENERATOR,
        },
        fixed_point::{FixedPoint, FixedPointVar},
        select::CondSelectGadget,
    },
    CommitProver, CommitVerifier, SingleProverCircuit,
};

/// The number of encryptions that are actively verified by the circuit
const NUM_ENCRYPTIONS: usize = 2 /* party0_note */ + 2 /* party1_note */ + 5 /* protocol_note */;

/// Represents the circuit definition of VALID MATCH ENCRYPTION
///
/// The generic constant `SCALAR_BITS` is the number of bits allowed in
/// an encryption's randomness. This will practically be 252 (the size of)
/// the Ristretto field, but is made generic to shrink the complexity of
/// the unit tests
#[derive(Clone, Debug)]
pub struct ValidMatchEncryption<const SCALAR_BITS: usize> {}
impl<const SCALAR_BITS: usize> ValidMatchEncryption<SCALAR_BITS> {
    /// Implements the circuitry for the VALID MATCH ENCRYPTION circuit
    pub fn circuit<CS: RandomizableConstraintSystem>(
        witness: ValidMatchEncryptionWitnessVar,
        statement: ValidMatchEncryptionStatementVar,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Check that all ciphertexts are encrypted properly under the relevant
        // public keys
        Self::check_encryptions(&witness, &statement, cs)?;

        // Check that the plaintext notes are properly derived from the match result
        // and the fees that were already committed to
        Self::validate_notes(&witness, &statement, cs);
        Ok(())
    }

    /// Checks the ciphertexts that must be validated by the circuit
    pub fn check_encryptions<CS: RandomizableConstraintSystem>(
        witness: &ValidMatchEncryptionWitnessVar,
        statement: &ValidMatchEncryptionStatementVar,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Validate the encryption of party0's note volumes
        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[0],
            witness.party0_note.volume1,
            statement.pk_settle1,
            cs,
        )?;
        cs.constrain(expected_ciphertext.0 - statement.volume1_ciphertext1.partial_shared_secret);
        cs.constrain(expected_ciphertext.1 - statement.volume1_ciphertext1.encrypted_message);

        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[1],
            witness.party0_note.volume2,
            statement.pk_settle1,
            cs,
        )?;
        cs.constrain(expected_ciphertext.0 - statement.volume2_ciphertext1.partial_shared_secret);
        cs.constrain(expected_ciphertext.1 - statement.volume2_ciphertext1.encrypted_message);

        // Validate the encryption of party1's note volumes
        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[2],
            witness.party1_note.volume1,
            statement.pk_settle2,
            cs,
        )?;
        cs.constrain(expected_ciphertext.0 - statement.volume1_ciphertext2.partial_shared_secret);
        cs.constrain(expected_ciphertext.1 - statement.volume1_ciphertext2.encrypted_message);

        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[3],
            witness.party1_note.volume2,
            statement.pk_settle2,
            cs,
        )?;
        cs.constrain(expected_ciphertext.0 - statement.volume2_ciphertext2.partial_shared_secret);
        cs.constrain(expected_ciphertext.1 - statement.volume2_ciphertext2.encrypted_message);

        // Validate the encryption of the protocol's note under the protocol key
        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[4],
            witness.protocol_note.mint1,
            statement.pk_settle_protocol,
            cs,
        )?;
        cs.constrain(
            expected_ciphertext.0 - statement.mint1_protocol_ciphertext.partial_shared_secret,
        );
        cs.constrain(expected_ciphertext.1 - statement.mint1_protocol_ciphertext.encrypted_message);

        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[5],
            witness.protocol_note.volume1,
            statement.pk_settle_protocol,
            cs,
        )?;
        cs.constrain(
            expected_ciphertext.0 - statement.volume1_protocol_ciphertext.partial_shared_secret,
        );
        cs.constrain(
            expected_ciphertext.1 - statement.volume1_protocol_ciphertext.encrypted_message,
        );

        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[6],
            witness.protocol_note.mint2,
            statement.pk_settle_protocol,
            cs,
        )?;
        cs.constrain(
            expected_ciphertext.0 - statement.mint2_protocol_ciphertext.partial_shared_secret,
        );
        cs.constrain(expected_ciphertext.1 - statement.mint2_protocol_ciphertext.encrypted_message);

        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[7],
            witness.protocol_note.volume2,
            statement.pk_settle_protocol,
            cs,
        )?;
        cs.constrain(
            expected_ciphertext.0 - statement.volume2_protocol_ciphertext.partial_shared_secret,
        );
        cs.constrain(
            expected_ciphertext.1 - statement.volume2_protocol_ciphertext.encrypted_message,
        );

        let expected_ciphertext = ElGamalGadget::<SCALAR_BITS>::encrypt(
            *DEFAULT_ELGAMAL_GENERATOR,
            witness.elgamal_randomness[8],
            witness.protocol_note.randomness,
            statement.pk_settle_protocol,
            cs,
        )?;
        cs.constrain(
            expected_ciphertext.0
                - statement
                    .randomness_protocol_ciphertext
                    .partial_shared_secret,
        );
        cs.constrain(
            expected_ciphertext.1 - statement.randomness_protocol_ciphertext.encrypted_message,
        );

        Ok(())
    }

    /// Check that the notes in the witness are properly formed given the match result
    /// and committed fees
    fn validate_notes<CS: RandomizableConstraintSystem>(
        witness: &ValidMatchEncryptionWitnessVar,
        statement: &ValidMatchEncryptionStatementVar,
        cs: &mut CS,
    ) {
        // If d == 0, then party0 buys the base and sells the quote; and we use the
        // constraints generated by the following method call
        let party0_buy_constraints =
            Self::party0_buy_base_constraints_satisfied(witness, statement, cs);

        // If d == 1, then party0 buys the quote and sells the base; and we use the
        // constraints generated by the following method call
        let party0_sell_constraints =
            Self::party1_buy_base_constraints_satisfied(witness, statement, cs);

        // Mux between the two and assert that the result is equal to one
        let selected_constraint_set = CondSelectGadget::select(
            party0_sell_constraints,
            party0_buy_constraints,
            witness.match_res.direction,
            cs,
        );
        cs.constrain(Variable::One() - selected_constraint_set);

        // Validate that the protocol note volumes are properly formed
        let protocol_expected_v1 = statement
            .protocol_fee
            .mul_integer(witness.match_res.base_amount, cs)
            .floor(cs);
        let protocol_expected_v2 = statement
            .protocol_fee
            .mul_integer(witness.match_res.quote_amount, cs)
            .floor(cs);

        cs.constrain(protocol_expected_v1 - witness.protocol_note.volume1);
        cs.constrain(protocol_expected_v2 - witness.protocol_note.volume2);

        // Validate the non-conditional components of the notes; i.e. mints, directions, randomness
        // The base mint in each note
        cs.constrain(witness.match_res.base_mint - witness.party0_note.mint1);
        cs.constrain(witness.match_res.base_mint - witness.party1_note.mint1);
        cs.constrain(witness.match_res.base_mint - witness.relayer0_note.mint1);
        cs.constrain(witness.match_res.base_mint - witness.relayer1_note.mint1);
        cs.constrain(witness.match_res.base_mint - witness.protocol_note.mint1);

        // The quote mint in each note
        cs.constrain(witness.match_res.quote_mint - witness.party0_note.mint2);
        cs.constrain(witness.match_res.quote_mint - witness.party1_note.mint2);
        cs.constrain(witness.match_res.quote_mint - witness.relayer0_note.mint2);
        cs.constrain(witness.match_res.quote_mint - witness.relayer1_note.mint2);
        cs.constrain(witness.match_res.quote_mint - witness.protocol_note.mint2);

        // The first direction in each note
        cs.constrain(witness.party0_note.direction1 - witness.match_res.direction);
        cs.constrain(
            witness.party1_note.direction1 - Variable::One() + witness.match_res.direction,
        );
        cs.constrain(witness.relayer0_note.direction1.into());
        cs.constrain(witness.relayer1_note.direction1.into());
        cs.constrain(witness.protocol_note.direction1.into());

        // The second direction in each note
        cs.constrain(
            witness.party0_note.direction2 - Variable::One() + witness.match_res.direction,
        );
        cs.constrain(witness.party1_note.direction2 - witness.match_res.direction);
        cs.constrain(witness.relayer0_note.direction2.into());
        cs.constrain(witness.relayer1_note.direction2.into());
        cs.constrain(witness.protocol_note.direction2.into());

        // The gas fee mint in each note
        cs.constrain(witness.party0_note.fee_mint - witness.party0_fee.gas_addr);
        cs.constrain(witness.party1_note.fee_mint - witness.party1_fee.gas_addr);
        cs.constrain(witness.relayer0_note.fee_mint - witness.party0_fee.gas_addr);
        cs.constrain(witness.relayer1_note.fee_mint - witness.party1_fee.gas_addr);
        cs.constrain(witness.protocol_note.fee_mint.into());

        // The gas amount in each note
        cs.constrain(witness.party0_note.fee_volume - witness.party0_fee.gas_token_amount);
        cs.constrain(witness.party1_note.fee_volume - witness.party1_fee.gas_token_amount);
        cs.constrain(witness.relayer0_note.fee_volume - witness.party0_fee.gas_token_amount);
        cs.constrain(witness.relayer1_note.fee_volume - witness.party1_fee.gas_token_amount);
        cs.constrain(witness.protocol_note.fee_volume.into());

        // The fee direction in each note
        cs.constrain(witness.party0_note.fee_direction - Variable::One());
        cs.constrain(witness.party1_note.fee_direction - Variable::One());
        cs.constrain(witness.relayer0_note.fee_direction.into());
        cs.constrain(witness.relayer1_note.fee_direction.into());
        cs.constrain(witness.protocol_note.fee_direction.into());

        // The match vs transfer flag for each note
        cs.constrain(witness.party0_note.type_ - Variable::One());
        cs.constrain(witness.party1_note.type_ - Variable::One());
        cs.constrain(witness.relayer0_note.type_.into());
        cs.constrain(witness.relayer1_note.type_.into());
        cs.constrain(witness.protocol_note.type_.into());

        // TODO: constrain note randomness
    }

    /// Creates the constraints that will be enforced if party 0 is buying the base asset
    /// and party 1 buys the quote asset
    ///
    /// Returns a boolean representing the satisfiability of the constraints needed when
    /// the match goes in this direction.
    ///
    /// The constrains distill in this method and those in the next method are muxed between
    /// in the caller depending on the direction of the match
    fn party0_buy_base_constraints_satisfied<CS: RandomizableConstraintSystem>(
        witness: &ValidMatchEncryptionWitnessVar,
        statement: &ValidMatchEncryptionStatementVar,
        cs: &mut CS,
    ) -> Variable {
        // Check that party1's note receives the base amount exchanged minus the fees
        let party0_base_fraction = Variable::One()
            - witness.party0_fee.percentage_fee.clone()
            - statement.protocol_fee.clone();
        let party0_base_expected = party0_base_fraction
            .mul_integer(witness.match_res.base_amount, cs)
            .floor(cs);
        let p0_mint1_constraint =
            EqGadget::eq(witness.party0_note.volume1, party0_base_expected, cs);

        // Check that party1's note sends the quote amount exchanged
        let p0_mint2_constraint = EqGadget::eq(
            witness.party0_note.volume2,
            witness.match_res.quote_amount,
            cs,
        );

        // Check that party0's note sends the base amount exchanged
        let p1_mint1_constraint = EqGadget::eq(
            witness.party1_note.volume1,
            witness.match_res.base_amount,
            cs,
        );

        // Check that party0's note receives the quote amount exchanged minus fees
        let party1_quote_fraction = Variable::One()
            - witness.party1_fee.percentage_fee.clone()
            - statement.protocol_fee.clone();
        let party1_quote_expected = party1_quote_fraction
            .mul_integer(witness.match_res.quote_amount, cs)
            .floor(cs);
        let p1_mint2_constraint =
            EqGadget::eq(witness.party1_note.volume2, party1_quote_expected, cs);

        // Check that relayer0's note receives the correct base amount fee
        let relayer0_mint1_expected = witness
            .party0_fee
            .percentage_fee
            .mul_integer(witness.match_res.base_amount, cs)
            .floor(cs);
        let relayer0_mint1_constraint =
            EqGadget::eq(witness.relayer0_note.volume1, relayer0_mint1_expected, cs);

        // Check that relayer0's note receives none of the quote asset
        let relayer0_mint2_constraint =
            EqGadget::eq(witness.relayer0_note.volume2, Variable::Zero(), cs);

        // Check that relayer1's note receives none of the base asset
        let relayer1_mint1_constraint =
            EqGadget::eq(witness.relayer1_note.volume1, Variable::Zero(), cs);

        // Check that relayer1's note receives the correct quote amount fee
        let relayer1_mint2_expected = witness
            .party1_fee
            .percentage_fee
            .mul_integer(witness.match_res.quote_amount, cs)
            .floor(cs);
        let relayer1_mint2_constraint =
            EqGadget::eq(witness.relayer1_note.volume2, relayer1_mint2_expected, cs);

        // Take the AND of all the constraints, this is done by adding them up (they are boolean) and checking
        // that their sum equals the number of constraints
        let sum = p0_mint1_constraint
            + p0_mint2_constraint
            + p1_mint1_constraint
            + p1_mint2_constraint
            + relayer0_mint1_constraint
            + relayer0_mint2_constraint
            + relayer1_mint1_constraint
            + relayer1_mint2_constraint;
        let n_constraints = Scalar::from(8u8);

        EqGadget::eq(sum, n_constraints * Variable::One(), cs)
    }

    /// Creates the constraints that will be enforced if party 0 is buying the quote asset
    /// and party 1 buys the base asset
    ///
    /// Returns a boolean representing the satisfiability of the constraints needed when
    /// the match goes in this direction.
    ///
    /// The constrains distill in this method and those in the previous method are muxed between
    /// in the caller depending on the direction of the match
    fn party1_buy_base_constraints_satisfied<CS: RandomizableConstraintSystem>(
        witness: &ValidMatchEncryptionWitnessVar,
        statement: &ValidMatchEncryptionStatementVar,
        cs: &mut CS,
    ) -> Variable {
        // Check that party0's note sends the base amount exchanged
        let p0_mint1_constraint = EqGadget::eq(
            witness.party0_note.volume1,
            witness.match_res.base_amount,
            cs,
        );

        // Check that party0's note receives the quote amount exchanged minus the fees
        let party0_quote_fraction = Variable::One()
            - witness.party0_fee.percentage_fee.clone()
            - statement.protocol_fee.clone();
        let party0_quote_expected = party0_quote_fraction
            .mul_integer(witness.match_res.quote_amount, cs)
            .floor(cs);
        let p0_mint2_constraint =
            EqGadget::eq(witness.party0_note.volume2, party0_quote_expected, cs);

        // Check that party1's note receives the base amount exchanged
        let party1_base_fraction = Variable::One()
            - witness.party1_fee.percentage_fee.clone()
            - statement.protocol_fee.clone();
        let party1_base_expected = party1_base_fraction
            .mul_integer(witness.match_res.base_amount, cs)
            .floor(cs);
        let p1_mint1_constraint =
            EqGadget::eq(witness.party1_note.volume1, party1_base_expected, cs);

        // Check that party1's note sends the quote amount exchanged
        let p1_mint2_constraint = EqGadget::eq(
            witness.party1_note.volume2,
            witness.match_res.quote_amount,
            cs,
        );

        // Check that relayer0's note receives none of the base asset
        let relayer0_mint1_constraint =
            EqGadget::eq(witness.relayer0_note.volume1, Variable::Zero(), cs);

        // Check that relayer0's note receives the correct quote amount fee
        let relayer0_mint2_expected = witness
            .party0_fee
            .percentage_fee
            .mul_integer(witness.match_res.quote_amount, cs)
            .floor(cs);
        let relayer0_mint2_constraint =
            EqGadget::eq(witness.relayer0_note.volume2, relayer0_mint2_expected, cs);

        // Check that relayer1's note receives the correct base amount fee
        let relayer1_mint1_expected = witness
            .party1_fee
            .percentage_fee
            .mul_integer(witness.match_res.base_amount, cs)
            .floor(cs);
        let relayer1_mint1_constraint =
            EqGadget::eq(witness.relayer1_note.volume1, relayer1_mint1_expected, cs);

        // Check that relayer1's note receives none of the quote asset
        let relayer1_mint2_constraint =
            EqGadget::eq(witness.relayer1_note.volume2, Variable::Zero(), cs);

        // Take the AND of all the constraints, this is done by adding them up (they are boolean) and checking
        // that their sum equals the number of constraints
        let sum = p0_mint1_constraint
            + p0_mint2_constraint
            + p1_mint1_constraint
            + p1_mint2_constraint
            + relayer0_mint1_constraint
            + relayer0_mint2_constraint
            + relayer1_mint1_constraint
            + relayer1_mint2_constraint;
        let n_constraints = Scalar::from(8u8);

        EqGadget::eq(sum, n_constraints * Variable::One(), cs)
    }
}

/// The witness type for the VALID MATCH ENCRYPTION circuit
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionWitness {
    /// The result of the match process; a completed match
    pub match_res: MatchResult,
    /// The first party's fee committed to in the match process
    pub party0_fee: Fee,
    /// The second party's fee committed to in the match process
    pub party1_fee: Fee,
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
    /// The randomness used in the ElGamal encryptions to generate shared secrets
    pub elgamal_randomness: [Scalar; NUM_ENCRYPTIONS],
}

/// A witness for VALID MATCH ENCRYPTION that has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionWitnessVar {
    /// The result of the match process; a completed match
    pub match_res: MatchResultVar,
    /// The first party's fee committed to in the match process
    pub party0_fee: FeeVar,
    /// The second party's fee committed to in the match process
    pub party1_fee: FeeVar,
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
    /// The randomness used in the ElGamal encryptions to generate shared secrets
    pub elgamal_randomness: [Variable; NUM_ENCRYPTIONS],
}

/// A commitment to the witness type for the VALID MATCH ENCRYPTION circuit
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionWitnessCommitment {
    /// The result of the match process; a completed match
    pub match_res: CommittedMatchResult,
    /// The first party's fee committed to in the match process
    pub party0_fee: CommittedFee,
    /// The second party's fee committed to in the match process
    pub party1_fee: CommittedFee,
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
    /// The randomness used in the ElGamal encryptions to generate shared secrets
    pub elgamal_randomness: [CompressedRistretto; NUM_ENCRYPTIONS],
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
        let (fee1_var, fee1_comm) = self.party0_fee.commit_prover(rng, prover).unwrap();
        let (fee2_var, fee2_comm) = self.party1_fee.commit_prover(rng, prover).unwrap();
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
        let (randomness_comms, randomness_vars): (Vec<CompressedRistretto>, Vec<Variable>) = self
            .elgamal_randomness
            .iter()
            .map(|randomness| prover.commit(*randomness, Scalar::random(rng)))
            .unzip();

        Ok((
            ValidMatchEncryptionWitnessVar {
                match_res: match_res_var,
                party0_fee: fee1_var,
                party1_fee: fee2_var,
                party0_note: party0_note_var,
                party1_note: party1_note_var,
                relayer0_note: relayer0_note_var,
                relayer1_note: relayer1_note_var,
                protocol_note: protocol_note_var,
                elgamal_randomness: randomness_vars.try_into().unwrap(),
            },
            ValidMatchEncryptionWitnessCommitment {
                match_res: match_res_comm,
                party0_fee: fee1_comm,
                party1_fee: fee2_comm,
                party0_note: party0_note_comm,
                party1_note: party1_note_comm,
                relayer0_note: relayer0_note_comm,
                relayer1_note: relayer1_note_comm,
                protocol_note: protocol_note_comm,
                elgamal_randomness: randomness_comms.try_into().unwrap(),
            },
        ))
    }
}

impl CommitVerifier for ValidMatchEncryptionWitnessCommitment {
    type VarType = ValidMatchEncryptionWitnessVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let match_res_var = self.match_res.commit_verifier(verifier).unwrap();
        let fee1_var = self.party0_fee.commit_verifier(verifier).unwrap();
        let fee2_var = self.party1_fee.commit_verifier(verifier).unwrap();
        let party0_note_var = self.party0_note.commit_verifier(verifier).unwrap();
        let party1_note_var = self.party1_note.commit_verifier(verifier).unwrap();
        let relayer0_note_var = self.relayer0_note.commit_verifier(verifier).unwrap();
        let relayer1_note_var = self.relayer1_note.commit_verifier(verifier).unwrap();
        let protocol_note_var = self.protocol_note.commit_verifier(verifier).unwrap();
        let randomness_vars = self
            .elgamal_randomness
            .iter()
            .map(|randomness| verifier.commit(*randomness))
            .collect_vec();

        Ok(ValidMatchEncryptionWitnessVar {
            match_res: match_res_var,
            party0_fee: fee1_var,
            party1_fee: fee2_var,
            party0_note: party0_note_var,
            party1_note: party1_note_var,
            relayer0_note: relayer0_note_var,
            relayer1_note: relayer1_note_var,
            protocol_note: protocol_note_var,
            elgamal_randomness: randomness_vars.try_into().unwrap(),
        })
    }
}

/// The statement type for the VALID MATCH ENCRYPTION circuit
///
/// Note that the statement does not include encryptions of all
/// note values. For efficiency, some of these values may be pre-encrypted
/// and have their ciphertext signed by an actor that holds sk_root. This gives
/// us the ability to drastically limit the amount of in-circuit encryption
///
/// Each of the ciphertexts is a 2-tuple of scalars; one being the ElGamal shared
/// secret of the encryption, and the other being the encrypted value itself
#[derive(Clone, Debug)]
pub struct ValidMatchEncryptionStatement {
    /// The public settle key of the first party's wallet
    pub pk_settle1: Scalar,
    /// The public settle key of the second party's wallet
    pub pk_settle2: Scalar,
    /// The public settle key of the protocol
    pub pk_settle_protocol: Scalar,
    /// The global protocol fee
    pub protocol_fee: FixedPoint,
    /// Encryption of the exchanged volume of mint1 under the first party's key
    pub volume1_ciphertext1: ElGamalCiphertext,
    /// Encryption of the exchanged volume of mint2 under the first party's key
    pub volume2_ciphertext1: ElGamalCiphertext,
    /// Encryption of the exchanged volume of mint1 under the second party's key
    pub volume1_ciphertext2: ElGamalCiphertext,
    /// Encryption of the exchanged volume of mint2 under the second party's key
    pub volume2_ciphertext2: ElGamalCiphertext,
    /// Encryption of the first mint under the protocol's public key
    pub mint1_protocol_ciphertext: ElGamalCiphertext,
    /// Encryption of the first mint's exchanged volume under the protocol's key
    pub volume1_protocol_ciphertext: ElGamalCiphertext,
    /// Encryption of the second mint under the protocol's public key
    pub mint2_protocol_ciphertext: ElGamalCiphertext,
    /// Encryption of the second mint's exchanged volume under the protocol's key
    pub volume2_protocol_ciphertext: ElGamalCiphertext,
    /// Encryption of the protocol note's randomness under the protocol's key
    pub randomness_protocol_ciphertext: ElGamalCiphertext,
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
    pub protocol_fee: FixedPointVar,
    /// Encryption of the exchanged volume of mint1 under the first party's key
    pub volume1_ciphertext1: ElGamalCiphertextVar,
    /// Encryption of the exchanged volume of mint2 under the first party's key
    pub volume2_ciphertext1: ElGamalCiphertextVar,
    /// Encryption of the exchanged volume of mint1 under the second party's key
    pub volume1_ciphertext2: ElGamalCiphertextVar,
    /// Encryption of the exchanged volume of mint2 under the second party's key
    pub volume2_ciphertext2: ElGamalCiphertextVar,
    /// Encryption of the first mint under the protocol's public key
    pub mint1_protocol_ciphertext: ElGamalCiphertextVar,
    /// Encryption of the first mint's exchanged volume under the protocol's key
    pub volume1_protocol_ciphertext: ElGamalCiphertextVar,
    /// Encryption of the second mint under the protocol's public key
    pub mint2_protocol_ciphertext: ElGamalCiphertextVar,
    /// Encryption of the second mint's exchanged volume under the protocol's key
    pub volume2_protocol_ciphertext: ElGamalCiphertextVar,
    /// Encryption of the protocol note's randomness under the protocol's key
    pub randomness_protocol_ciphertext: ElGamalCiphertextVar,
}

impl CommitProver for ValidMatchEncryptionStatement {
    type VarType = ValidMatchEncryptionStatementVar;
    type CommitType = (); // Statement variables need no commitment
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        _: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let pk_settle1_var = prover.commit_public(self.pk_settle1);
        let pk_settle2_var = prover.commit_public(self.pk_settle2);
        let pk_settle_protocol_var = prover.commit_public(self.pk_settle_protocol);
        let protocol_fee_var = self.protocol_fee.commit_public(prover);
        let volume1_ciphertext1_var = self.volume1_ciphertext1.commit_public(prover);
        let volume2_ciphertext1_var = self.volume2_ciphertext1.commit_public(prover);
        let volume1_ciphertext2_var = self.volume1_ciphertext2.commit_public(prover);
        let volume2_ciphertext2_var = self.volume2_ciphertext2.commit_public(prover);
        let mint1_protocol_ciphertext_var = self.mint1_protocol_ciphertext.commit_public(prover);
        let volume1_protocol_ciphertext_var =
            self.volume1_protocol_ciphertext.commit_public(prover);
        let mint2_protocol_ciphertext_var = self.mint2_protocol_ciphertext.commit_public(prover);
        let volume2_protocol_ciphertext_var =
            self.volume2_protocol_ciphertext.commit_public(prover);
        let randomness_protocol_ciphertext_var =
            self.randomness_protocol_ciphertext.commit_public(prover);

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
        let protocol_fee_var = self.protocol_fee.commit_public(verifier);
        let volume1_ciphertext1_var = self.volume1_ciphertext1.commit_public(verifier);
        let volume2_ciphertext1_var = self.volume2_ciphertext1.commit_public(verifier);
        let volume1_ciphertext2_var = self.volume1_ciphertext2.commit_public(verifier);
        let volume2_ciphertext2_var = self.volume2_ciphertext2.commit_public(verifier);
        let mint1_protocol_ciphertext_var = self.mint1_protocol_ciphertext.commit_public(verifier);
        let volume1_protocol_ciphertext_var =
            self.volume1_protocol_ciphertext.commit_public(verifier);
        let mint2_protocol_ciphertext_var = self.mint2_protocol_ciphertext.commit_public(verifier);
        let volume2_protocol_ciphertext_var =
            self.volume2_protocol_ciphertext.commit_public(verifier);
        let randomness_protocol_ciphertext_var =
            self.randomness_protocol_ciphertext.commit_public(verifier);

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

impl<const SCALAR_BITS: usize> SingleProverCircuit for ValidMatchEncryption<SCALAR_BITS> {
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

#[cfg(test)]
mod valid_match_encryption_tests {

    use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
    use curve25519_dalek::scalar::Scalar;
    use integration_helpers::mpc_network::field::get_ristretto_group_modulus;
    use lazy_static::lazy_static;
    use merlin::Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use mpc_ristretto::mpc_scalar::scalar_to_u64;
    use num_bigint::{BigInt, BigUint};
    use rand_core::{OsRng, RngCore};

    use crate::{
        test_helpers::bulletproof_prove_and_verify,
        types::{
            fee::Fee,
            note::{Note, NoteType},
            order::OrderSide,
            r#match::MatchResult,
        },
        zk_gadgets::{
            elgamal::{ElGamalCiphertext, DEFAULT_ELGAMAL_GENERATOR},
            fixed_point::FixedPoint,
        },
        CommitProver,
    };

    use super::{ValidMatchEncryption, ValidMatchEncryptionStatement, ValidMatchEncryptionWitness};

    const ELGAMAL_BITS: usize = 3;

    // --------------
    // | Dummy Data |
    // --------------

    const PROTOCOL_FEE: f32 = 0.01;
    lazy_static! {
        static ref DUMMY_MATCH: MatchResult = MatchResult {
            quote_mint: BigInt::from(1u8),
            base_mint: BigInt::from(1u8),
            quote_amount: 300,
            base_amount: 200,
            direction: 1,
            execution_price: FixedPoint::from(2.),
            max_minus_min_amount: 10,
            min_amount_order_index: 0
        };
        static ref DUMMY_FEE1: Fee = Fee {
            settle_key: BigUint::from(42u64),
            gas_addr: BigUint::from(10u64),
            gas_token_amount: 2,
            percentage_fee: FixedPoint::from(0.01)
        };
        static ref DUMMY_FEE2: Fee = Fee {
            settle_key: BigUint::from(1729u64),
            gas_addr: BigUint::from(10u64),
            gas_token_amount: 2,
            percentage_fee: FixedPoint::from(0.01)
        };
    }

    // -----------
    // | Helpers |
    // -----------

    fn create_dummy_witness_and_statement(
        match_: MatchResult,
    ) -> (ValidMatchEncryptionWitness, ValidMatchEncryptionStatement) {
        // A helper to select based on direction
        macro_rules! sel {
            ($a:expr, $b:expr) => {
                if match_.direction == 0 {
                    $a
                } else {
                    $b
                }
            };
        }

        let buy = OrderSide::Buy;
        let sell = OrderSide::Sell;

        let mut rng = OsRng {};
        let randomness = rng.next_u64();

        let relayer_fee_fraction = DUMMY_FEE1.percentage_fee.clone();
        let protocol_fee_fraction = DUMMY_FEE2.percentage_fee.clone();

        // The remainder after fees are applied
        let party_fee_fraction =
            FixedPoint::from_integer(1u64) - relayer_fee_fraction - protocol_fee_fraction;

        let party_quote_amount =
            scalar_to_u64(&(party_fee_fraction * match_.quote_amount.into()).floor());
        let party_base_amount =
            scalar_to_u64(&(party_fee_fraction * match_.base_amount.into()).floor());

        let relayer_quote_amount =
            scalar_to_u64(&(relayer_fee_fraction.clone() * match_.quote_amount.into()).floor());
        let relayer_base_amount =
            scalar_to_u64(&(relayer_fee_fraction * match_.base_amount.into()).floor());

        let protocol_quote_amount =
            scalar_to_u64(&(protocol_fee_fraction * match_.quote_amount.into()).floor());
        let protocol_base_amount =
            scalar_to_u64(&(protocol_fee_fraction * match_.base_amount.into()).floor());

        // Clones of the fees
        let fee_tuple1 = DUMMY_FEE1.clone();
        let fee_tuple2 = DUMMY_FEE2.clone();

        let party0_note = Note {
            mint1: match_.base_mint.clone().try_into().unwrap(),
            volume1: sel!(party_base_amount, match_.base_amount),
            direction1: sel!(buy, sell),
            mint2: match_.quote_mint.clone().try_into().unwrap(),
            volume2: sel!(match_.quote_amount, party_quote_amount),
            direction2: sel!(sell, buy),
            fee_mint: fee_tuple1.gas_addr.clone().try_into().unwrap(),
            fee_volume: fee_tuple1.gas_token_amount,
            fee_direction: sell,
            type_: NoteType::Match,
            randomness,
        };

        let party1_note = Note {
            mint1: match_.base_mint.clone().try_into().unwrap(),
            volume1: sel!(match_.base_amount, party_base_amount),
            direction1: sel!(sell, buy),
            mint2: match_.quote_mint.clone().try_into().unwrap(),
            volume2: sel!(party_quote_amount, match_.quote_amount),
            direction2: sel!(buy, sell),
            fee_mint: fee_tuple2.gas_addr.clone().try_into().unwrap(),
            fee_volume: fee_tuple2.gas_token_amount,
            fee_direction: sell,
            type_: NoteType::Match,
            randomness: randomness + 1,
        };

        let relayer0_note = Note {
            mint1: match_.base_mint.clone().try_into().unwrap(),
            volume1: sel!(relayer_base_amount, 0),
            direction1: buy,
            mint2: match_.quote_mint.clone().try_into().unwrap(),
            volume2: sel!(0, relayer_quote_amount),
            direction2: buy,
            fee_mint: fee_tuple1.gas_addr.try_into().unwrap(),
            fee_volume: fee_tuple2.gas_token_amount,
            fee_direction: buy,
            type_: NoteType::InternalTransfer,
            randomness: randomness + 2,
        };

        let relayer1_note = Note {
            mint1: match_.base_mint.clone().try_into().unwrap(),
            volume1: sel!(0, relayer_base_amount),
            direction1: buy,
            mint2: match_.quote_mint.clone().try_into().unwrap(),
            volume2: sel!(relayer_quote_amount, 0),
            direction2: buy,
            fee_mint: fee_tuple2.gas_addr.try_into().unwrap(),
            fee_volume: fee_tuple2.gas_token_amount,
            fee_direction: buy,
            type_: NoteType::InternalTransfer,
            randomness: randomness + 3,
        };

        let protocol_note = Note {
            mint1: match_.base_mint.clone().try_into().unwrap(),
            volume1: protocol_base_amount,
            direction1: buy,
            mint2: match_.quote_mint.clone().try_into().unwrap(),
            volume2: protocol_quote_amount,
            direction2: buy,
            fee_mint: 0,
            fee_volume: 0,
            fee_direction: buy,
            type_: NoteType::InternalTransfer,
            randomness: randomness + 4,
        };

        // Generate encryptions for the statement
        let mut rng = OsRng {};
        let pk_settle1 = scalar_to_biguint(&Scalar::random(&mut rng));
        let pk_settle2 = scalar_to_biguint(&Scalar::random(&mut rng));
        let pk_settle_protocol = scalar_to_biguint(&Scalar::random(&mut rng));

        let (v1c1_cipher, randomness1) =
            elgamal_encrypt(&BigUint::from(party0_note.volume1), &pk_settle1);
        let (v2c1_cipher, randomness2) =
            elgamal_encrypt(&BigUint::from(party0_note.volume2), &pk_settle1);
        let (v1c2_cipher, randomness3) =
            elgamal_encrypt(&BigUint::from(party1_note.volume1), &pk_settle2);
        let (v2c2_cipher, randomness4) =
            elgamal_encrypt(&BigUint::from(party1_note.volume2), &pk_settle2);

        let (protocol_mint1_cipher, randomness5) =
            elgamal_encrypt(&BigUint::from(protocol_note.mint1), &pk_settle_protocol);
        let (protocol_volume1_cipher, randomness6) =
            elgamal_encrypt(&BigUint::from(protocol_note.volume1), &pk_settle_protocol);
        let (protocol_mint2_cipher, randomness7) =
            elgamal_encrypt(&BigUint::from(protocol_note.mint2), &pk_settle_protocol);
        let (protocol_volume2_cipher, randomness8) =
            elgamal_encrypt(&BigUint::from(protocol_note.volume2), &pk_settle_protocol);
        let (protocol_randomness_cipher, randomness9) = elgamal_encrypt(
            &BigUint::from(protocol_note.randomness),
            &pk_settle_protocol,
        );

        (
            ValidMatchEncryptionWitness {
                match_res: match_,
                party0_fee: DUMMY_FEE1.clone(),
                party1_fee: DUMMY_FEE2.clone(),
                party0_note,
                party1_note,
                relayer0_note,
                relayer1_note,
                protocol_note,
                elgamal_randomness: [
                    randomness1,
                    randomness2,
                    randomness3,
                    randomness4,
                    randomness5,
                    randomness6,
                    randomness7,
                    randomness8,
                    randomness9,
                ],
            },
            ValidMatchEncryptionStatement {
                pk_settle1: biguint_to_scalar(&pk_settle1),
                pk_settle2: biguint_to_scalar(&pk_settle2),
                pk_settle_protocol: biguint_to_scalar(&pk_settle_protocol),
                protocol_fee: FixedPoint::from(PROTOCOL_FEE),
                volume1_ciphertext1: v1c1_cipher,
                volume2_ciphertext1: v2c1_cipher,
                volume1_ciphertext2: v1c2_cipher,
                volume2_ciphertext2: v2c2_cipher,
                mint1_protocol_ciphertext: protocol_mint1_cipher,
                volume1_protocol_ciphertext: protocol_volume1_cipher,
                mint2_protocol_ciphertext: protocol_mint2_cipher,
                volume2_protocol_ciphertext: protocol_volume2_cipher,
                randomness_protocol_ciphertext: protocol_randomness_cipher,
            },
        )
    }

    /// Generates an ElGamal encryption of the given plaintext message; returns the ciphertext
    /// and the randomness used to create the shared secret
    fn elgamal_encrypt(message: &BigUint, pubkey: &BigUint) -> (ElGamalCiphertext, Scalar) {
        let mut rng = OsRng {};
        let randomness = scalar_to_biguint(&Scalar::random(&mut rng)) % (1u8 << ELGAMAL_BITS);
        let field_mod = get_ristretto_group_modulus();

        let ciphertext_1 =
            scalar_to_biguint(&DEFAULT_ELGAMAL_GENERATOR).modpow(&randomness, &field_mod);

        let shared_secret = pubkey.modpow(&randomness, &field_mod);
        let encrypted_message = (shared_secret * message) % field_mod;

        (
            ElGamalCiphertext {
                partial_shared_secret: biguint_to_scalar(&ciphertext_1),
                encrypted_message: biguint_to_scalar(&encrypted_message),
            },
            biguint_to_scalar(&randomness),
        )
    }

    // ---------
    // | Tests |
    // ---------

    /// Test a valid witness and statement for the VALID MATCH ENCRYPTION circuit
    #[test]
    fn test_valid_encryption() {
        let (witness, statement) = create_dummy_witness_and_statement(DUMMY_MATCH.clone());

        let res =
            bulletproof_prove_and_verify::<ValidMatchEncryption<ELGAMAL_BITS>>(witness, statement);
        assert!(res.is_ok());
    }

    /// Tests a valid witness and statement, this time with the parties on the opposite order side
    #[test]
    fn test_swapped_direction() {
        let mut rng = OsRng {};
        let mut match_ = DUMMY_MATCH.clone();
        match_.direction = 1 - match_.direction;
        let (witness, statement) = create_dummy_witness_and_statement(match_);

        let mut prover_transcript = Transcript::new("test".as_bytes());
        let pc_gens = PedersenGens::default();
        let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

        let (witness_var, _) = witness.commit_prover(&mut rng, &mut prover).unwrap();
        let (statement_var, _) = statement.commit_prover(&mut rng, &mut prover).unwrap();

        ValidMatchEncryption::<ELGAMAL_BITS>::circuit(witness_var, statement_var, &mut prover)
            .unwrap();
        assert!(prover.constraints_satisfied());
    }
}
