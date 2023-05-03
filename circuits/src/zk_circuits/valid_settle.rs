//! Defines the VALID SETTLE circuit, which is proven after a match, validating that
//! both party's secret shares have been updated properly with the result of the match

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    BulletproofGens,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        r#match::{CommittedMatchResult, LinkableMatchResultCommitment, MatchResultVar},
        wallet::{WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar},
    },
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit definition of `VALID SETTLE`
pub struct ValidSettle<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The circuit representing `VALID SETTLE`
    pub fn circuit<CS: RandomizableConstraintSystem>(
        statement: ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        witness: ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        unimplemented!()
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID SETTLE`
#[derive(Clone, Debug)]
pub struct ValidSettleWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The match result to be applied to the wallet shares
    pub match_res: LinkableMatchResultCommitment,
    /// The public secret shares of the first party before the match is applied
    pub party0_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the second party before the match is applied
    pub party1_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// The witness type for `VALID SETTLE`, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidSettleWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The match result to be applied to the wallet shares
    pub match_res: MatchResultVar,
    /// The public secret shares of the first party before the match is applied
    pub party0_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the second party before the match is applied
    pub party1_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// A commitment to the witness type for `VALID SETTLE`,
/// allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidSettleWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The match result to be applied to the wallet shares
    pub match_res: CommittedMatchResult,
    /// The public secret shares of the first party before the match is applied
    pub party0_public_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the second party before the match is applied
    pub party1_public_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (match_res_var, match_res_comm) = self.match_res.commit_witness(rng, prover).unwrap();
        let (party0_shares_var, party0_shares_comm) = self
            .party0_public_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (party1_shares_var, party1_shares_comm) = self
            .party1_public_shares
            .commit_witness(rng, prover)
            .unwrap();

        Ok((
            ValidSettleWitnessVar {
                match_res: match_res_var,
                party0_public_shares: party0_shares_var,
                party1_public_shares: party1_shares_var,
            },
            ValidSettleWitnessCommitment {
                match_res: match_res_comm,
                party0_public_shares: party0_shares_comm,
                party1_public_shares: party1_shares_comm,
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
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let match_res_var = self.match_res.commit_verifier(verifier).unwrap();
        let party0_share_vars = self.party0_public_shares.commit_verifier(verifier).unwrap();
        let party1_share_vars = self.party1_public_shares.commit_verifier(verifier).unwrap();

        Ok(ValidSettleWitnessVar {
            match_res: match_res_var,
            party0_public_shares: party0_share_vars,
            party1_public_shares: party1_share_vars,
        })
    }
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID SETTLE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidSettleStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The modified public secret shares of the first party
    pub party0_modified_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares of the second party
    pub party1_modified_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The index of the balance that the first party sent in the settlement
    pub party0_send_balance_index: usize,
    /// The index of teh balance that the first party received in the settlement
    pub party0_receive_balance_index: usize,
    /// The index of the first party's order that was matched
    pub party0_order_index: usize,
    /// The index of the balance that the second party sent in the settlement
    pub party1_send_balance_index: usize,
    /// The index of teh balance that the second party received in the settlement
    pub party1_receive_balance_index: usize,
    /// The index of the second party's order that was matched
    pub party1_order_index: usize,
}

/// The statement type for `VALID SETTLE`, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidSettleStatementVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The modified public secret shares of the first party
    pub party0_modified_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares of the second party
    pub party1_modified_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The index of the balance that the first party sent in the settlement
    pub party0_send_balance_index: Variable,
    /// The index of teh balance that the first party received in the settlement
    pub party0_receive_balance_index: Variable,
    /// The index of the first party's order that was matched
    pub party0_order_index: Variable,
    /// The index of the balance that the second party sent in the settlement
    pub party1_send_balance_index: Variable,
    /// The index of teh balance that the second party received in the settlement
    pub party1_receive_balance_index: Variable,
    /// The index of the second party's order that was matched
    pub party1_order_index: Variable,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitPublic
    for ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does nto error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let party0_share_vars = self.party0_modified_shares.commit_public(cs).unwrap();
        let party1_share_vars = self.party1_modified_shares.commit_public(cs).unwrap();
        let party0_send_index_var =
            cs.commit_public(Scalar::from(self.party0_send_balance_index as u64));
        let party0_receive_index_var =
            cs.commit_public(Scalar::from(self.party0_receive_balance_index as u64));
        let party0_order_index_var = cs.commit_public(Scalar::from(self.party0_order_index as u64));
        let party1_send_index_var =
            cs.commit_public(Scalar::from(self.party1_send_balance_index as u64));
        let party1_receive_index_var =
            cs.commit_public(Scalar::from(self.party1_receive_balance_index as u64));
        let party1_order_index_var = cs.commit_public(Scalar::from(self.party1_order_index as u64));

        Ok(ValidSettleStatementVar {
            party0_modified_shares: party0_share_vars,
            party1_modified_shares: party1_share_vars,
            party0_send_balance_index: party0_send_index_var,
            party0_receive_balance_index: party0_receive_index_var,
            party0_order_index: party0_order_index_var,
            party1_send_balance_index: party1_send_index_var,
            party1_receive_balance_index: party1_receive_index_var,
            party1_order_index: party1_order_index_var,
        })
    }
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 1024;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), crate::errors::ProverError> {
        // Commit to the witness and statement
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        // Apply the circuit constraints
        Self::circuit(statement_var, witness_var, &mut prover);

        // Prove the relation
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
        let statement_var = statement.commit_public(&mut verifier).unwrap();

        // Apply the circuit constraints
        Self::circuit(statement_var, witness_var, &mut verifier);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
