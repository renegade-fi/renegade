//! Defines the `VALID REBLIND` circuit, which proves:
//!     1. State inclusion validity of the input
//!     2. CSPRNG execution integrity to sample new wallet blinders
//!     3. Re-blinding of a wallet using the sampled blinders

use curve25519_dalek::ristretto::CompressedRistretto;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        keychain::SecretIdentificationKey,
        wallet::{
            Nullifier, WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar,
            WalletShareCommitment,
        },
    },
    zk_gadgets::merkle::{MerkleOpening, MerkleOpeningCommitment, MerkleOpeningVar, MerkleRoot},
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit definition for `VALID REBLIND`
pub struct ValidReblind<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidReblind<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    /// Apply the constraints of `VALID REBLIND` to the given constraint system
    pub fn circuit<CS: RandomizableConstraintSystem>(
        statement: ValidReblindStatementVar,
        witness: ValidReblindWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for VALID REBLIND
#[derive(Clone, Debug)]
pub struct ValidReblindWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the original wallet
    pub original_wallet_private_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the original wallet
    pub original_wallet_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The private secret shares of the reblinded wallet
    pub reblinded_wallet_private_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the reblinded wallet
    pub reblinded_wallet_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The merkle opening of the original wallet's private shares
    pub private_share_opening: MerkleOpening,
    /// The merkle opening of the original wallet's public shares
    pub public_share_opening: MerkleOpening,
    /// The secret match key corresponding to the wallet's public match key
    pub sk_match: SecretIdentificationKey,
}

/// The witness type for VALID REBLIND, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidReblindWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the original wallet
    pub original_wallet_private_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the original wallet
    pub original_wallet_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The private secret shares of the reblinded wallet
    pub reblinded_wallet_private_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the reblinded wallet
    pub reblinded_wallet_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The merkle opening of the original wallet's private shares
    pub private_share_opening: MerkleOpeningVar,
    /// The merkle opening of the original wallet's public shares
    pub public_share_opening: MerkleOpeningVar,
    /// The secret match key corresponding to the wallet's public match key
    pub sk_match: Variable,
}

/// A commitment to the witness type for VALID REBLIND,
/// allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidReblindWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the original wallet
    pub original_wallet_private_shares:
        WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the original wallet
    pub original_wallet_public_shares:
        WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The private secret shares of the reblinded wallet
    pub reblinded_wallet_private_shares:
        WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the reblinded wallet
    pub reblinded_wallet_public_shares:
        WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The merkle opening of the original wallet's private shares
    pub private_share_opening: MerkleOpeningCommitment,
    /// The merkle opening of the original wallet's public shares
    pub public_share_opening: MerkleOpeningCommitment,
    /// The secret match key corresponding to the wallet's public match key
    pub sk_match: CompressedRistretto,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type VarType = ValidReblindWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidReblindWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut mpc_bulletproof::r1cs::Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (original_private_share_vars, original_private_share_comms) = self
            .original_wallet_private_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (original_public_share_vars, original_public_share_comms) = self
            .original_wallet_public_shares
            .commit_witness(rng, prover)
            .unwrap();

        let (reblinded_private_share_vars, reblinded_private_share_comms) = self
            .reblinded_wallet_private_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (reblinded_public_share_vars, reblinded_public_share_comms) = self
            .reblinded_wallet_public_shares
            .commit_witness(rng, prover)
            .unwrap();

        let (private_opening_var, private_opening_comm) = self
            .private_share_opening
            .commit_witness(rng, prover)
            .unwrap();
        let (public_opening_var, public_opening_comm) = self
            .public_share_opening
            .commit_witness(rng, prover)
            .unwrap();

        let (sk_match_var, sk_match_comm) = self.sk_match.commit_witness(rng, prover).unwrap();

        Ok((
            ValidReblindWitnessVar {
                original_wallet_private_shares: original_private_share_vars,
                original_wallet_public_shares: original_public_share_vars,
                reblinded_wallet_private_shares: reblinded_private_share_vars,
                reblinded_wallet_public_shares: reblinded_public_share_vars,
                private_share_opening: private_opening_var,
                public_share_opening: public_opening_var,
                sk_match: sk_match_var,
            },
            ValidReblindWitnessCommitment {
                original_wallet_private_shares: original_private_share_comms,
                original_wallet_public_shares: original_public_share_comms,
                reblinded_wallet_private_shares: reblinded_private_share_comms,
                reblinded_wallet_public_shares: reblinded_public_share_comms,
                private_share_opening: private_opening_comm,
                public_share_opening: public_opening_comm,
                sk_match: sk_match_comm,
            },
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for ValidReblindWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type VarType = ValidReblindWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let original_private_share_vars = self
            .original_wallet_private_shares
            .commit_verifier(verifier)
            .unwrap();
        let original_public_share_vars = self
            .original_wallet_public_shares
            .commit_verifier(verifier)
            .unwrap();

        let reblinded_private_share_vars = self
            .reblinded_wallet_private_shares
            .commit_verifier(verifier)
            .unwrap();
        let reblinded_public_share_vars = self
            .reblinded_wallet_public_shares
            .commit_verifier(verifier)
            .unwrap();

        let private_opening_var = self
            .private_share_opening
            .commit_verifier(verifier)
            .unwrap();
        let public_opening_var = self.public_share_opening.commit_verifier(verifier).unwrap();

        let sk_match_var = self.sk_match.commit_verifier(verifier).unwrap();

        Ok(ValidReblindWitnessVar {
            original_wallet_private_shares: original_private_share_vars,
            original_wallet_public_shares: original_public_share_vars,
            reblinded_wallet_private_shares: reblinded_private_share_vars,
            reblinded_wallet_public_shares: reblinded_public_share_vars,
            private_share_opening: private_opening_var,
            public_share_opening: public_opening_var,
            sk_match: sk_match_var,
        })
    }
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for VALID REBLIND
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidReblindStatement {
    /// The nullifier of the original wallet's private secret shares
    pub original_private_share_nullifier: Nullifier,
    /// The nullifier of the original wallet's public secret shares
    pub original_public_share_nullifier: Nullifier,
    /// A commitment to the private secret shares of the reblinded wallet
    pub reblinded_private_share_commitment: WalletShareCommitment,
    /// The global merkle root to prove inclusion into
    pub merkle_root: MerkleRoot,
}

/// The statement type for VALID REBLIND, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidReblindStatementVar {
    /// The nullifier of the original wallet's private secret shares
    pub original_private_share_nullifier: Variable,
    /// The nullifier of the original wallet's public secret shares
    pub original_public_share_nullifier: Variable,
    /// A commitment to the private secret shares of the reblinded wallet
    pub reblinded_private_share_commitment: Variable,
    /// The global merkle root to prove inclusion into
    pub merkle_root: Variable,
}

impl CommitPublic for ValidReblindStatement {
    type VarType = ValidReblindStatementVar;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let private_share_nullifier_var = self
            .original_private_share_nullifier
            .commit_public(cs)
            .unwrap();
        let public_share_nullifier_var = self
            .original_public_share_nullifier
            .commit_public(cs)
            .unwrap();
        let private_share_commitment_var = self
            .reblinded_private_share_commitment
            .commit_public(cs)
            .unwrap();
        let merkle_root_var = self.merkle_root.commit_public(cs).unwrap();

        Ok(ValidReblindStatementVar {
            original_private_share_nullifier: private_share_nullifier_var,
            original_public_share_nullifier: public_share_nullifier_var,
            reblinded_private_share_commitment: private_share_commitment_var,
            merkle_root: merkle_root_var,
        })
    }
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidReblind<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type Witness = ValidReblindWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidReblindWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidReblindStatement;

    const BP_GENS_CAPACITY: usize = 1024;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness and statement
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
        // Commit to the witness and statement
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
