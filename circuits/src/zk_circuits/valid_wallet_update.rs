//! Defines the `VALID WALLET UPDATE` circuit
//!
//! This circuit proves that a user-generated update to a wallet is valid, and that
//! the state nullification/creation is computed correctly

// ----------------------
// | Circuit Definition |
// ----------------------

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
        keychain::PublicSigningKey,
        transfers::{ExternalTransfer, ExternalTransferVar},
        wallet::{
            Nullifier, WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar,
            WalletShareCommitment,
        },
    },
    zk_gadgets::{
        merkle::{MerkleOpening, MerkleOpeningCommitment, MerkleOpeningVar, MerkleRoot},
        nonnative::NonNativeElementVar,
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
{
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit<CS: RandomizableConstraintSystem>(
        statement: ValidWalletUpdateStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        witness: ValidWalletUpdateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        unimplemented!("")
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
        Self::circuit(statement_var, witness_var, &mut prover);

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
        Self::circuit(statement_var, witness_var, &mut verifier);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
