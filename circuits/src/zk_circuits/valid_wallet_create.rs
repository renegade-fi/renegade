//! Defines the VALID WALLET CREATE circuit that proves that a committed
//! wallet is a wallet of all zero values, i.e. empty orders, balances,
//! and fees
//!
//! The user proves this statement to bootstrap into the system with a fresh
//! wallet that may be deposited into.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.1
//! for a formal specification

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::OsRng;

use crate::{
    errors::{ProverError, VerifierError},
    types::fee::{CommittedFee, Fee, FeeVar},
    CommitProver, CommitVerifier, SingleProverCircuit, MAX_FEES,
};

/// The circuitry for the valid wallet create statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreate;

#[allow(unused)]
impl ValidWalletCreate {
    /// Applies constraints to the constraint system specifying the statment of
    /// VALID WALLET CREATE
    fn apply_constraints<CS>(
        cs: &mut CS,
        expected_commit: Variable,
        wallet_ciphertext: Vec<Variable>,
        witness: ValidWalletCreateVar,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
    {
        // Check that the commitment is to an empty wallet with the given randomness
        // keys, and fees

        Ok(())
    }

    /// Validates
    fn check_commitment<CS>(
        cs: &mut CS,
        expected_commit: Variable,
        witness: ValidWalletCreateVar,
    ) -> Result<(), ProverError>
    where
        CS: RandomizableConstraintSystem,
    {
        Ok(())
    }
}

/// The parameterization for the VALID WALLET CREATE statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreateStatement {
    /// The expected commitment of the newly created wallet
    pub wallet_commitment: Scalar,
    /// The ElGamal encryption of the wallet under the view key
    pub wallet_ciphertext: Vec<Scalar>,
}

/// The witness for the VALID WALLET CREATE statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreateWitness {
    /// The fees to initialize the wallet with; may be nonzero
    pub fees: [Fee; MAX_FEES],
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomenss: Scalar,
    /// The root secret key, used to derive all fine-grained permissioned keys
    pub root_secret_key: Scalar,
    /// The root public key
    pub root_public_key: Scalar,
    /// The match secret key, knowing this key gives an actor permission to match orders
    pub match_secret_key: Scalar,
    /// The match public key
    pub match_public_key: Scalar,
    /// The settle secret key, knowing this key gives an actor permission to settle matches
    pub settle_secret_key: Scalar,
    /// The settle public key
    pub settle_public_key: Scalar,
    /// The view secret key, knowing this key gives an actor permission to view the wallet
    pub view_secret_key: Scalar,
    /// The view public key
    pub view_public_key: Scalar,
}

/// The committed witness for the VALID WALLET CREATE proof
#[derive(Clone, Debug)]
pub struct ValidWalletCreateCommittment {
    /// The fees to initialize the wallet with; may be nonzero
    pub fees: [CommittedFee; MAX_FEES],
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomenss: CompressedRistretto,
    /// The root secret key, used to derive all fine-grained permissioned keys
    pub root_secret_key: CompressedRistretto,
    /// The root public key
    pub root_public_key: CompressedRistretto,
    /// The match secret key, knowing this key gives an actor permission to match orders
    pub match_secret_key: CompressedRistretto,
    /// The match public key
    pub match_public_key: CompressedRistretto,
    /// The settle secret key, knowing this key gives an actor permission to settle matches
    pub settle_secret_key: CompressedRistretto,
    /// The settle public key
    pub settle_public_key: CompressedRistretto,
    /// The view secret key, knowing this key gives an actor permission to view the wallet
    pub view_secret_key: CompressedRistretto,
    /// The view public key
    pub view_public_key: CompressedRistretto,
}

/// The proof-system allocated witness for VALID WALLET CREATE
#[derive(Clone, Debug)]
pub struct ValidWalletCreateVar {
    /// The fees to initialize the wallet with; may be nonzero
    pub fees: [FeeVar; MAX_FEES],
    /// The wallet randomness, used to hide commitments and nullifiers
    pub wallet_randomenss: Variable,
    /// The root secret key, used to derive all fine-grained permissioned keys
    pub root_secret_key: Variable,
    /// The root public key
    pub root_public_key: Variable,
    /// The match secret key, knowing this key gives an actor permission to match orders
    pub match_secret_key: Variable,
    /// The match public key
    pub match_public_key: Variable,
    /// The settle secret key, knowing this key gives an actor permission to settle matches
    pub settle_secret_key: Variable,
    /// The settle public key
    pub settle_public_key: Variable,
    /// The view secret key, knowing this key gives an actor permission to view the wallet
    pub view_secret_key: Variable,
    /// The view public key
    pub view_public_key: Variable,
}

impl CommitProver for ValidWalletCreateWitness {
    type CommitType = ValidWalletCreateCommittment;
    type VarType = ValidWalletCreateVar;
    type ErrorType = ();

    fn commit_prover<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (fee_vars, fee_commitments): (Vec<FeeVar>, Vec<CommittedFee>) = self
            .fees
            .iter()
            .map(|fee| fee.commit_prover(rng, prover).unwrap())
            .unzip();

        let (randomness_comm, randomness_var) =
            prover.commit(self.wallet_randomenss, Scalar::random(rng));
        let (sk_root_comm, sk_root_var) = prover.commit(self.root_secret_key, Scalar::random(rng));
        let (pk_root_comm, pk_root_var) = prover.commit(self.root_public_key, Scalar::random(rng));
        let (sk_match_comm, sk_match_var) =
            prover.commit(self.match_secret_key, Scalar::random(rng));
        let (pk_match_comm, pk_match_var) =
            prover.commit(self.match_public_key, Scalar::random(rng));
        let (sk_settle_comm, sk_settle_var) =
            prover.commit(self.settle_secret_key, Scalar::random(rng));
        let (pk_settle_comm, pk_settle_var) =
            prover.commit(self.settle_public_key, Scalar::random(rng));
        let (sk_view_comm, sk_view_var) = prover.commit(self.view_secret_key, Scalar::random(rng));
        let (pk_view_comm, pk_view_var) = prover.commit(self.view_public_key, Scalar::random(rng));

        Ok((
            ValidWalletCreateVar {
                fees: fee_vars.try_into().unwrap(),
                wallet_randomenss: randomness_var,
                root_secret_key: sk_root_var,
                root_public_key: pk_root_var,
                match_secret_key: sk_match_var,
                match_public_key: pk_match_var,
                settle_secret_key: sk_settle_var,
                settle_public_key: pk_settle_var,
                view_secret_key: sk_view_var,
                view_public_key: pk_view_var,
            },
            ValidWalletCreateCommittment {
                fees: fee_commitments.try_into().unwrap(),
                wallet_randomenss: randomness_comm,
                root_secret_key: sk_root_comm,
                root_public_key: pk_root_comm,
                match_secret_key: sk_match_comm,
                match_public_key: pk_match_comm,
                settle_secret_key: sk_settle_comm,
                settle_public_key: pk_settle_comm,
                view_secret_key: sk_view_comm,
                view_public_key: pk_view_comm,
            },
        ))
    }
}

impl CommitVerifier for ValidWalletCreateCommittment {
    type VarType = ValidWalletCreateVar;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let fee_vars = self
            .fees
            .iter()
            .map(|fee| fee.commit_verifier(verifier).unwrap())
            .collect_vec();

        let randomness_var = verifier.commit(self.wallet_randomenss);
        let sk_root_var = verifier.commit(self.root_secret_key);
        let pk_root_var = verifier.commit(self.root_public_key);
        let sk_match_var = verifier.commit(self.match_secret_key);
        let pk_match_var = verifier.commit(self.match_public_key);
        let sk_settle_var = verifier.commit(self.settle_secret_key);
        let pk_settle_var = verifier.commit(self.settle_public_key);
        let sk_view_var = verifier.commit(self.view_secret_key);
        let pk_view_var = verifier.commit(self.view_secret_key);

        Ok(ValidWalletCreateVar {
            fees: fee_vars.try_into().unwrap(),
            wallet_randomenss: randomness_var,
            root_secret_key: sk_root_var,
            root_public_key: pk_root_var,
            match_secret_key: sk_match_var,
            match_public_key: pk_match_var,
            settle_secret_key: sk_settle_var,
            settle_public_key: pk_settle_var,
            view_secret_key: sk_view_var,
            view_public_key: pk_view_var,
        })
    }
}

impl SingleProverCircuit for ValidWalletCreate {
    type Statement = ValidWalletCreateStatement;
    type Witness = ValidWalletCreateWitness;
    type WitnessCommitment = ValidWalletCreateCommittment;

    const BP_GENS_CAPACITY: usize = 64;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError> {
        // Commit to the witness
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_prover(&mut rng, &mut prover).unwrap();

        // Commit to the statement
        let (_, wallet_commitment_var) = prover.commit_public(statement.wallet_commitment);
        let (_, wallet_ciphertext_vars): (Vec<CompressedRistretto>, Vec<Variable>) = statement
            .wallet_ciphertext
            .iter()
            .map(|felt| prover.commit_public(*felt))
            .unzip();

        // Apply the constraints
        Self::apply_constraints(
            &mut prover,
            wallet_commitment_var,
            wallet_ciphertext_vars,
            witness_var,
        )
        .map_err(ProverError::R1CS)?;

        // Prove the statment
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
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();

        // Commit to the statement
        let wallet_ciphertext_vars = statement
            .wallet_ciphertext
            .iter()
            .map(|felt| verifier.commit_public(*felt))
            .collect_vec();
        let wallet_commitment_var = verifier.commit_public(statement.wallet_commitment);

        // Apply the constraints
        Self::apply_constraints(
            &mut verifier,
            wallet_commitment_var,
            wallet_ciphertext_vars,
            witness_var,
        )
        .map_err(VerifierError::R1CS)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
