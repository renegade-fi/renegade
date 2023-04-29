//! Defines the VALID WALLET CREATE circuit that proves that a committed
//! wallet is a wallet of all zero values, i.e. empty orders, balances,
//! and fees
//!
//! The user proves this statement to bootstrap into the system with a fresh
//! wallet that may be deposited into.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.1
//! for a formal specification

use std::char::MAX;

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
    r1cs_mpc::R1CSError,
    BulletproofGens,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    types::wallet::{
        WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar, WalletVar,
    },
    zk_gadgets::commitments::WalletShareCommitGadget,
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit, MAX_BALANCES, MAX_FEES,
    MAX_ORDERS,
};

/// The number of zero Scalars to use when representing an empty balance
/// One for the mint, one for the amount
const BALANCE_ZEROS: usize = 2;
/// The number of zero Scalars to use when representing an empty order
/// zero'd fields are the two mints, the side, the amount, and the price
const ORDER_ZEROS: usize = 5;

/// A type alias for an instantiation of this circuit with default generics
pub type ValidWalletCreateDefault = ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuitry for the valid wallet create statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreate<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Applies constraints to the constraint system specifying the statement of
    /// VALID WALLET CREATE
    fn circuit<CS>(
        mut statement: ValidWalletCreateStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        mut witness: ValidWalletCreateVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
    {
        // Validate the commitment given in the statement is a valid commitment to the private secret shares
        let commitment =
            WalletShareCommitGadget::compute_commitment(&witness.private_wallet_share, cs)?;
        cs.constrain(commitment - statement.private_shares_commitment);

        // Unblind the shares then reconstruct the wallet
        witness.private_wallet_share.unblind();
        statement.public_wallet_shares.unblind();
        let wallet = witness.private_wallet_share + statement.public_wallet_shares;

        // Verify that the orders and balances are zero'd
        Self::verify_zero_wallet(wallet, cs);

        Ok(())
    }

    /// Constrains a wallet to have all zero'd out orders and balances
    fn verify_zero_wallet<CS: RandomizableConstraintSystem>(
        wallet: WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>,
        cs: &mut CS,
    ) {
        // Constrain balances to be zero
        for balance in wallet.balances.into_iter() {
            cs.constrain(balance.mint);
            cs.constrain(balance.amount);
        }

        // Constrain orders to be zero
        for order in wallet.orders.into_iter() {
            cs.constrain(order.base_mint);
            cs.constrain(order.quote_mint);
            cs.constrain(order.side);
            cs.constrain(order.price.repr);
            cs.constrain(order.amount);
            cs.constrain(order.timestamp);
        }
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness for the VALID WALLET CREATE statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreateWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the new wallet
    pub private_wallet_share: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// The proof-system allocated witness for VALID WALLET CREATE
#[derive(Clone, Debug)]
pub struct ValidWalletCreateVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the new wallet
    pub private_wallet_share: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// The committed witness for the VALID WALLET CREATE proof
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletCreateWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The private secret shares of the new wallet
    pub private_wallet_share: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type CommitType = ValidWalletCreateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type VarType = ValidWalletCreateVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_witness<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (wallet_share_var, wallet_share_comm) = self
            .private_wallet_share
            .commit_witness(rng, prover)
            .unwrap();
        Ok((
            ValidWalletCreateVar {
                private_wallet_share: wallet_share_var,
            },
            ValidWalletCreateWitnessCommitment {
                private_wallet_share: wallet_share_comm,
            },
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for ValidWalletCreateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type VarType = ValidWalletCreateVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let wallet_share_var = self.private_wallet_share.commit_verifier(verifier).unwrap();
        Ok(ValidWalletCreateVar {
            private_wallet_share: wallet_share_var,
        })
    }
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for the `VALID WALLET CREATE` circuit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletCreateStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The commitment to the private secret shares of the wallet
    pub private_shares_commitment: Scalar,
    /// The public secret shares of the wallet
    pub public_wallet_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// The statement type for the `VALID WALLET CREATE` circuit, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidWalletCreateStatementVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The commitment to the private secret shares of the wallet
    pub private_shares_commitment: Variable,
    /// The public secret shares of the wallet
    pub public_wallet_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitPublic
    for ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type VarType = ValidWalletCreateStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let private_commitment_var = self.private_shares_commitment.commit_public(cs).unwrap();
        let public_shares_var = self.public_wallet_shares.commit_public(cs).unwrap();

        Ok(ValidWalletCreateStatementVar {
            private_shares_commitment: private_commitment_var,
            public_wallet_shares: public_shares_var,
        })
    }
}

// ---------------------
// | Prove/Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Statement = ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Witness = ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidWalletCreateWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 10000;

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
        let statement_var = statement.commit_public(&mut verifier).unwrap();

        // Apply the constraints
        Self::circuit(statement_var, witness_var, &mut verifier).map_err(VerifierError::R1CS)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

// ---------
// | Tests |
// ---------
