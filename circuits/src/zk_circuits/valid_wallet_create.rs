//! Defines the VALID WALLET CREATE circuit that proves that a committed
//! wallet is a wallet of all zero values, i.e. empty orders, balances,
//! and fees
//!
//! The user proves this statement to bootstrap into the system with a fresh
//! wallet that may be deposited into.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.1
//! for a formal specification

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
    zk_gadgets::wallet_operations::WalletShareCommitGadget,
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit, MAX_BALANCES, MAX_FEES,
    MAX_ORDERS,
};

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
        witness: ValidWalletCreateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
    {
        // Validate the commitment given in the statement is a valid commitment to the private secret shares
        let commitment = WalletShareCommitGadget::compute_private_commitment(
            witness.private_wallet_share.clone(),
            cs,
        )?;
        cs.constrain(commitment - statement.private_shares_commitment);

        // Unblind the public shares then reconstruct the wallet
        let blinder = witness.private_wallet_share.blinder.clone()
            + statement.public_wallet_shares.blinder.clone();
        statement.public_wallet_shares.unblind(blinder);
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
pub struct ValidWalletCreateWitnessVar<
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
    type VarType = ValidWalletCreateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
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
            ValidWalletCreateWitnessVar {
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
    type VarType = ValidWalletCreateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let wallet_share_var = self.private_wallet_share.commit_verifier(verifier).unwrap();
        Ok(ValidWalletCreateWitnessVar {
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
    type WitnessVar = ValidWalletCreateWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type StatementVar = ValidWalletCreateStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 10000;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: Self::WitnessVar,
        statement_var: Self::StatementVar,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Apply the constraints over the allocated witness & statement
        Self::circuit(statement_var, witness_var, cs)
    }

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
        Self::apply_constraints(witness_var, statement_var, &mut prover)
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
        // Commit to the witness and statement
        let witness_var = witness_commitment.commit_verifier(&mut verifier).unwrap();
        let statement_var = statement.commit_public(&mut verifier).unwrap();

        // Apply the constraints
        Self::apply_constraints(witness_var, statement_var, &mut verifier)
            .map_err(VerifierError::R1CS)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use rand_core::OsRng;

    use crate::{
        native_helpers::compute_wallet_private_share_commitment,
        test_helpers::bulletproof_prove_and_verify,
        types::{balance::Balance, order::Order},
        zk_circuits::{
            test_helpers::{
                create_wallet_shares, SizedWallet, INITIAL_BALANCES, INITIAL_ORDERS,
                INITIAL_WALLET, MAX_BALANCES, MAX_FEES, MAX_ORDERS,
            },
            valid_wallet_create::{
                ValidWalletCreate, ValidWalletCreateStatement, ValidWalletCreateWitness,
            },
        },
        CommitPublic, CommitWitness,
    };

    /// Witness with default size parameters
    type SizedWitness = ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    /// Statement with default size parameters
    type SizedStatement = ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // -----------
    // | Helpers |
    // -----------

    /// Helper to get a zero'd out dummy wallet
    fn create_empty_wallet() -> SizedWallet {
        // Zero out the balances and orders of the dummy wallet
        let mut wallet = INITIAL_WALLET.clone();
        wallet
            .balances
            .iter_mut()
            .for_each(|b| *b = Balance::default());
        wallet.orders.iter_mut().for_each(|o| *o = Order::default());

        wallet
    }

    /// Create a default, valid witness and statement for `VALID WALLET CREATE`
    fn create_default_witness_statement() -> (SizedWitness, SizedStatement) {
        // Create a wallet and split it into secret shares
        let wallet = create_empty_wallet();
        create_witness_statement_from_wallet(&wallet)
    }

    /// Create a witness and statement from a given wallet
    fn create_witness_statement_from_wallet(
        wallet: &SizedWallet,
    ) -> (SizedWitness, SizedStatement) {
        let (private_shares, public_shares) = create_wallet_shares(wallet);

        // Build a commitment to the private secret shares
        let commitment = compute_wallet_private_share_commitment(private_shares.clone());

        // Prove and verify
        let witness = ValidWalletCreateWitness {
            private_wallet_share: private_shares,
        };
        let statement = ValidWalletCreateStatement {
            private_shares_commitment: commitment,
            public_wallet_shares: public_shares,
        };

        (witness, statement)
    }

    /// Asserts that a given witness, statement pair is invalid
    fn assert_invalid_witness_statement(witness: SizedWitness, statement: SizedStatement) {
        // Create a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Allocate the witness and statement in the constraint system
        let mut rng = OsRng {};
        let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        // Apply the constraints
        ValidWalletCreate::circuit(statement_var, witness_var, &mut prover).unwrap();
        assert!(!prover.constraints_satisfied());
    }

    // ---------
    // | Tests |
    // ---------

    /// Tests that the circuit correctly verifies with valid zero'd balance and orders lists
    #[test]
    fn test_valid_initial_wallet() {
        let (witness, statement) = create_default_witness_statement();

        let res = bulletproof_prove_and_verify::<
            ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        >(witness, statement);
        assert!(res.is_ok())
    }

    /// Tests the case in which the commitment to the private shares is incorrect
    #[test]
    fn test_invalid_commitment() {
        let (witness, mut statement) = create_default_witness_statement();
        statement.private_shares_commitment += Scalar::from(1u8);

        assert_invalid_witness_statement(witness, statement);
    }

    /// Tests the case in which a non-zero order is given
    #[test]
    fn test_nonzero_order() {
        let mut wallet = create_empty_wallet();
        wallet.orders[0] = INITIAL_ORDERS[0].clone();

        let (witness, statement) = create_witness_statement_from_wallet(&wallet);
        assert_invalid_witness_statement(witness, statement);
    }

    /// Tests the cas in which a non-zero balance is given
    #[test]
    fn test_nonzero_balance() {
        let mut wallet = create_empty_wallet();
        wallet.balances[0] = INITIAL_BALANCES[0].clone();

        let (witness, statement) = create_witness_statement_from_wallet(&wallet);
        assert_invalid_witness_statement(witness, statement);
    }
}
