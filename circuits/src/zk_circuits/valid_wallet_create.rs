//! Defines the VALID WALLET CREATE circuit that proves that a committed
//! wallet is a wallet of all zero values, i.e. empty orders, balances,
//! and fees
//!
//! The user proves this statement to bootstrap into the system with a fresh
//! wallet that may be deposited into.
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.1
//! for a formal specification

use circuit_macros::circuit_type;
use circuit_types::{
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
    },
    wallet::{WalletShare, WalletVar},
};
use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use mpc_bulletproof::{
    r1cs::{LinearCombination, RandomizableConstraintSystem, Variable},
    r1cs_mpc::R1CSError,
};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{zk_gadgets::wallet_operations::WalletShareCommitGadget, SingleProverCircuit};

/// A type alias for an instantiation of this circuit with default generics
pub type SizedValidWalletCreate = ValidWalletCreate<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

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
        statement: ValidWalletCreateStatementVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        witness: ValidWalletCreateWitnessVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
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
        let blinder = witness.private_wallet_share.blinder + statement.public_wallet_shares.blinder;
        let unblinded_public_shares = statement.public_wallet_shares.unblind_shares(blinder);
        let wallet = witness.private_wallet_share + unblinded_public_shares;

        // Verify that the orders and balances are zero'd
        Self::verify_zero_wallet(wallet, cs);

        Ok(())
    }

    /// Constrains a wallet to have all zero'd out orders and balances
    fn verify_zero_wallet<CS: RandomizableConstraintSystem>(
        wallet: WalletVar<LinearCombination, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // Constrain balances to be zero
        for balance_var in wallet.balances.into_iter().flat_map(|b| b.to_vars()) {
            cs.constrain(balance_var);
        }

        // Constrain orders to be zero
        for order_var in wallet.orders.into_iter().flat_map(|o| o.to_vars()) {
            cs.constrain(order_var);
        }
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness for the VALID WALLET CREATE statement
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidWalletCreateWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The private secret shares of the new wallet
    pub private_wallet_share: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}
/// A type alias that attached system-wide default generics to the witness type
pub type SizedValidWalletCreateWitness =
    ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for the `VALID WALLET CREATE` circuit
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletCreateStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The commitment to the private secret shares of the wallet
    pub private_shares_commitment: Scalar,
    /// The public secret shares of the wallet
    pub public_wallet_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}
/// A type alias that attaches system-wide default generics to the statement type
pub type SizedValidWalletCreateStatement =
    ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

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

    const BP_GENS_CAPACITY: usize = 10000;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        Self::circuit(statement_var, witness_var, cs)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        balance::Balance, native_helpers::compute_wallet_private_share_commitment, order::Order,
    };

    use crate::zk_circuits::test_helpers::{
        create_wallet_shares, SizedWallet, INITIAL_WALLET, MAX_BALANCES, MAX_FEES, MAX_ORDERS,
    };

    use super::{ValidWalletCreateStatement, ValidWalletCreateWitness};

    /// Witness with default size parameters
    pub type SizedWitness = ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    /// Statement with default size parameters
    pub type SizedStatement = ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // -----------
    // | Helpers |
    // -----------

    /// Helper to get a zero'd out dummy wallet
    pub fn create_empty_wallet() -> SizedWallet {
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
    pub fn create_default_witness_statement() -> (SizedWitness, SizedStatement) {
        // Create a wallet and split it into secret shares
        let wallet = create_empty_wallet();
        create_witness_statement_from_wallet(&wallet)
    }

    /// Create a witness and statement from a given wallet
    pub fn create_witness_statement_from_wallet(
        wallet: &SizedWallet,
    ) -> (SizedWitness, SizedStatement) {
        let (private_shares, public_shares) = create_wallet_shares(wallet.clone());

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
}

#[cfg(test)]
pub mod tests {
    use circuit_types::traits::CircuitBaseType;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use mpc_stark::algebra::scalar::Scalar;
    use rand::thread_rng;

    use crate::{
        test_helpers::bulletproof_prove_and_verify,
        zk_circuits::{
            test_helpers::{INITIAL_BALANCES, INITIAL_ORDERS, MAX_BALANCES, MAX_FEES, MAX_ORDERS},
            valid_wallet_create::{
                test_helpers::create_default_witness_statement, ValidWalletCreate,
            },
        },
    };

    use super::test_helpers::{
        create_empty_wallet, create_witness_statement_from_wallet, SizedStatement, SizedWitness,
    };

    /// Asserts that a given witness, statement pair is invalid
    pub(super) fn assert_invalid_witness_statement(
        witness: SizedWitness,
        statement: SizedStatement,
    ) {
        // Create a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Allocate the witness and statement in the constraint system
        let mut rng = thread_rng();
        let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover);
        let statement_var = statement.commit_public(&mut prover);

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
