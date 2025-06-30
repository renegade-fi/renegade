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
    PlonkCircuit,
    traits::{BaseType, CircuitBaseType, CircuitVarType, SingleProverCircuit},
    wallet::{WalletShare, WalletVar},
};
use constants::{MAX_BALANCES, MAX_ORDERS};
use constants::{Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::zk_gadgets::wallet_operations::{FeeGadget, WalletGadget};

/// A type alias for an instantiation of this circuit with default generics
pub type SizedValidWalletCreate = ValidWalletCreate<MAX_BALANCES, MAX_ORDERS>;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuitry for the valid wallet create statement
#[derive(Clone, Debug)]
pub struct ValidWalletCreate<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
    ValidWalletCreate<MAX_BALANCES, MAX_ORDERS>
{
    /// Applies constraints to the constraint system specifying the statement of
    /// VALID WALLET CREATE
    fn circuit(
        statement: &ValidWalletCreateStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidWalletCreateWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Validate the commitment given in the statement is a valid commitment to the
        // wallet shares
        let commitment = WalletGadget::compute_wallet_share_commitment(
            &statement.public_wallet_shares,
            &witness.private_wallet_share,
            cs,
        )?;
        cs.enforce_equal(commitment, statement.wallet_share_commitment)?;

        // Check that the prover knows the blinder seed
        // This prevents a prover from choosing a blinder maliciously to block another
        // wallet
        let public_blinder = statement.public_wallet_shares.blinder;
        let blinder_seed = witness.blinder_seed;
        WalletGadget::<MAX_BALANCES, MAX_ORDERS>::validate_public_blinder_from_seed(
            public_blinder,
            blinder_seed,
            cs,
        )?;

        // Unblind the public shares then reconstruct the wallet
        let wallet = WalletGadget::wallet_from_shares(
            &statement.public_wallet_shares,
            &witness.private_wallet_share,
            cs,
        )?;

        // Verify that the match fee is a valid fee take
        FeeGadget::constrain_valid_fee(wallet.max_match_fee, cs)?;

        // Verify that the orders and balances are zero'd
        Self::verify_zero_wallet(wallet, cs)
    }

    /// Constrains a wallet to have all zero'd out orders and balances
    fn verify_zero_wallet(
        wallet: WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Constrain balances to be zero
        let zero = cs.zero();
        for balance_var in wallet.balances.into_iter().flat_map(|b| b.to_vars()) {
            cs.enforce_equal(balance_var, zero)?;
        }

        // Constrain orders to be zero
        for order_var in wallet.orders.into_iter().flat_map(|o| o.to_vars()) {
            cs.enforce_equal(order_var, zero)?;
        }

        // Constrain the keychain nonce to be zero
        cs.enforce_equal(wallet.keys.nonce, zero)?;
        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness for the VALID WALLET CREATE statement
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidWalletCreateWitness<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The private secret shares of the new wallet
    pub private_wallet_share: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The blinder seed, used to validate the construction of the blinder
    pub blinder_seed: Scalar,
}
/// A type alias that attached system-wide default generics to the witness type
pub type SizedValidWalletCreateWitness = ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for the `VALID WALLET CREATE` circuit
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidWalletCreateStatement<const MAX_BALANCES: usize, const MAX_ORDERS: usize> {
    /// The commitment to the secret shares of the wallet
    pub wallet_share_commitment: Scalar,
    /// The public secret shares of the wallet
    pub public_wallet_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
}
/// A type alias that attaches system-wide default generics to the statement
/// type
pub type SizedValidWalletCreateStatement = ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS>;

// ---------------------
// | Prove/Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidWalletCreate<MAX_BALANCES, MAX_ORDERS>
{
    type Statement = ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("Valid Wallet Create ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    fn apply_constraints(
        witness_var: ValidWalletCreateWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement_var: ValidWalletCreateStatementVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        balance::Balance, native_helpers::compute_wallet_share_commitment, order::Order,
    };
    use constants::Scalar;
    use rand::thread_rng;

    use crate::zk_circuits::test_helpers::{
        INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS, SizedWallet,
        create_wallet_shares_with_blinder_seed,
    };

    use super::{ValidWalletCreateStatement, ValidWalletCreateWitness};

    /// Witness with default size parameters
    pub type SizedWitness = ValidWalletCreateWitness<MAX_BALANCES, MAX_ORDERS>;
    /// Statement with default size parameters
    pub type SizedStatement = ValidWalletCreateStatement<MAX_BALANCES, MAX_ORDERS>;

    // -----------
    // | Helpers |
    // -----------

    /// Helper to get a zero'd out dummy wallet
    pub fn create_empty_wallet() -> SizedWallet {
        // Zero out the balances and orders of the dummy wallet
        let mut wallet = INITIAL_WALLET.clone();
        wallet.balances.iter_mut().for_each(|b| *b = Balance::default());
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
        let mut rng = thread_rng();
        let blinder_seed = Scalar::random(&mut rng);
        let mut wallet = wallet.clone();
        let (private_shares, public_shares) =
            create_wallet_shares_with_blinder_seed(&mut wallet, blinder_seed);

        // Build a commitment to the private secret shares
        let commitment = compute_wallet_share_commitment(&public_shares, &private_shares);

        // Prove and verify
        let witness =
            ValidWalletCreateWitness { private_wallet_share: private_shares, blinder_seed };
        let statement = ValidWalletCreateStatement {
            wallet_share_commitment: commitment,
            public_wallet_shares: public_shares,
        };

        (witness, statement)
    }
}

#[cfg(test)]
pub mod tests {
    use circuit_types::{FEE_BITS, fixed_point::FixedPoint, traits::SingleProverCircuit};
    use constants::Scalar;
    use rand::thread_rng;

    use crate::{
        singleprover_prove_and_verify,
        zk_circuits::{
            check_constraint_satisfaction,
            test_helpers::{INITIAL_BALANCES, INITIAL_ORDERS, MAX_BALANCES, MAX_ORDERS},
            valid_wallet_create::{
                ValidWalletCreate, test_helpers::create_default_witness_statement,
            },
        },
    };

    use super::test_helpers::{create_empty_wallet, create_witness_statement_from_wallet};

    /// A type alias for the circuit with testing parameters attached
    type SizedWalletCreate = ValidWalletCreate<MAX_BALANCES, MAX_ORDERS>;

    // ---------
    // | Tests |
    // ---------

    /// A helper test to print the number of constraints in the circuit
    ///
    /// Useful for benchmarking while modifying the circuit
    #[test]
    #[ignore]
    fn test_n_constraints() {
        let layout =
            ValidWalletCreate::<{ constants::MAX_BALANCES }, { constants::MAX_ORDERS }>::get_circuit_layout()
                .unwrap();
        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Tests that the circuit correctly verifies with valid zero'd balance and
    /// orders lists
    #[test]
    fn test_valid_initial_wallet() {
        let (witness, statement) = create_default_witness_statement();
        singleprover_prove_and_verify::<ValidWalletCreate<MAX_BALANCES, MAX_ORDERS>>(
            witness, statement,
        )
        .unwrap()
    }

    /// Tests the case in which the commitment to the private shares is
    /// incorrect
    #[test]
    fn test_invalid_commitment() {
        let (witness, mut statement) = create_default_witness_statement();
        statement.wallet_share_commitment += Scalar::from(1u8);

        assert!(!check_constraint_satisfaction::<SizedWalletCreate>(&witness, &statement))
    }

    /// Tests the case in which a non-zero order is given
    #[test]
    fn test_nonzero_order() {
        let mut wallet = create_empty_wallet();
        wallet.orders[0] = INITIAL_ORDERS[0].clone();

        let (witness, statement) = create_witness_statement_from_wallet(&wallet);
        assert!(!check_constraint_satisfaction::<SizedWalletCreate>(&witness, &statement));
    }

    /// Tests the case in which a non-zero balance is given
    #[test]
    fn test_nonzero_balance() {
        let mut wallet = create_empty_wallet();
        wallet.balances[0] = INITIAL_BALANCES[0].clone();

        let (witness, statement) = create_witness_statement_from_wallet(&wallet);
        assert!(!check_constraint_satisfaction::<SizedWalletCreate>(&witness, &statement));
    }

    /// Tests the case in which the keychain nonce is non-zero
    #[test]
    fn test_nonzero_nonce() {
        let mut wallet = create_empty_wallet();
        wallet.keys.nonce += Scalar::one();

        let (witness, statement) = create_witness_statement_from_wallet(&wallet);
        assert!(!check_constraint_satisfaction::<SizedWalletCreate>(&witness, &statement));
    }

    /// Test the case in which the match fee is invalid
    #[test]
    fn test_invalid_match_fee() {
        let mut wallet = create_empty_wallet();
        let fee_repr = Scalar::from(2u8).pow(FEE_BITS as u64); // max fee plus one
        wallet.max_match_fee = FixedPoint { repr: fee_repr };

        let (witness, statement) = create_witness_statement_from_wallet(&wallet);
        assert!(!check_constraint_satisfaction::<SizedWalletCreate>(&witness, &statement));
    }

    /// Test the case in which the public blinder is not correctly constructed
    /// from the blinder seed
    #[test]
    fn test_invalid_public_blinder() {
        let mut rng = thread_rng();
        let (mut witness, statement) = create_default_witness_statement();
        witness.blinder_seed = Scalar::random(&mut rng);

        assert!(!check_constraint_satisfaction::<SizedWalletCreate>(&witness, &statement));
    }
}
