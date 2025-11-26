//! Defines the `VALID ORDER CANCELLATION` circuit
//!
//! This circuit proves that an order cancellation is valid. The circuit
//! verifies that the intent exists in the Merkle tree and that the nullifier
//! has been correctly computed. The contracts will then spend the nullifier to
//! mark the intent as cancelled.

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{
    Nullifier, PlonkCircuit,
    intent::DarkpoolStateIntent,
    merkle::{MerkleOpening, MerkleRoot},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{Variable, errors::CircuitError, traits::Circuit};
use serde::{Deserialize, Serialize};

use crate::{
    SingleProverCircuit,
    zk_gadgets::{
        CommitmentGadget, NullifierGadget, PoseidonMerkleHashGadget, ShareGadget,
        comparators::EqGadget,
    },
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `VALID ORDER CANCELLATION` circuit
pub struct ValidOrderCancellationCircuit<const MERKLE_HEIGHT: usize>;

/// The `VALID ORDER CANCELLATION` circuit with default const generic sizing
/// parameters
pub type SizedValidOrderCancellationCircuit = ValidOrderCancellationCircuit<MERKLE_HEIGHT>;

impl<const MERKLE_HEIGHT: usize> ValidOrderCancellationCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &ValidOrderCancellationStatementVar,
        witness: &ValidOrderCancellationWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Check that the intent exists in the Merkle tree
        let intent = &witness.old_intent;
        let old_intent_private_shares =
            ShareGadget::compute_complementary_shares(&intent.public_share, &intent.inner, cs)?;
        let old_intent_commitment =
            CommitmentGadget::compute_commitment(intent, &old_intent_private_shares, cs)?;

        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            old_intent_commitment,
            &witness.old_intent_opening,
            statement.merkle_root,
            cs,
        )?;

        // 2. Verify the computed nullifier matches the one in the statement
        let nullifier = NullifierGadget::compute_nullifier(intent, cs)?;
        EqGadget::constrain_eq(&nullifier, &statement.old_intent_nullifier, cs)?;

        // 3. Verify that the owner leaked in the statement matches the intent's owner
        EqGadget::constrain_eq(&intent.inner.owner, &statement.owner, cs)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID ORDER CANCELLATION`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidOrderCancellationWitness<const MERKLE_HEIGHT: usize> {
    /// The existing intent in the darkpool state
    pub old_intent: DarkpoolStateIntent,
    /// The Merkle opening proving the old intent exists in the tree
    pub old_intent_opening: MerkleOpening<MERKLE_HEIGHT>,
}

/// A `VALID ORDER CANCELLATION` witness with default const generic sizing
/// parameters
pub type SizedValidOrderCancellationWitness = ValidOrderCancellationWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID ORDER CANCELLATION`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidOrderCancellationStatement {
    /// The Merkle root to which the old intent opens
    pub merkle_root: MerkleRoot,
    /// The nullifier of the old intent
    pub old_intent_nullifier: Nullifier,
    /// The owner of the intent, leaked here to allow the contracts to verify
    /// that cancellation is authorized by the owner
    pub owner: Address,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for ValidOrderCancellationCircuit<MERKLE_HEIGHT>
{
    type Witness = ValidOrderCancellationWitness<MERKLE_HEIGHT>;
    type Statement = ValidOrderCancellationStatement;

    fn name() -> String {
        format!("Valid Order Cancellation ({MERKLE_HEIGHT})")
    }

    fn apply_constraints(
        witness_var: ValidOrderCancellationWitnessVar<MERKLE_HEIGHT>,
        statement_var: ValidOrderCancellationStatementVar,
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
    use circuit_types::intent::Intent;

    use crate::{
        test_helpers::{
            check_constraints_satisfied, create_merkle_opening, create_random_state_wrapper,
            random_intent,
        },
        zk_circuits::valid_order_cancellation::{
            SizedValidOrderCancellationCircuit, SizedValidOrderCancellationWitness,
        },
    };

    use super::{ValidOrderCancellationStatement, ValidOrderCancellationWitness};

    /// The height of the Merkle tree to test on
    const MERKLE_HEIGHT: usize = 10;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &SizedValidOrderCancellationWitness,
        statement: &ValidOrderCancellationStatement,
    ) -> bool {
        check_constraints_satisfied::<SizedValidOrderCancellationCircuit>(witness, statement)
    }

    /// Construct a witness and statement with valid data
    pub fn create_dummy_witness_statement()
    -> (SizedValidOrderCancellationWitness, ValidOrderCancellationStatement) {
        let intent = random_intent();
        create_dummy_witness_statement_with_intent(intent)
    }

    /// Create a dummy witness and statement with a given intent
    pub fn create_dummy_witness_statement_with_intent(
        intent: Intent,
    ) -> (SizedValidOrderCancellationWitness, ValidOrderCancellationStatement) {
        // Create the old intent with initial stream states
        let old_intent = create_random_state_wrapper(intent.clone());

        // Compute commitment and nullifier for the old intent
        let old_intent_commitment = old_intent.compute_commitment();
        let old_intent_nullifier = old_intent.compute_nullifier();

        // Create a Merkle opening for the old intent
        let (merkle_root, old_intent_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(old_intent_commitment);

        // Build the witness and statement
        let witness = ValidOrderCancellationWitness { old_intent, old_intent_opening };
        let statement = ValidOrderCancellationStatement {
            merkle_root,
            old_intent_nullifier,
            owner: intent.owner,
        };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use circuit_types::traits::SingleProverCircuit;

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = ValidOrderCancellationCircuit::<10>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_order_cancellation_constraints() {
        let (witness, statement) = test_helpers::create_dummy_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }
}
