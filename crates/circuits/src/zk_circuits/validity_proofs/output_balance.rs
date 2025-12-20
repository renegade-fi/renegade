//! Define the `OUTPUT BALANCE VALIDITY` circuit
//!
//! This circuit proves that a given output balance is valid. The output balance
//! is validated via a Merkle opening.

use circuit_macros::circuit_type;
use circuit_types::{
    Nullifier, PlonkCircuit,
    balance::{
        Balance, BalanceShareVar, DarkpoolStateBalance, DarkpoolStateBalanceVar,
        PostMatchBalanceShare,
    },
    merkle::{MerkleOpening, MerkleRoot},
    state_wrapper::PartialCommitment,
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{
    Variable,
    errors::CircuitError,
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
};
use serde::{Deserialize, Serialize};

use crate::{
    SingleProverCircuit,
    zk_circuits::settlement::{
        OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK, OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK,
        intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit,
    },
    zk_gadgets::{
        comparators::EqGadget,
        shares::ShareGadget,
        state_rotation::{
            StateElementRotationArgsWithPartialCommitment, StateElementRotationGadget,
        },
        stream_cipher::StreamCipherGadget,
    },
};

/// The size of the partial commitment to the balance
const BALANCE_PARTIAL_COMMITMENT_SIZE: usize =
    Balance::NUM_SCALARS - PostMatchBalanceShare::NUM_SCALARS;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `OUTPUT BALANCE VALIDITY` circuit
pub struct OutputBalanceValidityCircuit<const MERKLE_HEIGHT: usize>;

/// The `OUTPUT BALANCE VALIDITY` circuit with default const generic sizing
/// parameters
pub type SizedOutputBalanceValidityCircuit = OutputBalanceValidityCircuit<MERKLE_HEIGHT>;

impl<const MERKLE_HEIGHT: usize> OutputBalanceValidityCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    #[allow(unused_variables)]
    pub fn circuit(
        statement: &OutputBalanceValidityStatementVar,
        witness: &mut OutputBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Recover the implied private shares from the base type
        let private_shares = ShareGadget::compute_complementary_shares(
            &witness.old_balance.public_share,
            &witness.old_balance.inner,
            cs,
        )?;

        // Create a new balance element
        let (new_balance, new_private_shares) =
            Self::build_new_balance(&private_shares, witness, cs)?;

        // Verify rotation
        let mut rotation_args = StateElementRotationArgsWithPartialCommitment {
            old_version: witness.old_balance.clone(),
            old_private_share: private_shares,
            old_opening: witness.balance_opening.clone(),
            merkle_root: statement.merkle_root,
            nullifier: statement.old_balance_nullifier,
            new_version: new_balance,
            new_private_share: new_private_shares,
            new_partial_commitment: statement.new_partial_commitment.clone(),
            recovery_id: statement.recovery_id,
        };
        StateElementRotationGadget::rotate_version_with_partial_commitment(
            BALANCE_PARTIAL_COMMITMENT_SIZE,
            &mut rotation_args,
            cs,
        )?;

        Ok(())
    }

    /// Create a new balance element
    ///
    /// Returns the new balance and private shares.
    fn build_new_balance(
        private_shares: &BalanceShareVar,
        witness: &OutputBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, BalanceShareVar), CircuitError> {
        let mut new_balance = witness.old_balance.clone();
        let mut new_balance_private_shares = private_shares.clone();

        // Re-encrypt the amount and fees fields as they'll change during the match
        let post_match_balance = ShareGadget::build_post_match_balance(&new_balance.inner);
        let (new_private_share, new_public_share) =
            StreamCipherGadget::encrypt(&post_match_balance, &mut new_balance.share_stream, cs)?;
        ShareGadget::update_balance_share_post_match(
            &mut new_balance_private_shares,
            &new_private_share,
        );
        ShareGadget::update_balance_share_post_match(
            &mut new_balance.public_share,
            &new_public_share,
        );

        // Constrain the denormalized balance fields in the witness
        EqGadget::constrain_eq(&new_public_share, &witness.post_match_balance_shares, cs)?;
        EqGadget::constrain_eq(&new_balance.inner, &witness.balance, cs)?;
        Ok((new_balance, new_balance_private_shares))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `OUTPUT BALANCE VALIDITY`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputBalanceValidityWitness<const MERKLE_HEIGHT: usize> {
    /// The output balance
    pub old_balance: DarkpoolStateBalance,
    /// The Merkle opening proving the output balance exists in the tree
    pub balance_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// A denormalized copy of the balance
    ///
    /// Places here to proof-link the circuit into the settlement circuit.
    #[link_groups = "output_balance_settlement_party0,output_balance_settlement_party1"]
    pub balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    ///
    /// These values are proof-linked into the settlement circuit.
    #[link_groups = "output_balance_settlement_party0,output_balance_settlement_party1"]
    pub post_match_balance_shares: PostMatchBalanceShare,
}

/// A `OUTPUT BALANCE VALIDITY` witness with default const generic sizing
/// parameters
pub type SizedOutputBalanceValidityWitness = OutputBalanceValidityWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `OUTPUT BALANCE VALIDITY`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutputBalanceValidityStatement {
    // The Merkle root to which the balance opens
    pub merkle_root: MerkleRoot,
    /// The nullifier of the balance
    pub old_balance_nullifier: Nullifier,
    /// The partial commitment to the balance
    pub new_partial_commitment: PartialCommitment,
    /// The recovery identifier of the balance
    pub recovery_id: Scalar,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for OutputBalanceValidityCircuit<MERKLE_HEIGHT>
{
    type Witness = OutputBalanceValidityWitness<MERKLE_HEIGHT>;
    type Statement = OutputBalanceValidityStatement;

    fn name() -> String {
        format!("Output Balance Validity ({MERKLE_HEIGHT})")
    }

    /// This circuit has one proof linking group:
    /// - output_balance_settlement: The linking group between OUTPUT BALANCE
    ///   VALIDITY and the settlement circuits.
    ///
    /// The layout for this group is inherited from the settlement circuit.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let circuit_layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout()?;
        let group_layout0 = circuit_layout.get_group_layout(OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK);
        let group_layout1 = circuit_layout.get_group_layout(OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK);

        Ok(vec![
            (OUTPUT_BALANCE_SETTLEMENT_PARTY0_LINK.to_string(), Some(group_layout0)),
            (OUTPUT_BALANCE_SETTLEMENT_PARTY1_LINK.to_string(), Some(group_layout1)),
        ])
    }

    fn apply_constraints(
        mut witness_var: OutputBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        statement_var: OutputBalanceValidityStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &mut witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::balance::PostMatchBalance;

    use crate::test_helpers::{
        check_constraints_satisfied, create_merkle_opening, create_random_state_wrapper,
        random_balance,
    };

    use super::*;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints<const MERKLE_HEIGHT: usize>(
        witness: &OutputBalanceValidityWitness<MERKLE_HEIGHT>,
        statement: &OutputBalanceValidityStatement,
    ) -> bool {
        check_constraints_satisfied::<OutputBalanceValidityCircuit<MERKLE_HEIGHT>>(
            witness, statement,
        )
    }

    /// Construct a witness and statement with valid data using a random balance
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>()
    -> (OutputBalanceValidityWitness<MERKLE_HEIGHT>, OutputBalanceValidityStatement) {
        create_witness_statement_with_balance::<MERKLE_HEIGHT>(random_balance())
    }

    /// Construct a witness and statement with valid data using the provided
    /// balance
    pub fn create_witness_statement_with_balance<const MERKLE_HEIGHT: usize>(
        balance_inner: Balance,
    ) -> (OutputBalanceValidityWitness<MERKLE_HEIGHT>, OutputBalanceValidityStatement) {
        let old_balance = create_random_state_wrapper(balance_inner.clone());

        // Compute commitment, nullifier, and create Merkle opening for the balance
        let balance_commitment = old_balance.compute_commitment();
        let old_balance_nullifier = old_balance.compute_nullifier();
        let (merkle_root, balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(balance_commitment);

        // Create a new balance with updated post-match shares
        let mut new_balance = old_balance.clone();
        let post_match_balance = PostMatchBalance::from(balance_inner.clone());
        let post_match_balance_shares = new_balance.stream_cipher_encrypt(&post_match_balance);

        // Update the balance's public_share to include the re-encrypted shares
        new_balance.update_from_post_match(&post_match_balance_shares);

        // Compute recovery_id and partial commitment for the new balance
        let recovery_id = new_balance.compute_recovery_id();
        let new_partial_commitment =
            new_balance.compute_partial_commitment(super::BALANCE_PARTIAL_COMMITMENT_SIZE);

        // Build the witness
        let witness = OutputBalanceValidityWitness {
            old_balance,
            balance_opening,
            balance: balance_inner,
            post_match_balance_shares,
        };

        // Build the statement
        let statement = OutputBalanceValidityStatement {
            merkle_root,
            old_balance_nullifier,
            new_partial_commitment,
            recovery_id,
        };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::random_scalar;

    use super::*;
    use circuit_types::traits::SingleProverCircuit;
    use constants::MERKLE_HEIGHT;
    use rand::{Rng, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = OutputBalanceValidityCircuit::<MERKLE_HEIGHT>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_output_balance_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    // --- Invalid Proof Linking Fields --- //

    /// Test the case in which the denormalized balance fields do not match the
    /// state element
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__denormalized_balance_mismatch() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        // Modify a field on the balance
        let mut balance_scalars = witness.balance.to_scalars();
        let idx = rng.gen_range(0..balance_scalars.len());
        balance_scalars[idx] = random_scalar();
        witness.balance = Balance::from_scalars(&mut balance_scalars.into_iter());

        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the post-match balance shares do not match the
    /// ones computed in the circuit
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__post_match_balance_shares_mismatch() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        let mut post_match_balance_shares = witness.post_match_balance_shares.to_scalars();
        let idx = rng.gen_range(0..post_match_balance_shares.len());
        post_match_balance_shares[idx] = random_scalar();
        witness.post_match_balance_shares =
            PostMatchBalanceShare::from_scalars(&mut post_match_balance_shares.into_iter());

        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    // The rest of the test cases are covered in the test cases for the
    // `StateElementRotationGadget` test suite
}
