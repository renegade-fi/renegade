//! Defines the `INTENT AND BALANCE VALIDITY` circuit
//!
//! This circuit proves that a given intent and balance pair is valid for a
//! subsequent fill (not the first fill) of an intent. The intent is validated
//! by its presence in the Merkle tree via a Merkle opening. The balance is also
//! validated via a Merkle opening. Unlike the first fill circuit, we do not
//! rotate the one-time authorizing key on the balance.

use circuit_macros::circuit_type;
use circuit_types::{
    Nullifier, PlonkCircuit,
    merkle::{MerkleOpening, MerkleRoot},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
};
use constants::{MERKLE_HEIGHT, Scalar, ScalarField};
use darkpool_types::{
    balance::{
        DarkpoolBalance, DarkpoolBalanceShareVar, DarkpoolStateBalance, DarkpoolStateBalanceVar,
        PostMatchBalanceShare, PostMatchBalanceShareVar,
    },
    intent::{DarkpoolStateIntent, DarkpoolStateIntentVar, Intent, IntentShare, IntentShareVar},
    state_wrapper::PartialCommitment,
};
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
    zk_circuits::{
        settlement::{
            INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK, INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK,
            intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit,
        },
        validity_proofs::intent_and_balance_first_fill::BALANCE_PARTIAL_COMMITMENT_SIZE,
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

/// The number of shares in the partial commitment for the intent
///
/// We omit the `amount_in` share (last share of the `Intent` type) as this will
/// be updated in the match settlement.
pub const INTENT_PARTIAL_COMMITMENT_SIZE: usize = IntentShare::NUM_SCALARS - 1;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT AND BALANCE VALIDITY` circuit
pub struct IntentAndBalanceValidityCircuit<const MERKLE_HEIGHT: usize>;

/// The `INTENT AND BALANCE VALIDITY` circuit with default const generic sizing
/// parameters
pub type SizedIntentAndBalanceValidityCircuit = IntentAndBalanceValidityCircuit<MERKLE_HEIGHT>;

impl<const MERKLE_HEIGHT: usize> IntentAndBalanceValidityCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentAndBalanceValidityStatementVar,
        witness: &mut IntentAndBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Validate the intent
        Self::validate_intent(witness, statement, cs)?;

        // 2. Validate the balance
        Self::validate_balance(witness, statement, cs)?;

        // 3. Verify the intent <-> balance cross-constraints
        // - The input token of the intent must match the mint of the balance
        // - The owner of the intent must match the owner of the balance
        EqGadget::constrain_eq(&witness.intent.in_token, &witness.balance.mint, cs)?;
        EqGadget::constrain_eq(&witness.intent.owner, &witness.balance.owner, cs)
    }

    // --- Intent Constraints --- //

    /// Validate the intent
    fn validate_intent(
        witness: &IntentAndBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        statement: &IntentAndBalanceValidityStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Bind the denormalized intent to the one in the state element
        EqGadget::constrain_eq(&witness.intent, &witness.old_intent.inner, cs)?;

        // Recover the private shares for the old intent
        let old_private_shares = ShareGadget::compute_complementary_shares(
            &witness.old_intent.public_share,
            &witness.old_intent.inner,
            cs,
        )?;

        // Build the new intent
        let (new_intent, new_intent_private_shares) =
            Self::build_new_intent(&old_private_shares, witness, cs)?;

        // Verify rotation
        let mut rotation_args = StateElementRotationArgsWithPartialCommitment {
            old_version: witness.old_intent.clone(),
            old_private_share: old_private_shares,
            old_opening: witness.old_intent_opening.clone(),
            merkle_root: statement.intent_merkle_root,
            nullifier: statement.old_intent_nullifier,
            new_version: new_intent,
            new_private_share: new_intent_private_shares,
            new_partial_commitment: statement.new_intent_partial_commitment.clone(),
            recovery_id: statement.intent_recovery_id,
        };

        StateElementRotationGadget::rotate_version_with_partial_commitment(
            INTENT_PARTIAL_COMMITMENT_SIZE,
            &mut rotation_args,
            cs,
        )
    }

    /// Build the new intent
    ///
    /// Returns the new intent and its private shares
    fn build_new_intent(
        private_shares: &IntentShareVar,
        witness: &IntentAndBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateIntentVar, IntentShareVar), CircuitError> {
        let mut new_intent = witness.old_intent.clone();
        let mut new_intent_private_shares = private_shares.clone();

        // Re-encrypt the `amount_in` field
        let (new_amount_private_share, new_amount_public_share) =
            StreamCipherGadget::encrypt::<Variable>(
                &new_intent.inner.amount_in,
                &mut new_intent.share_stream,
                cs,
            )?;
        new_intent_private_shares.amount_in = new_amount_private_share;
        new_intent.public_share.amount_in = new_amount_public_share;
        EqGadget::constrain_eq(&new_amount_public_share, &witness.new_amount_public_share, cs)?;

        Ok((new_intent, new_intent_private_shares))
    }

    // --- Balance Constraints --- //

    /// Validate the balance
    fn validate_balance(
        witness: &IntentAndBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        statement: &IntentAndBalanceValidityStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Bind the denormalized balance to the one in the state element
        EqGadget::constrain_eq(&witness.balance, &witness.old_balance.inner, cs)?;

        // Recover the private shares for the old balance
        let old_private_shares = ShareGadget::compute_complementary_shares(
            &witness.old_balance.public_share,
            &witness.old_balance.inner,
            cs,
        )?;

        // Build the new balance
        let (new_balance, new_balance_private_shares) =
            Self::build_new_balance(&old_private_shares, witness, cs)?;

        // Verify rotation
        let mut rotation_args = StateElementRotationArgsWithPartialCommitment {
            old_version: witness.old_balance.clone(),
            old_private_share: old_private_shares,
            old_opening: witness.old_balance_opening.clone(),
            merkle_root: statement.balance_merkle_root,
            nullifier: statement.old_balance_nullifier,
            new_version: new_balance,
            new_private_share: new_balance_private_shares,
            new_partial_commitment: statement.balance_partial_commitment.clone(),
            recovery_id: statement.balance_recovery_id,
        };

        StateElementRotationGadget::rotate_version_with_partial_commitment(
            BALANCE_PARTIAL_COMMITMENT_SIZE,
            &mut rotation_args,
            cs,
        )
    }

    /// Build the new balance
    fn build_new_balance(
        private_shares: &DarkpoolBalanceShareVar,
        witness: &IntentAndBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, DarkpoolBalanceShareVar), CircuitError> {
        let mut new_balance = witness.old_balance.clone();
        let mut new_balance_private_shares = private_shares.clone();

        // Re-encrypt the `amount` field
        let post_match_balance = ShareGadget::build_post_match_balance(&new_balance.inner);
        let (new_private_share, new_public_share) =
            StreamCipherGadget::encrypt::<PostMatchBalanceShareVar>(
                &post_match_balance,
                &mut new_balance.share_stream,
                cs,
            )?;

        // Apply the re-encrypted post-match balance shares to the private shares
        ShareGadget::update_balance_share_post_match(
            &mut new_balance_private_shares,
            &new_private_share,
        );
        ShareGadget::update_balance_share_post_match(
            &mut new_balance.public_share,
            &new_public_share,
        );

        // Constrain the post-match public shares in the witness
        EqGadget::constrain_eq(&new_public_share, &witness.post_match_balance_shares, cs)?;
        Ok((new_balance, new_balance_private_shares))
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `INTENT AND BALANCE VALIDITY`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalanceValidityWitness<const MERKLE_HEIGHT: usize> {
    // --- Intent --- //
    /// The existing intent in the darkpool state
    pub old_intent: DarkpoolStateIntent,
    /// The Merkle opening proving the old intent exists in the tree
    pub old_intent_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The intent which this circuit is settling a match for
    ///
    /// This value is denormalized from the `old_intent` to enable proof linking
    /// between this circuit's witness and the `INTENT AND BALANCE PUBLIC
    /// SETTLEMENT` circuit's witness.
    #[link_groups = "intent_and_balance_settlement_party0,intent_and_balance_settlement_party1"]
    pub intent: Intent,
    /// The new public share of the `amount_in` field after the value has been
    /// re-encrypted. This value appears only in the witness and is proof-linked
    /// into the settlement proof. Doing so prevents the verifier from learning
    /// the pre- and post- public share or the `amount_in` field which would
    /// leak the match size.
    #[link_groups = "intent_and_balance_settlement_party0,intent_and_balance_settlement_party1"]
    pub new_amount_public_share: Scalar,

    // --- Balance --- //
    /// The existing balance in the darkpool state
    pub old_balance: DarkpoolStateBalance,
    /// The Merkle opening proving the old balance exists in the tree
    pub old_balance_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// The balance which capitalizes the intent
    #[link_groups = "intent_and_balance_settlement_party0,intent_and_balance_settlement_party1"]
    pub balance: DarkpoolBalance,
    /// The updated public shares of the post-match balance
    #[link_groups = "intent_and_balance_settlement_party0,intent_and_balance_settlement_party1"]
    pub post_match_balance_shares: PostMatchBalanceShare,
}

/// A `INTENT AND BALANCE VALIDITY` witness with default const generic sizing
/// parameters
pub type SizedIntentAndBalanceValidityWitness = IntentAndBalanceValidityWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT AND BALANCE VALIDITY`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalanceValidityStatement {
    // --- Intent --- //
    /// The Merkle root to which the old intent opens
    pub intent_merkle_root: MerkleRoot,
    /// The nullifier of the old intent
    pub old_intent_nullifier: Nullifier,
    /// A partial commitment to the new intent
    ///
    /// We omit the public share of the `amount_in` field here as this will
    /// change _during_ the match settlement. Instead, we commit to _all_
    /// private shares and _all_ public shares other than the `amount_in`
    /// field.
    pub new_intent_partial_commitment: PartialCommitment,
    /// The recovery identifier of the new intent
    pub intent_recovery_id: Scalar,

    // --- Balance --- //
    /// The Merkle root to which the old balance opens
    pub balance_merkle_root: MerkleRoot,
    /// The nullifier of the old balance
    pub old_balance_nullifier: Nullifier,
    /// The partial commitment to the new balance
    pub balance_partial_commitment: PartialCommitment,
    /// The recovery identifier of the new balance
    pub balance_recovery_id: Scalar,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for IntentAndBalanceValidityCircuit<MERKLE_HEIGHT>
{
    type Witness = IntentAndBalanceValidityWitness<MERKLE_HEIGHT>;
    type Statement = IntentAndBalanceValidityStatement;

    fn name() -> String {
        format!("Intent And Balance Validity ({MERKLE_HEIGHT})")
    }

    /// INTENT AND BALANCE VALIDITY has two proof linking groups:
    /// - intent_and_balance_settlement_party0: The linking group between INTENT
    ///   AND BALANCE VALIDITY and the first party's intent and balance
    /// - intent_and_balance_settlement_party1: The linking group between INTENT
    ///   AND BALANCE VALIDITY and the second party's intent and balance
    ///
    /// This circuit inherits the group layouts from the private settlement
    /// circuit.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout()?;
        let group_layout0 = layout.get_group_layout(INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK);
        let group_layout1 = layout.get_group_layout(INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK);
        Ok(vec![
            (INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK.to_string(), Some(group_layout0)),
            (INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK.to_string(), Some(group_layout1)),
        ])
    }

    fn apply_constraints(
        mut witness_var: IntentAndBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        statement_var: IntentAndBalanceValidityStatementVar,
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
    use darkpool_types::{
        balance::{DarkpoolStateBalance, PostMatchBalance},
        intent::Intent,
    };

    use crate::{
        test_helpers::{
            check_constraints_satisfied, create_merkle_opening, create_random_state_wrapper,
            random_intent,
        },
        zk_circuits::validity_proofs::{
            intent_and_balance::{
                INTENT_PARTIAL_COMMITMENT_SIZE, IntentAndBalanceValidityCircuit,
                IntentAndBalanceValidityStatement, IntentAndBalanceValidityWitness,
            },
            intent_and_balance_first_fill::{
                BALANCE_PARTIAL_COMMITMENT_SIZE, test_helpers::create_matching_balance_for_intent,
            },
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints<const MERKLE_HEIGHT: usize>(
        witness: &IntentAndBalanceValidityWitness<MERKLE_HEIGHT>,
        statement: &IntentAndBalanceValidityStatement,
    ) -> bool {
        check_constraints_satisfied::<IntentAndBalanceValidityCircuit<MERKLE_HEIGHT>>(
            witness, statement,
        )
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>()
    -> (IntentAndBalanceValidityWitness<MERKLE_HEIGHT>, IntentAndBalanceValidityStatement) {
        let intent = random_intent();
        create_witness_statement_with_intent::<MERKLE_HEIGHT>(intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent<const MERKLE_HEIGHT: usize>(
        intent: Intent,
    ) -> (IntentAndBalanceValidityWitness<MERKLE_HEIGHT>, IntentAndBalanceValidityStatement) {
        let (balance, _key) = create_matching_balance_for_intent(&intent);
        create_witness_statement_with_intent_and_balance::<MERKLE_HEIGHT>(intent, &balance)
    }

    /// Create a witness and statement with the given intent and balance
    pub fn create_witness_statement_with_intent_and_balance<const MERKLE_HEIGHT: usize>(
        intent: Intent,
        balance: &DarkpoolStateBalance,
    ) -> (IntentAndBalanceValidityWitness<MERKLE_HEIGHT>, IntentAndBalanceValidityStatement) {
        // Create the old intent with initial stream states
        let old_intent = create_random_state_wrapper(intent.clone());

        // Compute commitment and nullifier for the old intent
        let old_intent_commitment = old_intent.compute_commitment();
        let old_intent_nullifier = old_intent.compute_nullifier();

        // Create a Merkle opening for the old intent
        let (intent_merkle_root, old_intent_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(old_intent_commitment);

        // Create a new intent which re-encrypts the `amount_in` field
        let mut new_intent = old_intent.clone();
        let new_amount = new_intent.inner.amount_in;
        let new_amount_public_share = new_intent.stream_cipher_encrypt(&new_amount);
        new_intent.public_share.amount_in = new_amount_public_share;

        // Compute recovery_id and partial commitment for the new intent
        let intent_recovery_id = new_intent.compute_recovery_id();
        let new_intent_partial_commitment =
            new_intent.compute_partial_commitment(INTENT_PARTIAL_COMMITMENT_SIZE);

        // Compute the state rotation information for the old balance
        let old_balance_nullifier = balance.compute_nullifier();
        let balance_commitment = balance.compute_commitment();
        let (balance_merkle_root, old_balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(balance_commitment);

        // Create a new balance with updated post-match shares
        let mut new_balance = balance.clone();
        let post_match_balance = PostMatchBalance::from(balance.inner.clone());
        let post_match_balance_shares = new_balance.stream_cipher_encrypt(&post_match_balance);

        // Update the balance's public_share to include the re-encrypted post-match
        // shares. This matches what the circuit does in build_and_validate_balance
        new_balance.update_from_post_match(&post_match_balance_shares);

        // Compute the partial commitment for the new balance
        let balance_recovery_id = new_balance.compute_recovery_id();
        let balance_partial_commitment =
            new_balance.compute_partial_commitment(BALANCE_PARTIAL_COMMITMENT_SIZE);

        // Build the witness
        let witness = IntentAndBalanceValidityWitness {
            old_intent,
            old_intent_opening,
            intent,
            new_amount_public_share,
            old_balance: balance.clone(),
            old_balance_opening,
            balance: new_balance.inner,
            post_match_balance_shares,
        };
        let statement = IntentAndBalanceValidityStatement {
            intent_merkle_root,
            old_intent_nullifier,
            new_intent_partial_commitment,
            intent_recovery_id,
            balance_merkle_root,
            old_balance_nullifier,
            balance_partial_commitment,
            balance_recovery_id,
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
        let layout =
            IntentAndBalanceValidityCircuit::<MERKLE_HEIGHT>::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_and_balance_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    // --- Invalid Intent Tests --- //

    /// Test the case in which the denormalized intent does not match the one in
    /// the state element
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__denormalized_intent_mismatch() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        let mut intent_scalars = witness.intent.to_scalars();
        let idx = rng.gen_range(0..intent_scalars.len());
        intent_scalars[idx] = random_scalar();
        witness.intent = Intent::from_scalars(&mut intent_scalars.into_iter());
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the new amount public share does not match the
    /// one in the witness
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__new_amount_public_share_mismatch() {
        let (mut witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();
        witness.new_amount_public_share = random_scalar();
        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    // --- Invalid Balance Tests --- //

    /// Test the case in which the denormalized balance does not match the one
    /// in the state element
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__denormalized_balance_mismatch() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_witness_statement::<MERKLE_HEIGHT>();

        let mut balance_scalars = witness.balance.to_scalars();
        let idx = rng.gen_range(0..balance_scalars.len());
        balance_scalars[idx] = random_scalar();
        witness.balance = DarkpoolBalance::from_scalars(&mut balance_scalars.into_iter());

        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the post-match balance shares in the witness
    /// don't match those computed in the circuit
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

    // State rotation test cases are covered in the test cases for the
    // `StateElementRotationGadget` test suite
}
