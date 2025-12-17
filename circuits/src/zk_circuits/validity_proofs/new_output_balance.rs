//! Helpers for proving and validating proofs of NEW OUTPUT BALANCE VALIDITY
//!
//! This circuit proves the construction of a new balance to receive the output
//! of a match into.
//!
//! We authorize a new balance by bootstrapping off of an existing balance. This
//! establishes a chain of authorization from the owner's EOA through the
//! existing balance to the new balance. Practically speaking, new balances are
//! only created by a first fill of a Renegade settled intent, so an input
//! balance will be available to bootstrap from.

use circuit_macros::circuit_type;
use circuit_types::{
    PlonkCircuit,
    balance::{
        Balance, BalanceShareVar, DarkpoolStateBalance, DarkpoolStateBalanceVar,
        PostMatchBalanceShare, PreMatchBalanceShare,
    },
    merkle::{MerkleOpening, MerkleOpeningVar, MerkleRoot},
    schnorr::SchnorrSignature,
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
        PoseidonMerkleHashGadget,
        comparators::EqGadget,
        schnorr::SchnorrGadget,
        shares::ShareGadget,
        state_primitives::{CommitmentGadget, RecoveryIdGadget},
    },
};

/// The number of public shares to include in the partial commitment to the
/// updated balance
///
/// This is the set of shares that will not change after the match.
const NEW_BALANCE_PARTIAL_COMMITMENT_SIZE: usize =
    Balance::NUM_SCALARS - PostMatchBalanceShare::NUM_SCALARS;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `NEW OUTPUT BALANCE VALIDITY` circuit
pub struct NewOutputBalanceValidityCircuit<const MERKLE_HEIGHT: usize>;

/// The `NEW OUTPUT BALANCE VALIDITY` circuit with default const
/// generic sizing parameters
pub type SizedNewOutputBalanceValidityCircuit = NewOutputBalanceValidityCircuit<MERKLE_HEIGHT>;

impl<const MERKLE_HEIGHT: usize> NewOutputBalanceValidityCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &NewOutputBalanceValidityStatementVar,
        witness: &mut NewOutputBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // 1. Validate the newly created balance's fields
        Self::validate_new_balance(witness, cs)?;

        // 2. Validate the balance shares and build the private shares
        let private_shares = Self::validate_balance_shares(witness, statement, cs)?;

        // 3. Compute the recovery identifier for the new balance
        let mut balance = witness.new_balance.clone();
        let initial_balance = balance.clone();
        let recovery_id = RecoveryIdGadget::compute_recovery_id(&mut balance, cs)?;
        EqGadget::constrain_eq(&recovery_id, &statement.recovery_id, cs)?;

        // 4. Compute both the initial (full) and partial commitments together using the
        //    shared prefix gadget. The initial commitment uses the balance before
        //    recovery_id is computed, and the partial commitment uses the balance after
        //    recovery_id is computed
        let (new_balance_commitment, new_balance_partial_commitment) =
            CommitmentGadget::compute_partial_commitments_with_shared_prefix(
                NEW_BALANCE_PARTIAL_COMMITMENT_SIZE,
                &private_shares,
                &initial_balance,
                &private_shares,
                &balance,
                cs,
            )?;

        EqGadget::constrain_eq(
            &new_balance_partial_commitment,
            &statement.new_balance_partial_commitment,
            cs,
        )?;

        // 5. Authorize the new balance by verifying the existing balance's Merkle
        //    inclusion and checking the signature
        Self::authorize_new_balance(new_balance_commitment, witness, statement, cs)
    }

    /// Build the balance state wrapper
    ///
    /// Returns the private shares
    fn validate_balance_shares(
        witness: &NewOutputBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        statement: &NewOutputBalanceValidityStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<BalanceShareVar, CircuitError> {
        let balance = &witness.balance;
        let public_share = &witness.new_balance.public_share;

        // Compute the private shares for the balance
        let private_shares = ShareGadget::compute_complementary_shares(public_share, balance, cs)?;

        // Build the pre-match balance shares and check that they match the statement
        let pre_match_balance_shares = ShareGadget::build_pre_match_balance_share(public_share);
        EqGadget::constrain_eq(&pre_match_balance_shares, &statement.pre_match_balance_shares, cs)?;

        // Build the post-match balance shares
        let post_match_balance_shares = ShareGadget::build_post_match_balance_share(public_share);
        EqGadget::constrain_eq(&post_match_balance_shares, &witness.post_match_balance_shares, cs)?;

        Ok(private_shares)
    }

    /// Validate the newly created balance's fields
    fn validate_new_balance(
        witness: &NewOutputBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Check that the denormalize balance field matches the state element
        // We denormalize for proof linking, but prove authorization over the state
        // element
        let balance = &witness.balance;
        EqGadget::constrain_eq(balance, &witness.new_balance.inner, cs)?;

        let zero = cs.zero();
        // 1. The balance amount should be zero
        EqGadget::constrain_eq(&balance.amount, &zero, cs)?;

        // 2. The balance fees should be zero
        EqGadget::constrain_eq(&balance.relayer_fee_balance, &zero, cs)?;
        EqGadget::constrain_eq(&balance.protocol_fee_balance, &zero, cs)?;
        Ok(())
    }

    /// Authorize the new balance by verifying the existing balance's Merkle
    /// inclusion and checking the signature
    fn authorize_new_balance(
        new_balance_commitment: Variable,
        witness: &NewOutputBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        statement: &NewOutputBalanceValidityStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // First verify the Merkle opening for the existing balance
        Self::verify_existing_balance_merkle_opening(
            &witness.existing_balance,
            &witness.existing_balance_opening,
            statement.existing_balance_merkle_root,
            cs,
        )?;

        // Check the signature over the new balance's commitment
        let key = &witness.existing_balance.inner.authority;
        SchnorrGadget::verify_signature(
            &witness.new_balance_authorization_signature,
            &new_balance_commitment,
            key,
            cs,
        )?;

        // The new balance must match the existing balance in: owner, authority, and
        // relayer fee recipient
        let new_balance = &witness.balance;
        let existing_balance = &witness.existing_balance.inner;
        EqGadget::constrain_eq(&new_balance.owner, &existing_balance.owner, cs)?;
        EqGadget::constrain_eq(&new_balance.authority, &existing_balance.authority, cs)?;
        EqGadget::constrain_eq(
            &new_balance.relayer_fee_recipient,
            &existing_balance.relayer_fee_recipient,
            cs,
        )
    }

    /// Verify the Merkle opening for the existing balance
    fn verify_existing_balance_merkle_opening(
        existing_balance: &DarkpoolStateBalanceVar,
        opening: &MerkleOpeningVar<MERKLE_HEIGHT>,
        root: Variable,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Build a commitment to the existing balance
        let existing_balance_private_shares = ShareGadget::compute_complementary_shares(
            &existing_balance.public_share,
            &existing_balance.inner,
            cs,
        )?;
        let existing_balance_commitment = CommitmentGadget::compute_commitment(
            existing_balance,
            &existing_balance_private_shares,
            cs,
        )?;

        // Verify the Merkle opening
        PoseidonMerkleHashGadget::compute_and_constrain_root_prehashed(
            existing_balance_commitment,
            opening,
            root,
            cs,
        )
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `NEW OUTPUT BALANCE VALIDITY`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewOutputBalanceValidityWitness<const MERKLE_HEIGHT: usize> {
    // --- New Balance --- //
    /// The initial balance
    pub new_balance: DarkpoolStateBalance,
    /// The inner balance
    ///
    /// We duplicate this value here to proof-link the balance into the
    /// settlement circuit.
    #[link_groups = "output_balance_settlement_party0,output_balance_settlement_party1"]
    pub balance: Balance,
    /// The balance public shares which are updated in the settlement circuit
    ///
    /// These values are proof-linked into the settlement circuit
    #[link_groups = "output_balance_settlement_party0,output_balance_settlement_party1"]
    pub post_match_balance_shares: PostMatchBalanceShare,

    // --- Bootstrapping Balance --- //
    /// The existing input balance off of which we bootstrap the new balance's
    /// authorization
    pub existing_balance: DarkpoolStateBalance,
    /// The opening of the existing input balance to the Merkle root
    pub existing_balance_opening: MerkleOpening<MERKLE_HEIGHT>,
    /// A signature over the new balance's commitment by the existing balance's
    /// authority key
    pub new_balance_authorization_signature: SchnorrSignature,
}

/// A `NEW OUTPUT BALANCE VALIDITY` witness with default const
/// generic sizing parameters
pub type SizedNewOutputBalanceValidityWitness = NewOutputBalanceValidityWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `NEW OUTPUT BALANCE VALIDITY`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewOutputBalanceValidityStatement {
    /// The Merkle root to which the existing balance opens
    ///
    /// This balance bootstraps the new balance's authorization
    pub existing_balance_merkle_root: MerkleRoot,
    /// The pre-match balance shares for the new balance
    pub pre_match_balance_shares: PreMatchBalanceShare,
    /// A partial commitment to the new output balance
    pub new_balance_partial_commitment: PartialCommitment,
    /// The recovery identifier of the new output balance
    pub recovery_id: Scalar,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for NewOutputBalanceValidityCircuit<MERKLE_HEIGHT>
{
    type Witness = NewOutputBalanceValidityWitness<MERKLE_HEIGHT>;
    type Statement = NewOutputBalanceValidityStatement;

    fn name() -> String {
        format!("New Output Balance Validity ({MERKLE_HEIGHT})")
    }

    /// NEW OUTPUT BALANCE VALIDITY has one proof linking group:
    /// - output_balance_settlement: The linking group between NEW OUTPUT
    ///   BALANCE VALIDITY and the settlement circuits.
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
        mut witness_var: NewOutputBalanceValidityWitnessVar<MERKLE_HEIGHT>,
        statement_var: NewOutputBalanceValidityStatementVar,
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
    use crate::test_helpers::{
        check_constraints_satisfied, create_merkle_opening, create_random_state_wrapper,
        create_state_wrapper, random_balance, random_schnorr_keypair, random_zeroed_balance,
    };

    use super::*;

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints<const MERKLE_HEIGHT: usize>(
        witness: &NewOutputBalanceValidityWitness<MERKLE_HEIGHT>,
        statement: &NewOutputBalanceValidityStatement,
    ) -> bool {
        check_constraints_satisfied::<NewOutputBalanceValidityCircuit<MERKLE_HEIGHT>>(
            witness, statement,
        )
    }

    /// Create a witness and statement with default sizing generics
    pub fn create_sized_witness_statement()
    -> (SizedNewOutputBalanceValidityWitness, NewOutputBalanceValidityStatement) {
        // Create a random balance
        let balance_inner = random_zeroed_balance();
        create_witness_statement_with_balance::<MERKLE_HEIGHT>(balance_inner)
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>()
    -> (NewOutputBalanceValidityWitness<MERKLE_HEIGHT>, NewOutputBalanceValidityStatement) {
        // Create a random balance
        let balance_inner = random_zeroed_balance();
        create_witness_statement_with_balance::<MERKLE_HEIGHT>(balance_inner)
    }

    /// Construct a witness and statement with the given balance
    ///
    /// The balance must be zeroed (amount = 0, fees = 0) to satisfy the circuit
    /// constraints
    pub fn create_witness_statement_with_balance<const MERKLE_HEIGHT: usize>(
        mut balance_inner: Balance,
    ) -> (NewOutputBalanceValidityWitness<MERKLE_HEIGHT>, NewOutputBalanceValidityStatement) {
        let (private_key, public_key) = random_schnorr_keypair();

        balance_inner.amount = 0;
        balance_inner.relayer_fee_balance = 0;
        balance_inner.protocol_fee_balance = 0;
        balance_inner.authority = public_key;
        let mut balance = create_state_wrapper(balance_inner.clone());
        let initial_commitment = balance.compute_commitment();

        let mut existing_balance_inner = random_balance();
        existing_balance_inner.owner = balance_inner.owner;
        existing_balance_inner.authority = public_key;
        existing_balance_inner.relayer_fee_recipient = balance_inner.relayer_fee_recipient;
        let existing_balance = create_random_state_wrapper(existing_balance_inner);

        let existing_balance_commitment = existing_balance.compute_commitment();
        let (merkle_root, existing_balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(existing_balance_commitment);

        // Sign a commitment to the new balance
        let new_balance_authorization_signature = private_key.sign(&initial_commitment).unwrap();

        // Build the witness with the initial streams (before mutations)
        // We need to clone before computing recovery_id since that mutates the balance
        let new_balance = balance.clone();
        let post_match_balance_shares = PostMatchBalanceShare::from(balance.public_share.clone());
        let pre_match_balance_shares = PreMatchBalanceShare::from(balance.public_share.clone());

        // Compute the recovery identifier (mutates recovery_stream)
        let recovery_id = balance.compute_recovery_id();
        let new_balance_partial_commitment =
            balance.compute_partial_commitment(NEW_BALANCE_PARTIAL_COMMITMENT_SIZE);

        let witness = NewOutputBalanceValidityWitness {
            new_balance,
            balance: balance.inner,
            post_match_balance_shares,
            existing_balance,
            existing_balance_opening,
            new_balance_authorization_signature,
        };

        // Build the statement
        let statement = NewOutputBalanceValidityStatement {
            existing_balance_merkle_root: merkle_root,
            pre_match_balance_shares,
            new_balance_partial_commitment,
            recovery_id,
        };

        (witness, statement)
    }
}

#[cfg(test)]
mod test {
    use crate::test_helpers::{random_address, random_amount, random_scalar};

    use super::*;
    use circuit_types::{schnorr::SchnorrPrivateKey, traits::SingleProverCircuit};
    use rand::{Rng, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = SizedNewOutputBalanceValidityCircuit::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_new_output_balance_constraints() {
        let (witness, statement) = test_helpers::create_sized_witness_statement();
        assert!(test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    // --- Invalid Balance Tests --- //

    /// Test the case in which the balance amount is non-zero
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__non_zero_amount() {
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        witness.balance.amount = random_amount();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the relayer fee balance is non-zero
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__non_zero_relayer_fee_balance() {
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        witness.balance.relayer_fee_balance = random_amount();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the protocol fee balance is non-zero
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__non_zero_protocol_fee_balance() {
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        witness.balance.protocol_fee_balance = random_amount();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the balance's owner field doesn't match the
    /// existing balance
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__owner_mismatch() {
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        witness.balance.owner = random_address();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the balance's authority field doesn't match the
    /// existing balance
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__authority_mismatch() {
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        let (_, wrong_authority) = crate::test_helpers::random_schnorr_keypair();
        witness.balance.authority = wrong_authority;
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the balance's relayer fee recipient field doesn't
    /// match the existing balance
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__relayer_fee_recipient_mismatch() {
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        witness.balance.relayer_fee_recipient = random_address();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Statement Tests --- //

    /// Test the case in which the pre-match balance shares are modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_statement__pre_match_balance_shares_modified() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_sized_witness_statement();

        let mut shares = statement.pre_match_balance_shares.to_scalars();
        let idx = rng.gen_range(0..shares.len());
        shares[idx] = random_scalar();
        statement.pre_match_balance_shares =
            PreMatchBalanceShare::from_scalars(&mut shares.into_iter());

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the recovery ID is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_statement__recovery_id_modified() {
        let (witness, mut statement) = test_helpers::create_sized_witness_statement();

        statement.recovery_id = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the new balance partial commitment is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_statement__new_balance_partial_commitment_modified() {
        let (witness, mut statement) = test_helpers::create_sized_witness_statement();

        statement.new_balance_partial_commitment.private_commitment = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Witness Tests --- //

    /// Test the case in which the post-match balance shares are modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_witness__post_match_balance_shares_modified() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        let mut shares = witness.post_match_balance_shares.to_scalars();
        let idx = rng.gen_range(0..shares.len());
        shares[idx] = random_scalar();
        witness.post_match_balance_shares =
            PostMatchBalanceShare::from_scalars(&mut shares.into_iter());

        assert!(!test_helpers::check_constraints::<MERKLE_HEIGHT>(&witness, &statement));
    }

    /// Test the case in which the Merkle opening is corrupted
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_witness__merkle_opening_corrupted() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        let random_index = rng.gen_range(0..witness.existing_balance_opening.elems.len());
        witness.existing_balance_opening.elems[random_index] = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the signature is invalid
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_witness__invalid_signature() {
        let (mut witness, statement) = test_helpers::create_sized_witness_statement();

        // Create a signature with a different key
        let balance = witness.new_balance.clone();
        let bal_commitment = balance.compute_commitment();

        let wrong_private_key = SchnorrPrivateKey::random();
        let wrong_signature = wrong_private_key.sign(&bal_commitment).unwrap();
        witness.new_balance_authorization_signature = wrong_signature;
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }
}
