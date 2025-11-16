//! Defines the `INTENT AND BALANCE FIRST FILL VALIDITY` circuit
//!
//! This circuit proves that a given intent and balance pair is valid for the
//! first fill of an intent. We must authorize the intent without leaking the
//! owner of the intent in this case. To do so, we leak the one-time authorizing
//! key on the balance and allow the user to rotate it. A signature is checked
//! on the intent's commitment and the new one-time authorizing key by the
//! leaked key.

use alloy_primitives::Address;
use circuit_macros::circuit_type;
use circuit_types::{
    Commitment, Nullifier, PlonkCircuit,
    balance::{
        Balance, BalanceShareVar, DarkpoolStateBalance, DarkpoolStateBalanceVar, PostMatchBalance,
        PostMatchBalanceShare, PostMatchBalanceShareVar,
    },
    csprng::PoseidonCSPRNG,
    intent::{DarkpoolStateIntentVar, Intent, IntentShare, PreMatchIntentShare},
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
        INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK, INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK,
        intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit,
    },
    zk_gadgets::{
        ShareGadget, StateElementRotationArgsWithPartialCommitment, StateElementRotationGadget,
        StreamCipherGadget,
        comparators::EqGadget,
        poseidon::PoseidonHashGadget,
        primitives::bitlength::{AmountGadget, PriceGadget},
        state_primitives::{CommitmentGadget, RecoveryIdGadget},
    },
};

/// The size of the partial commitment to the balance
pub const BALANCE_PARTIAL_COMMITMENT_SIZE: usize =
    Balance::NUM_SCALARS - PostMatchBalance::NUM_SCALARS;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The `INTENT AND BALANCE FIRST FILL VALIDITY` circuit
pub struct IntentAndBalanceFirstFillValidityCircuit<const MERKLE_HEIGHT: usize>;

/// The `INTENT AND BALANCE FIRST FILL VALIDITY` circuit with default const
/// generic sizing parameters
pub type SizedIntentAndBalanceFirstFillValidityCircuit =
    IntentAndBalanceFirstFillValidityCircuit<MERKLE_HEIGHT>;

impl<const MERKLE_HEIGHT: usize> IntentAndBalanceFirstFillValidityCircuit<MERKLE_HEIGHT> {
    /// Apply the circuit constraints to a given constraint system
    pub fn circuit(
        statement: &IntentAndBalanceFirstFillValidityStatementVar,
        witness: &mut IntentAndBalanceFirstFillValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Validate the intent and balance
        Self::validate_balance(statement, witness, cs)?;
        let original_intent_commitment = Self::build_and_validate_intent(statement, witness, cs)?;

        // Validate hte commitment to the intent and the one-time authorizing address
        let mut hasher = PoseidonHashGadget::new(cs.zero());
        let expected_commitment =
            hasher.hash(&[original_intent_commitment, witness.new_one_time_address], cs)?;
        EqGadget::constrain_eq(
            &expected_commitment,
            &statement.intent_and_authorizing_address_commitment,
            cs,
        )?;

        Ok(())
    }

    // --- Intent Constraints --- //

    /// Validate the intent
    ///
    /// Returns the commitment to the original intent
    fn build_and_validate_intent(
        statement: &IntentAndBalanceFirstFillValidityStatementVar,
        witness: &mut IntentAndBalanceFirstFillValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        // Verify the intent's fields
        Self::verify_intent_fields(witness, cs)?;

        // Build the intent state wrapper and verify its recovery ID
        let original_intent = Self::build_intent_state_wrapper(statement, witness, cs)?;
        let mut new_intent = original_intent.clone();
        let recovery_id = RecoveryIdGadget::compute_recovery_id(&mut new_intent, cs)?;
        EqGadget::constrain_eq(&recovery_id, &statement.intent_recovery_id, cs)?;

        // Verify the intent's commitments
        Self::compute_and_verify_intent_commitments(
            &original_intent,
            &new_intent,
            witness,
            statement,
            cs,
        )
    }

    // Verify the intent's construction
    fn verify_intent_fields(
        witness: &IntentAndBalanceFirstFillValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let intent = &witness.intent;
        let balance = &witness.balance;

        // The intent and balance must have the same owner
        EqGadget::constrain_eq(&intent.owner, &balance.owner, cs)?;

        // The `min_price` and `amount_in` fields must be valid bitlengths
        PriceGadget::constrain_valid_price(intent.min_price, cs)?;
        AmountGadget::constrain_valid_amount(intent.amount_in, cs)?;

        // The balance's mint must match the intent's input token; i.e. the balance
        // must actually capitalize the intent
        EqGadget::constrain_eq(&balance.mint, &intent.in_token, cs)
    }

    /// Build the intent state wrapper
    fn build_intent_state_wrapper(
        statement: &IntentAndBalanceFirstFillValidityStatementVar,
        witness: &mut IntentAndBalanceFirstFillValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<DarkpoolStateIntentVar, CircuitError> {
        let intent = &witness.intent;
        let share_stream = &mut witness.initial_intent_share_stream;
        let recovery_stream = &mut witness.initial_intent_recovery_stream;

        // Sample public shares for the intent
        let public_share =
            ShareGadget::compute_complementary_shares(&witness.private_intent_shares, intent, cs)?;
        let expected_pre_match_share = ShareGadget::build_pre_match_intent_share(&public_share);
        EqGadget::constrain_eq(&expected_pre_match_share, &statement.intent_public_share, cs)?;
        EqGadget::constrain_eq(&public_share.amount_in, &witness.new_amount_public_share, cs)?;

        // Build the intent state wrapper
        let state_wrapper = DarkpoolStateIntentVar {
            inner: intent.clone(),
            share_stream: share_stream.clone(),
            recovery_stream: recovery_stream.clone(),
            public_share,
        };
        Ok(state_wrapper)
    }

    /// Verify the intent's commitments
    ///
    /// Returns the commitment to the original intent
    fn compute_and_verify_intent_commitments(
        original_intent: &DarkpoolStateIntentVar,
        new_intent: &DarkpoolStateIntentVar,
        witness: &IntentAndBalanceFirstFillValidityWitnessVar<MERKLE_HEIGHT>,
        statement: &IntentAndBalanceFirstFillValidityStatementVar,
        cs: &mut PlonkCircuit,
    ) -> Result<Variable, CircuitError> {
        // Compute the full commitment to the pre-update intent and a partial
        // (private-only) commitment to the post-update intent.
        // The full commitment is used to authorize the intent via an owner-delegated
        // signer. The partial commitment is resumed in-contract to commit to the new
        // intent after the first fill has updated its public shares.
        // For this reason, the partial commitment only commits to the private shares.
        let (old_private_comm, new_private_comm) =
            CommitmentGadget::compute_private_commitments_with_shared_prefix(
                &witness.private_intent_shares,
                &witness.private_intent_shares,
                original_intent,
                new_intent,
                cs,
            )?;
        let initial_intent_commitment = CommitmentGadget::compute_commitment_from_private::<Intent>(
            old_private_comm,
            &original_intent.public_share,
            cs,
        )?;

        EqGadget::constrain_eq(&new_private_comm, &statement.intent_private_share_commitment, cs)?;
        Ok(initial_intent_commitment)
    }

    // --- Balance Constraints --- //

    /// Validate the balance
    fn validate_balance(
        statement: &IntentAndBalanceFirstFillValidityStatementVar,
        witness: &IntentAndBalanceFirstFillValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let balance = &witness.old_balance;
        // Bind the denormalized balance to the one in the state element
        EqGadget::constrain_eq(&witness.balance, &balance.inner, cs)?;

        // Leak the balance's one-time authorizing address
        EqGadget::constrain_eq(
            &balance.inner.one_time_authority,
            &statement.one_time_authorizing_address,
            cs,
        )?;

        // Create the new balance
        let old_balance_private_shares =
            ShareGadget::compute_complementary_shares(&balance.public_share, &balance.inner, cs)?;
        let (new_balance, new_balance_private_shares) =
            Self::create_new_balance(&old_balance_private_shares, statement, witness, cs)?;

        // Verify the balance's rotation
        let mut args = StateElementRotationArgsWithPartialCommitment {
            old_version: balance.clone(),
            old_private_share: old_balance_private_shares.clone(),
            old_opening: witness.balance_opening.clone(),
            merkle_root: statement.merkle_root,
            nullifier: statement.old_balance_nullifier,
            new_version: new_balance.clone(),
            new_private_share: new_balance_private_shares.clone(),
            new_partial_commitment: statement.balance_partial_commitment.clone(),
            recovery_id: statement.balance_recovery_id,
        };
        StateElementRotationGadget::rotate_version_with_partial_commitment(
            BALANCE_PARTIAL_COMMITMENT_SIZE,
            &mut args,
            cs,
        )?;

        Ok(())
    }

    /// Create the new balance
    ///
    /// Returns the new balance and the private shares of the new balance
    fn create_new_balance(
        old_balance_private_shares: &BalanceShareVar,
        statement: &IntentAndBalanceFirstFillValidityStatementVar,
        witness: &IntentAndBalanceFirstFillValidityWitnessVar<MERKLE_HEIGHT>,
        cs: &mut PlonkCircuit,
    ) -> Result<(DarkpoolStateBalanceVar, BalanceShareVar), CircuitError> {
        // Update the balance
        let mut new_balance = witness.old_balance.clone();
        let mut new_balance_private_shares = old_balance_private_shares.clone();

        // Re-encrypt the new one-time authorizing address
        new_balance.inner.one_time_authority = witness.new_one_time_address;
        let (new_one_time_private_share, new_one_time_public_share) =
            StreamCipherGadget::encrypt::<Variable>(
                &witness.new_one_time_address,
                &mut new_balance.share_stream,
                cs,
            )?;
        new_balance_private_shares.one_time_authority = new_one_time_private_share;
        new_balance.public_share.one_time_authority = new_one_time_public_share;
        EqGadget::constrain_eq(
            &new_one_time_public_share,
            &statement.new_one_time_address_public_share,
            cs,
        )?;

        // Re-encrypt the post-match balance shares so that they may be updated in the
        // settlement circuit. Re-encryption here prevents the shares from being tracked
        // across transactions.
        let post_match_shares = ShareGadget::build_post_match_balance(&new_balance.inner);
        let (new_private_share, new_public_share) =
            StreamCipherGadget::encrypt::<PostMatchBalanceShareVar>(
                &post_match_shares,
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

/// The witness type for `INTENT AND BALANCE FIRST FILL VALIDITY`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalanceFirstFillValidityWitness<const MERKLE_HEIGHT: usize> {
    // --- Intent --- //
    /// The new intent
    ///
    /// The intent will be authorized by the balance's one-time authorizing key
    /// for the first fill.
    #[link_groups = "intent_and_balance_settlement_party0,intent_and_balance_settlement_party1"]
    pub intent: Intent,
    /// The initial intent share CSPRNG
    pub initial_intent_share_stream: PoseidonCSPRNG,
    /// The initial intent recovery stream
    pub initial_intent_recovery_stream: PoseidonCSPRNG,
    /// The private shares of the intent
    pub private_intent_shares: IntentShare,
    /// The new public share fo the intent's `amount_in` field
    ///
    /// We leak all other public shares in the statement of this circuit, but we
    /// only leak the new public share after it's been updated by the
    /// settlement circuit.
    #[link_groups = "intent_and_balance_settlement_party0,intent_and_balance_settlement_party1"]
    pub new_amount_public_share: Scalar,

    // --- Balance --- //
    /// The balance which capitalizes the intent
    pub old_balance: DarkpoolStateBalance,
    /// The balance which capitalizes the intent, denormalized from the state
    /// element balance here so that it may be proof-linked into the settlement
    /// proof.
    #[link_groups = "intent_and_balance_settlement_party0,intent_and_balance_settlement_party1"]
    pub balance: Balance,
    /// The updated public shares of the post-match balance
    #[link_groups = "intent_and_balance_settlement_party0,intent_and_balance_settlement_party1"]
    pub post_match_balance_shares: PostMatchBalanceShare,
    /// The new one-time authorizing address after the previous value has been
    /// leaked
    pub new_one_time_address: Address,
    /// The opening of the balance
    pub balance_opening: MerkleOpening<MERKLE_HEIGHT>,
}

/// A `INTENT AND BALANCE FIRST FILL VALIDITY` witness with default const
/// generic sizing parameters
pub type SizedIntentAndBalanceFirstFillValidityWitness =
    IntentAndBalanceFirstFillValidityWitness<MERKLE_HEIGHT>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `INTENT AND BALANCE FIRST FILL VALIDITY`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IntentAndBalanceFirstFillValidityStatement {
    /// The Merkle root to which the balance opens
    pub merkle_root: MerkleRoot,
    /// A commitment to the new one-time address and the original intent's
    /// commitment
    ///
    /// A signature over this commitment by the previous one-time authorizing
    /// address is checked in-contract. This authorizes both the creation of the
    /// new intent by the owner and the rotation of the one-time authorizing
    /// address.
    pub intent_and_authorizing_address_commitment: Commitment,

    // --- Intent --- //
    /// The public shares of the intent minus the `amount_in` field
    ///
    /// The public share of the `amount_in` field is leaked after it's been
    /// updated by the settlement circuit.
    pub intent_public_share: PreMatchIntentShare,
    /// The partial commitment to the original intent
    ///
    /// This commitment commits to all fields except the public share of the
    /// `amount_in` field. The smart contracts will resume the commitment by
    /// hashing in this share to the partial commitment.
    pub intent_private_share_commitment: Commitment,
    /// The recovery identifier of the new intent
    pub intent_recovery_id: Scalar,

    // --- Balance --- //
    /// The partial commitment to the new balance
    pub balance_partial_commitment: PartialCommitment,
    /// The public share of the one-time authorizing address after it has been
    /// re-encrypted
    pub new_one_time_address_public_share: Scalar,
    /// The nullifier of the old balance
    pub old_balance_nullifier: Nullifier,
    /// The recovery identifier of the new balance
    pub balance_recovery_id: Scalar,
    /// The owner-delegated authorizing signer of the balance
    ///
    /// This one-time signer allows the balance to authorize a single intent for
    /// the first fill. This address may be rotated after it is used to prevent
    /// linking across transactions.
    pub one_time_authorizing_address: Address,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MERKLE_HEIGHT: usize> SingleProverCircuit
    for IntentAndBalanceFirstFillValidityCircuit<MERKLE_HEIGHT>
{
    type Witness = IntentAndBalanceFirstFillValidityWitness<MERKLE_HEIGHT>;
    type Statement = IntentAndBalanceFirstFillValidityStatement;

    fn name() -> String {
        "Intent And Balance First Fill Validity".to_string()
    }

    /// INTENT AND BALANCE FIRST FILL VALIDITY has two proof linking groups:
    /// - intent_and_balance_settlement_party0: The linking group between INTENT
    ///   AND BALANCE FIRST FILL VALIDITY and the first party's intent and
    ///   balance
    /// - intent_and_balance_settlement_party1: The linking group between INTENT
    ///   AND BALANCE FIRST FILL VALIDITY and the second party's intent and
    ///   balance
    ///
    /// This circuit inherits the group layouts from the private settlement
    /// circuit.
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let circuit_layout = IntentAndBalancePrivateSettlementCircuit::get_circuit_layout()?;
        let group_layout0 =
            circuit_layout.get_group_layout(INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK);
        let group_layout1 =
            circuit_layout.get_group_layout(INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK);

        Ok(vec![
            (INTENT_AND_BALANCE_SETTLEMENT_PARTY0_LINK.to_string(), Some(group_layout0)),
            (INTENT_AND_BALANCE_SETTLEMENT_PARTY1_LINK.to_string(), Some(group_layout1)),
        ])
    }

    fn apply_constraints(
        mut witness_var: IntentAndBalanceFirstFillValidityWitnessVar<MERKLE_HEIGHT>,
        statement_var: IntentAndBalanceFirstFillValidityStatementVar,
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
    use circuit_types::{
        balance::{Balance, DarkpoolStateBalance, PostMatchBalance},
        intent::{Intent, PreMatchIntentShare},
    };
    use renegade_crypto::{fields::address_to_scalar, hash::compute_poseidon_hash};

    use crate::{
        test_helpers::{
            check_constraints_satisfied, create_merkle_opening, create_random_state_wrapper,
            create_state_wrapper, random_address, random_amount, random_intent,
        },
        zk_circuits::{
            validity_proofs::intent_and_balance_first_fill::IntentAndBalanceFirstFillValidityStatement,
            validity_proofs::intent_and_balance_first_fill::{
                BALANCE_PARTIAL_COMMITMENT_SIZE, IntentAndBalanceFirstFillValidityWitness,
                SizedIntentAndBalanceFirstFillValidityCircuit,
                SizedIntentAndBalanceFirstFillValidityWitness,
            },
        },
    };

    // -----------
    // | Helpers |
    // -----------

    /// Check that the constraints are satisfied on the given witness and
    /// statement
    pub fn check_constraints(
        witness: &SizedIntentAndBalanceFirstFillValidityWitness,
        statement: &IntentAndBalanceFirstFillValidityStatement,
    ) -> bool {
        check_constraints_satisfied::<SizedIntentAndBalanceFirstFillValidityCircuit>(
            witness, statement,
        )
    }

    /// Construct a witness and statement with valid data
    pub fn create_witness_statement<const MERKLE_HEIGHT: usize>() -> (
        IntentAndBalanceFirstFillValidityWitness<MERKLE_HEIGHT>,
        IntentAndBalanceFirstFillValidityStatement,
    ) {
        let intent = random_intent();
        create_witness_statement_with_intent(&intent)
    }

    /// Create a witness and statement with the given intent
    pub fn create_witness_statement_with_intent<const MERKLE_HEIGHT: usize>(
        intent: &Intent,
    ) -> (
        IntentAndBalanceFirstFillValidityWitness<MERKLE_HEIGHT>,
        IntentAndBalanceFirstFillValidityStatement,
    ) {
        let balance = create_matching_balance_for_intent(intent);
        create_witness_statement_with_intent_and_balance(intent, balance)
    }

    /// Create a witness and statement with the given intent and balance
    pub fn create_witness_statement_with_intent_and_balance<const MERKLE_HEIGHT: usize>(
        intent: &Intent,
        balance: DarkpoolStateBalance,
    ) -> (
        IntentAndBalanceFirstFillValidityWitness<MERKLE_HEIGHT>,
        IntentAndBalanceFirstFillValidityStatement,
    ) {
        // Create the intent state wrapper
        let initial_intent = create_state_wrapper(intent.clone());

        // Get the intent shares
        let private_intent_shares = initial_intent.private_shares();
        let intent_public_share = initial_intent.public_share();
        let new_amount_public_share = intent_public_share.amount_in;
        let intent_pre_match_share = PreMatchIntentShare::from(intent_public_share.clone());

        // Compute intent commitments for the original and new intents
        let mut new_intent = initial_intent.clone();
        let original_intent_commitment = initial_intent.compute_commitment();
        let intent_recovery_id = new_intent.compute_recovery_id();
        let intent_private_share_commitment = new_intent.compute_private_commitment();

        // Compute the state rotation information for the original balance
        let one_time_authority = balance.inner.one_time_authority;
        let old_balance_nullifier = balance.compute_nullifier();
        let balance_commitment = balance.compute_commitment();
        let (merkle_root, balance_opening) =
            create_merkle_opening::<MERKLE_HEIGHT>(balance_commitment);

        // Create a new balance with updated post-match shares
        let new_one_time_address = random_address();
        let mut new_balance = balance.clone();
        new_balance.inner.one_time_authority = new_one_time_address;
        let new_one_time_share = new_balance.stream_cipher_encrypt(&new_one_time_address);
        new_balance.public_share.one_time_authority = new_one_time_share;

        let post_match_balance = PostMatchBalance::from(balance.inner.clone());
        let post_match_balance_shares = new_balance.stream_cipher_encrypt(&post_match_balance);

        // Update the balance's public_share to include the re-encrypted post-match
        // shares. This matches what the circuit does in create_new_balance
        new_balance.update_from_post_match(&post_match_balance_shares);

        // Compute the partial commitment for the new balance
        let balance_recovery_id = new_balance.compute_recovery_id();
        let balance_partial_commitment =
            new_balance.compute_partial_commitment(BALANCE_PARTIAL_COMMITMENT_SIZE);

        // Commit to the new intent and one-time authorizing address
        let intent_and_authorizing_address_commitment = compute_poseidon_hash(&[
            original_intent_commitment,
            address_to_scalar(&new_one_time_address),
        ]);

        // Build the witness
        let witness = IntentAndBalanceFirstFillValidityWitness {
            intent: initial_intent.inner,
            initial_intent_share_stream: initial_intent.share_stream,
            initial_intent_recovery_stream: initial_intent.recovery_stream,
            private_intent_shares,
            new_amount_public_share,
            old_balance: balance.clone(),
            balance: balance.inner,
            post_match_balance_shares,
            balance_opening,
            new_one_time_address,
        };

        // Build the statement
        let statement = IntentAndBalanceFirstFillValidityStatement {
            merkle_root,
            intent_public_share: intent_pre_match_share,
            intent_private_share_commitment,
            intent_recovery_id,
            balance_partial_commitment,
            new_one_time_address_public_share: new_one_time_share,
            old_balance_nullifier,
            balance_recovery_id,
            one_time_authorizing_address: one_time_authority,
            intent_and_authorizing_address_commitment,
        };

        (witness, statement)
    }

    /// Create a balance that matches the given intent
    ///
    /// The balance will have the same owner and mint as the intent's in_token,
    /// with random values for other fields.
    pub fn create_matching_balance_for_intent(intent: &Intent) -> DarkpoolStateBalance {
        let balance_inner = Balance {
            mint: intent.in_token,
            owner: intent.owner,
            relayer_fee_recipient: random_address(),
            one_time_authority: random_address(),
            relayer_fee_balance: random_amount(),
            protocol_fee_balance: random_amount(),
            amount: random_amount(),
        };
        create_random_state_wrapper(balance_inner)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        test_helpers::{random_address, random_intent, random_scalar},
        zk_circuits::validity_proofs::intent_and_balance_first_fill::test_helpers::{
            create_matching_balance_for_intent, create_witness_statement_with_intent,
        },
    };

    use super::*;
    use circuit_types::{
        fixed_point::FixedPoint, max_amount, max_price, traits::SingleProverCircuit,
    };
    use rand::{Rng, thread_rng};

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    fn test_n_constraints() {
        let layout = SizedIntentAndBalanceFirstFillValidityCircuit::get_circuit_layout().unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// Test that constraints are satisfied on a valid witness and statement
    #[test]
    fn test_valid_intent_and_balance_first_fill_constraints() {
        let (witness, statement) = test_helpers::create_witness_statement();
        assert!(test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Intent Tests --- //

    /// Test the case in which the intent's owner does not match the balance's
    /// owner
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__owner_mismatch() {
        let mut intent = random_intent();
        let balance = create_matching_balance_for_intent(&intent);
        intent.owner = random_address();

        let (witness, statement) =
            test_helpers::create_witness_statement_with_intent_and_balance(&intent, balance);
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the balance holds a different mint than the
    /// intent's in_token
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__balance_mint_mismatch() {
        let intent = random_intent();
        let mut balance = create_matching_balance_for_intent(&intent);
        balance.inner.mint = random_address();

        let (witness, statement) = test_helpers::create_witness_statement_with_intent_and_balance(
            &intent,
            balance.clone(),
        );
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the intent's amount_in is not of valid bitlength
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__amount_in_not_valid_bitlength() {
        let mut intent = random_intent();
        intent.amount_in = max_amount() + 1;

        let (witness, statement) = create_witness_statement_with_intent(&intent);
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the intent's minimum price is not of valid
    /// bitlength
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__min_price_not_valid_bitlength() {
        let mut intent = random_intent();
        intent.min_price = max_price() + FixedPoint::from_integer(1);

        let (witness, statement) = create_witness_statement_with_intent(&intent);
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the new amount share in the witness doesn't match
    /// that of the intent
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__new_amount_share_mismatch() {
        let (mut witness, statement) = test_helpers::create_witness_statement();

        witness.new_amount_public_share = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the intent's public shares are modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__public_shares_modified() {
        let mut rng = thread_rng();
        let (witness, mut statement) = test_helpers::create_witness_statement();

        let mut public_shares = statement.intent_public_share.to_scalars();
        let idx = rng.gen_range(0..public_shares.len());
        public_shares[idx] = random_scalar();
        statement.intent_public_share =
            PreMatchIntentShare::from_scalars(&mut public_shares.into_iter());

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the intent's private share commitment is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__private_share_commitment_modified() {
        let (witness, mut statement) = test_helpers::create_witness_statement();

        statement.intent_private_share_commitment = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the intent's recovery ID is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__recovery_id_modified() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.intent_recovery_id = random_scalar();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the new intent's commitment is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_intent__new_intent_commitment_modified() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.intent_and_authorizing_address_commitment = random_scalar();

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    // --- Invalid Balance Tests --- //

    /// Test the case in which the balance's one-time authorizing address does
    /// not match the one leaked in the statement
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__one_time_authorizing_address_mismatch() {
        let (witness, mut statement) = test_helpers::create_witness_statement();
        statement.one_time_authorizing_address = random_address();

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the new one-time authorizing address is modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__new_one_time_authorizing_address_modified() {
        let (mut witness, statement) = test_helpers::create_witness_statement();
        witness.new_one_time_address = random_address();
        assert!(!test_helpers::check_constraints(&witness, &statement));
    }

    /// Test the case in which the post-match balance shares are modified
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_balance__post_match_balance_shares_modified() {
        let mut rng = thread_rng();
        let (mut witness, statement) = test_helpers::create_witness_statement();

        let mut shares = witness.post_match_balance_shares.to_scalars();
        let idx = rng.gen_range(0..shares.len());
        shares[idx] = random_scalar();
        witness.post_match_balance_shares =
            PostMatchBalanceShare::from_scalars(&mut shares.into_iter());

        assert!(!test_helpers::check_constraints(&witness, &statement));
    }
}
