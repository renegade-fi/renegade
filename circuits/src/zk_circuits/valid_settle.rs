//! Defines the VALID SETTLE circuit, which is proven after a match, validating that
//! both party's secret shares have been updated properly with the result of the match

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier,
    },
    BulletproofGens,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        r#match::{CommittedMatchResult, LinkableMatchResultCommitment, MatchResultVar},
        wallet::{WalletSecretShare, WalletSecretShareCommitment, WalletSecretShareVar},
    },
    zk_gadgets::{
        comparators::{EqGadget, EqVecGadget},
        select::CondSelectVectorGadget,
    },
    CommitPublic, CommitVerifier, CommitWitness, SingleProverCircuit,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit definition of `VALID SETTLE`
pub struct ValidSettle<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The circuit representing `VALID SETTLE`
    pub fn circuit<CS: RandomizableConstraintSystem>(
        statement: ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        witness: ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // Select the balances received by each party
        let mut party0_party1_received = CondSelectVectorGadget::select(
            &[
                witness.match_res.base_amount,
                witness.match_res.quote_amount,
            ],
            &[
                witness.match_res.quote_amount,
                witness.match_res.base_amount,
            ],
            witness.match_res.direction,
            cs,
        );

        let party0_received_amount = party0_party1_received.remove(0);
        let party1_received_amount = party0_party1_received.remove(0);

        // Constrain the wallet updates to party0's shares
        Self::validate_balance_updates(
            statement.party0_send_balance_index,
            party1_received_amount.clone(),
            statement.party0_receive_balance_index,
            party0_received_amount.clone(),
            &witness.party0_public_shares,
            &statement.party0_modified_shares,
            cs,
        );

        Self::validate_order_updates(
            statement.party0_order_index,
            witness.match_res.base_amount,
            &witness.party0_public_shares,
            &statement.party0_modified_shares,
            cs,
        );

        Self::validate_fees_keys_blinder_updates(
            witness.party0_public_shares,
            statement.party0_modified_shares,
            cs,
        );

        // Constrain the wallet update to party1's shares
        Self::validate_balance_updates(
            statement.party1_send_balance_index,
            party0_received_amount,
            statement.party1_receive_balance_index,
            party1_received_amount,
            &witness.party1_public_shares,
            &statement.party1_modified_shares,
            cs,
        );

        Self::validate_order_updates(
            statement.party1_order_index,
            witness.match_res.base_amount,
            &witness.party1_public_shares,
            &statement.party1_modified_shares,
            cs,
        );

        Self::validate_fees_keys_blinder_updates(
            witness.party1_public_shares,
            statement.party1_modified_shares,
            cs,
        );
    }

    /// Verify that the balance updates to a wallet are valid
    ///
    /// That is, all balances in the settled wallet are the same as in the pre-settle wallet
    /// except for the balance sent and the balance received, which have the correct amounts
    /// applied from the match
    fn validate_balance_updates<CS: RandomizableConstraintSystem>(
        send_index: Variable,
        send_amount: LinearCombination,
        receive_index: Variable,
        received_amount: LinearCombination,
        pre_update_shares: &WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        post_update_shares: &WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        let mut send_term = -send_amount;
        let mut receive_term: LinearCombination = received_amount;

        let mut curr_index: LinearCombination = Variable::Zero().into();
        for (pre_update_balance, post_update_balance) in pre_update_shares
            .balances
            .clone()
            .into_iter()
            .zip(post_update_shares.balances.clone().into_iter())
        {
            // Mask the send term
            let send_term_index_mask = EqGadget::eq(send_index.into(), curr_index.clone(), cs);
            let (_, new_send_term, curr_send_term) =
                cs.multiply(send_term_index_mask.into(), send_term);
            send_term = new_send_term.into();

            // Mask the receive term
            let receive_term_index_mask =
                EqGadget::eq(receive_index.into(), curr_index.clone(), cs);
            let (_, new_receive_term, curr_receive_term) =
                cs.multiply(receive_term_index_mask.into(), receive_term);
            receive_term = new_receive_term.into();

            // Add the terms together to get the expected update
            let expected_balance_amount =
                pre_update_balance.amount.clone() + curr_send_term + curr_receive_term;
            let mut expected_balances_shares = pre_update_balance;
            expected_balances_shares.amount = expected_balance_amount;

            EqVecGadget::constrain_eq_vec(
                &Into::<Vec<LinearCombination>>::into(expected_balances_shares),
                &Into::<Vec<LinearCombination>>::into(post_update_balance),
                cs,
            );

            // Increment the index
            curr_index += Variable::One();
        }
    }

    /// Verify that order updates to a wallet are valid
    ///
    /// The orders should all be equal except that the amount of the matched order
    /// should be decremented by the amount of the base token swapped
    fn validate_order_updates<CS: RandomizableConstraintSystem>(
        order_index: Variable,
        base_amount_swapped: Variable,
        pre_update_shares: &WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        post_update_shares: &WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        let mut amount_delta = -base_amount_swapped;

        let mut curr_index: LinearCombination = Variable::Zero().into();
        for (pre_update_order, post_update_order) in pre_update_shares
            .orders
            .clone()
            .into_iter()
            .zip(post_update_shares.orders.clone().into_iter())
        {
            // Mask with the index
            let index_mask = EqGadget::eq(order_index.into(), curr_index.clone(), cs);
            let (_, new_amount_delta, curr_delta_term) =
                cs.multiply(index_mask.into(), amount_delta);
            amount_delta = new_amount_delta.into();

            // Constrain the order update to be correct
            let expected_order_volume = pre_update_order.amount.clone() + curr_delta_term;
            let mut expected_order_shares = pre_update_order.clone();
            expected_order_shares.amount = expected_order_volume;

            EqVecGadget::constrain_eq_vec(
                &Into::<Vec<LinearCombination>>::into(expected_order_shares),
                &Into::<Vec<LinearCombination>>::into(post_update_order.clone()),
                cs,
            );

            // Increment the index
            curr_index += Variable::One();
        }
    }

    /// Validate that fees, keys, and blinders remain the same in the pre and post
    /// wallet shares
    fn validate_fees_keys_blinder_updates<CS: RandomizableConstraintSystem>(
        mut pre_update_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        mut post_update_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        let mut pre_update_share_vec: Vec<LinearCombination> = Vec::new();
        for fee in pre_update_shares.fees.into_iter() {
            pre_update_share_vec.append(&mut fee.into());
        }
        pre_update_share_vec.append(&mut pre_update_shares.keys.pk_root.words);
        pre_update_share_vec.push(pre_update_shares.keys.pk_match);
        pre_update_share_vec.push(pre_update_shares.blinder);

        let mut post_update_share_vec: Vec<LinearCombination> = Vec::new();
        for fee in post_update_shares.fees.into_iter() {
            post_update_share_vec.append(&mut fee.into());
        }
        post_update_share_vec.append(&mut post_update_shares.keys.pk_root.words);
        post_update_share_vec.push(post_update_shares.keys.pk_match);
        post_update_share_vec.push(post_update_shares.blinder);

        EqVecGadget::constrain_eq_vec(&pre_update_share_vec, &post_update_share_vec, cs);
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID SETTLE`
#[derive(Clone, Debug)]
pub struct ValidSettleWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The match result to be applied to the wallet shares
    pub match_res: LinkableMatchResultCommitment,
    /// The public secret shares of the first party before the match is applied
    pub party0_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the second party before the match is applied
    pub party1_public_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// The witness type for `VALID SETTLE`, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidSettleWitnessVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The match result to be applied to the wallet shares
    pub match_res: MatchResultVar,
    /// The public secret shares of the first party before the match is applied
    pub party0_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the second party before the match is applied
    pub party1_public_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// A commitment to the witness type for `VALID SETTLE`,
/// allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidSettleWitnessCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The match result to be applied to the wallet shares
    pub match_res: CommittedMatchResult,
    /// The public secret shares of the first party before the match is applied
    pub party0_public_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the second party before the match is applied
    pub party1_public_shares: WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (match_res_var, match_res_comm) = self.match_res.commit_witness(rng, prover).unwrap();
        let (party0_shares_var, party0_shares_comm) = self
            .party0_public_shares
            .commit_witness(rng, prover)
            .unwrap();
        let (party1_shares_var, party1_shares_comm) = self
            .party1_public_shares
            .commit_witness(rng, prover)
            .unwrap();

        Ok((
            ValidSettleWitnessVar {
                match_res: match_res_var,
                party0_public_shares: party0_shares_var,
                party1_public_shares: party1_shares_var,
            },
            ValidSettleWitnessCommitment {
                match_res: match_res_comm,
                party0_public_shares: party0_shares_comm,
                party1_public_shares: party1_shares_comm,
            },
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let match_res_var = self.match_res.commit_verifier(verifier).unwrap();
        let party0_share_vars = self.party0_public_shares.commit_verifier(verifier).unwrap();
        let party1_share_vars = self.party1_public_shares.commit_verifier(verifier).unwrap();

        Ok(ValidSettleWitnessVar {
            match_res: match_res_var,
            party0_public_shares: party0_share_vars,
            party1_public_shares: party1_share_vars,
        })
    }
}

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID SETTLE`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidSettleStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The modified public secret shares of the first party
    pub party0_modified_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares of the second party
    pub party1_modified_shares: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The index of the balance that the first party sent in the settlement
    pub party0_send_balance_index: usize,
    /// The index of teh balance that the first party received in the settlement
    pub party0_receive_balance_index: usize,
    /// The index of the first party's order that was matched
    pub party0_order_index: usize,
    /// The index of the balance that the second party sent in the settlement
    pub party1_send_balance_index: usize,
    /// The index of teh balance that the second party received in the settlement
    pub party1_receive_balance_index: usize,
    /// The index of the second party's order that was matched
    pub party1_order_index: usize,
}

/// The statement type for `VALID SETTLE`, allocated in a constraint system
#[derive(Clone, Debug)]
pub struct ValidSettleStatementVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The modified public secret shares of the first party
    pub party0_modified_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares of the second party
    pub party1_modified_shares: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The index of the balance that the first party sent in the settlement
    pub party0_send_balance_index: Variable,
    /// The index of teh balance that the first party received in the settlement
    pub party0_receive_balance_index: Variable,
    /// The index of the first party's order that was matched
    pub party0_order_index: Variable,
    /// The index of the balance that the second party sent in the settlement
    pub party1_send_balance_index: Variable,
    /// The index of teh balance that the second party received in the settlement
    pub party1_receive_balance_index: Variable,
    /// The index of the second party's order that was matched
    pub party1_order_index: Variable,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitPublic
    for ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does nto error

    fn commit_public<CS: RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let party0_share_vars = self.party0_modified_shares.commit_public(cs).unwrap();
        let party1_share_vars = self.party1_modified_shares.commit_public(cs).unwrap();
        let party0_send_index_var =
            cs.commit_public(Scalar::from(self.party0_send_balance_index as u64));
        let party0_receive_index_var =
            cs.commit_public(Scalar::from(self.party0_receive_balance_index as u64));
        let party0_order_index_var = cs.commit_public(Scalar::from(self.party0_order_index as u64));
        let party1_send_index_var =
            cs.commit_public(Scalar::from(self.party1_send_balance_index as u64));
        let party1_receive_index_var =
            cs.commit_public(Scalar::from(self.party1_receive_balance_index as u64));
        let party1_order_index_var = cs.commit_public(Scalar::from(self.party1_order_index as u64));

        Ok(ValidSettleStatementVar {
            party0_modified_shares: party0_share_vars,
            party1_modified_shares: party1_share_vars,
            party0_send_balance_index: party0_send_index_var,
            party0_receive_balance_index: party0_receive_index_var,
            party0_order_index: party0_order_index_var,
            party1_send_balance_index: party1_send_index_var,
            party1_receive_balance_index: party1_receive_index_var,
            party1_order_index: party1_order_index_var,
        })
    }
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type WitnessCommitment = ValidSettleWitnessCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 1024;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), crate::errors::ProverError> {
        // Commit to the witness and statement
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        // Apply the circuit constraints
        Self::circuit(statement_var, witness_var, &mut prover);

        // Prove the relation
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

        // Apply the circuit constraints
        Self::circuit(statement_var, witness_var, &mut verifier);

        // Verify the proof
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
