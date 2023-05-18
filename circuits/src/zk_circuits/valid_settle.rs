//! Defines the VALID SETTLE circuit, which is proven after a match, validating that
//! both party's secret shares have been updated properly with the result of the match

use curve25519_dalek::scalar::Scalar;
use mpc_bulletproof::{
    r1cs::{
        LinearCombination, Prover, R1CSError, R1CSProof, RandomizableConstraintSystem, Variable,
        Verifier,
    },
    BulletproofGens,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    errors::{ProverError, VerifierError},
    types::{
        r#match::{CommittedMatchResult, LinkableMatchResultCommitment, MatchResultVar},
        wallet::{
            LinkableWalletSecretShare, WalletSecretShare, WalletSecretShareCommitment,
            WalletSecretShareVar,
        },
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
                witness.match_res.quote_amount,
                witness.match_res.base_amount,
            ],
            &[
                witness.match_res.base_amount,
                witness.match_res.quote_amount,
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
            expected_balances_shares.amount = expected_balance_amount.clone();

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
    pub party0_public_shares: LinkableWalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the second party before the match is applied
    pub party1_public_shares: LinkableWalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    type WitnessVar = ValidSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type StatementVar = ValidSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    const BP_GENS_CAPACITY: usize = 1024;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: Self::WitnessVar,
        statement_var: Self::StatementVar,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        // Apply the constraints over the allocated witness & statement
        Self::circuit(statement_var, witness_var, cs);
        Ok(())
    }

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: Prover,
    ) -> Result<(Self::WitnessCommitment, R1CSProof), crate::errors::ProverError> {
        // Commit to the witness and statement
        let mut rng = OsRng {};
        let (witness_var, witness_comm) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        Self::apply_constraints(witness_var, statement_var, &mut prover)
            .map_err(ProverError::R1CS)?;

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

        Self::apply_constraints(witness_var, statement_var, &mut verifier)
            .map_err(VerifierError::R1CS)?;

        // Verify the proof
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
    #![allow(non_snake_case)]

    use curve25519_dalek::scalar::Scalar;
    use lazy_static::lazy_static;
    use merlin::Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use num_bigint::BigUint;
    use rand_core::OsRng;

    use crate::{
        types::{
            order::{Order, OrderSide},
            r#match::MatchResult,
        },
        zk_circuits::test_helpers::{
            create_wallet_shares, SizedWallet, INITIAL_BALANCES, INITIAL_FEES, MAX_BALANCES,
            MAX_FEES, MAX_ORDERS, PUBLIC_KEYS, TIMESTAMP,
        },
        zk_gadgets::fixed_point::FixedPoint,
        CommitPublic, CommitWitness,
    };

    use super::{ValidSettle, ValidSettleStatement, ValidSettleWitness};

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        /// The first of two wallets that match
        static ref WALLET1: SizedWallet = {
            let orders = [
                Order {
                    quote_mint: 1u8.into(),
                    base_mint: 2u8.into(),
                    side: OrderSide::Buy,
                    price: FixedPoint::from(5.),
                    amount: 1,
                    timestamp: TIMESTAMP,
                },
                Order::default()
            ];

            SizedWallet {
                balances: INITIAL_BALANCES.clone(),
                orders,
                fees: INITIAL_FEES.clone(),
                keys: PUBLIC_KEYS.clone(),
                blinder: Scalar::from(1u8),
            }
        };

        /// The second of two wallets to match, the first wallet with the order side flipped
        static ref WALLET2: SizedWallet = {
            let mut wallet = WALLET1.clone();
            wallet.orders[0].side = OrderSide::Sell;

            wallet
        };

        /// The result of matching the two orders in the wallets above
        static ref MATCH_RES: MatchResult = MatchResult {
            quote_mint: 1u8.into(),
            base_mint: 2u8.into(),
            quote_amount: 5,
            base_amount: 1,
            direction: 0, /* party0 buys base */
            execution_price: FixedPoint::from(5.),
            max_minus_min_amount: 0,
            min_amount_order_index: 0,
        };
    }

    /// The witness type for `VALID SETTLE` with default size parameters attached
    type SizedWitness = ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    /// The statement type for `VALID SETTLE` with default size parameters attached
    type SizedStatement = ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    // -----------
    // | Helpers |
    // -----------

    /// Construct a witness and statement for `VALID SETTLE`
    fn create_witness_statement(
        party0_wallet: SizedWallet,
        party1_wallet: SizedWallet,
        match_res: MatchResult,
    ) -> (SizedWitness, SizedStatement) {
        // Mux between received mints based on the match direction
        let (
            party0_received_mint,
            party0_received_amount,
            party1_received_mint,
            party1_received_amount,
        ) = match match_res.direction {
            // Party 1 buys the base mint, sells the quote
            0 => (
                match_res.base_mint.clone(),
                match_res.base_amount,
                match_res.quote_mint.clone(),
                match_res.quote_amount,
            ),
            // Party 0 buys the quote mint, sells the base
            1 => (
                match_res.quote_mint.clone(),
                match_res.quote_amount,
                match_res.base_mint.clone(),
                match_res.base_amount,
            ),
            _ => unreachable!("match direction must be 0 or 1"),
        };

        // Find the send and receive balances for each party to update at
        let party0_send_index =
            find_balance_in_wallet(&party1_received_mint, &party0_wallet).unwrap();
        let party0_receive_index =
            find_balance_in_wallet(&party0_received_mint, &party0_wallet).unwrap();
        let party1_send_index =
            find_balance_in_wallet(&party0_received_mint, &party1_wallet).unwrap();
        let party1_receive_index =
            find_balance_in_wallet(&party1_received_mint, &party1_wallet).unwrap();

        // Find the orders matched
        let party0_order_index =
            find_order_in_wallet(&match_res.base_mint, &match_res.quote_mint, &party0_wallet)
                .unwrap();
        let party1_order_index =
            find_order_in_wallet(&match_res.base_mint, &match_res.quote_mint, &party1_wallet)
                .unwrap();

        // Split the wallets into secret shares
        let (_, party0_public_shares) = create_wallet_shares(&party0_wallet);
        let (_, party1_public_shares) = create_wallet_shares(&party1_wallet);

        // Update party0's public shares with the match
        let mut party0_modified_shares = party0_public_shares.clone();
        party0_modified_shares.balances[party0_send_index].amount -=
            Scalar::from(party1_received_amount);
        party0_modified_shares.balances[party0_receive_index].amount +=
            Scalar::from(party0_received_amount);
        party0_modified_shares.orders[party0_order_index].amount -=
            Scalar::from(match_res.base_amount);

        // Update party1's public shares with the match
        let mut party1_modified_shares = party1_public_shares.clone();
        party1_modified_shares.balances[party1_send_index].amount -=
            Scalar::from(party0_received_amount);
        party1_modified_shares.balances[party1_receive_index].amount +=
            Scalar::from(party1_received_amount);
        party1_modified_shares.orders[party1_order_index].amount -=
            Scalar::from(match_res.base_amount);

        let witness = ValidSettleWitness {
            match_res: match_res.into(),
            party0_public_shares: party0_public_shares.into(),
            party1_public_shares: party1_public_shares.into(),
        };
        let statement = ValidSettleStatement {
            party0_modified_shares,
            party1_modified_shares,
            party0_send_balance_index: party0_send_index,
            party0_receive_balance_index: party0_receive_index,
            party0_order_index,
            party1_send_balance_index: party1_send_index,
            party1_receive_balance_index: party1_receive_index,
            party1_order_index,
        };

        (witness, statement)
    }

    /// Find the index of the balance with the given mint in the given wallet
    fn find_balance_in_wallet(mint: &BigUint, wallet: &SizedWallet) -> Option<usize> {
        wallet
            .balances
            .iter()
            .enumerate()
            .find(|(_ind, b)| mint.eq(&b.mint))
            .map(|(ind, _balance)| ind) // keep only the index
    }

    /// Find the index of the order within the given wallet that is on the given asset pair's book
    fn find_order_in_wallet(
        base_mint: &BigUint,
        quote_mint: &BigUint,
        wallet: &SizedWallet,
    ) -> Option<usize> {
        wallet
            .orders
            .iter()
            .enumerate()
            .find(|(_ind, order)| {
                base_mint.eq(&order.base_mint) && quote_mint.eq(&order.quote_mint)
            })
            .map(|(ind, _order)| ind) // keep only the index
    }

    /// Return true if the given witness and statement satisfy the constraints of
    /// the VALID SETTLE circuit
    fn constraints_satisfied(witness: SizedWitness, statement: SizedStatement) -> bool {
        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Allocate the witness and statement in the constraint system
        let mut rng = OsRng {};
        let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover).unwrap();
        let statement_var = statement.commit_public(&mut prover).unwrap();

        // Apply the constraints
        ValidSettle::circuit(statement_var, witness_var, &mut prover);
        prover.constraints_satisfied()
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests a valid witness and statement pair
    #[test]
    fn test_valid_settle() {
        let party0_wallet = WALLET1.clone();
        let party1_wallet = WALLET2.clone();
        let match_res = MATCH_RES.clone();
        let (witness, statement) =
            create_witness_statement(party0_wallet, party1_wallet, match_res);

        assert!(constraints_satisfied(witness, statement))
    }

    /// Tests a valid witness and statement pair going the opposite direction
    #[test]
    fn test_valid_settle__party0_sells_base() {
        let party0_wallet = WALLET2.clone();
        let party1_wallet = WALLET1.clone();
        let match_res = MATCH_RES.clone();
        let (witness, statement) =
            create_witness_statement(party0_wallet, party1_wallet, match_res);

        assert!(constraints_satisfied(witness, statement));
    }

    /// Tests the case in which an incorrect balance index is given
    #[test]
    fn test_invalid_settle__invalid_balance_index() {
        let party0_wallet = WALLET1.clone();
        let party1_wallet = WALLET2.clone();
        let match_res = MATCH_RES.clone();
        let (witness, original_statement) =
            create_witness_statement(party0_wallet, party1_wallet, match_res);

        // Party 0 send balance corrupted
        let mut statement = original_statement.clone();
        statement.party0_send_balance_index += 1;
        assert!(!constraints_satisfied(witness.clone(), statement));

        // Party 0 receive balance corrupted
        let mut statement = original_statement.clone();
        statement.party0_receive_balance_index += 1;
        assert!(!constraints_satisfied(witness.clone(), statement));

        // Party 1 send balance corrupted
        let mut statement = original_statement.clone();
        statement.party1_send_balance_index += 1;
        assert!(!constraints_satisfied(witness.clone(), statement));

        // Party 1 receive balance corrupted
        let mut statement = original_statement;
        statement.party1_receive_balance_index += 1;
        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test the case in which the order index of a settlement is incorrect
    #[test]
    fn test_invalid_settle__invalid_order_index() {
        let party0_wallet = WALLET1.clone();
        let party1_wallet = WALLET2.clone();
        let match_res = MATCH_RES.clone();
        let (witness, original_statement) =
            create_witness_statement(party0_wallet, party1_wallet, match_res);

        // Party 0 order index corrupted
        let mut statement = original_statement.clone();
        statement.party0_order_index += 1;
        assert!(!constraints_satisfied(witness.clone(), statement));

        // Party 1 order index corrupted
        let mut statement = original_statement;
        statement.party1_order_index += 1;
        assert!(!constraints_satisfied(witness, statement));
    }

    /// Test case in which the send balance is incorrectly updated
    #[test]
    fn test_invalid_settle__invalid_send_balance() {
        let party0_wallet = WALLET1.clone();
        let party1_wallet = WALLET2.clone();
        let match_res = MATCH_RES.clone();
        let (witness, mut statement) =
            create_witness_statement(party0_wallet, party1_wallet, match_res);

        // Modify the send balance of party 0
        statement.party0_modified_shares.balances[statement.party0_send_balance_index].amount +=
            Scalar::one();

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests the case in which the receive balance is incorrectly updated
    #[test]
    fn test_invalid_settle__invalid_receive_balance() {
        let party0_wallet = WALLET1.clone();
        let party1_wallet = WALLET2.clone();
        let match_res = MATCH_RES.clone();
        let (witness, mut statement) =
            create_witness_statement(party0_wallet, party1_wallet, match_res);

        // Modify the receive balance of party 1
        statement.party1_modified_shares.balances[statement.party1_receive_balance_index].amount +=
            Scalar::one();

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests the case in which the order amount is incorrectly modified
    #[test]
    fn test_invalid_settle__invalid_order_update() {
        let party0_wallet = WALLET1.clone();
        let party1_wallet = WALLET2.clone();
        let match_res = MATCH_RES.clone();
        let (witness, mut statement) =
            create_witness_statement(party0_wallet, party1_wallet, match_res);

        // Modify the order of party 0
        statement.party0_modified_shares.orders[statement.party0_order_index].amount -=
            Scalar::one();

        assert!(!constraints_satisfied(witness, statement));
    }

    /// Tests cases in which an element is spuriously modified that should not be
    #[test]
    fn test_invalid_settle__spurious_modifications() {
        let party0_wallet = WALLET1.clone();
        let party1_wallet = WALLET2.clone();
        let match_res = MATCH_RES.clone();
        let (witness, original_statement) =
            create_witness_statement(party0_wallet, party1_wallet, match_res);

        // Modify a balance that should not be modified
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.balances[statement.party0_send_balance_index].mint +=
            Scalar::one();

        assert!(!constraints_satisfied(witness.clone(), statement));

        // Modify an order that should not be modified
        let mut statement = original_statement.clone();
        statement.party1_modified_shares.orders[statement.party1_order_index].price -=
            Scalar::one();

        assert!(!constraints_satisfied(witness.clone(), statement));

        // Modify a fee
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.fees[0].gas_token_amount += Scalar::one();

        assert!(!constraints_satisfied(witness.clone(), statement));

        // Modify a key
        let mut statement = original_statement.clone();
        statement.party1_modified_shares.keys.pk_match += Scalar::one();

        assert!(!constraints_satisfied(witness.clone(), statement));

        // Modify the blinder
        let mut statement = original_statement;
        statement.party0_modified_shares.blinder += Scalar::one();

        assert!(!constraints_satisfied(witness, statement));
    }
}
