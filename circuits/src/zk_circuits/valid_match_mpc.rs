//! Defines the VALID MATCH MPC circuit that proves knowledge of orders
//! which intersect to the given matches result
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.5
//! for a formal specification

// TODO: Remove this lint allowance
#![allow(unused)]

use std::{borrow::Borrow, marker::PhantomData};

use curve25519_dalek::digest::generic_array::typenum::private::IsLessOrEqualPrivate;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::r1cs::ConstraintSystem;
use mpc_bulletproof::r1cs_mpc::MpcConstraintSystem;
use mpc_bulletproof::{
    r1cs::{LinearCombination, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::{
        MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem, MpcVariable,
        MultiproverError, R1CSError, SharedR1CSProof,
    },
    BulletproofGens,
};
use mpc_ristretto::mpc_scalar::scalar_to_u64;
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto, beaver::SharedValueSource,
    network::MpcNetwork,
};
use rand_core::OsRng;

use crate::scalar_to_bigint;
use crate::zk_gadgets::comparators::{
    GreaterThanEqGadget, GreaterThanEqZeroGadget, MultiproverGreaterThanEqGadget,
    MultiproverGreaterThanEqZeroGadget,
};
use crate::zk_gadgets::select::{
    CondSelectGadget, CondSelectVectorGadget, MultiproverCondSelectGadget,
    MultiproverCondSelectVectorGadget,
};
use crate::{
    errors::{MpcError, ProverError, VerifierError},
    mpc::SharedFabric,
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{
        balance::{
            AuthenticatedBalance, AuthenticatedBalanceVar, AuthenticatedCommittedBalance, Balance,
            BalanceVar, CommittedBalance,
        },
        fee::{AuthenticatedCommittedFee, AuthenticatedFee, CommittedFee, Fee},
        order::{
            AuthenticatedCommittedOrder, AuthenticatedOrder, AuthenticatedOrderVar, CommittedOrder,
            Order, OrderVar,
        },
        r#match::{
            AuthenticatedCommittedMatchResult, AuthenticatedMatchResult,
            AuthenticatedMatchResultVar, CommittedMatchResult, MatchResultVar,
        },
    },
    zk_gadgets::poseidon::{MultiproverPoseidonHashGadget, PoseidonHashGadget},
    CommitSharedProver, CommitVerifier, MultiProverCircuit, Open,
};

const ORDER_LENGTH_SCALARS: usize = 5; // mint1, mint2, direction, price, amount
const BALANCE_LENGTH_SCALARS: usize = 2; // amount, direction
const FEE_LENGTH_SCALARS: usize = 4; // settle_key, gas_addr, gas_token_amount, percentage_fee

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchMpcCircuit<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    _phantom: &'a PhantomData<(N, S)>,
}

impl<'a, N: 'a + MpcNetwork + Send, S: 'a + SharedValueSource<Scalar>>
    ValidMatchMpcCircuit<'a, N, S>
{
    /// Assert that the hash of an input equals the expected public value
    ///
    /// This is used throughout the statement to assert input consistency with
    /// linked proofs
    pub fn input_consistency_check<L, CS>(
        cs: &mut CS,
        input: &[L],
        expected_out: &L,
        fabric: SharedFabric<N, S>,
    ) -> Result<(), ProverError>
    where
        L: Into<MpcLinearCombination<N, S>> + Clone,
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Build a hasher and constrain the hash of the input to equal the expected output
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = MultiproverPoseidonHashGadget::new(hash_params, fabric);
        hasher.hash(cs, input, expected_out)
    }

    /// The single prover version of the input consistency check
    ///
    /// Used to apply constraints to a verifier or for local testing
    pub(crate) fn input_consistency_single_prover<L, CS>(
        cs: &mut CS,
        input: &[L],
        expected_out: &L,
    ) -> Result<(), R1CSError>
    where
        L: Into<LinearCombination> + Clone,
        CS: RandomizableConstraintSystem,
    {
        // Build a hasher and constrain the hash of the input to equal the expected output
        let hash_params = PoseidonSpongeParameters::default();
        let mut hasher = PoseidonHashGadget::new(hash_params);
        hasher.hash(cs, input, expected_out.clone())
    }

    /// The order crossing check, verifies that the matches result is valid given the orders
    /// and balances of the two parties
    pub fn matching_engine_check<CS>(
        cs: &mut CS,
        order1: AuthenticatedOrderVar<N, S>,
        order2: AuthenticatedOrderVar<N, S>,
        balance1: AuthenticatedBalanceVar<N, S>,
        balance2: AuthenticatedBalanceVar<N, S>,
        matches: AuthenticatedMatchResultVar<N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<(), ProverError>
    where
        CS: MpcRandomizableConstraintSystem<'a, N, S>,
    {
        // Check that both orders are for the matched asset pair
        cs.constrain(&order1.quote_mint - &matches.quote_mint);
        cs.constrain(&order1.base_mint - &matches.base_mint);
        cs.constrain(&order2.quote_mint - &matches.quote_mint);
        cs.constrain(&order2.base_mint - &matches.base_mint);

        // Check that the direction of the match is the same as the first party's direction
        cs.constrain(&matches.direction - &order1.side);

        // Check that the orders are on opposite sides of the market. It is assumed that order
        // sides are already constrained to be binary when they are submitted. More broadly it
        // is assumed that orders are well formed, checking this amounts to checking their inclusion
        // in the state tree, which is done in `input_consistency_check`
        cs.constrain(&order1.side + order2.side - MpcVariable::one(fabric.0.clone()));

        // Check that price is correctly computed to be the midpoint
        // i.e. price1 + price2 = 2 * execution_price
        cs.constrain(&order1.price + &order2.price - Scalar::from(2u64) * &matches.execution_price);

        // Constrain the min_amount_order_index to be binary
        // i.e. 0 === min_amount_order_index * (1 - min_amount_order_index)
        let (_, _, mul_out) = cs
            .multiply(
                &matches.min_amount_order_index.clone().into(),
                &(MpcLinearCombination::from_scalar(Scalar::one(), fabric.0.clone())
                    - &matches.min_amount_order_index),
            )
            .map_err(ProverError::Collaborative)?;
        cs.constrain(mul_out.into());

        // Check that the amount of base currency exchanged is equal to the minimum of the two
        // order's amounts

        // 1. Constraint he max_minus_min_amount to be correctly computed with respect to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = &order1.amount - &order2.amount;
        let max_minus_min2 = &order2.amount - &order1.amount;
        let max_minus_min_expected = MultiproverCondSelectGadget::select(
            cs,
            max_minus_min1,
            max_minus_min2,
            matches.min_amount_order_index.into(),
            fabric.clone(),
        )?;
        cs.constrain(&max_minus_min_expected - &matches.max_minus_min_amount);

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be computed correctly.
        // I.e. the above constraint forces `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) - min(amounts)
        MultiproverGreaterThanEqZeroGadget::<'_, 32 /* bitlength */, _, _>::constrain_greater_than_zero(
            cs,
            matches.max_minus_min_amount.clone(),
            fabric.clone(),
        )?;

        // 3. Constrain the executed base amount to be the minimum of the two order amounts
        // We use the identity
        //      min(a, b) = 1/2 * (a + b - [max(a, b) - min(a, b)])
        // Above we are given max(a, b) - min(a, b), so we can enforce the constraint
        //      2 * executed_amount = amount1 + amount2 - max_minus_min_amount
        let lhs = Scalar::from(2u64) * &matches.base_amount;
        let rhs = &order1.amount + &order2.amount - &matches.max_minus_min_amount;
        cs.constrain(lhs - rhs);

        // The quote amount should then equal the price multiplied by the base amount
        let (_, _, expected_quote_amount) = cs
            .multiply(
                &matches.base_amount.clone().into(),
                &matches.execution_price.into(),
            )
            .map_err(ProverError::Collaborative)?;
        cs.constrain(expected_quote_amount - &matches.quote_amount);

        // Ensure the balances cover the orders
        // 1. Mux between the (mint, amount) pairs that the parties are expected to cover by the
        // direction of the order

        // The selections in the case that party 0 is on the buy side of the match
        let party0_buy_side_selection = vec![
            matches.base_mint.clone(),
            matches.base_amount.clone(),
            matches.quote_mint.clone(),
            matches.quote_amount.clone(),
        ];

        let party1_buy_side_selection = vec![
            matches.quote_mint.clone(),
            matches.quote_amount.clone(),
            matches.base_mint.clone(),
            matches.base_amount.clone(),
        ];

        let selected_values = MultiproverCondSelectVectorGadget::select(
            cs,
            party0_buy_side_selection,
            party1_buy_side_selection,
            matches.direction,
            fabric.clone(),
        )?;

        // Destructure the conditional selection
        let party0_buy_mint = selected_values[0].to_owned();
        let party0_buy_amount = selected_values[1].to_owned();
        let party1_buy_mint = selected_values[2].to_owned();
        let party1_buy_amount = selected_values[3].to_owned();

        // Constrain the mints on the balances to be correct
        cs.constrain(&party0_buy_mint - &balance1.mint);
        cs.constrain(&party1_buy_mint - &balance2.mint);

        // Constrain the amounts of the balances to subsume the obligations from the match
        MultiproverGreaterThanEqGadget::<'_, 64 /* bitlength */, N, S>::constrain_greater_than_eq(
            cs,
            balance1.amount.into(),
            party0_buy_amount,
            fabric.clone(),
        );

        MultiproverGreaterThanEqGadget::<'_, 64 /* bitlength */, N, S>::constrain_greater_than_eq(
            cs,
            balance2.amount.into(),
            party1_buy_amount,
            fabric,
        );

        Ok(())
    }

    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    pub fn matching_engine_check_single_prover<CS>(
        cs: &mut CS,
        order1: OrderVar,
        order2: OrderVar,
        balance1: BalanceVar,
        balance2: BalanceVar,
        matches: MatchResultVar,
    ) -> Result<(), R1CSError>
    where
        CS: RandomizableConstraintSystem,
    {
        // Check that both of the orders are for the matched asset pair
        cs.constrain(order1.quote_mint - matches.quote_mint);
        cs.constrain(order1.base_mint - matches.base_mint);
        cs.constrain(order2.quote_mint - matches.quote_mint);
        cs.constrain(order2.base_mint - matches.base_mint);

        // Constrain the direction of the match to the direction of the first party's order
        cs.constrain(matches.direction - order1.side);

        // Check that the orders are in opposite directions
        cs.constrain(order1.side + order2.side - Scalar::one());

        // Constrain the execution price to the midpoint of the two order prices
        cs.constrain(order1.price + order2.price - Scalar::from(2u64) * matches.execution_price);

        // Constrain the min_amount_order_index to be binary
        // i.e. 0 === min_amount_order_index * (1 - min_amount_order_index)
        let (_, _, mul_out) = cs.multiply(
            matches.min_amount_order_index.into(),
            Scalar::one() - matches.min_amount_order_index,
        );
        cs.constrain(mul_out.into());

        // Check that the amount of base currency exchanged is equal to the minimum of the two
        // order's amounts

        // 1. Constraint he max_minus_min_amount to be correctly computed with respect to the argmin
        // witness variable min_amount_order_index
        let max_minus_min1 = order1.amount - order2.amount;
        let max_minus_min2 = order2.amount - order1.amount;
        let max_minus_min_expected = CondSelectGadget::select(
            cs,
            max_minus_min1,
            max_minus_min2,
            matches.min_amount_order_index.into(),
        );
        cs.constrain(max_minus_min_expected - matches.max_minus_min_amount);

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be computed correctly.
        // I.e. the above constraint forces `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) - min(amounts)
        GreaterThanEqZeroGadget::<32 /* bitlength */>::constrain_greater_than_zero(
            cs,
            matches.max_minus_min_amount,
        );

        // 3. Constrain the executed base amount to be the minimum of the two order amounts
        // We use the identity
        //      min(a, b) = 1/2 * (a + b - [max(a, b) - min(a, b)])
        // Above we are given max(a, b) - min(a, b), so we can enforce the constraint
        //      2 * executed_amount = amount1 + amount2 - max_minus_min_amount
        let lhs = Scalar::from(2u64) * matches.base_amount;
        let rhs = order1.amount + order2.amount - matches.max_minus_min_amount;
        cs.constrain(lhs - rhs);

        // The quote amount should then equal the price multiplied by the base amount
        let (_, _, expected_quote_amount) =
            cs.multiply(matches.base_amount.into(), matches.execution_price.into());
        cs.constrain(expected_quote_amount - matches.quote_amount);

        // Ensure that the balances cover the obligations from the match
        // 1. Mux between the (mint, amount) pairs that the parties are expected to cover by the
        // direction of the order

        // The selections in the case that party 0 is on the buy side of the match
        let party0_buy_side_selection = vec![
            matches.base_mint,
            matches.base_amount,
            matches.quote_mint,
            matches.quote_amount,
        ];

        let party1_buy_side_selection = vec![
            matches.quote_mint,
            matches.quote_amount,
            matches.base_mint,
            matches.base_amount,
        ];

        let selected_values = CondSelectVectorGadget::select(
            cs,
            party0_buy_side_selection,
            party1_buy_side_selection,
            matches.direction,
        );

        // Destructure the conditional selection
        let party0_buy_mint = selected_values[0].to_owned();
        let party0_buy_amount = selected_values[1].to_owned();
        let party1_buy_mint = selected_values[2].to_owned();
        let party1_buy_amount = selected_values[3].to_owned();

        // Constrain the mints on the balances to be correct
        cs.constrain(party0_buy_mint - balance1.mint);
        cs.constrain(party1_buy_mint - balance2.mint);

        // Constrain the amounts of the balances to subsume the obligations from the match
        GreaterThanEqGadget::<64 /* bitlength */>::constrain_greater_than_eq(
            cs,
            balance1.amount.into(),
            party0_buy_amount,
        );

        GreaterThanEqGadget::<64 /* bitlength */>::constrain_greater_than_eq(
            cs,
            balance2.amount.into(),
            party1_buy_amount,
        );

        Ok(())
    }
}

/// The witness type for the circuit proving the VALID MATCH MPC statement
///
/// Note that the witness structure does not include both orders or balances.
/// This is because the witness is distributed (neither party knows both sides)
/// and is realized during the commit phase of the collaborative proof.
///
/// TODO: Add in the fee tuples from each party
#[derive(Clone, Debug)]
pub struct ValidMatchMpcWitness<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The local party's order that was matched by MPC
    pub my_order: Order,
    /// A balance known by the local party that covers the position
    /// expressed in their order
    pub my_balance: Balance,
    /// A fee that covers the gas and transaction fee of the local party
    pub my_fee: Fee,
    /// The result of running a match MPC on the given orders
    ///
    /// We do not open this value before proving so that we can avoid leaking information
    /// before the collaborative proof has finished
    pub match_res: AuthenticatedMatchResult<N, S>,
}

/// Represents a commitment to the VALID MATCH MPC witness
#[derive(Clone, Debug)]
pub struct ValidMatchCommitmentShared<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// A commitment to the first party's order
    pub order1: AuthenticatedCommittedOrder<N, S>,
    /// A commitment to the first party's balance
    pub balance1: AuthenticatedCommittedBalance<N, S>,
    /// A commitment to the first party's fee
    pub fee1: AuthenticatedCommittedFee<N, S>,
    /// A commitment to the second party's order
    pub order2: AuthenticatedCommittedOrder<N, S>,
    /// A commitment to the second party's balance
    pub balance2: AuthenticatedCommittedBalance<N, S>,
    /// A commitment to the first party's fee
    pub fee2: AuthenticatedCommittedFee<N, S>,
    /// A commitment to the match result from the MPC
    pub match_result: AuthenticatedCommittedMatchResult<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<ValidMatchCommitmentShared<N, S>>
    for Vec<AuthenticatedCompressedRistretto<N, S>>
{
    fn from(commit: ValidMatchCommitmentShared<N, S>) -> Self {
        let order1_vec = Into::<Vec<_>>::into(commit.order1);
        let balance1_vec = Into::<Vec<_>>::into(commit.balance1);
        let fee1_vec = Into::<Vec<_>>::into(commit.fee1);
        let order2_vec = Into::<Vec<_>>::into(commit.order2);
        let balance2_vec = Into::<Vec<_>>::into(commit.balance2);
        let fee2_vec = Into::<Vec<_>>::into(commit.fee2);
        let match_vec = Into::<Vec<_>>::into(commit.match_result);

        order1_vec
            .into_iter()
            .chain(balance1_vec.into_iter())
            .chain(fee1_vec.into_iter())
            .chain(order2_vec.into_iter())
            .chain(balance2_vec.into_iter())
            .chain(fee2_vec.into_iter())
            .chain(match_vec.into_iter())
            .collect_vec()
    }
}

/// An opened committment to the VALID MATCH MPC witness
#[derive(Clone, Debug)]
pub struct ValidMatchCommitment {
    /// A commitment to the first party's order
    pub order1: CommittedOrder,
    /// A commitment to the first party's balance
    pub balance1: CommittedBalance,
    /// A commitment to the first party's fee
    pub fee1: CommittedFee,
    /// A commitment to the second party's order
    pub order2: CommittedOrder,
    /// A commitment to the second party's balance
    pub balance2: CommittedBalance,
    /// A commitment to the first party's fee
    pub fee2: CommittedFee,
    /// A commitment to the match result
    pub match_result: CommittedMatchResult,
}

impl From<&[CompressedRistretto]> for ValidMatchCommitment {
    fn from(commitments: &[CompressedRistretto]) -> Self {
        Self {
            order1: CommittedOrder {
                quote_mint: commitments[0],
                base_mint: commitments[1],
                side: commitments[2],
                price: commitments[3],
                amount: commitments[4],
            },
            balance1: CommittedBalance {
                mint: commitments[5],
                amount: commitments[6],
            },
            fee1: CommittedFee {
                settle_key: commitments[7],
                gas_addr: commitments[8],
                gas_token_amount: commitments[9],
                percentage_fee: commitments[10],
            },
            order2: CommittedOrder {
                quote_mint: commitments[11],
                base_mint: commitments[12],
                side: commitments[13],
                price: commitments[14],
                amount: commitments[15],
            },
            balance2: CommittedBalance {
                mint: commitments[16],
                amount: commitments[17],
            },
            fee2: CommittedFee {
                settle_key: commitments[18],
                gas_addr: commitments[19],
                gas_token_amount: commitments[20],
                percentage_fee: commitments[21],
            },
            match_result: CommittedMatchResult {
                quote_mint: commitments[22],
                base_mint: commitments[23],
                quote_amount: commitments[24],
                base_amount: commitments[25],
                direction: commitments[26],
                execution_price: commitments[27],
                max_minus_min_amount: commitments[28],
                min_amount_order_index: commitments[29],
            },
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open for ValidMatchCommitmentShared<N, S> {
    type OpenOutput = ValidMatchCommitment;
    type Error = MpcError;

    fn open(self) -> Result<Self::OpenOutput, Self::Error> {
        let all_commitments: Vec<AuthenticatedCompressedRistretto<N, S>> = self.into();
        let opened_values: Vec<CompressedRistretto> =
            AuthenticatedCompressedRistretto::batch_open(&all_commitments)
                .map_err(|err| MpcError::SharingError(err.to_string()))?
                .into_iter()
                .map(|val| val.value())
                .collect();

        Ok(Into::<ValidMatchCommitment>::into(opened_values.borrow()))
    }

    fn open_and_authenticate(self) -> Result<Self::OpenOutput, Self::Error> {
        let all_commitments: Vec<AuthenticatedCompressedRistretto<_, _>> = self.into();
        let opened_values: Vec<CompressedRistretto> =
            AuthenticatedCompressedRistretto::batch_open_and_authenticate(&all_commitments)
                .map_err(|err| MpcError::SharingError(err.to_string()))?
                .into_iter()
                .map(|val| val.value())
                .collect();

        Ok(Into::<ValidMatchCommitment>::into(opened_values.borrow()))
    }
}

/// The parameterization for the VALID MATCH MPC statement
///
/// TODO: Add in midpoint oracle prices
/// TODO: Commitments to the randomness
#[derive(Debug, Clone)]
pub struct ValidMatchMpcStatement {
    /// The expected hash of the first order
    pub hash_order1: Scalar,
    /// The expected hash of the first balance
    pub hash_balance1: Scalar,
    /// The expected hash of the first party's fee
    pub hash_fee1: Scalar,
    /// The expected hash of the first party's randomness
    pub hash_randomness1: Scalar,
    /// The expected hash of the second order
    pub hash_order2: Scalar,
    /// The expected hash of the sceond balance
    pub hash_balance2: Scalar,
    /// The expected hash of the second party's fee
    pub hash_fee2: Scalar,
    /// The expected hash of the second party's randomness
    pub hash_randomness2: Scalar,
}

/// Prover implementation of the Valid Match circuit
impl<'a, N: 'a + MpcNetwork + Send, S: SharedValueSource<Scalar>> MultiProverCircuit<'a, N, S>
    for ValidMatchMpcCircuit<'a, N, S>
{
    type Statement = ValidMatchMpcStatement;
    type Witness = ValidMatchMpcWitness<N, S>;
    type WitnessCommitment = ValidMatchCommitmentShared<N, S>;

    const BP_GENS_CAPACITY: usize = 16384;

    fn prove(
        witness: Self::Witness,
        statement: Self::Statement,
        mut prover: MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<(ValidMatchCommitmentShared<N, S>, SharedR1CSProof<N, S>), ProverError> {
        // Commit to party 0's inputs first, then party 1's inputs
        let mut rng = OsRng {};

        let (party0_vars, party0_comm) = (
            witness.my_order.clone(),
            witness.my_balance.clone(),
            witness.my_fee.clone(),
        )
            .commit(0 /* owning_party */, &mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;
        let (party1_vars, party1_comm) = (witness.my_order, witness.my_balance, witness.my_fee)
            .commit(1 /* owning_party */, &mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;

        let (match_var, match_commit) = witness
            .match_res
            .commit(0 /* owning_party */, &mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;

        // Destructure the committed values
        let party0_order = party0_vars.0;
        let party0_balance = party0_vars.1;
        let party0_fee = party0_vars.2;
        let party1_order = party1_vars.0;
        let party1_balance = party1_vars.1;
        let party1_fee = party1_vars.2;

        // Commit to the public statement variables
        let (_, hash_o1_var) = prover.commit_public(statement.hash_order1);
        let (_, hash_b1_var) = prover.commit_public(statement.hash_balance1);
        let (_, hash_f1_var) = prover.commit_public(statement.hash_fee1);
        let (_, hash_o2_var) = prover.commit_public(statement.hash_order2);
        let (_, hash_b2_var) = prover.commit_public(statement.hash_balance2);
        let (_, hash_f2_var) = prover.commit_public(statement.hash_fee2);

        // Check input consistency on all orders, balances, and fees
        Self::input_consistency_check(
            &mut prover,
            &Into::<Vec<MpcVariable<_, _>>>::into(party0_order.clone()),
            &hash_o1_var,
            fabric.clone(),
        )?;
        Self::input_consistency_check(
            &mut prover,
            &Into::<Vec<MpcVariable<_, _>>>::into(party0_balance.clone()),
            &hash_b1_var,
            fabric.clone(),
        )?;
        Self::input_consistency_check(
            &mut prover,
            &Into::<Vec<MpcVariable<_, _>>>::into(party0_fee),
            &hash_f1_var,
            fabric.clone(),
        )?;
        Self::input_consistency_check(
            &mut prover,
            &Into::<Vec<MpcVariable<_, _>>>::into(party1_order.clone()),
            &hash_o2_var,
            fabric.clone(),
        )?;
        Self::input_consistency_check(
            &mut prover,
            &Into::<Vec<MpcVariable<_, _>>>::into(party1_balance.clone()),
            &hash_b2_var,
            fabric.clone(),
        )?;
        Self::input_consistency_check(
            &mut prover,
            &Into::<Vec<MpcVariable<_, _>>>::into(party1_fee),
            &hash_f2_var,
            fabric.clone(),
        )?;

        // TODO: Check that the balances cover the orders
        Self::matching_engine_check(
            &mut prover,
            party0_order,
            party1_order,
            party0_balance,
            party1_balance,
            match_var,
            fabric,
        )?;

        // Prover the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::Collaborative)?;

        Ok((
            ValidMatchCommitmentShared {
                order1: party0_comm.0,
                balance1: party0_comm.1,
                fee1: party0_comm.2,
                order2: party1_comm.0,
                balance2: party1_comm.1,
                fee2: party1_comm.2,
                match_result: match_commit,
            },
            proof,
        ))
    }

    fn verify(
        witness_commitment: ValidMatchCommitment,
        statement: Self::Statement,
        proof: R1CSProof,
        mut verifier: Verifier,
    ) -> Result<(), VerifierError> {
        // Commit to the input variables from the provers
        let party0_order = witness_commitment
            .order1
            .commit_verifier(&mut verifier)
            .unwrap();
        let party0_balance = witness_commitment
            .balance1
            .commit_verifier(&mut verifier)
            .unwrap();
        let party0_fee = witness_commitment
            .fee1
            .commit_verifier(&mut verifier)
            .unwrap();
        let party1_order = witness_commitment
            .order2
            .commit_verifier(&mut verifier)
            .unwrap();
        let party1_balance = witness_commitment
            .balance2
            .commit_verifier(&mut verifier)
            .unwrap();
        let party1_fee = witness_commitment
            .fee2
            .commit_verifier(&mut verifier)
            .unwrap();

        let match_res_var = witness_commitment
            .match_result
            .commit_verifier(&mut verifier)
            .unwrap();

        // Commit to the statement variables
        let hash_o1_var = verifier.commit_public(statement.hash_order1);
        let hash_b1_var = verifier.commit_public(statement.hash_balance1);
        let hash_f1_var = verifier.commit_public(statement.hash_fee1);
        let hash_o2_var = verifier.commit_public(statement.hash_order2);
        let hash_b2_var = verifier.commit_public(statement.hash_balance2);
        let hash_f2_var = verifier.commit_public(statement.hash_fee2);

        // Apply constraints to the verifier
        Self::input_consistency_single_prover(
            &mut verifier,
            &Into::<Vec<Variable>>::into(party0_order.clone()),
            &hash_o1_var,
        )
        .map_err(VerifierError::R1CS)?;
        Self::input_consistency_single_prover(
            &mut verifier,
            &Into::<Vec<Variable>>::into(party0_balance.clone()),
            &hash_b1_var,
        )
        .map_err(VerifierError::R1CS)?;
        Self::input_consistency_single_prover(
            &mut verifier,
            &Into::<Vec<Variable>>::into(party0_fee),
            &hash_f1_var,
        )
        .map_err(VerifierError::R1CS)?;
        Self::input_consistency_single_prover(
            &mut verifier,
            &Into::<Vec<Variable>>::into(party1_order.clone()),
            &hash_o2_var,
        )
        .map_err(VerifierError::R1CS)?;
        Self::input_consistency_single_prover(
            &mut verifier,
            &Into::<Vec<Variable>>::into(party1_balance.clone()),
            &hash_b2_var,
        )
        .map_err(VerifierError::R1CS)?;
        Self::input_consistency_single_prover(
            &mut verifier,
            &Into::<Vec<Variable>>::into(party1_fee),
            &hash_f2_var,
        )
        .map_err(VerifierError::R1CS)?;

        // Check that the matches value is properly formed
        Self::matching_engine_check_single_prover(
            &mut verifier,
            party0_order,
            party1_order,
            party0_balance,
            party1_balance,
            match_res_var,
        )
        .map_err(VerifierError::R1CS)?;

        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        verifier
            .verify(&proof, &bp_gens)
            .map_err(VerifierError::R1CS)
    }
}
