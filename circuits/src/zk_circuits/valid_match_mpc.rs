//! Defines the VALID MATCH MPC circuit that proves knowledge of orders
//! which intersect to the given matches result
//!
//! See the whitepaper (https://renegade.fi/whitepaper.pdf) appendix A.5
//! for a formal specification

use std::{borrow::Borrow, marker::PhantomData};

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
    r1cs_mpc::{
        MpcLinearCombination, MpcProver, MpcRandomizableConstraintSystem, MpcVariable, R1CSError,
        SharedR1CSProof,
    },
    BulletproofGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto, beaver::SharedValueSource,
    network::MpcNetwork,
};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};

use crate::{
    errors::{MpcError, ProverError, VerifierError},
    mpc::SharedFabric,
    mpc_gadgets::poseidon::PoseidonSpongeParameters,
    types::{
        balance::{
            AuthenticatedBalanceVar, AuthenticatedCommittedBalance, BalanceVar, CommittedBalance,
        },
        order::{AuthenticatedCommittedOrder, AuthenticatedOrderVar, CommittedOrder, OrderVar},
        r#match::{
            AuthenticatedCommittedMatchResult, AuthenticatedMatchResultVar, CommittedMatchResult,
            MatchResultVar,
        },
    },
    zk_gadgets::poseidon::MultiproverPoseidonHashGadget,
    CommitSharedProver, CommitVerifier, MultiProverCircuit, Open,
};
use crate::{
    types::r#match::AuthenticatedLinkableMatchResultCommitment,
    zk_gadgets::{
        fixed_point::AuthenticatedFixedPointVar,
        select::{
            CondSelectGadget, CondSelectVectorGadget, MultiproverCondSelectGadget,
            MultiproverCondSelectVectorGadget,
        },
    },
};
use crate::{
    types::{balance::LinkableBalanceCommitment, order::LinkableOrderCommitment},
    zk_gadgets::{
        comparators::{
            GreaterThanEqGadget, GreaterThanEqZeroGadget, MultiproverGreaterThanEqGadget,
            MultiproverGreaterThanEqZeroGadget,
        },
        fixed_point::{CommittedFixedPoint, FixedPointVar},
    },
};

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchMpcCircuit<'a, N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// Phantom
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
        hasher.hash(input, expected_out, cs)
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

        // Check that the prices of the orders overlap
        // 1. Mux buy/sell side based on the direction of the match
        let prices = MultiproverCondSelectVectorGadget::select(
            cs,
            &[order2.price.repr.clone(), order1.price.repr.clone()],
            &[order1.price.repr.clone(), order2.price.repr.clone()],
            matches.direction.clone().into(),
            fabric.clone(),
        )?;
        let buy_side_price = AuthenticatedFixedPointVar {
            repr: prices[0].to_owned(),
        };
        let sell_side_price = AuthenticatedFixedPointVar {
            repr: prices[1].to_owned(),
        };

        // 2. Enforce that the buy side price is greater than or equal to the sell side price
        MultiproverGreaterThanEqGadget::<'_, 64 /* bitlength */, N, S>::constrain_greater_than_eq(
            buy_side_price.repr,
            sell_side_price.repr,
            fabric.clone(),
            cs,
        )?;

        // Check that price is correctly computed to be the midpoint
        // i.e. price1 + price2 = 2 * execution_price
        let double_execution_price: AuthenticatedFixedPointVar<_, _> = matches
            .execution_price
            .mul_integer(
                MpcLinearCombination::from_scalar(Scalar::from(2u64), fabric.0.clone()),
                cs,
            )
            .map_err(ProverError::Collaborative)?;
        double_execution_price.constrain_equal(&(&order1.price + &order2.price), cs);

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
            max_minus_min1,
            max_minus_min2,
            matches.min_amount_order_index.into(),
            fabric.clone(),
            cs,
        )?;
        cs.constrain(&max_minus_min_expected - &matches.max_minus_min_amount);

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be computed correctly.
        // I.e. the above constraint forces `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) - min(amounts)
        MultiproverGreaterThanEqZeroGadget::<'_, 32 /* bitlength */, _, _>::constrain_greater_than_zero(
            matches.max_minus_min_amount.clone(),
            fabric.clone(),
            cs,
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
        let expected_quote_amount = matches
            .execution_price
            .mul_integer(&matches.base_amount, cs)
            .map_err(ProverError::Collaborative)?;
        expected_quote_amount.constrain_equal_integer(&matches.quote_amount, cs);

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
            &party0_buy_side_selection,
            &party1_buy_side_selection,
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
            balance1.amount.into(),
            party0_buy_amount,
            fabric.clone(),
            cs,
        )?;

        MultiproverGreaterThanEqGadget::<'_, 64 /* bitlength */, N, S>::constrain_greater_than_eq(
            balance2.amount.into(),
            party1_buy_amount,
            fabric,
            cs,
        )?;

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

        // Check that the prices of the orders overlap
        // 1. Mux buy/sell side based on the direction of the match
        let prices = CondSelectVectorGadget::select(
            &[order2.price.repr.clone(), order1.price.repr.clone()],
            &[order1.price.repr.clone(), order2.price.repr.clone()],
            matches.direction.into(),
            cs,
        );
        let buy_side_price = FixedPointVar {
            repr: prices[0].to_owned(),
        };
        let sell_side_price = FixedPointVar {
            repr: prices[1].to_owned(),
        };

        // 2. Enforce that the buy side price is greater than or equal to the sell side price
        GreaterThanEqGadget::<64 /* bitlength */>::constrain_greater_than_eq(
            buy_side_price.repr,
            sell_side_price.repr,
            cs,
        );

        // Constrain the execution price to the midpoint of the two order prices
        let double_execution_price = matches
            .execution_price
            .mul_integer(Scalar::from(2u64) * Variable::One(), cs);
        double_execution_price.constraint_equal(order1.price + order2.price, cs);

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
            max_minus_min1,
            max_minus_min2,
            matches.min_amount_order_index.into(),
            cs,
        );
        cs.constrain(max_minus_min_expected - matches.max_minus_min_amount);

        // 2. Constrain the max_minus_min_amount value to be positive
        // This, along with the previous check, constrain `max_minus_min_amount` to be computed correctly.
        // I.e. the above constraint forces `max_minus_min_amount` to be either max(amounts) - min(amounts)
        // or min(amounts) - max(amounts).
        // Constraining the value to be positive forces it to be equal to max(amounts) - min(amounts)
        GreaterThanEqZeroGadget::<32 /* bitlength */>::constrain_greater_than_zero(
            matches.max_minus_min_amount,
            cs,
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
        let expected_quote_amount = matches.execution_price.mul_integer(matches.base_amount, cs);
        expected_quote_amount.constraint_equal_integer(matches.quote_amount, cs);

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
            &party0_buy_side_selection,
            &party1_buy_side_selection,
            matches.direction,
            cs,
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
            balance1.amount.into(),
            party0_buy_amount,
            cs,
        );

        GreaterThanEqGadget::<64 /* bitlength */>::constrain_greater_than_eq(
            balance2.amount.into(),
            party1_buy_amount,
            cs,
        );

        Ok(())
    }
}

/// The witness type for the circuit proving the VALID MATCH MPC statement
///
/// Note that the witness structure does not include both orders or balances.
/// This is because the witness is distributed (neither party knows both sides)
/// and is realized during the commit phase of the collaborative proof.
#[derive(Debug)]
pub struct ValidMatchMpcWitness<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The local party's order that was matched by MPC
    pub my_order: LinkableOrderCommitment,
    /// A balance known by the local party that covers the position
    /// expressed in their order
    pub my_balance: LinkableBalanceCommitment,
    /// The result of running a match MPC on the given orders
    ///
    /// We do not open this value before proving so that we can avoid leaking information
    /// before the collaborative proof has finished
    pub match_res: AuthenticatedLinkableMatchResultCommitment<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for ValidMatchMpcWitness<N, S> {
    fn clone(&self) -> Self {
        Self {
            my_order: self.my_order.clone(),
            my_balance: self.my_balance.clone(),
            match_res: self.match_res.clone(),
        }
    }
}

/// Represents a commitment to the VALID MATCH MPC witness
#[derive(Clone, Debug)]
pub struct ValidMatchCommitmentShared<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// A commitment to the first party's order
    pub order1: AuthenticatedCommittedOrder<N, S>,
    /// A commitment to the first party's balance
    pub balance1: AuthenticatedCommittedBalance<N, S>,
    /// A commitment to the second party's order
    pub order2: AuthenticatedCommittedOrder<N, S>,
    /// A commitment to the second party's balance
    pub balance2: AuthenticatedCommittedBalance<N, S>,
    /// A commitment to the match result from the MPC
    pub match_result: AuthenticatedCommittedMatchResult<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<ValidMatchCommitmentShared<N, S>>
    for Vec<AuthenticatedCompressedRistretto<N, S>>
{
    fn from(commit: ValidMatchCommitmentShared<N, S>) -> Self {
        let order1_vec = Into::<Vec<_>>::into(commit.order1);
        let balance1_vec = Into::<Vec<_>>::into(commit.balance1);
        let order2_vec = Into::<Vec<_>>::into(commit.order2);
        let balance2_vec = Into::<Vec<_>>::into(commit.balance2);
        let match_vec = Into::<Vec<_>>::into(commit.match_result);

        order1_vec
            .into_iter()
            .chain(balance1_vec.into_iter())
            .chain(order2_vec.into_iter())
            .chain(balance2_vec.into_iter())
            .chain(match_vec.into_iter())
            .collect_vec()
    }
}

/// An opened commitment to the VALID MATCH MPC witness
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchCommitment {
    /// A commitment to the first party's order
    pub order1: CommittedOrder,
    /// A commitment to the first party's balance
    pub balance1: CommittedBalance,
    /// A commitment to the second party's order
    pub order2: CommittedOrder,
    /// A commitment to the second party's balance
    pub balance2: CommittedBalance,
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
                price: CommittedFixedPoint {
                    repr: commitments[3],
                },
                amount: commitments[4],
                timestamp: commitments[5],
            },
            balance1: CommittedBalance {
                mint: commitments[6],
                amount: commitments[7],
            },
            order2: CommittedOrder {
                quote_mint: commitments[8],
                base_mint: commitments[9],
                side: commitments[10],
                price: CommittedFixedPoint {
                    repr: commitments[11],
                },
                amount: commitments[12],
                timestamp: commitments[13],
            },
            balance2: CommittedBalance {
                mint: commitments[14],
                amount: commitments[15],
            },
            match_result: CommittedMatchResult {
                quote_mint: commitments[16],
                base_mint: commitments[17],
                quote_amount: commitments[18],
                base_amount: commitments[19],
                direction: commitments[20],
                execution_price: CommittedFixedPoint {
                    repr: commitments[21],
                },
                max_minus_min_amount: commitments[22],
                min_amount_order_index: commitments[23],
            },
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open<N, S>
    for ValidMatchCommitmentShared<N, S>
{
    type OpenOutput = ValidMatchCommitment;
    type Error = MpcError;

    fn open(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
        let all_commitments: Vec<AuthenticatedCompressedRistretto<N, S>> = self.into();
        let opened_values: Vec<CompressedRistretto> =
            AuthenticatedCompressedRistretto::batch_open(&all_commitments)
                .map_err(|err| MpcError::SharingError(err.to_string()))?
                .into_iter()
                .map(|val| val.value())
                .collect();

        Ok(Into::<ValidMatchCommitment>::into(opened_values.borrow()))
    }

    fn open_and_authenticate(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidMatchMpcStatement {}

/// Prover implementation of the Valid Match circuit
impl<'a, N: 'a + MpcNetwork + Send, S: SharedValueSource<Scalar>> MultiProverCircuit<'a, N, S>
    for ValidMatchMpcCircuit<'a, N, S>
{
    type Statement = ValidMatchMpcStatement;
    type Witness = ValidMatchMpcWitness<N, S>;
    type WitnessCommitment = ValidMatchCommitmentShared<N, S>;

    const BP_GENS_CAPACITY: usize = 256;

    fn prove(
        witness: Self::Witness,
        _statement: Self::Statement,
        mut prover: MpcProver<'a, '_, '_, N, S>,
        fabric: SharedFabric<N, S>,
    ) -> Result<(ValidMatchCommitmentShared<N, S>, SharedR1CSProof<N, S>), ProverError> {
        // Commit to party 0's inputs first, then party 1's inputs
        let mut rng = OsRng {};

        let (party0_vars, party0_comm) = (witness.my_order.clone(), witness.my_balance.clone())
            .commit(0 /* owning_party */, &mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;
        let (party1_vars, party1_comm) = (witness.my_order, witness.my_balance)
            .commit(1 /* owning_party */, &mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;

        let (match_var, match_commit) = witness
            .match_res
            .commit(0 /* owning_party */, &mut rng, &mut prover)
            .map_err(ProverError::Mpc)?;

        // Destructure the committed values
        let party0_order = party0_vars.0;
        let party0_balance = party0_vars.1;
        let party1_order = party1_vars.0;
        let party1_balance = party1_vars.1;

        Self::matching_engine_check(
            &mut prover,
            party0_order,
            party1_order,
            party0_balance,
            party1_balance,
            match_var,
            fabric,
        )?;

        // Prove the statement
        let bp_gens = BulletproofGens::new(Self::BP_GENS_CAPACITY, 1 /* party_capacity */);
        let proof = prover.prove(&bp_gens).map_err(ProverError::Collaborative)?;

        Ok((
            ValidMatchCommitmentShared {
                order1: party0_comm.0,
                balance1: party0_comm.1,
                order2: party1_comm.0,
                balance2: party1_comm.1,
                match_result: match_commit,
            },
            proof,
        ))
    }

    fn verify(
        witness_commitment: ValidMatchCommitment,
        _statement: Self::Statement,
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
        let party1_order = witness_commitment
            .order2
            .commit_verifier(&mut verifier)
            .unwrap();
        let party1_balance = witness_commitment
            .balance2
            .commit_verifier(&mut verifier)
            .unwrap();

        let match_res_var = witness_commitment
            .match_result
            .commit_verifier(&mut verifier)
            .unwrap();

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
