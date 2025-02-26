//! Defines a malleable version of the `VALID MATCH SETTLE ATOMIC` circuit
//!
//! Malleable here means that the match amount is not known at the time the
//! witness and statement are created. Instead, we constrain a valid range of
//! amounts that the internal order and balance can support

// ----------------------
// | Circuit Definition |
// ----------------------

use circuit_macros::circuit_type;
use circuit_types::{
    balance::{Balance, BalanceVar},
    fees::{FeeTakeRate, FeeTakeRateVar},
    order::{Order, OrderVar},
    r#match::{BoundedMatchResult, BoundedMatchResultVar},
    traits::{BaseType, CircuitBaseType, CircuitVarType, SingleProverCircuit},
    wallet::WalletShare,
    Address, PlonkCircuit, AMOUNT_BITS,
};
use constants::{Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, proof_linking::GroupLayout, traits::Circuit, Variable};
use serde::{Deserialize, Serialize};

use crate::zk_gadgets::{
    arithmetic::NoopGadget,
    comparators::{EqGadget, GreaterThanEqGadget},
    fixed_point::FixedPointGadget,
    select::CondSelectVectorGadget,
    wallet_operations::{AmountGadget, FeeGadget, PriceGadget},
};

/// The circuit implementation of `VALID MALLEABLE MATCH SETTLE ATOMIC`
pub struct ValidMalleableMatchSettleAtomic<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;
/// A `VALID MALLEABLE MATCH SETTLE ATOMIC` with default state element sizing
pub type SizedValidMalleableMatchSettleAtomic =
    ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
    ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The circuit constraints for `VALID MALLEABLE MATCH SETTLE ATOMIC`
    pub fn circuit(
        statement: &ValidMalleableMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMalleableMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Constrain the malleable fields
        Self::constrain_malleable_fields(statement, cs)?;
        // Type validation on the inputs
        Self::validate_inputs(statement, witness, cs)?;
        // Validate the construction of the bounded match result
        Self::validate_match_result(statement, witness, cs)?;
        // Validate the price protection
        PriceGadget::validate_price_protection(
            &statement.bounded_match_result.price,
            &witness.internal_party_order,
            cs,
        )?;

        // Lastly, we make public the internal party's public shares _before_
        // modification. These are proof-linked into the witness from `VALID
        // COMMITMENTS`, but we need to ensure the shares in the witness correspond to
        // those in the statement
        EqGadget::constrain_eq(
            &statement.internal_party_public_shares,
            &witness.internal_party_public_shares,
            cs,
        )
    }

    /// Constrain the fields that appear in no constraints to prevent them from
    /// being changed
    fn constrain_malleable_fields(
        statement: &ValidMalleableMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The relayer fee address, and both the internal/external fee rates all need
        // constraints
        NoopGadget::constrain_noop(&statement.relayer_fee_address, cs)?;
        NoopGadget::constrain_noop(&statement.internal_fee_rates, cs)?;
        NoopGadget::constrain_noop(&statement.external_fee_rates, cs)
    }

    // --- Input Validation --- //

    /// Validate the inputs: bit-lengths, ranges, etc.
    pub(super) fn validate_inputs(
        statement: &ValidMalleableMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        _witness: &ValidMalleableMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        Self::type_validate_match_result(&statement.bounded_match_result, cs)?;
        Self::type_validate_fee_rates(
            &statement.internal_fee_rates,
            &statement.external_fee_rates,
            cs,
        )
    }

    /// Validate the match result
    fn type_validate_match_result(
        match_res: &BoundedMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let min_amt = match_res.min_base_amount;
        let max_amt = match_res.max_base_amount;

        // The min/max base amounts must be constructed correctly
        // and the min amount must be less than the max amount
        AmountGadget::constrain_valid_amount(min_amt, cs)?;
        AmountGadget::constrain_valid_amount(max_amt, cs)?;
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(max_amt, min_amt, cs)?;

        // The price must be a valid price
        PriceGadget::constrain_valid_price(match_res.price, cs)
    }

    /// Validate the fee rates
    fn type_validate_fee_rates(
        internal_fee: &FeeTakeRateVar,
        external_fee: &FeeTakeRateVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        FeeGadget::constrain_valid_fee(external_fee.relayer_fee_rate, cs)?;
        FeeGadget::constrain_valid_fee(external_fee.protocol_fee_rate, cs)?;
        FeeGadget::constrain_valid_fee(internal_fee.relayer_fee_rate, cs)?;
        FeeGadget::constrain_valid_fee(internal_fee.protocol_fee_rate, cs)
    }

    // --- Matching Engine Constraints --- //

    /// Validate the match result
    pub(super) fn validate_match_result(
        statement: &ValidMalleableMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMalleableMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let match_res = &statement.bounded_match_result;
        let order = &witness.internal_party_order;
        let send_bal = &witness.internal_party_balance;
        let recv_bal = &witness.internal_party_receive_balance;
        let internal_fees = &statement.internal_fee_rates;

        // Check that the match is on the correct pair, in the correct direction
        cs.enforce_equal(match_res.quote_mint, order.quote_mint)?;
        cs.enforce_equal(match_res.base_mint, order.base_mint)?;
        cs.enforce_equal(order.side.into(), match_res.direction.into())?;

        // Check that the max match amount does not exceed the order size
        let max_amt = match_res.max_base_amount;
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(order.amount, max_amt, cs)?;

        // Check that the internal party's capitalization
        Self::validate_balance_updates(match_res, send_bal, recv_bal, order, internal_fees, cs)
    }

    /// Check that the internal party's balance capitalizes the maximum match
    fn validate_balance_updates(
        match_res: &BoundedMatchResultVar,
        send_bal: &BalanceVar,
        recv_bal: &BalanceVar,
        order: &OrderVar,
        internal_fees: &FeeTakeRateVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Compute the maximum amounts sent and received
        let max_base = match_res.max_base_amount;
        let max_quote_fp = match_res.price.mul_integer(max_base, cs)?;
        let max_quote = FixedPointGadget::floor(max_quote_fp, cs)?;

        // Select the appropriate amount based on the internal party's side
        // `order.side = 1` implies that the internal party sells the base asset
        let max_send_recv = CondSelectVectorGadget::select(
            &[max_base, max_quote],
            &[max_quote, max_base],
            order.side,
            cs,
        )?;
        let max_send = max_send_recv[0];
        let max_recv = max_send_recv[1];

        Self::validate_match_capitalized(max_send, send_bal, cs)?;
        Self::validate_receive_balance_overflow(max_recv, recv_bal, internal_fees, cs)
    }

    /// Validate that the match is capitalized by the internal party'
    fn validate_match_capitalized(
        max_send: Variable,
        send_bal: &BalanceVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(send_bal.amount, max_send, cs)
    }

    /// Validate that the maximum match does not overflow the internal party's
    /// receive balance
    fn validate_receive_balance_overflow(
        max_recv: Variable,
        recv_bal: &BalanceVar,
        fees: &FeeTakeRateVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Compute the maximum fees taken in the match
        let relayer_fee_fp = fees.relayer_fee_rate.mul_integer(max_recv, cs)?;
        let relayer_fee = FixedPointGadget::floor(relayer_fee_fp, cs)?;
        let protocol_fee_fp = fees.protocol_fee_rate.mul_integer(max_recv, cs)?;
        let protocol_fee = FixedPointGadget::floor(protocol_fee_fp, cs)?;

        // Compute the maximum updates to internal party's balance
        let updated_amount = cs.add(recv_bal.amount, max_recv)?;
        let updated_relayer_fee = cs.add(recv_bal.relayer_fee_balance, relayer_fee)?;
        let updated_protocol_fee = cs.add(recv_bal.protocol_fee_balance, protocol_fee)?;

        // Check that none of the values overflow
        AmountGadget::constrain_valid_amount(updated_amount, cs)?;
        AmountGadget::constrain_valid_amount(updated_relayer_fee, cs)?;
        AmountGadget::constrain_valid_amount(updated_protocol_fee, cs)
    }
}

/// The witness type for `VALID MALLEABLE MATCH SETTLE ATOMIC`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMalleableMatchSettleAtomicWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The internal party's order
    pub internal_party_order: Order,
    /// The internal party's balance
    pub internal_party_balance: Balance,
    /// The internal party's receive balance
    pub internal_party_receive_balance: Balance,
    /// The internal party's public shares before settlement
    pub internal_party_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
}

/// The statement type for `VALID MALLEABLE MATCH SETTLE ATOMIC`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMalleableMatchSettleAtomicStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The result of the match
    pub bounded_match_result: BoundedMatchResult,
    /// The fee rates charged to the external party
    pub external_fee_rates: FeeTakeRate,
    /// The fee rates charged to the internal party
    pub internal_fee_rates: FeeTakeRate,
    /// The public wallet shares of the internal party
    pub internal_party_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The address at which the relayer wishes to receive their fee due from
    /// the external party
    pub relayer_fee_address: Address,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidMalleableMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidMalleableMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("VALID MALLEABLE MATCH SETTLE ATOMIC ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        Ok(vec![])
    }

    fn apply_constraints(
        witness_var: ValidMalleableMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement_var: ValidMalleableMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

pub mod test_helpers {
    //! Helpers for testing the `VALID MALLEABLE MATCH SETTLE ATOMIC` circuit

    use circuit_types::{fixed_point::FixedPoint, r#match::MatchResult};
    use rand::{thread_rng, Rng};
    use renegade_crypto::fields::scalar_to_u128;

    use crate::{
        test_helpers::random_orders_and_match,
        zk_circuits::{
            test_helpers::{create_wallet_shares, random_address, MAX_BALANCES, MAX_ORDERS},
            valid_match_settle::test_helpers::build_wallet_and_indices_from_order,
        },
    };

    use super::*;

    /// An atomic match settle circuit with testing sizing parameters
    pub type SizedValidMalleableMatchSettleAtomic =
        ValidMalleableMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>;
    /// A witness with testing sizing parameters
    pub type SizedValidMalleableMatchSettleAtomicWitness =
        ValidMalleableMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;
    /// A statement with testing sizing parameters
    pub type SizedValidMalleableMatchSettleAtomicStatement =
        ValidMalleableMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>;

    /// The default relayer fee (4bps)
    pub const DEFAULT_RELAYER_FEE: f64 = 0.0004;
    /// The default protocol fee (2bps)
    pub const DEFAULT_PROTOCOL_FEE: f64 = 0.0002;

    /// Get the default relayer fee
    pub fn default_relayer_fee() -> FixedPoint {
        FixedPoint::from_f64_round_down(DEFAULT_RELAYER_FEE)
    }

    /// Get the default protocol fee
    pub fn default_protocol_fee() -> FixedPoint {
        FixedPoint::from_f64_round_down(DEFAULT_PROTOCOL_FEE)
    }

    /// Get the default fee rates
    pub fn default_fee_rates() -> FeeTakeRate {
        FeeTakeRate {
            relayer_fee_rate: FixedPoint::from_f64_round_down(DEFAULT_RELAYER_FEE),
            protocol_fee_rate: FixedPoint::from_f64_round_down(DEFAULT_PROTOCOL_FEE),
        }
    }

    /// Create a valid witness and statement
    pub fn create_witness_statement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>() -> (
        ValidMalleableMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMalleableMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        // Setup the orders, match, and wallet
        let (o1, o2, price, mut match_res) = random_orders_and_match();
        let (internal_order, _external_order) = if rand::random() {
            (o1, o2)
        } else {
            match_res.direction = !match_res.direction;
            (o2, o1)
        };

        create_witness_statement_from_order_and_match(price, &internal_order, match_res)
    }

    /// Create a witness and statement wherein the internal order is a buy
    pub fn create_witness_statement_buy_side<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    ) -> (
        ValidMalleableMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMalleableMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let (o1, o2, price, mut match_res) = random_orders_and_match();
        let internal_order = if o1.side.is_buy() {
            o1
        } else {
            match_res.direction = !match_res.direction;
            o2
        };

        create_witness_statement_from_order_and_match(price, &internal_order, match_res)
    }

    /// Create a witness and statement wherein the internal order is a sell
    pub fn create_witness_statement_sell_side<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    ) -> (
        ValidMalleableMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMalleableMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let (o1, o2, price, mut match_res) = random_orders_and_match();
        let internal_order = if o1.side.is_sell() {
            o1
        } else {
            match_res.direction = !match_res.direction;
            o2
        };

        create_witness_statement_from_order_and_match(price, &internal_order, match_res)
    }

    /// Create a witness and statement from an internal order and match result
    pub fn create_witness_statement_from_order_and_match<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        price: FixedPoint,
        internal_order: &Order,
        match_res: MatchResult,
    ) -> (
        ValidMalleableMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMalleableMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let (wallet1, party0_indices) =
            build_wallet_and_indices_from_order(internal_order, &match_res);
        let (_, internal_party_public_shares) = create_wallet_shares(&wallet1);

        let internal_party_balance = wallet1.balances[party0_indices.balance_send].clone();
        let internal_party_receive_balance =
            wallet1.balances[party0_indices.balance_receive].clone();
        let witness = ValidMalleableMatchSettleAtomicWitness {
            internal_party_order: internal_order.clone(),
            internal_party_balance,
            internal_party_receive_balance,
            internal_party_public_shares: internal_party_public_shares.clone(),
        };

        let bounded_match_result = create_bounded_match_result(price, match_res);
        let statement = ValidMalleableMatchSettleAtomicStatement {
            bounded_match_result,
            external_fee_rates: default_fee_rates(),
            internal_fee_rates: default_fee_rates(),
            internal_party_public_shares,
            relayer_fee_address: random_address(),
        };

        (witness, statement)
    }

    /// Create a bounded match result from a match result
    pub fn create_bounded_match_result(
        price: FixedPoint,
        match_res: MatchResult,
    ) -> BoundedMatchResult {
        // Sample a random minimum amount
        let mut rng = thread_rng();
        let max_base_amount = match_res.base_amount;
        let min_amt_discount = 1. - rng.gen_range(0.01..0.05); // 1-5% off max
        let min_base_amount_fp =
            FixedPoint::from_f64_round_down(min_amt_discount) * Scalar::from(max_base_amount);
        let min_base_amount = scalar_to_u128(&min_base_amount_fp.floor());

        BoundedMatchResult {
            quote_mint: match_res.quote_mint,
            base_mint: match_res.base_mint,
            price,
            min_base_amount,
            max_base_amount,
            direction: match_res.direction,
        }
    }
}

#[cfg(test)]
mod tests {
    use circuit_types::{
        fixed_point::FixedPoint,
        max_price,
        traits::{BaseType, CircuitBaseType, SingleProverCircuit},
        wallet::WalletShare,
        PlonkCircuit,
    };
    use constants::Scalar;
    use itertools::Itertools;
    use mpc_relation::{proof_linking::LinkableCircuit, traits::Circuit};
    use rand::{thread_rng, Rng};
    use renegade_crypto::fields::scalar_to_u128;

    use crate::{
        test_helpers::max_amount,
        zk_circuits::{
            check_constraint_satisfaction,
            test_helpers::{random_address, MAX_BALANCES, MAX_ORDERS},
            valid_malleable_match_settle_atomic::{
                test_helpers::{
                    create_witness_statement_buy_side, create_witness_statement_sell_side,
                },
                ValidMalleableMatchSettleAtomic,
            },
        },
    };

    use super::{
        test_helpers::{
            create_witness_statement, SizedValidMalleableMatchSettleAtomic,
            SizedValidMalleableMatchSettleAtomicStatement,
            SizedValidMalleableMatchSettleAtomicWitness,
        },
        ValidMalleableMatchSettleAtomicStatementVar, ValidMalleableMatchSettleAtomicWitnessVar,
    };

    // -----------
    // | Helpers |
    // -----------

    /// A type alias for the statement variable with testing sizing parameters
    type SizedValidMalleableMatchSettleAtomicStatementVar =
        ValidMalleableMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>;
    /// A type alias for the witness variable with testing sizing parameters
    type SizedValidMalleableMatchSettleAtomicWitnessVar =
        ValidMalleableMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>;

    /// Check the constraints on a given witness and statement
    fn check_constraints(
        witness: &SizedValidMalleableMatchSettleAtomicWitness,
        statement: &SizedValidMalleableMatchSettleAtomicStatement,
    ) -> bool {
        check_constraint_satisfaction::<SizedValidMalleableMatchSettleAtomic>(witness, statement)
    }

    /// Check the type check constraints
    fn check_type_check_constraints(
        witness: &SizedValidMalleableMatchSettleAtomicWitness,
        statement: &SizedValidMalleableMatchSettleAtomicStatement,
    ) -> bool {
        let (witness_var, statement_var, mut cs) = setup_constraint_system(witness, statement);
        SizedValidMalleableMatchSettleAtomic::validate_inputs(
            &statement_var,
            &witness_var,
            &mut cs,
        )
        .unwrap();

        let statement_scalars = statement.to_scalars().iter().map(Scalar::inner).collect_vec();
        cs.check_circuit_satisfiability(&statement_scalars).is_ok()
    }

    /// Check the matching engine constraints on an input
    fn check_matching_engine_constraints(
        witness: &SizedValidMalleableMatchSettleAtomicWitness,
        statement: &SizedValidMalleableMatchSettleAtomicStatement,
    ) -> bool {
        let (witness_var, statement_var, mut cs) = setup_constraint_system(witness, statement);
        SizedValidMalleableMatchSettleAtomic::validate_match_result(
            &statement_var,
            &witness_var,
            &mut cs,
        )
        .unwrap();

        let statement_scalars = statement.to_scalars().iter().map(Scalar::inner).collect_vec();
        cs.check_circuit_satisfiability(&statement_scalars).is_ok()
    }

    // Setup a constraint system to test a subset of constraints
    fn setup_constraint_system(
        witness: &SizedValidMalleableMatchSettleAtomicWitness,
        statement: &SizedValidMalleableMatchSettleAtomicStatement,
    ) -> (
        SizedValidMalleableMatchSettleAtomicWitnessVar,
        SizedValidMalleableMatchSettleAtomicStatementVar,
        PlonkCircuit,
    ) {
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let layout = SizedValidMalleableMatchSettleAtomic::get_circuit_layout().unwrap();
        for (id, layout) in layout.group_layouts.into_iter() {
            cs.create_link_group(id, Some(layout));
        }

        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        (witness_var, statement_var, cs)
    }

    /// Print the number of gates in the circuit
    #[test]
    fn print_num_gates() {
        let layout = ValidMalleableMatchSettleAtomic::<
            { constants::MAX_BALANCES },
            { constants::MAX_ORDERS },
        >::get_circuit_layout()
        .unwrap();

        let n = layout.n_gates;
        let next_power_of_two = layout.n_gates.next_power_of_two();
        println!("Number of gates: {}", n);
        println!("Next power of two: {}", next_power_of_two);
    }

    // -----------------------
    // | Valid Witness Tests |
    // -----------------------

    /// Test a valid witness and statement (buy side)
    #[test]
    #[allow(non_snake_case)]
    fn test_valid_witness_statement__buy_side() {
        let (witness, statement) = create_witness_statement_buy_side();
        assert!(check_constraints(&witness, &statement));
    }

    /// Test a valid witness and statement (sell side)
    #[test]
    #[allow(non_snake_case)]
    fn test_valid_witness_statement__sell_side() {
        let (witness, statement) = create_witness_statement_sell_side();
        assert!(check_constraints(&witness, &statement));
    }

    // --------------------
    // | Type Check Tests |
    // --------------------

    /// Test an invalid max match amount
    #[test]
    fn test_invalid_max_base_amount() {
        let (witness, mut statement) = create_witness_statement();
        statement.bounded_match_result.max_base_amount = max_amount() + 1;

        assert!(!check_type_check_constraints(&witness, &statement));
    }

    /// Test an invalid min match amount
    #[test]
    fn test_invalid_min_base_amount() {
        let (witness, mut statement) = create_witness_statement();
        statement.bounded_match_result.min_base_amount = max_amount() + 1;
        assert!(!check_type_check_constraints(&witness, &statement));
    }

    /// Test a min amount greater than the max amount
    #[test]
    fn test_min_gt_max() {
        let (witness, mut statement) = create_witness_statement();
        statement.bounded_match_result.min_base_amount =
            statement.bounded_match_result.max_base_amount + 1;
        assert!(!check_type_check_constraints(&witness, &statement));
    }

    /// Test an invalid price
    #[test]
    fn test_invalid_price() {
        let (witness, mut statement) = create_witness_statement();
        let mut max_price = max_price();
        max_price.repr += Scalar::one();

        statement.bounded_match_result.price = max_price;
        assert!(!check_type_check_constraints(&witness, &statement));
    }

    /// Test invalid fee rates
    #[test]
    fn test_invalid_fee_rates() {
        let (witness, base_statement) = create_witness_statement();
        let invalid_fee = FixedPoint::from_integer(1);

        // Invalid external relayer fee rate
        let mut statement = base_statement.clone();
        statement.external_fee_rates.relayer_fee_rate = invalid_fee;
        assert!(!check_type_check_constraints(&witness, &statement));

        // Invalid external protocol fee rate
        let mut statement = base_statement.clone();
        statement.external_fee_rates.protocol_fee_rate = invalid_fee;
        assert!(!check_type_check_constraints(&witness, &statement));

        // Invalid internal relayer fee rate
        let mut statement = base_statement.clone();
        statement.internal_fee_rates.relayer_fee_rate = invalid_fee;
        assert!(!check_type_check_constraints(&witness, &statement));

        // Invalid internal protocol fee rate
        let mut statement = base_statement;
        statement.internal_fee_rates.protocol_fee_rate = invalid_fee;
        assert!(!check_type_check_constraints(&witness, &statement));
    }

    // -------------------------
    // | Matching Engine Tests |
    // -------------------------

    /// Test an invalid match on the wrong pair
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_match_pair() {
        let (witness, base_statement) = create_witness_statement();

        // Wrong base mint
        let mut statement = base_statement.clone();
        statement.bounded_match_result.base_mint = random_address();
        assert!(!check_matching_engine_constraints(&witness, &statement));

        // Wrong quote mint
        let mut statement = base_statement.clone();
        statement.bounded_match_result.quote_mint = random_address();
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test an invalid match in the wrong direction
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_match_direction() {
        let (witness, base_statement) = create_witness_statement();

        // Buy side, sell direction
        let mut statement = base_statement.clone();
        statement.bounded_match_result.direction = !statement.bounded_match_result.direction;
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test an invalid match amount that exceeds the order size
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_match_amount__exceeds_order_size() {
        let (witness, mut statement) = create_witness_statement();

        // Match amount exceeds order size
        statement.bounded_match_result.max_base_amount = witness.internal_party_order.amount + 1;
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test an invalid match in which the order is undercapitalized on the buy
    /// side
    #[test]
    #[allow(non_snake_case)]
    fn test_undercapitalized_match__buy_side() {
        let (mut witness, statement) = create_witness_statement_buy_side();

        // Buy side order will hold the quote asset
        let match_res = &statement.bounded_match_result;
        let max_quote_amt_fp = match_res.price * Scalar::from(match_res.max_base_amount);
        let max_quote_amt = scalar_to_u128(&max_quote_amt_fp.floor());

        witness.internal_party_balance.amount = max_quote_amt - 1;
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test an invalid match in which the order is undercapitalized on the sell
    /// side
    #[test]
    #[allow(non_snake_case)]
    fn test_undercapitalized_match__sell_side() {
        let (witness, mut statement) = create_witness_statement_sell_side();

        // Sell side order will hold the base asset
        let balance_amt = witness.internal_party_balance.amount;
        statement.bounded_match_result.max_base_amount = balance_amt + 1;
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test a balance overflow in the internal party's receive balance, buy
    /// side
    #[test]
    #[allow(non_snake_case)]
    fn test_receive_balance_overflow__buy_side() {
        let (mut witness, statement) = create_witness_statement_buy_side();

        // Buy side order will buy the base asset
        let buffer = max_amount() - statement.bounded_match_result.max_base_amount;
        witness.internal_party_receive_balance.amount = buffer + 1;
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test a balance overflow in the internal party's receive balance, sell
    /// side
    #[test]
    #[allow(non_snake_case)]
    fn test_receive_balance_overflow__sell_side() {
        let (mut witness, statement) = create_witness_statement_sell_side();

        // Sell side order will buy the quote asset
        let match_res = &statement.bounded_match_result;
        let max_quote_amount_fp = match_res.price * Scalar::from(match_res.max_base_amount);
        let max_quote_amount = scalar_to_u128(&max_quote_amount_fp.floor());

        let buffer = max_amount() - max_quote_amount;
        witness.internal_party_receive_balance.amount = buffer + 1;
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test a balance overflow in the receive party's relayer fee balance
    #[test]
    #[allow(non_snake_case)]
    fn test_relayer_fee_balance_overflow() {
        let (mut witness, statement) = create_witness_statement_buy_side();
        witness.internal_party_receive_balance.relayer_fee_balance = max_amount();
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test a balance overflow in the receive party's protocol fee balance
    #[test]
    #[allow(non_snake_case)]
    fn test_protocol_fee_balance_overflow() {
        let (mut witness, statement) = create_witness_statement_buy_side();
        witness.internal_party_receive_balance.protocol_fee_balance = max_amount();
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    // -------------------
    // | Misc Test Cases |
    // -------------------

    /// Test a price protection violation on the buy side
    #[test]
    #[allow(non_snake_case)]
    fn test_price_protection_violation__buy_side() {
        let (mut witness, statement) = create_witness_statement_buy_side();
        let price = statement.bounded_match_result.price;

        witness.internal_party_order.worst_case_price = price - Scalar::one();
        assert!(!check_constraints(&witness, &statement));
    }

    /// Test a price protection violation on the sell side
    #[test]
    #[allow(non_snake_case)]
    fn test_price_protection_violation__sell_side() {
        let (mut witness, statement) = create_witness_statement_sell_side();
        let price = statement.bounded_match_result.price;

        witness.internal_party_order.worst_case_price = price + Scalar::one();
        assert!(!check_constraints(&witness, &statement));
    }

    /// Test a modification to the wallet shares of the external party
    #[test]
    #[allow(non_snake_case)]
    fn test_internal_party_wallet_share_modification() {
        let mut rng = thread_rng();
        let (witness, mut statement) = create_witness_statement();
        let mut statement_scalars = statement.internal_party_public_shares.to_scalars();
        let random_idx = rng.gen_range(0..statement_scalars.len());
        statement_scalars[random_idx] = Scalar::random(&mut rng);

        statement.internal_party_public_shares =
            WalletShare::from_scalars(&mut statement_scalars.into_iter());
        assert!(!check_constraints(&witness, &statement));
    }
}
