//! The `VALID MATCH SETTLE ATOMIC` circuit
//!
//! This circuit verifies a match between two parties; one internal and one
//! external. An internal party is one with state committed into the darkpool,
//! while an external party is one whose funds sit outside the darkpool, on the
//! host chain.
//! with state committed into the darkpool, while an external party is one whose
//! funds sit outside the darkpool, on the host chain.
//!
//! VALID MATCH SETTLE ATOMIC allows the external party to match against a known
//! internal order; emulating the standard deposit, order placement, settlement,
//! and withdrawal flow in a single transaction.

use crate::{
    zk_gadgets::{
        arithmetic::NoopGadget,
        comparators::GreaterThanEqGadget,
        fixed_point::FixedPointGadget,
        select::{CondSelectGadget, CondSelectVectorGadget},
        wallet_operations::{AmountGadget, PriceGadget, WalletGadget},
    },
    SingleProverCircuit,
};
use circuit_macros::circuit_type;
use circuit_types::{
    balance::{Balance, BalanceVar},
    fees::FeeTake,
    fixed_point::{FixedPoint, FixedPointVar},
    order::{Order, OrderVar},
    r#match::{ExternalMatchResult, ExternalMatchResultVar, OrderSettlementIndices},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
    wallet::{WalletShare, WalletShareStateCommitment},
    Address, PlonkCircuit, AMOUNT_BITS,
};
use constants::{Scalar, ScalarField, MAX_BALANCES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{
    errors::CircuitError,
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
    Variable,
};
use serde::{Deserialize, Serialize};

use super::{valid_match_settle::ValidMatchSettle, VALID_COMMITMENTS_MATCH_SETTLE_LINK0};

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit implementation of `VALID MATCH SETTLE ATOMIC`
pub struct ValidMatchSettleAtomic<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;
/// A `VALID MATCH SETTLE ATOMIC` with default state element sizing
pub type SizedValidMatchSettleAtomic = ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>;
/// A `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS` with default state element
/// sizing
pub type SizedValidMatchSettleAtomicWithCommitments =
    ValidMatchSettleAtomicWithCommitments<MAX_BALANCES, MAX_ORDERS>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
    ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The circuit constraints for `VALID MATCH SETTLE ATOMIC`
    pub fn circuit(
        statement: &ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Constrain the malleable fields
        Self::constrain_malleable_fields(statement, witness, cs)?;
        // Validate the matching engine
        Self::validate_matching_engine(statement, witness, cs)?;
        // Validate the internal party's settlement
        Self::validate_settlement(statement, witness, cs)
    }

    /// Constrain the fields that appear in no constraints to prevent them from
    /// being changed
    fn constrain_malleable_fields(
        statement: &ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        _witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Constrain the relayer fee address
        NoopGadget::constrain_noop(&statement.relayer_fee_address, cs)
    }

    // --- Matching Engine Constraints --- //

    /// Validate the match result
    pub(super) fn validate_matching_engine(
        statement: &ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let internal_order = &witness.internal_party_order;
        let match_res = &statement.match_result;

        // Check that the match is on the correct pair, in the correct direction
        cs.enforce_equal(internal_order.quote_mint, match_res.quote_mint)?;
        cs.enforce_equal(internal_order.base_mint, match_res.base_mint)?;
        cs.enforce_equal(internal_order.side.into(), match_res.direction.into())?;

        // Validate the volumes and price at which the match executes
        Self::validate_price(witness.price, &statement.match_result, cs)?;
        AmountGadget::constrain_valid_amount(match_res.quote_amount, cs)?;
        AmountGadget::constrain_valid_amount(match_res.base_amount, cs)?;

        // Check that the matched volume does not exceed the internal party's order and
        // that it is capitalized by the internal party's send balance
        Self::validate_volume_constraints(
            &witness.internal_party_order,
            &witness.internal_party_balance,
            &statement.match_result,
            cs,
        )?;

        // Check that the price is within the user-defined limits
        PriceGadget::validate_price_protection(&witness.price, &witness.internal_party_order, cs)
    }

    /// Validate the price that the match executed at
    fn validate_price(
        price: FixedPointVar,
        match_res: &ExternalMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The price must be representable as a fixed point
        PriceGadget::constrain_valid_price(price, cs)?;

        // Check that the price implied by the match matches the price in the witness
        let base_amount = match_res.base_amount;
        let quote_amount = match_res.quote_amount;
        let expected_quote = price.mul_integer(base_amount, cs)?;
        FixedPointGadget::constrain_equal_floor(expected_quote, quote_amount, cs)
    }

    /// Validate that the internal party's balance capitalizes their side of the
    /// match
    fn validate_volume_constraints(
        internal_party_order: &OrderVar,
        internal_party_balance: &BalanceVar,
        match_res: &ExternalMatchResultVar,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Check that the match amount is less than or equal to the internal party's
        // order size
        let order_amount = internal_party_order.amount;
        let match_amount = match_res.base_amount;
        GreaterThanEqGadget::<AMOUNT_BITS>::constrain_greater_than_eq(
            order_amount,
            match_amount,
            cs,
        )?;

        // Check that the internal party's balance covers the amount of the match
        // If the direction of the order is 0 (buy the base) then the balance must
        // cover the amount of the quote token sold in the swap
        // If the direction of the order is 1 (sell the base) then the balance must
        // cover the amount of the base token sold in the swap
        let side = internal_party_order.side;
        let sell_amount =
            CondSelectGadget::select(&match_res.base_amount, &match_res.quote_amount, side, cs)?;

        let new_balance = cs.sub(internal_party_balance.amount, sell_amount)?;
        AmountGadget::constrain_valid_amount(new_balance, cs)
    }

    // --- Settlement Constraints --- //

    /// Validate the settlement of the atomic match
    pub(crate) fn validate_settlement(
        statement: &ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let match_res = &statement.match_result;
        let (base_amt, quote_amt) = (match_res.base_amount, match_res.quote_amount);
        let send_amt_receive_amt = CondSelectVectorGadget::select(
            &[base_amt, quote_amt],
            &[quote_amt, base_amt],
            match_res.direction,
            cs,
        )?;
        let (send_amt, receive_amt) = (send_amt_receive_amt[0], send_amt_receive_amt[1]);

        // Validate the internal party's settlement directly using the standard
        // settlement logic
        ValidMatchSettle::validate_party_settlement_singleprover(
            send_amt,
            receive_amt,
            base_amt,
            &witness.internal_party_receive_balance,
            witness.relayer_fee,
            statement.protocol_fee,
            &witness.internal_party_fees,
            &statement.internal_party_indices,
            &witness.internal_party_public_shares,
            &statement.internal_party_modified_shares,
            cs,
        )?;

        // Validate the external party's fees
        Self::validate_external_fees(statement, witness, cs)
    }

    /// Validate the external party's fees
    ///
    /// Note that we do not validate the relayer fee as the relayer may choose
    /// the fee on a per-match basis. Instead, we constrain the relayer fee only
    /// to be a valid amount
    fn validate_external_fees(
        statement: &ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let internal_order_side = witness.internal_party_order.side;
        let quote_amount = statement.match_result.quote_amount;
        let base_amount = statement.match_result.base_amount;
        let fee_take = &statement.external_party_fees;

        // Validate that both the protocol fee and relayer fee are valid amounts
        AmountGadget::constrain_valid_amount(fee_take.protocol_fee, cs)?;
        AmountGadget::constrain_valid_amount(fee_take.relayer_fee, cs)?;

        // If the internal order is a buy (side = 0) then the external party buys the
        // quote. If the internal order is a sell (side = 1) then the external party
        // buys the base
        let receive_amount =
            CondSelectGadget::select(&base_amount, &quote_amount, internal_order_side, cs)?;

        // Validate the protocol fee value
        let expected_protocol_fee = statement.protocol_fee.mul_integer(receive_amount, cs)?;
        FixedPointGadget::constrain_equal_floor(expected_protocol_fee, fee_take.protocol_fee, cs)
    }
}

/// The circuit implementation of `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS`
///
/// This circuit applies identical constraints as `VALID MATCH SETTLE ATOMIC`
/// except that it also computes the commitment to the internal party's updated
/// shares in the circuit
///
/// This is done to remove that computation from the contracts, where hashing is
/// somewhat expensive
pub struct ValidMatchSettleAtomicWithCommitments<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
    ValidMatchSettleAtomicWithCommitments<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The circuit constraints for `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS`
    pub fn circuit(
        statement: &ValidMatchSettleAtomicWithCommitmentsStatementVar<MAX_BALANCES, MAX_ORDERS>,
        witness: &ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply all the constraints from the standard match settle atomic circuit
        let match_settle_atomic_statement = ValidMatchSettleAtomicStatementVar {
            match_result: statement.match_result.clone(),
            external_party_fees: statement.external_party_fees.clone(),
            internal_party_modified_shares: statement.internal_party_modified_shares.clone(),
            internal_party_indices: statement.internal_party_indices.clone(),
            protocol_fee: statement.protocol_fee,
            relayer_fee_address: statement.relayer_fee_address,
        };
        ValidMatchSettleAtomic::circuit(&match_settle_atomic_statement, witness, cs)?;

        // Validate the commitment to the internal party's updated shares
        let commitment = WalletGadget::compute_wallet_commitment_from_private(
            &statement.internal_party_modified_shares,
            statement.private_share_commitment,
            cs,
        )?;
        cs.enforce_equal(commitment, statement.new_share_commitment)?;
        Ok(())
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID MATCH SETTLE ATOMIC`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleAtomicWitness<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The internal party's order
    #[link_groups = "valid_commitments_match_settle0"]
    pub internal_party_order: Order,
    /// The internal party's balance
    #[link_groups = "valid_commitments_match_settle0"]
    pub internal_party_balance: Balance,
    /// The internal party's receive balance
    #[link_groups = "valid_commitments_match_settle0"]
    pub internal_party_receive_balance: Balance,
    /// The internal party's managing relayer fee
    #[link_groups = "valid_commitments_match_settle0"]
    pub relayer_fee: FixedPoint,
    /// The internal party's public shares before settlement
    #[link_groups = "valid_commitments_match_settle0"]
    pub internal_party_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The price at which the match executes
    pub price: FixedPoint,
    /// The internal party's fee obligations as a result of the match
    pub internal_party_fees: FeeTake,
}

/// A `VALID MATCH SETTLE ATOMIC` witness with default const generic sizing
/// parameters
pub type SizedValidMatchSettleAtomicWitness =
    ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID MATCH SETTLE ATOMIC`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleAtomicStatement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The result of the match
    pub match_result: ExternalMatchResult,
    /// The external party's fee obligations as a result of the match
    pub external_party_fees: FeeTake,
    /// The modified public shares of the internal party
    pub internal_party_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The indices that settlement should modify in the internal party's wallet
    pub internal_party_indices: OrderSettlementIndices,
    /// The protocol fee used in the match
    pub protocol_fee: FixedPoint,
    /// The address at which the relayer wishes to receive their fee due from
    /// the external party
    pub relayer_fee_address: Address,
}

/// The statement type for `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleAtomicWithCommitmentsStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// A commitment to the internal party's private shares
    pub private_share_commitment: WalletShareStateCommitment,
    /// A commitment to the new wallet shares of the internal party
    pub new_share_commitment: WalletShareStateCommitment,
    /// The result of the match
    pub match_result: ExternalMatchResult,
    /// The external party's fee obligations as a result of the match
    pub external_party_fees: FeeTake,
    /// The modified public shares of the internal party
    pub internal_party_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The indices that settlement should modify in the internal party's wallet
    pub internal_party_indices: OrderSettlementIndices,
    /// The protocol fee used in the match
    pub protocol_fee: FixedPoint,
    /// The address at which the relayer wishes to receive their fee due from
    /// the external party
    pub relayer_fee_address: Address,
}

/// A `VALID MATCH SETTLE ATOMIC` statement with default const generic sizing
/// parameters
pub type SizedValidMatchSettleAtomicStatement =
    ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>;
/// A `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS` statement with default const
/// generic sizing parameters
pub type SizedValidMatchSettleAtomicWithCommitmentsStatement =
    ValidMatchSettleAtomicWithCommitmentsStatement<MAX_BALANCES, MAX_ORDERS>;

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("Valid Match Settle Atomic ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    /// VALID MATCH SETTLE ATOMIC has one proof linking group:
    /// - valid_commitments_match_settle0: The linking group between VALID
    ///   COMMITMENTS and VALID MATCH SETTLE. We directly use the first layout
    ///   from the standard match settle circuit here for simplicity
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let match_layout = ValidMatchSettle::get_circuit_layout()?;
        let layout = match_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK0);

        Ok(vec![(VALID_COMMITMENTS_MATCH_SETTLE_LINK0.to_string(), Some(layout))])
    }

    fn apply_constraints(
        witness_var: ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement_var: ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::circuit(&statement_var, &witness_var, cs).map_err(PlonkError::CircuitError)
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidMatchSettleAtomicWithCommitments<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidMatchSettleAtomicWithCommitmentsStatement<MAX_BALANCES, MAX_ORDERS>;
    type Witness = ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("Valid Match Settle Atomic With Commitments ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        ValidMatchSettleAtomic::proof_linking_groups()
    }

    fn apply_constraints(
        witness_var: ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement_var: ValidMatchSettleAtomicWithCommitmentsStatementVar<MAX_BALANCES, MAX_ORDERS>,
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
    use circuit_types::{
        fixed_point::FixedPoint,
        native_helpers::compute_wallet_commitment_from_private,
        order::Order,
        r#match::{ExternalMatchResult, MatchResult},
    };
    use constants::Scalar;
    use rand::thread_rng;
    use util::{
        matching_engine::{apply_match_to_shares, compute_fee_obligation},
        on_chain::get_protocol_fee,
    };

    use crate::{
        test_helpers::random_orders_and_match,
        zk_circuits::{
            test_helpers::{create_wallet_shares, random_address, MAX_BALANCES, MAX_ORDERS},
            valid_match_settle::test_helpers::build_wallet_and_indices_from_order,
        },
    };

    use super::{
        ValidMatchSettleAtomic, ValidMatchSettleAtomicStatement,
        ValidMatchSettleAtomicWithCommitments, ValidMatchSettleAtomicWithCommitmentsStatement,
        ValidMatchSettleAtomicWitness,
    };

    /// An atomic match settle circuit with testing sizing parameters
    pub type SizedValidMatchSettleAtomic = ValidMatchSettleAtomic<MAX_BALANCES, MAX_ORDERS>;
    /// An atomic match settle circuit with commitments with testing sizing
    /// parameters
    pub type SizedValidMatchSettleAtomicWithCommitments =
        ValidMatchSettleAtomicWithCommitments<MAX_BALANCES, MAX_ORDERS>;
    /// A witness with testing sizing parameters
    pub type SizedValidMatchSettleAtomicWitness =
        ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>;
    /// A statement with testing sizing parameters
    pub type SizedValidMatchSettleAtomicStatement =
        ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>;

    /// The default relayer fee (4bps)
    pub const DEFAULT_RELAYER_FEE: f64 = 0.0004;

    /// Get the default relayer fee as a fixed point
    pub fn default_relayer_fee() -> FixedPoint {
        FixedPoint::from_f64_round_down(DEFAULT_RELAYER_FEE)
    }

    /// Convert a statement of `VALID MATCH SETTLE ATOMIC` to a statement of
    /// `VALID MATCH SETTLE ATOMIC WITH COMMITMENTS`
    pub fn convert_to_with_commitments_statement<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        statement: &ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
    ) -> ValidMatchSettleAtomicWithCommitmentsStatement<MAX_BALANCES, MAX_ORDERS>
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let mut rng = thread_rng();
        let private_share_commitment = Scalar::random(&mut rng);
        let new_share_commitment = compute_wallet_commitment_from_private(
            &statement.internal_party_modified_shares,
            private_share_commitment,
        );

        ValidMatchSettleAtomicWithCommitmentsStatement {
            private_share_commitment,
            new_share_commitment,
            match_result: statement.match_result.clone(),
            external_party_fees: statement.external_party_fees,
            internal_party_modified_shares: statement.internal_party_modified_shares.clone(),
            internal_party_indices: statement.internal_party_indices,
            protocol_fee: statement.protocol_fee,
            relayer_fee_address: statement.relayer_fee_address.clone(),
        }
    }

    /// Create a valid witness and statement for the `VALID MATCH SETTLE ATOMIC
    /// WITH COMMITMENTS` circuit
    pub fn create_witness_statement_with_commitments<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >() -> (
        ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMatchSettleAtomicWithCommitmentsStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let (witness, statement) = create_witness_statement();
        let statement_with_commitments = convert_to_with_commitments_statement(&statement);

        (witness, statement_with_commitments)
    }

    /// Create a valid witness and statement for the circuit
    pub fn create_witness_statement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>() -> (
        ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
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

        create_witness_statement_from_order_and_match(price, &internal_order, &match_res)
    }

    /// Create a witness and statement wherein the internal order is a buy
    pub fn create_witness_statement_buy_side<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    ) -> (
        ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
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

        create_witness_statement_from_order_and_match(price, &internal_order, &match_res)
    }

    /// Create a witness and statement wherein the internal order is a sell
    pub fn create_witness_statement_sell_side<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
    ) -> (
        ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
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

        create_witness_statement_from_order_and_match(price, &internal_order, &match_res)
    }

    /// Create a witness and statement from an internal order and match result
    pub fn create_witness_statement_from_order_and_match<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        price: FixedPoint,
        internal_order: &Order,
        match_res: &MatchResult,
    ) -> (
        ValidMatchSettleAtomicWitness<MAX_BALANCES, MAX_ORDERS>,
        ValidMatchSettleAtomicStatement<MAX_BALANCES, MAX_ORDERS>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        let (wallet1, party0_indices) =
            build_wallet_and_indices_from_order(internal_order, match_res);
        let (_, internal_party_public_shares) = create_wallet_shares(&wallet1);
        let mut internal_party_modified_shares = internal_party_public_shares.clone();
        let internal_party_fees =
            compute_fee_obligation(default_relayer_fee(), internal_order.side, match_res);

        apply_match_to_shares(
            &mut internal_party_modified_shares,
            &party0_indices,
            internal_party_fees,
            match_res,
            internal_order.side,
        );

        let internal_party_balance = wallet1.balances[party0_indices.balance_send].clone();
        let internal_party_receive_balance =
            wallet1.balances[party0_indices.balance_receive].clone();
        let witness = ValidMatchSettleAtomicWitness {
            internal_party_order: internal_order.clone(),
            internal_party_balance,
            internal_party_receive_balance,
            price,
            relayer_fee: default_relayer_fee(),
            internal_party_fees,
            internal_party_public_shares,
        };

        let match_result = create_external_match_result(match_res);
        let statement = ValidMatchSettleAtomicStatement {
            match_result,
            external_party_fees: compute_fee_obligation(
                default_relayer_fee(),
                internal_order.side.opposite(),
                match_res,
            ),
            internal_party_modified_shares,
            internal_party_indices: party0_indices,
            protocol_fee: get_protocol_fee(),
            relayer_fee_address: random_address(),
        };

        (witness, statement)
    }

    /// Create an external match result from a match result
    fn create_external_match_result(match_res: &MatchResult) -> ExternalMatchResult {
        ExternalMatchResult {
            quote_mint: match_res.quote_mint.clone(),
            base_mint: match_res.base_mint.clone(),
            quote_amount: match_res.quote_amount,
            base_amount: match_res.base_amount,
            direction: match_res.direction,
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{
        test_helpers::max_amount,
        zk_circuits::{
            check_constraint_satisfaction,
            test_helpers::{MAX_BALANCES, MAX_ORDERS},
            valid_match_settle_atomic::{
                test_helpers::{
                    create_witness_statement, create_witness_statement_buy_side,
                    create_witness_statement_sell_side, create_witness_statement_with_commitments,
                },
                ValidMatchSettleAtomic, ValidMatchSettleAtomicWithCommitments,
            },
        },
    };
    use bigdecimal::ToPrimitive;
    use circuit_types::{
        fixed_point::FixedPoint,
        traits::{BaseType, CircuitBaseType, SingleProverCircuit},
        PlonkCircuit, PRICE_BITS,
    };
    use constants::Scalar;
    use itertools::Itertools;
    use mpc_relation::{proof_linking::LinkableCircuit, traits::Circuit};
    use num_bigint::BigUint;
    use rand::{distributions::uniform::SampleRange, thread_rng};
    use renegade_crypto::fields::biguint_to_scalar;

    use super::{
        test_helpers::{
            convert_to_with_commitments_statement, SizedValidMatchSettleAtomic,
            SizedValidMatchSettleAtomicStatement, SizedValidMatchSettleAtomicWithCommitments,
            SizedValidMatchSettleAtomicWitness,
        },
        ValidMatchSettleAtomicStatementVar, ValidMatchSettleAtomicWitnessVar,
    };

    // -----------
    // | Helpers |
    // -----------

    /// The witness variable type with testing const generic sizing parameters
    type SizedValidMatchSettleAtomicWitnessVar =
        ValidMatchSettleAtomicWitnessVar<MAX_BALANCES, MAX_ORDERS>;
    /// The statement variable type with testing const generic sizing parameters
    type SizedValidMatchSettleAtomicStatementVar =
        ValidMatchSettleAtomicStatementVar<MAX_BALANCES, MAX_ORDERS>;

    /// Check the constraints on a given witness and statement
    fn check_constraints(
        witness: &SizedValidMatchSettleAtomicWitness,
        statement: &SizedValidMatchSettleAtomicStatement,
    ) -> bool {
        let statement_with_commitments = convert_to_with_commitments_statement(statement);
        let res1 = check_constraint_satisfaction::<SizedValidMatchSettleAtomic>(witness, statement);
        let res2 = check_constraint_satisfaction::<SizedValidMatchSettleAtomicWithCommitments>(
            witness,
            &statement_with_commitments,
        );

        res1 && res2
    }

    /// Check only the matching engine constraints
    ///
    /// Used to isolate test cases
    fn check_matching_engine_constraints(
        witness: &SizedValidMatchSettleAtomicWitness,
        statement: &SizedValidMatchSettleAtomicStatement,
    ) -> bool {
        let (witness_var, statement_var, mut cs) = setup_constraint_system(witness, statement);
        SizedValidMatchSettleAtomic::validate_matching_engine(
            &statement_var,
            &witness_var,
            &mut cs,
        )
        .unwrap();

        // Check for satisfiability
        let statement_scalars = statement.to_scalars().iter().map(Scalar::inner).collect_vec();
        cs.check_circuit_satisfiability(&statement_scalars).is_ok()
    }

    /// Check only the settlement constraints
    fn check_settlement_constraints(
        witness: &SizedValidMatchSettleAtomicWitness,
        statement: &SizedValidMatchSettleAtomicStatement,
    ) -> bool {
        let (witness_var, statement_var, mut cs) = setup_constraint_system(witness, statement);
        SizedValidMatchSettleAtomic::validate_settlement(&statement_var, &witness_var, &mut cs)
            .unwrap();

        let statement_scalars = statement.to_scalars().iter().map(Scalar::inner).collect_vec();
        cs.check_circuit_satisfiability(&statement_scalars).is_ok()
    }

    fn setup_constraint_system(
        witness: &SizedValidMatchSettleAtomicWitness,
        statement: &SizedValidMatchSettleAtomicStatement,
    ) -> (
        SizedValidMatchSettleAtomicWitnessVar,
        SizedValidMatchSettleAtomicStatementVar,
        PlonkCircuit,
    ) {
        let mut cs = PlonkCircuit::new_turbo_plonk();
        let layout = SizedValidMatchSettleAtomic::get_circuit_layout().unwrap();
        for (id, layout) in layout.group_layouts.into_iter() {
            cs.create_link_group(id, Some(layout));
        }

        let witness_var = witness.create_witness(&mut cs);
        let statement_var = statement.create_public_var(&mut cs);

        (witness_var, statement_var, cs)
    }

    /// A helper to print the size of the `VALID MATCH SETTLE ATOMIC` circuit
    #[test]
    #[ignore]
    fn print_valid_match_settle_atomic_size() {
        let layout = ValidMatchSettleAtomic::<
            { constants::MAX_BALANCES },
            { constants::MAX_ORDERS },
        >::get_circuit_layout()
        .unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    /// A helper to print the size of the `VALID MATCH SETTLE ATOMIC WITH
    /// COMMITMENTS` circuit
    #[test]
    #[ignore]
    fn print_valid_match_settle_atomic_with_commitments_size() {
        let layout = ValidMatchSettleAtomicWithCommitments::<
            { constants::MAX_BALANCES },
            { constants::MAX_ORDERS },
        >::get_circuit_layout()
        .unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    // -----------------------
    // | Valid Witness Tests |
    // -----------------------

    /// Tests the `VALID MATCH SETTLE ATOMIC` circuit with a valid witness and
    /// statement
    #[test]
    fn test_valid_match_settle_atomic() {
        let (witness, statement) = create_witness_statement();
        assert!(check_constraints(&witness, &statement));
    }

    // -------------------------
    // | Matching Engine Tests |
    // -------------------------

    #[test]
    fn test_invalid_match_pair() {
        let (witness, original_statement) = create_witness_statement();

        // Incorrect quote mint
        let mut statement = original_statement.clone();
        statement.match_result.quote_mint += 1u8;
        assert!(!check_constraints(&witness, &statement));

        // Incorrect base mint
        let mut statement = original_statement;
        statement.match_result.base_mint += 1u8;
        assert!(!check_constraints(&witness, &statement));
    }

    /// Tests the case in which the match goes the wrong direction
    #[test]
    fn test_invalid_match_direction() {
        let (witness, mut statement) = create_witness_statement();

        // Incorrect direction
        statement.match_result.direction = !statement.match_result.direction;
        assert!(!check_constraints(&witness, &statement));
    }

    /// Tests the case where the price at which the match executes is invalid
    #[test]
    fn test_invalid_match_price() {
        let (mut witness, statement) = create_witness_statement();

        // Incorrect price, not equal to quote amount / base amount
        witness.price = witness.price - FixedPoint::from_integer(1);
        assert!(!check_matching_engine_constraints(&witness, &statement));

        // Invalid price, not representable in `PRICE_BITS` bits
        let max_representable = BigUint::from(1u8) << PRICE_BITS;
        let max_repr = biguint_to_scalar(&max_representable);
        let max_representable_price = FixedPoint::from_repr(max_repr);
        witness.price = max_representable_price;
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test the case in which the quote amount of the match is too high
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_match__quote_volume_exceeds_bounds() {
        // Quote amount too high
        let (mut witness, mut statement) = create_witness_statement_sell_side();
        let balance = &mut witness.internal_party_balance;
        let order = &mut witness.internal_party_order;

        // Setup the balance and order to be valid
        let price_int = 2;
        let price = FixedPoint::from_integer(price_int);
        balance.amount = max_amount();
        // This is technically impossible, but set above the max here to
        // isolate the constraint
        order.amount = max_amount() + 1;
        order.worst_case_price = price;

        // Setup the match result to be valid other than the quote amount
        statement.match_result.base_amount = max_amount();
        statement.match_result.quote_amount = max_amount() * price_int.to_u128().unwrap();
        witness.price = price;
        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test the case in which the base amount of the match is too high
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_match__base_volume_exceeds_bounds() {
        // Base amount too high
        let (mut witness, mut statement) = create_witness_statement_buy_side();
        let balance = &mut witness.internal_party_balance;
        let order = &mut witness.internal_party_order;

        let price = 0.5;
        let price_inverse = 2;
        let price = FixedPoint::from_f64_round_down(price);
        let quote_amount = max_amount() - 1;
        let base_amount = quote_amount * price_inverse;

        balance.amount = quote_amount;
        order.amount = base_amount;
        order.worst_case_price = price;

        // Setup the match result to be valid other than the base amount
        statement.match_result.quote_amount = balance.amount;
        statement.match_result.base_amount = base_amount;
        witness.price = price;

        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test the case in which a match exceeds the order's size
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_match__exceeds_order_size() {
        let (mut witness, statement) = create_witness_statement();
        let order = &mut witness.internal_party_order;
        order.amount = statement.match_result.base_amount - 1;

        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test the case in which the internal party's balance is too low
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_match__internal_party_balance_too_low() {
        let (mut witness, statement) = create_witness_statement();
        let balance = &mut witness.internal_party_balance;
        if witness.internal_party_order.side.is_buy() {
            balance.amount = statement.match_result.quote_amount - 1;
        } else {
            balance.amount = statement.match_result.base_amount - 1;
        }

        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    /// Test the case in which the price is out of the user-defined limits
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_match__price_out_of_bounds() {
        let (mut witness, statement) = create_witness_statement();
        let order = &mut witness.internal_party_order;
        let price = witness.price;
        if order.side.is_buy() {
            order.worst_case_price = price - FixedPoint::from_integer(1);
        } else {
            order.worst_case_price = price + FixedPoint::from_integer(1);
        }

        assert!(!check_matching_engine_constraints(&witness, &statement));
    }

    // --------------------
    // | Settlement Tests |
    // --------------------

    /// Test the case in which the relayer fee is out of bounds
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_settle__relayer_fee_out_of_bounds() {
        let (witness, mut statement) = create_witness_statement();
        statement.external_party_fees.relayer_fee = max_amount() + 1;

        assert!(!check_settlement_constraints(&witness, &statement));
    }

    /// Test the case in which the protocol fee is out of bounds
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_settle__protocol_fee_out_of_bounds() {
        let (witness, mut statement) = create_witness_statement();
        statement.external_party_fees.protocol_fee = max_amount() + 1;

        assert!(!check_settlement_constraints(&witness, &statement));
    }

    /// Test the case in which the protocol fee is incorrectly computed
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_settle__incorrect_protocol_fee() {
        let (witness, mut statement) = create_witness_statement();
        statement.external_party_fees.protocol_fee += 2;

        assert!(!check_settlement_constraints(&witness, &statement));
    }

    /// Test the case in which the internal party's order is incorrectly updated
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_settle__incorrect_order_update() {
        let (witness, mut statement) = create_witness_statement();
        let order_idx = statement.internal_party_indices.order;
        statement.internal_party_modified_shares.orders[order_idx].amount += Scalar::one();

        assert!(!check_settlement_constraints(&witness, &statement));
    }

    /// Test the case in which the internal party's send balance is incorrectly
    /// updated
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_settle__incorrect_send_balance_update() {
        let (witness, mut statement) = create_witness_statement();
        let balance_idx = statement.internal_party_indices.balance_send;
        statement.internal_party_modified_shares.balances[balance_idx].amount += Scalar::one();

        assert!(!check_settlement_constraints(&witness, &statement));
    }

    /// Test the case in which the internal party's receive balance is
    /// incorrectly updated
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_settle__incorrect_receive_balance_update() {
        let (witness, mut statement) = create_witness_statement();
        let balance_idx = statement.internal_party_indices.balance_receive;
        statement.internal_party_modified_shares.balances[balance_idx].amount += Scalar::one();

        assert!(!check_settlement_constraints(&witness, &statement));
    }

    /// Test the cases in which spurious updates to the internal party's shares
    /// are made
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_settle__spurious_updates() {
        let mut rng = thread_rng();
        let (witness, original_statement) = create_witness_statement();
        let indices = original_statement.internal_party_indices;

        // Modify a balance's mint
        let mut statement = original_statement.clone();
        let balance_idx = (0..MAX_BALANCES).sample_single(&mut rng);
        statement.internal_party_modified_shares.balances[balance_idx].mint += Scalar::one();
        assert!(!check_settlement_constraints(&witness, &statement));

        // Modify an uninvolved order's amount
        let mut statement = original_statement.clone();
        let range = 0..MAX_ORDERS;
        let mut order_idx = range.clone().sample_single(&mut rng);
        while order_idx == indices.order {
            order_idx = range.clone().sample_single(&mut rng);
        }
        statement.internal_party_modified_shares.orders[order_idx].amount += Scalar::one();
        assert!(!check_settlement_constraints(&witness, &statement));

        // Modify the wallet keychain
        let mut statement = original_statement.clone();
        statement.internal_party_modified_shares.keys.nonce += Scalar::one();
        assert!(!check_settlement_constraints(&witness, &statement));

        // Modify the wallet blinder
        let mut statement = original_statement.clone();
        statement.internal_party_modified_shares.blinder += Scalar::one();
        assert!(!check_settlement_constraints(&witness, &statement));
    }

    // ---------------------
    // | Commitments Tests |
    // ---------------------

    /// Test the case in which the prover modifies the private share commitment
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_commitments__modified_private_comm() {
        let mut rng = thread_rng();
        let (witness, mut statement) = create_witness_statement_with_commitments();
        statement.private_share_commitment = Scalar::random(&mut rng);

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettleAtomicWithCommitments>(
            &witness, &statement,
        ));
    }

    /// Test the case in which the prover modifies the new share commitment
    #[test]
    #[allow(non_snake_case)]
    fn test_invalid_commitments__modified_new_comm() {
        let mut rng = thread_rng();
        let (witness, mut statement) = create_witness_statement_with_commitments();
        statement.new_share_commitment = Scalar::random(&mut rng);

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettleAtomicWithCommitments>(
            &witness, &statement,
        ));
    }
}
