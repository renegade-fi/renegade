//! Defines the match-settle circuit which enforces validity of the matching
//! engine on two orders, and the settlement of the subsequent match into the
//! two traders' wallets
//!
//! Single and multiprover implementations are separated out for discoverability

pub mod multi_prover;
pub mod single_prover;

use circuit_types::{
    balance::Balance,
    fixed_point::FixedPoint,
    order::Order,
    r#match::MatchResult,
    traits::{
        BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType, MultiProverCircuit,
        MultiproverCircuitBaseType, SingleProverCircuit,
    },
    wallet::WalletShare,
    Fabric, MpcPlonkCircuit, PlonkCircuit,
};
use constants::{AuthenticatedScalar, Scalar, ScalarField, MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{errors::CircuitError, traits::Circuit, Variable};

use circuit_macros::circuit_type;
use serde::{Deserialize, Serialize};

use super::valid_commitments::OrderSettlementIndices;

/// A circuit with default sizing parameters
pub type SizedValidMatchSettle = ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// The circuitry for the valid match
///
/// This statement is only proven within the context of an MPC, so it only
/// implements the Multiprover circuit trait
#[derive(Clone, Debug)]
pub struct ValidMatchSettle<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Applies the constraints of the match-settle circuit
    pub fn multiprover_circuit(
        statement: &ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply the constraints of the match engine
        Self::validate_matching_engine(witness, fabric, cs)?;

        // Apply the constraints of the match settlement
        Self::validate_settlement(statement, witness, fabric, cs)
    }

    /// The order crossing check, for a single prover
    ///
    /// Used to apply constraints to the verifier
    pub fn singleprover_circuit(
        statement: &ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        witness: &ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Apply the constraints of the match engine
        Self::validate_matching_engine_singleprover(witness, cs)?;

        // Apply the constraints of the match settlement
        Self::validate_settlement_singleprover(statement, witness, cs)
    }
}

// -----------------------------------------
// | Witness and Statement Type Definition |
// -----------------------------------------

/// The full witness, recovered by opening the witness commitment, but never
/// realized in the plaintext by either party
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidMatchSettleWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The first party's order
    pub order1: Order,
    /// The first party's balance
    pub balance1: Balance,
    /// The price that the first party agreed to execute at for their asset
    pub price1: FixedPoint,
    /// The maximum amount that the first party may match
    pub amount1: Scalar,
    /// The second party's order
    pub order2: Order,
    /// The second party's balance
    pub balance2: Balance,
    /// The price that the second party agreed to execute at for their asset
    pub price2: FixedPoint,
    /// The maximum amount that the second party may match
    pub amount2: Scalar,
    /// The result of running a match MPC on the given orders
    ///
    /// We do not open this value before proving so that we can avoid leaking
    /// information before the collaborative proof has finished
    pub match_res: MatchResult,
    /// The public shares of the first party before the match is settled
    pub party0_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public shares of the second party before the match is settled
    pub party1_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}

/// A `VALID MATCH SETTLE` witness with default const generic sizing parameters
pub type SizedValidMatchSettleWitness = ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

/// The statement type for `VALID MATCH SETTLE`
#[circuit_type(serde, singleprover_circuit, mpc, multiprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidMatchSettleStatement<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The modified public secret shares of the first party
    pub party0_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The modified public secret shares of the second party
    pub party1_modified_shares: WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The indices that settlement should modify in the first party's wallet
    pub party0_indices: OrderSettlementIndices,
    /// The indices that settlement should modify in the second party's wallet
    pub party1_indices: OrderSettlementIndices,
}

/// A `VALID MATCH SETTLE` statement with default const generic sizing
/// parameters
pub type SizedValidSettleStatement = ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

// ---------------------
// | Prove Verify Flow |
// ---------------------

/// Prover implementation of the Valid Match circuit
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> MultiProverCircuit
    for ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = AuthenticatedValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = AuthenticatedValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type BaseCircuit = Self;

    fn apply_constraints_multiprover(
        witness: ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        statement: ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        fabric: &Fabric,
        cs: &mut MpcPlonkCircuit,
    ) -> Result<(), PlonkError> {
        Self::multiprover_circuit(&statement, &witness, fabric, cs)
            .map_err(PlonkError::CircuitError)
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> SingleProverCircuit
    for ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Witness = ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type Statement = ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    fn apply_constraints(
        witness: ValidMatchSettleWitnessVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        statement: ValidMatchSettleStatementVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        ValidMatchSettle::singleprover_circuit(&statement, &witness, cs)
            .map_err(PlonkError::CircuitError)
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        balance::Balance,
        order::{Order, OrderSide},
        r#match::MatchResult,
    };
    use constants::Scalar;
    use rand::{distributions::uniform::SampleRange, thread_rng, RngCore};

    use crate::{
        test_helpers::random_orders_and_match,
        zk_circuits::{
            test_helpers::{
                create_wallet_shares, SizedWallet, SizedWalletShare, INITIAL_WALLET, MAX_BALANCES,
                MAX_FEES, MAX_ORDERS,
            },
            valid_commitments::OrderSettlementIndices,
        },
    };

    use super::{ValidMatchSettle, ValidMatchSettleStatement, ValidMatchSettleWitness};

    /// A match settle circuit with default sizing parameters
    pub type SizedValidMatchSettle = ValidMatchSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    /// A witness with default sizing parameters attached
    pub type SizedValidMatchSettleWitness =
        ValidMatchSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    /// A statement with default sizing parameters attached
    pub type SizedValidMatchSettleStatement =
        ValidMatchSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    /// Create a dummy witness to match on
    pub fn dummy_witness_and_statement(
    ) -> (SizedValidMatchSettleWitness, SizedValidMatchSettleStatement) {
        let (o1, o2, price, match_res) = random_orders_and_match();

        // Build wallets for the crossing orders
        let (wallet1, party0_indices) = build_wallet_and_indices(&o1, &match_res);
        let (wallet2, party1_indices) = build_wallet_and_indices(&o2, &match_res);
        let (_, party0_public_shares) = create_wallet_shares(&wallet1);
        let (_, party1_public_shares) = create_wallet_shares(&wallet2);

        // Update the wallets
        let party0_modified_shares =
            apply_match_to_shares(&party0_public_shares, &party0_indices, &match_res, o1.side);
        let party1_modified_shares =
            apply_match_to_shares(&party1_public_shares, &party1_indices, &match_res, o2.side);

        let amount1 = Scalar::from(o1.amount);
        let amount2 = Scalar::from(o2.amount);

        (
            ValidMatchSettleWitness {
                order1: o1,
                balance1: wallet1.balances[party0_indices.balance_send as usize].clone(),
                price1: price,
                amount1,
                order2: o2,
                balance2: wallet2.balances[party1_indices.balance_send as usize].clone(),
                price2: price,
                amount2,
                match_res,
                party0_public_shares,
                party1_public_shares,
            },
            ValidMatchSettleStatement {
                party0_indices,
                party1_indices,
                party0_modified_shares,
                party1_modified_shares,
            },
        )
    }

    // Build two wallets and sample indices for the orders and balances for the
    // match to be placed into
    fn build_wallet_and_indices(
        order: &Order,
        match_res: &MatchResult,
    ) -> (SizedWallet, OrderSettlementIndices) {
        let mut rng = thread_rng();
        let mut wallet = INITIAL_WALLET.clone();

        let send = (0..MAX_BALANCES).sample_single(&mut rng);
        let recv = MAX_BALANCES - send - 1;
        let order_ind = (0..MAX_ORDERS).sample_single(&mut rng);

        // Insert the order and balances into the wallet
        wallet.orders[order_ind] = order.clone();
        wallet.balances[send] = send_balance(order, match_res);
        wallet.balances[recv] = receive_balance(order);

        (
            wallet,
            OrderSettlementIndices {
                balance_send: send as u64,
                balance_receive: recv as u64,
                order: order_ind as u64,
            },
        )
    }

    /// Build a send balance given an order
    ///
    /// This builds a balance that fully capitalizes the position the order
    /// represents
    fn send_balance(order: &Order, match_res: &MatchResult) -> Balance {
        let (mint, amount) = match order.side {
            // Buy the base sell the quote
            OrderSide::Buy => (order.quote_mint.clone(), match_res.quote_amount + 1),
            // Sell the base buy the quote
            OrderSide::Sell => (order.base_mint.clone(), match_res.base_amount + 1),
        };

        Balance { mint, amount }
    }

    /// Build a receive balance given an order
    ///
    /// This gives a random initial balance to the order
    fn receive_balance(order: &Order) -> Balance {
        let mut rng = thread_rng();
        let mint = match order.side {
            // Buy the base sell the quote
            OrderSide::Buy => order.base_mint.clone(),
            // Sell the base buy the quote
            OrderSide::Sell => order.quote_mint.clone(),
        };

        Balance {
            mint,
            amount: rng.next_u32() as u64,
        }
    }

    /// Applies a match to the shares of a wallet
    ///
    /// Returns a new wallet share with the match applied
    fn apply_match_to_shares(
        shares: &SizedWalletShare,
        indices: &OrderSettlementIndices,
        match_res: &MatchResult,
        side: OrderSide,
    ) -> SizedWalletShare {
        let (send_amt, recv_amt) = match side {
            // Buy side; send quote, receive base
            OrderSide::Buy => (match_res.quote_amount, match_res.base_amount),
            // Sell side; send base, receive quote
            OrderSide::Sell => (match_res.base_amount, match_res.quote_amount),
        };

        let mut new_shares = shares.clone();
        new_shares.balances[indices.balance_send as usize].amount -= Scalar::from(send_amt);
        new_shares.balances[indices.balance_receive as usize].amount += Scalar::from(recv_amt);
        new_shares.orders[indices.order as usize].amount -= Scalar::from(match_res.base_amount);

        new_shares
    }
}

#[cfg(test)]
mod tests {
    #![allow(non_snake_case)]
    use ark_mpc::PARTY0;
    use circuit_types::{fixed_point::FixedPoint, order::OrderSide, traits::MpcBaseType};

    use constants::Scalar;
    use rand::{thread_rng, Rng, RngCore};
    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        multiprover_prove_and_verify,
        zk_circuits::{
            test_helpers::check_constraint_satisfaction,
            valid_match_settle::test_helpers::{
                dummy_witness_and_statement, SizedValidMatchSettle,
            },
        },
    };

    /// Tests proving a valid match with a valid witness
    #[tokio::test]
    async fn prove_valid_witness() {
        let (witness, statement) = dummy_witness_and_statement();
        let (res, _) = execute_mock_mpc(move |fabric| {
            let witness = witness.clone();
            let statement = statement.clone();

            async move {
                let witness = witness.allocate(PARTY0, &fabric);
                let statement = statement.allocate(PARTY0, &fabric);

                multiprover_prove_and_verify::<SizedValidMatchSettle>(witness, statement, fabric)
                    .await
            }
        })
        .await;

        assert!(res.is_ok())
    }

    // ---------------
    // | Match Tests |
    // ---------------

    /// Randomly perform one of two operation
    macro_rules! rand_branch {
        ($x:expr, $y:expr) => {
            if rand::thread_rng().gen_bool(0.5) {
                $x;
            } else {
                $y;
            }
        };
    }

    /// Test the case in which the two parties attempt to match on different
    /// mints
    #[test]
    fn test_valid_match__different_mints() {
        let (original_witness, statement) = dummy_witness_and_statement();

        // One party switches the quote mint of their order
        let mut witness = original_witness.clone();
        rand_branch!(
            witness.order1.quote_mint += 1u8,
            witness.order2.quote_mint += 1u8
        );

        // Validate that the constraints are not satisfied
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));

        // Now test with base mint switched
        let mut witness = original_witness;
        rand_branch!(
            witness.order1.base_mint += 1u8,
            witness.order2.base_mint += 1u8
        );
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    /// Test the case in which the parties sit on the same side of the book
    #[test]
    fn test_valid_match__same_side() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Swap the sides of one of the orders
        rand_branch!(
            witness.order1.side = witness.order1.side.opposite(),
            witness.order2.side = witness.order2.side.opposite()
        );
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    /// Test the case in which the balance provided to the matching engine is
    /// not for the correct asset
    #[test]
    fn test_valid_match__invalid_balance_mint() {
        let (mut witness, statement) = dummy_witness_and_statement();

<<<<<<< HEAD
        // Corrupt the mint
=======
        // Switch the mint of the balance to be the wrong asset in the pair
>>>>>>> 1e36d44 (circuits: zk-circuits: valid-match-settle: Add match unit tests)
        rand_branch!(witness.balance1.mint += 1u8, witness.balance2.mint += 1u8);
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    /// Test the case in which the balance provided does not cover the
    /// advertised amount
    #[test]
    fn test_valid_match__insufficient_balance() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Reduce the balance to be less than the amount matched
        rand_branch!(witness.balance1.amount = 1, witness.balance2.amount = 1);
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    /// Test the case in which the matched amount exceeds the order size for a
    /// party
    #[test]
    fn test_valid_match__amount_exceeds_order() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Place one party's order amount below the min amount
        rand_branch!(
            witness.order1.amount = witness.match_res.base_amount - 1,
            witness.order2.amount = witness.match_res.base_amount - 1
        );

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    /// Test the case in which the `max_minus_min` field is incorrectly computed
    #[test]
    fn test_valid_match__incorrect_max_minus_min() {
        let mut rng = thread_rng();
        let (mut witness, statement) = dummy_witness_and_statement();

<<<<<<< HEAD
        // Change the max minus min amount
=======
        // Add one to the max minus min amount
>>>>>>> 1e36d44 (circuits: zk-circuits: valid-match-settle: Add match unit tests)
        witness.match_res.max_minus_min_amount = rng.next_u64();
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    /// Test the case in which the `min_amount_order_index` field is incorrectly
    /// computed
    #[test]
    fn test_valid_match__incorrect_min_amount_order_index() {
        let (mut witness, statement) = dummy_witness_and_statement();

        // Invert the index
        witness.match_res.min_amount_order_index = !witness.match_res.min_amount_order_index;
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    /// Test the case in which the execution price exceeds the buy side price
    /// protection
    #[test]
    fn test_valid_match__price_protection_violated_buy_side() {
        let (mut witness, statement) = dummy_witness_and_statement();
        let execution_price =
            (witness.match_res.quote_amount as f64) / (witness.match_res.base_amount as f64);

        // Execution price exceeds the buy side maximum price
        let new_price = FixedPoint::from_f64_round_down(execution_price - 1.);
        match witness.order1.side {
            OrderSide::Buy => witness.price1 = new_price,
            OrderSide::Sell => witness.price2 = new_price,
        };

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    /// Test the case in which the execution price falls sort of the sell
    /// side price protection
    #[test]
    fn test_valid_match__price_protection_violated_sell_side() {
        let (mut witness, statement) = dummy_witness_and_statement();
        let execution_price =
            (witness.match_res.quote_amount as f64) / (witness.match_res.base_amount as f64);

        // Execution price exceeds the buy side maximum price
        let new_price = FixedPoint::from_f64_round_down(execution_price + 1.);
        match witness.order1.side {
            OrderSide::Sell => witness.price1 = new_price,
            OrderSide::Buy => witness.price2 = new_price,
        };

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness, &statement
        ));
    }

    // --------------------
    // | Settlement Tests |
    // --------------------

    /// Tests the case in which an incorrect balance index is given
    #[test]
    fn test_invalid_settle__invalid_balance_index() {
        let (witness, original_statement) = dummy_witness_and_statement();

        // Party 0 send balance corrupted
        let mut statement = original_statement.clone();
        statement.party0_indices.balance_send += 1;
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));

        // Party 0 receive balance corrupted
        let mut statement = original_statement.clone();
        statement.party0_indices.balance_receive += 1;
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));

        // Party 1 send balance corrupted
        let mut statement = original_statement.clone();
        statement.party1_indices.balance_send += 1;
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));

        // Party 1 receive balance corrupted
        let mut statement = original_statement;
        statement.party1_indices.balance_receive += 1;
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));
    }

    /// Test the case in which the order index of a settlement is incorrect
    #[test]
    fn test_invalid_settle__invalid_order_index() {
        let (witness, original_statement) = dummy_witness_and_statement();

        // Party 0 order index corrupted
        let mut statement = original_statement.clone();
        statement.party0_indices.order += 1;
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));

        // Party 1 order index corrupted
        let mut statement = original_statement;
        statement.party1_indices.order += 1;
        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));
    }

    /// Test case in which the send balance is incorrectly updated
    #[test]
    fn test_invalid_settle__invalid_send_balance() {
        let (witness, mut statement) = dummy_witness_and_statement();

        // Modify the send balance of party 0
        statement.party0_modified_shares.balances
            [statement.party0_indices.balance_send as usize]
            .amount += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));
    }

    /// Tests the case in which the receive balance is incorrectly updated
    #[test]
    fn test_invalid_settle__invalid_receive_balance() {
        let (witness, mut statement) = dummy_witness_and_statement();

        // Modify the receive balance of party 1
        statement.party1_modified_shares.balances
            [statement.party1_indices.balance_receive as usize]
            .amount += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));
    }

    /// Tests the case in which the order amount is incorrectly modified
    #[test]
    fn test_invalid_settle__invalid_order_update() {
        let (witness, mut statement) = dummy_witness_and_statement();

        // Modify the order of party 0
        statement.party0_modified_shares.orders[statement.party0_indices.order as usize].amount -=
            Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));
    }

    /// Tests cases in which an element is spuriously modified that should not
    /// be
    #[test]
    fn test_invalid_settle__spurious_modifications() {
        let (witness, original_statement) = dummy_witness_and_statement();

        // Modify a balance that should not be modified
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.balances
            [statement.party0_indices.balance_send as usize]
            .mint += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));

        // Modify an order that should not be modified
        let mut statement = original_statement.clone();
        statement.party1_modified_shares.orders[statement.party1_indices.order as usize].amount -=
            Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));

        // Modify a fee
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.fees[0].gas_token_amount += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));

        // Modify a key
        let mut statement = original_statement.clone();
        statement.party1_modified_shares.keys.pk_match.key += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));

        // Modify the blinder
        let mut statement = original_statement;
        statement.party0_modified_shares.blinder += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedValidMatchSettle>(
            &witness.clone(),
            &statement
        ));
    }
}
