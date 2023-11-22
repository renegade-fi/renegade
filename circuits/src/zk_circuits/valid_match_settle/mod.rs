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
    use ark_mpc::PARTY0;
    use circuit_types::traits::MpcBaseType;

    use test_helpers::mpc_network::execute_mock_mpc;

    use crate::{
        multiprover_prove_and_verify,
        zk_circuits::valid_match_settle::test_helpers::{
            dummy_witness_and_statement, SizedValidMatchSettle,
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
}
