//! Defines the VALID SETTLE circuit, which is proven after a match, validating that
//! both party's secret shares have been updated properly with the result of the match

use circuit_macros::circuit_type;
use circuit_types::{
    r#match::LinkableMatchResult,
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
    },
    wallet::{LinkableWalletShare, WalletShare, WalletShareVar},
};
use constants::{MAX_BALANCES, MAX_FEES, MAX_ORDERS};
use mpc_bulletproof::r1cs::{LinearCombination, R1CSError, RandomizableConstraintSystem, Variable};
use mpc_stark::algebra::{scalar::Scalar, stark_curve::StarkPoint};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    zk_gadgets::{comparators::EqGadget, select::CondSelectVectorGadget},
    SingleProverCircuit,
};

// ----------------------
// | Circuit Definition |
// ----------------------

/// A type alias for the `ValidSettle` circuit with default sizing generics set
pub type SizedValidSettle = ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
/// The circuit definition of `VALID SETTLE`
pub struct ValidSettle<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>;
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    ValidSettle<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The circuit representing `VALID SETTLE`
    pub fn circuit<CS: RandomizableConstraintSystem>(
        statement: ValidSettleStatementVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        witness: ValidSettleWitnessVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        // Select the balances received by each party
        let mut party0_party1_received =
            CondSelectVectorGadget::select::<_, _, Variable, LinearCombination, _>(
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
        pre_update_shares: &WalletShareVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        post_update_shares: &WalletShareVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
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
            let send_term_index_mask = EqGadget::eq(send_index, curr_index.clone(), cs);
            let (_, new_send_term, curr_send_term) =
                cs.multiply(send_term_index_mask.into(), send_term);
            send_term = new_send_term.into();

            // Mask the receive term
            let receive_term_index_mask = EqGadget::eq(receive_index, curr_index.clone(), cs);
            let (_, new_receive_term, curr_receive_term) =
                cs.multiply(receive_term_index_mask.into(), receive_term);
            receive_term = new_receive_term.into();

            // Add the terms together to get the expected update
            let expected_balance_amount =
                pre_update_balance.amount + curr_send_term + curr_receive_term;
            let mut expected_balances_shares = pre_update_balance.to_lc();
            expected_balances_shares.amount = expected_balance_amount.clone();

            EqGadget::constrain_eq(expected_balances_shares, post_update_balance, cs);

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
        pre_update_shares: &WalletShareVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        post_update_shares: &WalletShareVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
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
            let index_mask = EqGadget::eq(order_index, curr_index.clone(), cs);
            let (_, new_amount_delta, curr_delta_term) =
                cs.multiply(index_mask.into(), amount_delta);
            amount_delta = new_amount_delta.into();

            // Constrain the order update to be correct
            let expected_order_volume = pre_update_order.amount + curr_delta_term;
            let mut expected_order_shares = pre_update_order.clone().to_lc();
            expected_order_shares.amount = expected_order_volume;

            EqGadget::constrain_eq(expected_order_shares, post_update_order, cs);

            // Increment the index
            curr_index += Variable::One();
        }
    }

    /// Validate that `match_fee`, keys, and blinders remain the same in the pre and post
    /// wallet shares
    fn validate_fees_keys_blinder_updates<CS: RandomizableConstraintSystem>(
        pre_update_shares: WalletShareVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        post_update_shares: WalletShareVar<Variable, MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        cs: &mut CS,
    ) {
        EqGadget::constrain_eq(
            pre_update_shares.match_fee,
            post_update_shares.match_fee,
            cs,
        );
        EqGadget::constrain_eq(pre_update_shares.keys, post_update_shares.keys, cs);
        EqGadget::constrain_eq(pre_update_shares.blinder, post_update_shares.blinder, cs);
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID SETTLE`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug)]
pub struct ValidSettleWitness<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The match result to be applied to the wallet shares
    pub match_res: LinkableMatchResult,
    /// The public secret shares of the first party before the match is applied
    pub party0_public_shares: LinkableWalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    /// The public secret shares of the second party before the match is applied
    pub party1_public_shares: LinkableWalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
}
/// A `VALID SETTLE` witness with default const generic sizing parameters
pub type SizedValidSettleWitness = ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

// -----------------------------
// | Statement Type Definition |
// -----------------------------

/// The statement type for `VALID SETTLE`
#[circuit_type(singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidSettleStatement<
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
    /// The index of the balance that the first party sent in the settlement
    pub party0_send_balance_index: u64,
    /// The index of teh balance that the first party received in the settlement
    pub party0_receive_balance_index: u64,
    /// The index of the first party's order that was matched
    pub party0_order_index: u64,
    /// The index of the balance that the second party sent in the settlement
    pub party1_send_balance_index: u64,
    /// The index of teh balance that the second party received in the settlement
    pub party1_receive_balance_index: u64,
    /// The index of the second party's order that was matched
    pub party1_order_index: u64,
}
/// A `VALID SETTLE` statement with default const generic sizing parameters
pub type SizedValidSettleStatement = ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

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

    const BP_GENS_CAPACITY: usize = 1024;

    fn apply_constraints<CS: RandomizableConstraintSystem>(
        witness_var: <Self::Witness as CircuitBaseType>::VarType<Variable>,
        statement_var: <Self::Statement as CircuitBaseType>::VarType<Variable>,
        cs: &mut CS,
    ) -> Result<(), R1CSError> {
        Self::circuit(statement_var, witness_var, cs);
        Ok(())
    }
}

// ---------
// | Tests |
// ---------

#[cfg(any(test, feature = "test_helpers"))]
pub mod test_helpers {
    use circuit_types::{
        order::{Order, OrderSide},
        r#match::MatchResult,
        traits::LinkableBaseType,
        wallet::Wallet,
    };
    use lazy_static::lazy_static;
    use mpc_stark::algebra::scalar::Scalar;
    use num_bigint::BigUint;

    use crate::zk_circuits::test_helpers::{
        create_wallet_shares, SizedWallet, INITIAL_WALLET, MAX_BALANCES, MAX_FEES, MAX_ORDERS,
        TIMESTAMP,
    };

    use super::{ValidSettleStatement, ValidSettleWitness};

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        /// The first of two wallets that match
        pub static ref WALLET1: SizedWallet = {
            let orders = [
                Order {
                    quote_mint: 1u8.into(),
                    base_mint: 2u8.into(),
                    side: OrderSide::Buy,
                    amount: 1,
                    // No price limit by default
                    worst_case_price: 100000u64.into(),
                    timestamp: TIMESTAMP,
                },
                Order::default()
            ];

            SizedWallet {
                orders,
                ..INITIAL_WALLET.clone()
            }
        };

        /// The second of two wallets to match, the first wallet with the order side flipped
        pub static ref WALLET2: SizedWallet = {
            let mut wallet = WALLET1.clone();
            wallet.orders[0].side = OrderSide::Sell;

            wallet
        };

        /// The result of matching the two orders in the wallets above
        pub static ref MATCH_RES: MatchResult = MatchResult {
            quote_mint: 1u8.into(),
            base_mint: 2u8.into(),
            quote_amount: 5,
            base_amount: 1,
            direction: 0, /* party0 buys base */
            protocol_quote_fee_amount: 0,
            protocol_base_fee_amount: 0,
            party0_relayer_fee_amount: 0,
            party1_relayer_fee_amount: 0,
            max_minus_min_amount: 0,
            min_amount_order_index: 0,
        };
    }

    /// The witness type for `VALID SETTLE` with default size parameters attached
    pub type SizedWitness = ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    /// The statement type for `VALID SETTLE` with default size parameters attached
    pub type SizedStatement = ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    /// Construct a witness and statement for `VALID SETTLE`
    pub fn create_witness_statement<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        party0_wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        party1_wallet: Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        match_res: MatchResult,
    ) -> (
        ValidSettleWitness<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
        ValidSettleStatement<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    )
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
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
        let (_, party0_public_shares) = create_wallet_shares(party0_wallet);
        let (_, party1_public_shares) = create_wallet_shares(party1_wallet);

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
            match_res: match_res.to_linkable(),
            party0_public_shares: party0_public_shares.to_linkable(),
            party1_public_shares: party1_public_shares.to_linkable(),
        };
        let statement = ValidSettleStatement {
            party0_modified_shares,
            party1_modified_shares,
            party0_send_balance_index: party0_send_index as u64,
            party0_receive_balance_index: party0_receive_index as u64,
            party0_order_index: party0_order_index as u64,
            party1_send_balance_index: party1_send_index as u64,
            party1_receive_balance_index: party1_receive_index as u64,
            party1_order_index: party1_order_index as u64,
        };

        (witness, statement)
    }

    /// Find the index of the balance with the given mint in the given wallet
    fn find_balance_in_wallet<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        mint: &BigUint,
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> Option<usize>
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        wallet
            .balances
            .iter()
            .enumerate()
            .find(|(_ind, b)| mint.eq(&b.mint))
            .map(|(ind, _balance)| ind) // keep only the index
    }

    /// Find the index of the order within the given wallet that is on the given asset pair's book
    fn find_order_in_wallet<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
    >(
        base_mint: &BigUint,
        quote_mint: &BigUint,
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>,
    ) -> Option<usize>
    where
        [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
    {
        wallet
            .orders
            .iter()
            .enumerate()
            .find(|(_ind, order)| {
                base_mint.eq(&order.base_mint) && quote_mint.eq(&order.quote_mint)
            })
            .map(|(ind, _order)| ind) // keep only the index
    }
}

#[cfg(test)]
mod test {
    #![allow(non_snake_case)]

    use circuit_types::traits::CircuitBaseType;
    use merlin::HashChainTranscript as Transcript;
    use mpc_bulletproof::{r1cs::Prover, PedersenGens};
    use mpc_stark::algebra::scalar::Scalar;
    use rand::thread_rng;

    use crate::zk_circuits::valid_settle::test_helpers::{
        create_witness_statement, MATCH_RES, WALLET1, WALLET2,
    };

    use super::{
        test_helpers::{SizedStatement, SizedWitness},
        ValidSettle,
    };

    /// Return true if the given witness and statement satisfy the constraints of
    /// the VALID SETTLE circuit
    fn constraints_satisfied(witness: SizedWitness, statement: SizedStatement) -> bool {
        // Build a constraint system
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        // Allocate the witness and statement in the constraint system
        let mut rng = thread_rng();
        let (witness_var, _) = witness.commit_witness(&mut rng, &mut prover);
        let statement_var = statement.commit_public(&mut prover);

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
        statement.party0_modified_shares.balances[statement.party0_send_balance_index as usize]
            .amount += Scalar::one();

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
        statement.party1_modified_shares.balances
            [statement.party1_receive_balance_index as usize]
            .amount += Scalar::one();

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
        statement.party0_modified_shares.orders[statement.party0_order_index as usize].amount -=
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
        statement.party0_modified_shares.balances[statement.party0_send_balance_index as usize]
            .mint += Scalar::one();

        assert!(!constraints_satisfied(witness.clone(), statement));

        // Modify an order that should not be modified
        let mut statement = original_statement.clone();
        statement.party1_modified_shares.orders[statement.party1_order_index as usize].amount -=
            Scalar::one();

        assert!(!constraints_satisfied(witness.clone(), statement));

        // Modify the `match_fee`
        let mut statement = original_statement.clone();
        statement.party0_modified_shares.match_fee.repr += Scalar::one();

        assert!(!constraints_satisfied(witness.clone(), statement));

        // Modify a key
        let mut statement = original_statement.clone();
        statement.party1_modified_shares.keys.pk_match.key += Scalar::one();

        assert!(!constraints_satisfied(witness.clone(), statement));

        // Modify the blinder
        let mut statement = original_statement;
        statement.party0_modified_shares.blinder += Scalar::one();

        assert!(!constraints_satisfied(witness, statement));
    }
}
