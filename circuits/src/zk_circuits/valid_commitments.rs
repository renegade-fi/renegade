//! The `VALID COMMITMENTS` circuit
//!
//! This circuit which leaks indices of balances and orders that will need to be
//! updated upon a successful match. Specifically, the circuit verifies that
//! balances, orders, etc are contained in a wallet at the claimed index. These
//! balances, orders, etc are then linked to the settlement proofs upon a
//! successful match.
//!
//! Note that the wallet's state inclusion in the global Merkle tree is proven
//! in a linked proof of `VALID REBLIND`.
//!
//! VALID COMMITMENTS is proven once per order in the wallet

use crate::{
    SingleProverCircuit,
    zk_circuits::{
        VALID_COMMITMENTS_MATCH_SETTLE_LINK0, VALID_COMMITMENTS_MATCH_SETTLE_LINK1,
        VALID_REBLIND_COMMITMENTS_LINK,
    },
    zk_gadgets::{
        comparators::{EqGadget, EqVecGadget, EqZeroGadget, GreaterThanEqGadget},
        wallet_operations::{FeeGadget, OrderGadget, WalletGadget},
    },
};
use circuit_macros::circuit_type;
use circuit_types::{
    FEE_BITS, PlonkCircuit,
    balance::{Balance, BalanceVar},
    fixed_point::FixedPoint,
    r#match::OrderSettlementIndices,
    order::{Order, OrderVar},
    traits::{BaseType, CircuitBaseType, CircuitVarType},
    wallet::{WalletShare, WalletVar},
};
use constants::{MAX_BALANCES, MAX_ORDERS, Scalar, ScalarField};
use mpc_plonk::errors::PlonkError;
use mpc_relation::{
    Variable,
    errors::CircuitError,
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
};
use serde::{Deserialize, Serialize};

use super::valid_match_settle::ValidMatchSettle;

// ----------------------
// | Circuit Definition |
// ----------------------

/// The circuit implementation of VALID COMMITMENTS
pub struct ValidCommitments<const MAX_BALANCES: usize, const MAX_ORDERS: usize>;
/// `VALID COMMITMENTS` with default state element sizing
pub type SizedValidCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS>;

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> ValidCommitments<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The circuit constraints for VALID COMMITMENTS
    pub fn circuit(
        statement: &ValidCommitmentsStatementVar,
        witness: &ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // Reconstruct the base and augmented wallets
        let base_wallet = WalletGadget::wallet_from_shares(
            &witness.public_secret_shares,
            &witness.private_secret_shares,
            cs,
        )?;
        let augmented_wallet = WalletGadget::wallet_from_shares(
            &witness.augmented_public_shares,
            &witness.private_secret_shares,
            cs,
        )?;

        // The mint that the wallet will receive if the order is matched
        let receive_mint = OrderGadget::get_buy_mint(&witness.order, cs)?;
        let send_mint = OrderGadget::get_sell_mint(&witness.order, cs)?;

        // The advertised relayer take rate in the witness should equal the authorized
        // take rate in the wallet
        let relayer_fee_repr = witness.relayer_fee.repr;
        let max_match_fee_repr = base_wallet.max_match_fee.repr;
        FeeGadget::constrain_valid_fee(witness.relayer_fee, cs)?;
        GreaterThanEqGadget::<FEE_BITS>::constrain_greater_than_eq(
            max_match_fee_repr,
            relayer_fee_repr,
            cs,
        )?;

        // Verify that the wallets are the same other than a possibly augmented balance
        // of zero for the received mint of the order. This augmented balance
        // must come in place of a previous balance that was zero.
        Self::verify_wallets_equal_with_augmentation(
            statement.indices.balance_receive,
            receive_mint,
            &base_wallet,
            &augmented_wallet,
            cs,
        )?;

        // Verify that the send balance is valid
        Self::verify_send_balance(
            statement.indices.balance_send,
            send_mint,
            &witness.balance_send,
            &augmented_wallet,
            cs,
        )?;

        // Verify that the receive balance is valid
        Self::verify_receive_balance(
            statement.indices.balance_receive,
            receive_mint,
            &witness.balance_receive,
            &augmented_wallet,
            cs,
        )?;

        // Verify that the order is valid and ready to match
        Self::verify_order(statement.indices.order, &witness.order, &augmented_wallet, cs)
    }

    /// Verify that two wallets are equal except possibly with a balance
    /// augmentation
    fn verify_wallets_equal_with_augmentation(
        receive_index: Variable,
        received_mint: Variable,
        base_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        augmented_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // All balances should be the same except possibly the balance at the receive
        // index. We allow this balance to be zero'd in the base wallet, and
        // have the received mint with zero balance in the augmented wallet
        let zero_var = cs.zero();
        let one_var = cs.one();
        let mut curr_index = zero_var;

        for (base_balance, augmented_balance) in
            base_wallet.balances.iter().zip(augmented_wallet.balances.iter())
        {
            // Non-augmented case, balances are equal
            let balances_eq = EqGadget::eq(base_balance, augmented_balance, cs)?;

            // Augmented case, a zero-value balance has replaced a previous balance with all
            // zero fields except the mint

            // Was the previous balance zero'd
            let prev_balance_zero = EqVecGadget::eq_zero_vec(
                &[
                    base_balance.amount,
                    base_balance.protocol_fee_balance,
                    base_balance.relayer_fee_balance,
                ],
                cs,
            )?;

            // Is the new balance at the given index equal to a valid augmentation
            let is_augmented = EqGadget::eq(
                augmented_balance,
                &BalanceVar {
                    mint: received_mint,
                    amount: zero_var,
                    protocol_fee_balance: zero_var,
                    relayer_fee_balance: zero_var,
                },
                cs,
            )?;

            // Augmentation may only happen at the claimed receive balance index
            let augmentation_index_mask = EqGadget::eq(&curr_index, &receive_index, cs)?;

            // Validate that the balance is either unmodified or augmented from (<old-mint>,
            // 0, 0, 0) to (receive_mint, 0, 0, 0)
            let valid_augmentation =
                cs.logic_and_all(&[prev_balance_zero, is_augmented, augmentation_index_mask])?;

            let valid_balance = cs.logic_or(valid_augmentation, balances_eq)?;
            cs.enforce_true(valid_balance)?;
            curr_index = cs.add(curr_index, one_var)?;
        }

        // All orders should be the same
        EqGadget::constrain_eq(&base_wallet.orders, &augmented_wallet.orders, cs)?;

        // Keys should be equal
        EqGadget::constrain_eq(&base_wallet.keys, &augmented_wallet.keys, cs)?;

        // Match fee, managing cluster, and blinder should be equal
        EqGadget::constrain_eq(&base_wallet.max_match_fee, &augmented_wallet.max_match_fee, cs)?;
        EqGadget::constrain_eq(
            &base_wallet.managing_cluster,
            &augmented_wallet.managing_cluster,
            cs,
        )?;
        EqGadget::constrain_eq(&base_wallet.blinder, &augmented_wallet.blinder, cs)
    }

    // ------------
    // | Balances |
    // ------------

    /// Verify the send balance of the witness
    fn verify_send_balance(
        ind_send: Variable,
        send_mint: Variable,
        send_balance: &BalanceVar,
        augmented_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The wallet must contain the given balance at the claimed index
        Self::contains_balance_at_index(ind_send, send_balance, augmented_wallet, cs)?;

        // The mint of the send balance must be the same as the mint sold by the order
        cs.enforce_equal(send_balance.mint, send_mint)?;

        // The balance amount cannot be zero
        let amount_zero = EqZeroGadget::eq_zero(&send_balance.amount, cs)?;
        cs.enforce_false(amount_zero)
    }

    /// Verify the receive balance of the witness
    ///
    /// Note that unlink the send balance, the receive balance may have zero
    /// amount
    fn verify_receive_balance(
        ind_receive: Variable,
        receive_mint: Variable,
        receive_balance: &BalanceVar,
        augmented_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The wallet must contain the given balance at the claimed index
        Self::contains_balance_at_index(ind_receive, receive_balance, augmented_wallet, cs)?;

        // The mint of the receive balance must be the same as the mint bought by the
        // order
        cs.enforce_equal(receive_balance.mint, receive_mint)?;

        // The receive balance mint must be unique in the wallet, i.e. an
        // augmentation may not have added a duplicate balance
        let mut curr_index = cs.zero();
        for balance in augmented_wallet.balances.iter() {
            // Whether the current balance and the receive balance are for the same mint
            let mint_eq = EqGadget::eq(&balance.mint, &receive_mint, cs)?;
            let mints_not_eq = cs.logic_neg(mint_eq)?;

            // Whether the current balance is pointing to the receive balance
            let at_receive_index = EqGadget::eq(&curr_index, &ind_receive, cs)?;

            // Either the mints are not equal or the indices are equal
            let valid_mint = cs.logic_or(mints_not_eq, at_receive_index)?;
            cs.enforce_true(valid_mint)?;
            curr_index = cs.add(curr_index, cs.one())?;
        }

        Ok(())
    }

    /// Verify that the wallet has the given balance at the specified index
    fn contains_balance_at_index(
        index: Variable,
        target_balance: &BalanceVar,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let mut curr_index = cs.zero();
        let mut balance_found = cs.false_var();

        for balance in wallet.balances.iter() {
            let index_mask = EqGadget::eq(&curr_index, &index, cs)?;
            let balances_eq = EqGadget::eq(balance, target_balance, cs)?;

            let found = cs.logic_and(index_mask, balances_eq)?;

            balance_found = cs.logic_or(balance_found, found)?;
            curr_index = cs.add(curr_index, cs.one())?;
        }

        cs.enforce_true(balance_found)
    }

    // ----------
    // | Orders |
    // ----------

    /// Verify the order given in the witness is valid for a match
    ///
    /// Note: the order side is constrained binary by its allocation as a
    /// `BoolVar` in the circuit
    fn verify_order(
        ind_order: Variable,
        order: &OrderVar,
        augmented_wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        // The order must be in the wallet at the claimed index
        Self::contains_order_at_index(ind_order, order, augmented_wallet, cs)?;

        // Neither the quote nor base mint may be zero
        let quote_zero = EqZeroGadget::eq_zero(&order.quote_mint, cs)?;
        let base_zero = EqZeroGadget::eq_zero(&order.base_mint, cs)?;
        let quote_or_base_zero = cs.logic_or(quote_zero, base_zero)?;
        cs.enforce_false(quote_or_base_zero)?;

        // The order amount may not be zero
        let amount_zero = EqZeroGadget::eq_zero(&order.amount, cs)?;
        cs.enforce_false(amount_zero)
    }

    /// Verify that the wallet has the given order at the specified index
    fn contains_order_at_index(
        index: Variable,
        target_order: &OrderVar,
        wallet: &WalletVar<MAX_BALANCES, MAX_ORDERS>,
        cs: &mut PlonkCircuit,
    ) -> Result<(), CircuitError> {
        let mut curr_index = cs.zero();
        let mut order_found = cs.false_var();

        for order in wallet.orders.iter() {
            let index_mask = EqGadget::eq(&curr_index, &index, cs)?;
            let orders_eq = EqGadget::eq(order, target_order, cs)?;

            let found = cs.logic_and(index_mask, orders_eq)?;
            order_found = cs.logic_or(order_found, found)?;
            curr_index = cs.add(curr_index, cs.one())?;
        }

        cs.enforce_true(order_found)
    }
}

// ---------------------------
// | Witness Type Definition |
// ---------------------------

/// The witness type for `VALID COMMITMENTS`
#[circuit_type(serde, singleprover_circuit)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidCommitmentsWitness<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The private secret shares of the wallet that have been reblinded for
    /// match
    #[link_groups = "valid_reblind_commitments"]
    pub private_secret_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The public secret shares of the wallet that have been reblinded for
    /// match
    #[link_groups = "valid_reblind_commitments"]
    pub public_secret_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
    /// The order that the prover intends to match against with this proof
    #[link_groups = "valid_commitments_match_settle0, valid_commitments_match_settle1"]
    pub order: Order,
    /// The balance that the wallet will send when the order is matched
    #[link_groups = "valid_commitments_match_settle0, valid_commitments_match_settle1"]
    pub balance_send: Balance,
    /// The balance that the wallet will receive into when the order is matched
    #[link_groups = "valid_commitments_match_settle0, valid_commitments_match_settle1"]
    pub balance_receive: Balance,
    /// The relayer's take rate for managing this order
    #[link_groups = "valid_commitments_match_settle0, valid_commitments_match_settle1"]
    pub relayer_fee: FixedPoint,
    /// The modified public secret shares, possibly with a zero'd balance added
    /// for the mint that will be received by this party upon a successful
    /// match
    #[link_groups = "valid_commitments_match_settle0, valid_commitments_match_settle1"]
    pub augmented_public_shares: WalletShare<MAX_BALANCES, MAX_ORDERS>,
}
/// A `VALID COMMITMENTS` witness with default const generic sizing parameters
pub type SizedValidCommitmentsWitness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS>;

/// The statement type for `VALID COMMITMENTS`
#[circuit_type(singleprover_circuit)]
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct ValidCommitmentsStatement {
    /// The indices used in settling this order once matched
    pub indices: OrderSettlementIndices,
}

// ---------------------
// | Prove Verify Flow |
// ---------------------

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> SingleProverCircuit
    for ValidCommitments<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    type Statement = ValidCommitmentsStatement;
    type Witness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS>;

    fn name() -> String {
        format!("Valid Commitments ({MAX_BALANCES}, {MAX_ORDERS})")
    }

    /// VALID COMMITMENTS has three proof linking groups:
    /// - valid_reblind_commitments: The linking group between VALID REBLIND and
    ///   VALID COMMITMENTS. This group is placed by VALID COMMITMENTS and
    ///   inherited by VALID REBLIND
    /// - valid_commitments_match_settle{0,1}: The linking groups between VALID
    ///   COMMITMENTS and VALID MATCH SETTLE. These two groups are placed by
    ///   VALID MATCH SETTLE and inherited by VALID COMMITMENTS
    ///
    /// To place the valid_reblind_commitments group, VALID COMMITMENTS
    /// specifies `None` for the layout
    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let match_layout = ValidMatchSettle::get_circuit_layout()?;
        let layout0 = match_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK0);
        let layout1 = match_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK1);

        Ok(vec![
            (VALID_REBLIND_COMMITMENTS_LINK.to_string(), None),
            (VALID_COMMITMENTS_MATCH_SETTLE_LINK0.to_string(), Some(layout0)),
            (VALID_COMMITMENTS_MATCH_SETTLE_LINK1.to_string(), Some(layout1)),
        ])
    }

    fn apply_constraints(
        witness_var: ValidCommitmentsWitnessVar<MAX_BALANCES, MAX_ORDERS>,
        statement_var: ValidCommitmentsStatementVar,
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
        Address,
        balance::Balance,
        native_helpers::create_wallet_shares_from_private,
        wallet::{Wallet, WalletShare},
    };

    use crate::zk_circuits::test_helpers::{MAX_BALANCES, MAX_ORDERS, create_wallet_shares};

    use super::{OrderSettlementIndices, ValidCommitmentsStatement, ValidCommitmentsWitness};

    /// A type alias for the VALID COMMITMENTS witness with size parameters
    /// attached
    pub type SizedWitness = ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS>;

    /// Construct a valid witness and statement from the given wallet
    ///
    /// Simply chooses a random order to match against from the wallet
    pub fn create_witness_and_statement<const MAX_BALANCES: usize, const MAX_ORDERS: usize>(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
    ) -> (ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS>, ValidCommitmentsStatement)
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        // Split the wallet into secret shares
        let (private_share, public_share) = create_wallet_shares(wallet);
        create_witness_and_statement_with_shares(wallet, &public_share, &private_share)
    }

    /// Create a witness and statement with wallet shares specified alongside
    /// the wallet
    pub fn create_witness_and_statement_with_shares<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
    >(
        wallet: &Wallet<MAX_BALANCES, MAX_ORDERS>,
        public_share: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
        private_share: &WalletShare<MAX_BALANCES, MAX_ORDERS>,
    ) -> (ValidCommitmentsWitness<MAX_BALANCES, MAX_ORDERS>, ValidCommitmentsStatement)
    where
        [(); MAX_BALANCES + MAX_ORDERS]: Sized,
    {
        // Choose an order and fee to match on
        let ind_order = 0;
        let order = wallet.orders[ind_order].clone();

        // Restructure the mints from the order direction
        let receive_mint = order.receive_mint().clone();
        let send_mint = order.send_mint().clone();

        let mut augmented_wallet = wallet.clone();

        // Find appropriate balances in the wallet
        let (ind_receive, balance_receive) = find_balance_or_augment(
            receive_mint,
            &mut augmented_wallet.balances,
            true, // augment
        );
        let (ind_send, balance_send) = find_balance_or_augment(
            send_mint,
            &mut augmented_wallet.balances,
            false, // augment
        );

        // After augmenting, split the augmented wallet into shares, using the same
        // private secret shares as the original (un-augmented) wallet
        let (_, augmented_public_shares) =
            create_wallet_shares_from_private(&augmented_wallet, private_share, wallet.blinder);

        let witness = ValidCommitmentsWitness {
            private_secret_shares: private_share.clone(),
            public_secret_shares: public_share.clone(),
            augmented_public_shares,
            order,
            relayer_fee: wallet.max_match_fee,
            balance_send,
            balance_receive,
        };

        let statement = ValidCommitmentsStatement {
            indices: OrderSettlementIndices {
                balance_send: ind_send,
                balance_receive: ind_receive,
                order: ind_order,
            },
        };

        (witness, statement)
    }

    /// Finds a balance for the given order returning the index and the balance
    /// itself
    ///
    /// If the balance does not exist the `augment` flag lets the method augment
    /// the wallet with a zero'd balance
    pub(super) fn find_balance_or_augment<const MAX_BALANCES: usize>(
        mint: Address,
        balances: &mut [Balance; MAX_BALANCES],
        augment: bool,
    ) -> (usize, Balance) {
        let balance = balances.iter().enumerate().find(|(_ind, balance)| balance.mint == mint);

        match balance {
            Some((ind, balance)) => (ind, balance.clone()),
            None => {
                if !augment {
                    panic!("balance not found in wallet");
                }

                // Find a zero'd balance
                let (zerod_index, _) = balances
                    .iter()
                    .enumerate()
                    .find(|(_ind, balance)| balance.mint == Address::from(0u8))
                    .expect("wallet must have zero'd balance to augment");

                balances[zerod_index] = Balance::new_from_mint(mint);
                (zerod_index, balances[zerod_index].clone())
            },
        }
    }
}

#[cfg(test)]
#[allow(non_snake_case)]
mod test {
    use circuit_types::{
        Address,
        balance::{Balance, BalanceShare},
        fixed_point::{FixedPoint, FixedPointShare},
        order::{OrderShare, OrderSide},
        traits::{SecretShareType, SingleProverCircuit},
    };
    use constants::Scalar;
    use lazy_static::lazy_static;
    use rand::{RngCore, thread_rng};

    use crate::zk_circuits::{
        VALID_COMMITMENTS_MATCH_SETTLE_LINK0, VALID_COMMITMENTS_MATCH_SETTLE_LINK1,
        VALID_REBLIND_COMMITMENTS_LINK, check_constraint_satisfaction,
        test_helpers::{INITIAL_WALLET, MAX_BALANCES, MAX_ORDERS, SizedWallet},
        valid_commitments::{
            SizedValidCommitments,
            test_helpers::{create_witness_and_statement, find_balance_or_augment},
        },
        valid_match_settle::SizedValidMatchSettle,
        valid_reblind::SizedValidReblind,
    };

    use super::ValidCommitments;

    // --------------
    // | Dummy Data |
    // --------------

    lazy_static! {
        /// A wallet needing augmentation to receive its side of an order
        static ref UNAUGMENTED_WALLET: SizedWallet = {
            // Zero the wallet balance corresponding to the received mint
            let mut wallet = INITIAL_WALLET.clone();
            let order_receive_mint = match wallet.orders[0].side {
                OrderSide::Buy => wallet.orders[0].base_mint.clone(),
                OrderSide::Sell => wallet.orders[0].quote_mint.clone(),
            };

            // Find the received mint balance
            let (balance_ind, _) = find_balance_or_augment(order_receive_mint, &mut wallet.balances, false /* augment */);
            wallet.balances[balance_ind] = Balance::default();
            wallet
        };
    }

    /// A type alias for the VALID COMMITMENTS circuit with size parameters
    pub type SizedCommitments = ValidCommitments<MAX_BALANCES, MAX_ORDERS>;

    /// A helper to print the number of constraints in the circuit
    ///
    /// Useful when benchmarking the circuit
    #[test]
    #[ignore]
    fn test_n_constraints() {
        let layout = ValidCommitments::<
            { constants::MAX_BALANCES },
            { constants::MAX_ORDERS },
        >::get_circuit_layout()
        .unwrap();

        let n_gates = layout.n_gates;
        let circuit_size = layout.circuit_size();
        println!("Number of constraints: {n_gates}");
        println!("Next power of two: {circuit_size}");
    }

    // --------------
    // | Test Cases |
    // --------------

    /// Tests that `VALID REBLIND` and `VALID COMMITMENTS` layout their shared
    /// linking group in the same way
    #[test]
    fn test_reblind_commitments_layout() {
        let commitments_layout = SizedValidCommitments::get_circuit_layout().unwrap();
        let reblind_layout = SizedValidReblind::get_circuit_layout().unwrap();

        let commitments_link = commitments_layout.get_group_layout(VALID_REBLIND_COMMITMENTS_LINK);
        let reblind_link = reblind_layout.get_group_layout(VALID_REBLIND_COMMITMENTS_LINK);

        assert_eq!(commitments_link, reblind_link);
    }

    /// Tests that `VALID COMMITMENTS` and `VALID MATCH SETTLE` layout their
    /// shared groups in the same way
    #[test]
    fn test_commitments_match_settle_layout() {
        let commitments_layout = SizedValidCommitments::get_circuit_layout().unwrap();
        let match_settle_layout = SizedValidMatchSettle::get_circuit_layout().unwrap();

        let comm_link0 = commitments_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK0);
        let comm_link1 = commitments_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK1);

        let match_link0 =
            match_settle_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK0);
        let match_link1 =
            match_settle_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK1);

        assert_eq!(comm_link0, match_link0);
        assert_eq!(comm_link1, match_link1);
    }

    /// Tests that the constraints may be satisfied by a valid witness
    /// and statement pair
    #[test]
    fn test_valid_commitments() {
        let wallet = INITIAL_WALLET.clone();
        let (witness, statement) = create_witness_and_statement(&wallet);

        assert!(check_constraint_satisfaction::<SizedCommitments>(&witness, &statement))
    }

    /// Tests the case in which an augmented balance must be added
    #[test]
    fn test_valid_commitments__valid_augmentation() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, statement) = create_witness_and_statement(&wallet);

        assert!(check_constraint_satisfaction::<SizedCommitments>(&witness, &statement))
    }

    /// Test the case in which a prover charges a lower fee than the wallet's
    /// configured maximum
    #[test]
    fn test_valid_commitments__valid_augmentation__lower_fee() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Prover charges a lower fee than the wallet's configured maximum
        let max_fee = witness.relayer_fee.to_f64();
        let new_fee = FixedPoint::from_f64_round_down(max_fee / 2.);
        witness.relayer_fee = new_fee;

        assert!(check_constraint_satisfaction::<SizedCommitments>(&witness, &statement))
    }

    // ------------------------
    // | Invalid Augmentation |
    // ------------------------

    /// Tests the case in which the prover attempts to add a non-zero balance to
    /// the augmented wallet
    #[test]
    fn test_invalid_commitment__augmented_nonzero_balance() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Prover attempt to augment the wallet with a non-zero balance
        let augmented_balance_index = statement.indices.balance_receive;
        witness.augmented_public_shares.balances[augmented_balance_index].amount += Scalar::one();
        witness.balance_receive.amount += 1u128;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests the case in which the prover clobbers a non-zero balance to
    /// augment the wallet
    #[test]
    fn test_invalid_commitment__augmentation_clobbers_balance() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Reset the original wallet such that the augmented balance was non-zero
        let augmentation_index = statement.indices.balance_receive;
        witness.public_secret_shares.balances[augmentation_index] = BalanceShare {
            amount: Scalar::one(),
            mint: Scalar::one(),
            protocol_fee_balance: Scalar::one(),
            relayer_fee_balance: Scalar::one(),
        };

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement))
    }

    /// Tests the case in which a prover attempts to modify an order in the
    /// augmented wallet
    #[test]
    fn test_invalid_commitment__augmentation_modifies_order() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify an order in the augmented wallet
        witness.augmented_public_shares.orders[1].amount += Scalar::one();

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Test the case in which a prover attempts to modify a fee in the
    /// augmented wallet
    #[test]
    fn test_invalid_commitment__augmentation_modifies_fee_balance() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify a relayer fee balance in the augmented wallet
        witness.augmented_public_shares.balances[1].relayer_fee_balance += Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));

        // Modify a protocol fee balance in the augmented wallet
        let (mut witness, statement) = create_witness_and_statement(&wallet);
        witness.augmented_public_shares.balances[1].protocol_fee_balance += Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Test the case in which a prover attempts to modify wallet keys and
    /// blinders in augmentation
    #[test]
    fn test_invalid_commitment__augmentation_modifies_keys() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (original_witness, statement) = create_witness_and_statement(&wallet);

        // Modify a key in the wallet
        let mut witness = original_witness.clone();
        witness.augmented_public_shares.keys.pk_match.key = Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));

        // Modify the nonce in the keychain, constraints should fail
        let mut witness = original_witness.clone();
        witness.augmented_public_shares.keys.nonce += Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Test the case in which a prover attempts to modify the match fee in an
    /// augmentation
    #[test]
    fn test_invalid_commitment__augmentation_modifies_match_fee() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the match fee in the wallet
        let mut rng = thread_rng();
        witness.augmented_public_shares.max_match_fee =
            FixedPointShare { repr: Scalar::random(&mut rng) };
        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests the case in which the prover provides an incorrect relayer fee in
    /// the witness
    #[test]
    fn test_invalid_commitments__higher_fee() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the relayer fee in the witness
        witness.relayer_fee.repr += Scalar::one(); // one above the configured maximum
        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Test the case in which a prover attempts to modify the managing cluster
    /// in an augmentation
    #[test]
    fn test_invalid_commitment__augmentation_modifies_cluster() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the managing cluster in the wallet
        witness.augmented_public_shares.managing_cluster.x += Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Test the case in which a prover attempts to modify the blinder in
    /// augmentation
    #[test]
    fn test_invalid_commitment__augmentation_modifies_blinder() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the wallet blinder
        witness.augmented_public_shares.blinder += Scalar::one();
        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement))
    }

    // -------------------
    // | Invalid Indices |
    // -------------------

    /// Test the case in which the index of the send balance is incorrect
    #[test]
    fn test_invalid_commitment__invalid_send_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the send balance
        statement.indices.balance_send += 1;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement))
    }

    /// Test the case in which the index of the receive balance is incorrect
    #[test]
    fn test_invalid_commitment__invalid_receive_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the send balance
        statement.indices.balance_receive += 1;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement))
    }

    /// Test the case in which the index of the matched order is incorrect
    #[test]
    fn test_invalid_commitment__invalid_order_index() {
        let wallet = UNAUGMENTED_WALLET.clone();
        let (witness, mut statement) = create_witness_and_statement(&wallet);

        // Modify the index of the order
        statement.indices.order += 1;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement))
    }

    // --------------------
    // | Invalid Balances |
    // --------------------

    /// Test the case in which a balance is missing from the wallet
    #[test]
    fn test_invalid_commitment__send_balance_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the send balance from the order
        let default_balance_share = BalanceShare {
            mint: Scalar::zero(),
            amount: Scalar::zero(),
            protocol_fee_balance: Scalar::zero(),
            relayer_fee_balance: Scalar::zero(),
        };
        witness.public_secret_shares.balances[statement.indices.balance_send] =
            default_balance_share.clone();
        witness.augmented_public_shares.balances[statement.indices.balance_send] =
            default_balance_share;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests the case in which the send balance has the wrong mint
    #[test]
    fn test_invalid_commitment__send_balance_wrong_mint() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the mint of the send balance
        witness.balance_send.mint = Address::from(rng.next_u64());

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests the case in which the send balance has zero amount
    #[test]
    fn test_invalid_commitment__send_balance_zero_amount() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the amount of the send balance
        witness.balance_send.amount = 0;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Test the case in which the receive balance is missing from the wallet
    #[test]
    fn test_invalid_commitment__receive_balance_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the receive balance from the order
        let default_balance_share = BalanceShare {
            mint: Scalar::zero(),
            amount: Scalar::zero(),
            protocol_fee_balance: Scalar::zero(),
            relayer_fee_balance: Scalar::zero(),
        };
        witness.public_secret_shares.balances[statement.indices.balance_receive] =
            default_balance_share.clone();
        witness.augmented_public_shares.balances[statement.indices.balance_receive] =
            default_balance_share;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests the case in which the receive balance has the wrong mint
    #[test]
    fn test_invalid_commitment__receive_balance_wrong_mint() {
        let mut rng = thread_rng();
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the mint of the receive balance
        witness.balance_receive.mint = Address::from(rng.next_u64());

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests the case in which the augmented receive balance created a
    /// duplicate mint
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_invalid_commitment__receive_balance_duplicate_mint() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        assert!(MAX_BALANCES == 2, "update this test to correctly modify a different balance");
        let bal_idx = statement.indices.balance_receive;
        let other_bal_idx = 1 - bal_idx;

        // Modify the receive balance to have been augmented with a duplicate mint
        let private_balance = witness.private_secret_shares.balances[bal_idx].clone();
        let public_balance = witness.public_secret_shares.balances[bal_idx].clone();

        witness.private_secret_shares.balances[other_bal_idx] = private_balance.clone();
        witness.public_secret_shares.balances[other_bal_idx] = public_balance.clone();
        witness.augmented_public_shares.balances[other_bal_idx] = public_balance;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Test the case in which the order is missing from the wallet
    #[test]
    fn test_invalid_commitment__order_missing() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify both public and private shares to give a correct blinding of a default
        // order, this ensures that other constraints (e.g. boolean constraints
        // on order side) are still satisfied, thereby isolating the missing
        // order constraint
        let blinder = witness.private_secret_shares.blinder + witness.public_secret_shares.blinder;
        let private_order = OrderShare {
            quote_mint: Scalar::zero(),
            base_mint: Scalar::zero(),
            side: Scalar::zero(),
            amount: Scalar::zero(),
            worst_case_price: FixedPointShare { repr: Scalar::zero() },
        };

        let private_order = private_order.clone();
        witness.private_secret_shares.orders[statement.indices.order] = private_order.clone();

        let public_order = private_order.blind(blinder);
        witness.public_secret_shares.orders[statement.indices.order] = public_order.clone();
        witness.augmented_public_shares.orders[statement.indices.order] = public_order;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests an invalid order with the base mint zero
    #[test]
    fn test_invalid_commitment__order_base_mint_zero() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the amount of the order
        witness.order.base_mint = Address::from(0u8);

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests an invalid order with the quote mint zero
    #[test]
    fn test_invalid_commitment__order_quote_mint_zero() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the quote mint of the order
        witness.order.quote_mint = Address::from(0u8);

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }

    /// Tests an invalid order with the amount zero
    #[test]
    fn test_invalid_commitment__order_amount_zero() {
        let wallet = INITIAL_WALLET.clone();
        let (mut witness, statement) = create_witness_and_statement(&wallet);

        // Modify the amount of the order
        witness.order.amount = 0;

        assert!(!check_constraint_satisfaction::<SizedCommitments>(&witness, &statement));
    }
}
