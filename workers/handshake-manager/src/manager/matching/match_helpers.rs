//! Helpers for matching orders

use circuit_types::{balance::Balance, fixed_point::FixedPoint, r#match::MatchResult, Amount};
use common::types::wallet::{Order, OrderIdentifier};
use util::matching_engine::match_orders_with_min_base_amount;

use crate::{error::HandshakeManagerError, manager::HandshakeExecutor};

/// A successful match between two orders
pub type SuccessfulMatch = (OrderIdentifier, MatchResult);

impl HandshakeExecutor {
    /// Run a match between two orders
    pub async fn find_match<I>(
        &self,
        order: &Order,
        balance: &Balance,
        price: FixedPoint,
        target_orders: I,
    ) -> Result<Option<SuccessfulMatch>, HandshakeManagerError>
    where
        I: IntoIterator<Item = OrderIdentifier>,
    {
        // Match against each other order in the local book
        for order_id in target_orders.into_iter() {
            // Lookup the other order and attempt to match with it
            let (order2, balance2) =
                match self.state.get_managed_order_and_balance(&order_id).await? {
                    Some((order, balance)) => (order, balance),
                    None => continue,
                };

            // If a match is successful, return the result
            let res = self.try_match(order, &order2, balance, &balance2, price);
            if let Some(match_result) = res {
                return Ok(Some((order_id, match_result)));
            }
        }

        Ok(None)
    }

    /// Try to match two orders, return the `MatchResult` if a match is found
    fn try_match(
        &self,
        o1: &Order,
        o2: &Order,
        b1: &Balance,
        b2: &Balance,
        price: FixedPoint,
    ) -> Option<MatchResult> {
        // Match the orders
        let min_base_amount = Amount::max(o1.min_fill_size, o2.min_fill_size);
        let min_quote_amount = self.min_fill_size;

        match_orders_with_min_base_amount(
            &o1.clone().into(),
            &o2.clone().into(),
            b1,
            b2,
            min_quote_amount,
            min_base_amount,
            price,
        )
    }
}
