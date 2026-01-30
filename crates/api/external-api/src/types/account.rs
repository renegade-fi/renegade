//! API types for account management

use serde::{Deserialize, Serialize};
use types_account::Account;
use uuid::Uuid;

use super::balance::ApiBalance;
use super::order::ApiOrder;

// --------------
// | Core Types |
// --------------

/// An account managed by the relayer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiAccount {
    /// The identifier used to index the wallet
    pub id: Uuid,
    /// A list of orders in this account
    pub orders: Vec<ApiOrder>,
    /// A list of balances in this account, keyed by token mint address
    pub balances: Vec<ApiBalance>,
}

#[cfg(feature = "full-api")]
impl From<Account> for ApiAccount {
    fn from(acct: Account) -> Self {
        let balances = acct.get_all_balances().into_iter().map(|balance| balance.into()).collect();
        let orders = acct.orders.into_values().map(|order| order.into()).collect();
        Self { id: acct.id, orders, balances }
    }
}
