pub mod gadgets;
pub mod wallet_commit;

use crate::circuits::wallet_commit::{
    WalletVar
};

/**
 * Constants
 */
pub const MAX_ORDERS: usize = 20;
pub const MAX_BALANCES: usize = 20;
pub const MAX_MATCHES: usize = MAX_ORDERS * MAX_ORDERS;
