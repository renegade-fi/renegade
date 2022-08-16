pub mod constants;
pub mod gadgets;
pub mod poseidon;
pub mod types;
pub mod wallet_match;

/**
 * Constants
 */
pub const MAX_ORDERS: usize = 20;
pub const MAX_BALANCES: usize = 20;
pub const MAX_MATCHES: usize = MAX_ORDERS * MAX_ORDERS;
