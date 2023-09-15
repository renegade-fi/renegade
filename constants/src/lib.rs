//! Defines system-wide constants for node execution

#![deny(unsafe_code)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(missing_docs)]

// -------------------------
// | System-Wide Constants |
// -------------------------

/// The system-wide value of MAX_BALANCES; the number of allowable balances a wallet holds
pub const MAX_BALANCES: usize = 5;

/// The system-wide value of MAX_ORDERS; the number of allowable orders a wallet holds
pub const MAX_ORDERS: usize = 5;

/// The system-wide value of MAX_FEES; the number of allowable fees a wallet holds
pub const MAX_FEES: usize = 2;

/// The height of the Merkle state tree used by the contract
pub const MERKLE_HEIGHT: usize = 32;

/// The number of historical roots the contract stores as being valid
pub const MERKLE_ROOT_HISTORY_LENGTH: usize = 30;

/// The percentage fee the protocol takes on each side of a match
pub const PROTOCOL_FEE: f64 = 0.0003; // 3 basis points

// ----------------------
// | Starknet Constants |
// ----------------------

/// The deployment block for the Mainnet contract
/// TODO: Update this once the contract is deployed
pub const MAINNET_CONTRACT_DEPLOYMENT_BLOCK: u64 = 780361;

/// The deployment block for the Goerli contract
pub const GOERLI_CONTRACT_DEPLOYMENT_BLOCK: u64 = 780361;

/// The deployment block for the devnet contract
pub const DEVNET_CONTRACT_DEPLOYMENT_BLOCK: u64 = 0;

// ----------------------
// | Pubsub Topic Names |
// ----------------------

/// The topic published to when the handshake manager begins a new
/// match computation with a peer
pub const HANDSHAKE_STATUS_TOPIC: &str = "handshakes";

/// The topic published to when a state change occurs on an order
pub const ORDER_STATE_CHANGE_TOPIC: &str = "order-state";
