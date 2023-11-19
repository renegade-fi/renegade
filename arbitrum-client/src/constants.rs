//! Constant values referenced by the Arbitrum client.

/// The chain environment
#[derive(Clone, Copy)]
pub enum Chain {
    /// Mainnet chain
    Mainnet,
    /// Testnet chain
    Testnet,
    /// Devnet chain
    Devnet,
}

/// The RPC url for a devnet chain
pub const DEVNET_RPC_URL: &str = "http://localhost:8547";
/// The RPC url for a testnet chain
pub const TESTNET_RPC_URL: &str = "https://stylus-testnet.arbitrum.io/rpc";

/// The block number at which the darkpool was deployed on devnet
pub const DEVNET_DEPLOY_BLOCK: u64 = 0;
/// The block number at which the darkpool was deployed on testnet
pub const TESTNET_DEPLOY_BLOCK: u64 = 604069;
