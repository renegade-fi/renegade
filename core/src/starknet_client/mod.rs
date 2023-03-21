//! Provides a wrapper around the starknet_core clients that holds node
//! specific information (keys, api credentials, etc) and provides a cleaner
//! interface for interacting with on-chain state in Renegade specific patterns

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::error::Error as SerdeError;
use starknet::core::types::FieldElement as StarknetFieldElement;

pub mod client;

/// Starknet mainnet chain-id
/// TODO: use `starknet-rs` implementation once we upgrade versions
pub const STARKNET_MAINNET_ID: StarknetFieldElement = StarknetFieldElement::from_mont([
    17696389056366564951,
    18446744073709551615,
    18446744073709551615,
    502562008147966918,
]);

/// Starknet testnet chain-id
pub const STARKNET_TESTNET_ID: StarknetFieldElement = StarknetFieldElement::from_mont([
    3753493103916128178,
    18446744073709548950,
    18446744073709551615,
    398700013197595345,
]);

/// A chain identifier used to decide chain-specific behaviors
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum ChainId {
    /// Starknet's alpha-goerli testnet chain
    #[serde(rename = "goerli")]
    AlphaGoerli,
    /// Starknet mainnet
    #[serde(rename = "mainnet")]
    Mainnet,
}

impl From<ChainId> for StarknetFieldElement {
    fn from(chain_id: ChainId) -> StarknetFieldElement {
        match chain_id {
            ChainId::AlphaGoerli => STARKNET_TESTNET_ID,
            ChainId::Mainnet => STARKNET_MAINNET_ID,
        }
    }
}

impl FromStr for ChainId {
    type Err = SerdeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}
