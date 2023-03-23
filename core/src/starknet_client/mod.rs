//! Provides a wrapper around the starknet_core clients that holds node
//! specific information (keys, api credentials, etc) and provides a cleaner
//! interface for interacting with on-chain state in Renegade specific patterns

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use starknet::core::{types::FieldElement as StarknetFieldElement, utils::get_selector_from_name};

pub mod client;
pub mod error;

// -------------
// | Selectors |
// -------------

lazy_static! {
    /// The event selector for internal node changes
    pub static ref INTERNAL_NODE_CHANGED_EVENT_SELECTOR: StarknetFieldElement =
        get_selector_from_name("Merkle_internal_node_changed").unwrap();
    /// The event selector for Merkle value insertion
    pub static ref VALUE_INSERTED_EVENT_SELECTOR: StarknetFieldElement =
        get_selector_from_name("Merkle_value_inserted").unwrap();
}

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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "goerli" {
            Ok(Self::AlphaGoerli)
        } else if s == "mainnet" {
            Ok(Self::Mainnet)
        } else {
            Err(format!("unknown chain ID {s}"))
        }
    }
}
