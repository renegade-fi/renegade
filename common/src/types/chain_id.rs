//! Defines Starknet chain IDs

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use starknet::core::{
    types::FieldElement as StarknetFieldElement, utils::cairo_short_string_to_felt,
};

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

/// Starknet devnet chain-id
pub const STARKNET_DEVNET_ID: StarknetFieldElement = STARKNET_TESTNET_ID;

/// A chain identifier used to decide chain-specific behaviors
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub enum ChainId {
    /// Starknet's alpha-goerli testnet chain
    #[serde(rename = "goerli")]
    AlphaGoerli,
    /// Starknet mainnet
    #[serde(rename = "mainnet")]
    Mainnet,
    /// A locally hosted devnet node
    #[serde(rename = "devnet")]
    Devnet,
    /// A Katana devnet node at `localhost:5050`
    #[serde(rename = "katana")]
    Katana,
}

impl From<ChainId> for StarknetFieldElement {
    fn from(chain_id: ChainId) -> StarknetFieldElement {
        match chain_id {
            ChainId::AlphaGoerli => STARKNET_TESTNET_ID,
            ChainId::Mainnet => STARKNET_MAINNET_ID,
            ChainId::Devnet => STARKNET_DEVNET_ID,
            ChainId::Katana => cairo_short_string_to_felt("KATANA").unwrap(),
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
        } else if s == "devnet" {
            Ok(Self::Devnet)
        } else if s == "katana" {
            Ok(Self::Katana)
        } else {
            Err(format!("unknown chain ID {s}"))
        }
    }
}
