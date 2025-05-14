//! Represents a chain environment

use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

/// The chain environment
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Chain {
    /// The Arbitrum Sepolia chain
    ArbitrumSepolia,
    /// The Arbitrum One chain
    ArbitrumOne,
    /// The Base Sepolia chain
    BaseSepolia,
    /// The Base Mainnet chain
    BaseMainnet,
    /// Any local devnet chain
    Devnet,
}

impl Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::ArbitrumSepolia => write!(f, "arbitrum-sepolia"),
            Chain::ArbitrumOne => write!(f, "arbitrum-one"),
            Chain::BaseSepolia => write!(f, "base-sepolia"),
            Chain::BaseMainnet => write!(f, "base-mainnet"),
            Chain::Devnet => write!(f, "devnet"),
        }
    }
}

impl FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "arbitrum-sepolia" => Ok(Chain::ArbitrumSepolia),
            "arbitrum-one" => Ok(Chain::ArbitrumOne),
            "base-sepolia" => Ok(Chain::BaseSepolia),
            "base-mainnet" => Ok(Chain::BaseMainnet),
            "devnet" => Ok(Chain::Devnet),
            _ => Err(format!("Invalid chain: {s}")),
        }
    }
}
