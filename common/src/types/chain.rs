//! Represents a chain environment

use std::{fmt::Display, str::FromStr};

use serde::{Deserialize, Serialize};

/// The chain environment
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Chain {
    /// Mainnet chain
    Mainnet,
    /// Testnet chain
    Testnet,
    /// Devnet chain
    Devnet,
}

impl Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Chain::Mainnet => write!(f, "mainnet"),
            Chain::Testnet => write!(f, "testnet"),
            Chain::Devnet => write!(f, "devnet"),
        }
    }
}

impl FromStr for Chain {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "mainnet" => Ok(Chain::Mainnet),
            "testnet" => Ok(Chain::Testnet),
            "devnet" => Ok(Chain::Devnet),
            _ => Err(format!("Invalid chain: {s}")),
        }
    }
}
