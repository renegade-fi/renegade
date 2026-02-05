//! Represents a chain environment

use std::{fmt::Display, str::FromStr};

use alloy::primitives::{Address, address};
use serde::{Deserialize, Serialize};

/// The chain environment
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum Chain {
    /// The Arbitrum Sepolia chain
    ArbitrumSepolia,
    /// The Arbitrum One chain
    ArbitrumOne,
    /// The Base Sepolia chain
    BaseSepolia,
    /// The Base Mainnet chain
    BaseMainnet,
    /// The Ethereum Sepolia chain
    EthereumSepolia,
    /// The Ethereum Mainnet chain
    EthereumMainnet,
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
            Chain::EthereumSepolia => write!(f, "ethereum-sepolia"),
            Chain::EthereumMainnet => write!(f, "ethereum-mainnet"),
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
            "ethereum-sepolia" => Ok(Chain::EthereumSepolia),
            "ethereum-mainnet" => Ok(Chain::EthereumMainnet),
            "devnet" => Ok(Chain::Devnet),
            _ => Err(format!("Invalid chain: {s}")),
        }
    }
}

impl Chain {
    /// Get the chain ID for this chain
    pub fn chain_id(&self) -> u64 {
        match self {
            Chain::ArbitrumSepolia => 421614,
            Chain::ArbitrumOne => 42161,
            Chain::BaseSepolia => 84532,
            Chain::BaseMainnet => 8453,
            Chain::EthereumSepolia => 11155111,
            Chain::EthereumMainnet => 1,
            Chain::Devnet => 31337,
        }
    }

    /// Get the Permit2 address for this chain
    pub fn permit2_addr(&self) -> Address {
        match self {
            Chain::ArbitrumSepolia => address!("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
            Chain::ArbitrumOne => address!("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
            Chain::BaseSepolia => address!("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
            Chain::BaseMainnet => address!("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
            Chain::EthereumSepolia => address!("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
            Chain::EthereumMainnet => address!("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
            Chain::Devnet => address!("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
        }
    }
}
