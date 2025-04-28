//! Constant values referenced by the Arbitrum client.

use std::{fmt::Display, marker::PhantomData, str::FromStr};

use alloy_sol_types::SolCall;
use ark_ff::{BigInt, Fp};
use constants::{Scalar, MERKLE_HEIGHT};
use lazy_static::lazy_static;
use renegade_crypto::hash::compute_poseidon_hash;
use serde::{Deserialize, Serialize};

use crate::abi::Darkpool::{
    newWalletCall, processAtomicMatchSettleCall, processAtomicMatchSettleWithReceiverCall,
    processMalleableAtomicMatchSettleCall, processMalleableAtomicMatchSettleWithReceiverCall,
    processMatchSettleCall, redeemFeeCall, settleOfflineFeeCall, settleOnlineRelayerFeeCall,
    updateWalletCall,
};

/// The chain environment
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
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

/// A type alias for a selector
pub type Selector = [u8; SELECTOR_LEN];
/// The number of bytes in a Solidity function selector
pub const SELECTOR_LEN: usize = 4;
/// A list of known selectors for the darkpool contract
pub(crate) const KNOWN_SELECTORS: [[u8; SELECTOR_LEN]; 8] = [
    NEW_WALLET_SELECTOR,
    UPDATE_WALLET_SELECTOR,
    PROCESS_MATCH_SETTLE_SELECTOR,
    PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR,
    PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR,
    SETTLE_ONLINE_RELAYER_FEE_SELECTOR,
    SETTLE_OFFLINE_FEE_SELECTOR,
    REDEEM_FEE_SELECTOR,
];

/// Selector for `newWallet`
pub const NEW_WALLET_SELECTOR: [u8; SELECTOR_LEN] = newWalletCall::SELECTOR;
/// Selector for `updateWallet`
pub const UPDATE_WALLET_SELECTOR: [u8; SELECTOR_LEN] = updateWalletCall::SELECTOR;
/// Selector for `processMatchSettle`
pub const PROCESS_MATCH_SETTLE_SELECTOR: [u8; SELECTOR_LEN] = processMatchSettleCall::SELECTOR;
/// Selector for `processAtomicMatchSettle`
pub const PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR: [u8; SELECTOR_LEN] =
    processAtomicMatchSettleCall::SELECTOR;
/// Selector for `processAtomicMatchSettleWithReceiver`
pub const PROCESS_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR: [u8; SELECTOR_LEN] =
    processAtomicMatchSettleWithReceiverCall::SELECTOR;
/// Selector for `processMalleableAtomicMatchSettleWithReceiver`
pub const PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_WITH_RECEIVER_SELECTOR: [u8; SELECTOR_LEN] =
    processMalleableAtomicMatchSettleWithReceiverCall::SELECTOR;
/// Selector for `processMalleableAtomicMatchSettle`
pub const PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR: [u8; SELECTOR_LEN] =
    processMalleableAtomicMatchSettleCall::SELECTOR;
/// Selector for `settleOnlineRelayerFee`
pub const SETTLE_ONLINE_RELAYER_FEE_SELECTOR: [u8; SELECTOR_LEN] =
    settleOnlineRelayerFeeCall::SELECTOR;
/// Selector for `settleOfflineFee`
pub const SETTLE_OFFLINE_FEE_SELECTOR: [u8; SELECTOR_LEN] = settleOfflineFeeCall::SELECTOR;
/// Selector for `redeemFee`
pub const REDEEM_FEE_SELECTOR: [u8; SELECTOR_LEN] = redeemFeeCall::SELECTOR;

// The following are used for cases in which runtime type-based event filtering
// is not possible. In these cases, we must construct filters manually using ABI
// signatures

/// The abi signature for the `WalletUpdated` event
pub const WALLET_UPDATED_EVENT_NAME: &str = "WalletUpdated";
/// The abi signature for the `NullifierSpent` event
pub const NULLIFIER_SPENT_EVENT_NAME: &str = "NullifierSpent";
/// The interval at which to poll for pending transactions
pub const BLOCK_POLLING_INTERVAL_MS: u64 = 100;
/// The interval at which to poll for event filters
pub const EVENT_FILTER_POLLING_INTERVAL_MS: u64 = 7000;

lazy_static! {
    // ------------------------
    // | Merkle Tree Metadata |
    // ------------------------

    /// The value of an empty leaf in the Merkle tree,
    /// computed as the Keccak-256 hash of the string "renegade",
    /// reduced modulo the scalar field order when interpreted as a
    /// big-endian unsigned integer
    pub static ref EMPTY_LEAF_VALUE: Scalar = Scalar::new(Fp(
        BigInt([
            14542100412480080699,
            1005430062575839833,
            8810205500711505764,
            2121377557688093532,
        ]),
        PhantomData,
    ));

    /// The default values of an authentication path; i.e. the values in the path before any
    /// path elements are changed by insertions
    ///
    /// These values are simply recursive hashes of the empty leaf value, as this builds the
    /// empty tree
    pub static ref DEFAULT_AUTHENTICATION_PATH: [Scalar; MERKLE_HEIGHT] = {
        let mut values = Vec::with_capacity(MERKLE_HEIGHT);

        let mut curr_val = *EMPTY_LEAF_VALUE;
        for _ in 0..MERKLE_HEIGHT {
            values.push(curr_val);
            curr_val = compute_poseidon_hash(&[curr_val, curr_val]);
        }

        values.try_into().unwrap()
    };
}
