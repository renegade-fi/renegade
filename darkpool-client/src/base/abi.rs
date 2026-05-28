//! Re-exports of the Base v1 darkpool's per-method selector constants.
//!
//! Parallels `darkpool-client::arbitrum::abi`. Base v1 has a smaller set of
//! callable methods than arbitrum v1 (no `*_with_receiver` variants, no
//! `settleOnlineRelayerFee`) — only the seven listed here.
//!
//! These come from `renegade_solidity_abi::v1::IDarkpool::*Call::SELECTOR`,
//! which is the canonical Solidity ABI. Keeping them named here so external
//! consumers (e.g. tools/redeem-v1-fees-onchain) don't need to take a direct
//! dep on `renegade-solidity-abi`.

use alloy::consensus::constants::SELECTOR_LEN;
use alloy_sol_types::SolCall;
use renegade_solidity_abi::v1::IDarkpool::{
    createWalletCall, processAtomicMatchSettleCall, processMalleableAtomicMatchSettleCall,
    processMatchSettleCall, redeemFeeCall, settleOfflineFeeCall, updateWalletCall,
};

/// Selector for `createWallet`.
pub const NEW_WALLET_SELECTOR: [u8; SELECTOR_LEN] = createWalletCall::SELECTOR;
/// Selector for `updateWallet`.
pub const UPDATE_WALLET_SELECTOR: [u8; SELECTOR_LEN] = updateWalletCall::SELECTOR;
/// Selector for `processMatchSettle`.
pub const PROCESS_MATCH_SETTLE_SELECTOR: [u8; SELECTOR_LEN] = processMatchSettleCall::SELECTOR;
/// Selector for `processAtomicMatchSettle`.
pub const PROCESS_ATOMIC_MATCH_SETTLE_SELECTOR: [u8; SELECTOR_LEN] =
    processAtomicMatchSettleCall::SELECTOR;
/// Selector for `processMalleableAtomicMatchSettle`.
pub const PROCESS_MALLEABLE_ATOMIC_MATCH_SETTLE_SELECTOR: [u8; SELECTOR_LEN] =
    processMalleableAtomicMatchSettleCall::SELECTOR;
/// Selector for `settleOfflineFee`.
pub const SETTLE_OFFLINE_FEE_SELECTOR: [u8; SELECTOR_LEN] = settleOfflineFeeCall::SELECTOR;
/// Selector for `redeemFee`.
pub const REDEEM_FEE_SELECTOR: [u8; SELECTOR_LEN] = redeemFeeCall::SELECTOR;
