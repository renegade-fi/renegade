//! Solidity ABI definitions of smart contracts, events, and other on-chain
//! data structures used by the darkpool client.
#![allow(missing_docs)]
#![allow(unused_doc_comments)]
#![allow(clippy::too_many_arguments)]

use alloy::consensus::constants::SELECTOR_LEN;
use alloy_sol_types::{sol, SolCall};
use Darkpool::*;

sol! {
    #[sol(rpc)]
    contract Darkpool {
        function isNullifierSpent(uint256 memory nullifier) external view returns (bool);
        function isPublicBlinderUsed(uint256 memory blinder) external view returns (bool);
        function getRoot() external view returns (uint256);
        function getFee() external view returns (uint256);
        function getExternalMatchFeeForAsset(address memory asset) external view returns (uint256);
        function getPubkey() external view returns (uint256[2]);
        function getProtocolExternalFeeCollectionAddress() external view returns (address);
        function rootInHistory(uint256 memory root) external view returns (bool);

        function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external;
        function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory wallet_commitment_signature, bytes memory transfer_aux_data) external;
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs,) external;
        function processAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
        function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
        function processMalleableAtomicMatchSettle(uint256 quote_amount, uint256 base_amount, bytes memory internal_party_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
        function processMalleableAtomicMatchSettleWithReceiver(uint256 quote_amount, uint256 base_amount, address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
        function settleOnlineRelayerFee(bytes memory proof, bytes memory valid_relayer_fee_settlement_statement, bytes memory relayer_wallet_commitment_signature) external;
        function settleOfflineFee(bytes memory proof, bytes memory valid_offline_fee_settlement_statement) external;
        function redeemFee(bytes memory proof, bytes memory valid_fee_redemption_statement, bytes memory recipient_wallet_commitment_signature) external;

        event NullifierSpent(uint256 indexed nullifier);
        event WalletUpdated(uint256 indexed wallet_blinder_share);
        event MerkleOpeningNode(uint8 indexed height, uint128 indexed index, uint256 indexed new_value);
        event MerkleInsertion(uint128 indexed index, uint256 indexed value);
        event NotePosted(uint256 indexed note_commitment);

        // Only available in the integration testing contract
        function clearMerkle() external;
    }
}

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
