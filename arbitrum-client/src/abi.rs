//! Solidity ABI definitions of smart contracts, events, and other on-chain
//! data structures used by the Arbitrum client.
#![allow(missing_docs)]
#![allow(unused_doc_comments)]

use alloy_sol_types::sol;
use ethers::contract::abigen;

#[cfg(not(feature = "integration"))]
abigen!(
    DarkpoolContract,
    r#"[
        function isNullifierSpent(uint256 memory nullifier) external view returns (bool)
        function isPublicBlinderUsed(uint256 memory blinder) external view returns (bool)
        function getRoot() external view returns (uint256)
        function getFee() external view returns (uint256)
        function getExternalMatchFeeForAsset(address memory asset) external view returns (uint256)function getPubkey() external view returns (uint256[2])
        function getProtocolExternalFeeCollectionAddress() external view returns (address)
        function rootInHistory(uint256 memory root) external view returns (bool)

        function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external
        function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory wallet_commitment_signature, bytes memory transfer_aux_data) external
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external
        function processAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external
        function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external
        function settleOnlineRelayerFee(bytes memory proof, bytes memory valid_relayer_fee_settlement_statement, bytes memory relayer_wallet_commitment_signature) external
        function settleOfflineFee(bytes memory proof, bytes memory valid_offline_fee_settlement_statement) external
        function redeemFee(bytes memory proof, bytes memory valid_fee_redemption_statement, bytes memory recipient_wallet_commitment_signature) external

        event WalletUpdated(uint256 indexed wallet_blinder_share)
        event MerkleOpeningNode(uint8 indexed height, uint128 indexed index, uint256 indexed new_value)
        event MerkleInsertion(uint128 indexed index, uint256 indexed value)
        event NullifierSpent(uint256 indexed nullifier)
        event NotePosted(uint256 indexed note_commitment)
    ]"#
);

/// This ABI represents the Darkpool testing contract,
/// which contains all the same methods as the Darkpool (from which it
/// inherits), but also exposes some additional methods for testing purposes.
#[cfg(feature = "integration")]
abigen!(
    DarkpoolContract,
    r#"[
        function isNullifierSpent(uint256 memory nullifier) external view returns (bool)
        function isPublicBlinderUsed(uint256 memory blinder) external view returns (bool)
        function getRoot() external view returns (uint256)
        function getFee() external view returns (uint256)
        function getExternalMatchFeeForAsset(address memory asset) external view returns (uint256)
        function getPubkey() external view returns (uint256[2])
        function getProtocolExternalFeeCollectionAddress() external view returns (address)
        function rootInHistory(uint256 memory root) external view returns (bool)

        function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external
        function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory wallet_commitment_signature, bytes memory transfer_aux_data) external
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external
        function processAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external
        function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external
        function settleOnlineRelayerFee(bytes memory proof, bytes memory valid_relayer_fee_settlement_statement, bytes memory relayer_wallet_commitment_signature) external
        function settleOfflineFee(bytes memory proof, bytes memory valid_offline_fee_settlement_statement) external
        function redeemFee(bytes memory proof, bytes memory valid_fee_redemption_statement, bytes memory recipient_wallet_commitment_signature) external

        event WalletUpdated(uint256 indexed wallet_blinder_share)
        event MerkleOpeningNode(uint8 indexed height, uint128 indexed index, uint256 indexed new_value)
        event MerkleInsertion(uint128 indexed index, uint256 indexed value)
        event NullifierSpent(uint256 indexed nullifier)
        event NotePosted(uint256 indexed note_commitment)

        function clearMerkle() external
    ]"#
);

sol! {
    function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external;
    function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory wallet_commitment_signature, bytes memory transfer_aux_data) external;
    function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs,) external;
    function processAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
    function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
    function settleOnlineRelayerFee(bytes memory proof, bytes memory valid_relayer_fee_settlement_statement, bytes memory relayer_wallet_commitment_signature) external;
    function settleOfflineFee(bytes memory proof, bytes memory valid_offline_fee_settlement_statement) external;
    function redeemFee(bytes memory proof, bytes memory valid_fee_redemption_statement, bytes memory recipient_wallet_commitment_signature) external;
}
