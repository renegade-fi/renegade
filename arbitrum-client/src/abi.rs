//! Solidity ABI definitions of smart contracts, events, and other on-chain
//! data structures used by the Arbitrum client.
#![allow(missing_docs)]

use alloy_sol_types::sol;
use ethers::contract::abigen;

#[cfg(not(feature = "integration"))]
abigen!(
    DarkpoolContract,
    r#"[
        function isNullifierSpent(bytes memory nullifier) external view returns (bool)
        function getRoot() external view returns (bytes)
        function rootInHistory(bytes memory root) external view returns (bool)

        function newWallet(bytes memory wallet_blinder_share, bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external
        function updateWallet(bytes memory wallet_blinder_share, bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory public_inputs_signature) external
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_0_valid_commitments_proof, bytes memory party_0_valid_reblind_proof, bytes memory party_1_match_payload, bytes memory party_1_valid_commitments_proof, bytes memory party_1_valid_reblind_proof, bytes memory valid_match_settle_proof, bytes memory valid_match_settle_statement_bytes,) external

        event WalletUpdated(bytes indexed wallet_blinder_share)
        event NodeChanged(uint8 indexed height, uint128 indexed index, bytes indexed new_value_hash, bytes new_value)
        event NullifierSpent(uint256 nullifier)
    ]"#
);

/// This ABI represents the Darkpool testing contract,
/// which contains all the same methods as the Darkpool (from which it
/// inherits), but also exposes some additional methods for testing purposes.
#[cfg(feature = "integration")]
abigen!(
    DarkpoolContract,
    r#"[
        function isNullifierSpent(bytes memory nullifier) external view returns (bool)
        function getRoot() external view returns (bytes)
        function rootInHistory(bytes memory root) external view returns (bool)

        function newWallet(bytes memory wallet_blinder_share, bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external
        function updateWallet(bytes memory wallet_blinder_share, bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory public_inputs_signature) external
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_0_valid_commitments_proof, bytes memory party_0_valid_reblind_proof, bytes memory party_1_match_payload, bytes memory party_1_valid_commitments_proof, bytes memory party_1_valid_reblind_proof, bytes memory valid_match_settle_proof, bytes memory valid_match_settle_statement_bytes,) external

        event WalletUpdated(bytes indexed wallet_blinder_share)
        event NodeChanged(uint8 indexed height, uint128 indexed index, bytes indexed new_value_hash, bytes new_value)
        event NullifierSpent(uint256 nullifier)


        function clearMerkle() external
    ]"#
);

sol! {
    function newWallet(bytes memory wallet_blinder_share, bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external;
    function updateWallet(bytes memory wallet_blinder_share, bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory public_inputs_signature) external;
    function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_0_valid_commitments_proof, bytes memory party_0_valid_reblind_proof, bytes memory party_1_match_payload, bytes memory party_1_valid_commitments_proof, bytes memory party_1_valid_reblind_proof, bytes memory valid_match_settle_proof, bytes memory valid_match_settle_statement_bytes,) external;
}
