//! Various helpers for Arbitrum client execution

use alloy::primitives::U256;
use alloy_sol_types::SolCall;
use circuit_types::{
    elgamal::{BabyJubJubPoint, ElGamalCiphertext},
    note::NOTE_CIPHERTEXT_SIZE,
    r#match::OrderSettlementIndices,
    traits::BaseType,
    Amount, SizedWalletShare,
};
use constants::Scalar;
use ethers::types::Bytes;
use serde::{Deserialize, Serialize};
use util::matching_engine::apply_match_to_shares;

use crate::{
    abi::{
        newWalletCall, processAtomicMatchSettleCall, processAtomicMatchSettleWithReceiverCall,
        processMalleableAtomicMatchSettleCall, processMalleableAtomicMatchSettleWithReceiverCall,
        processMatchSettleCall, redeemFeeCall, settleOfflineFeeCall, settleOnlineRelayerFeeCall,
        updateWalletCall,
    },
    contract_types::{
        MatchPayload, ValidFeeRedemptionStatement as ContractValidFeeRedemptionStatement,
        ValidMalleableMatchSettleAtomicStatement as ContractValidMalleableMatchSettleAtomicStatement,
        ValidMatchSettleAtomicStatement as ContractValidMatchSettleAtomicStatement,
        ValidMatchSettleStatement as ContractValidMatchSettleStatement,
        ValidOfflineFeeSettlementStatement as ContractValidOfflineFeeSettlementStatement,
        ValidRelayerFeeSettlementStatement as ContractValidRelayerFeeSettlementStatement,
        ValidWalletCreateStatement as ContractValidWalletCreateStatement,
        ValidWalletUpdateStatement as ContractValidWalletUpdateStatement,
    },
    conversion::{
        to_circuit_bounded_match_result, to_circuit_fee_rates, to_circuit_order_settlement_indices,
    },
    errors::ArbitrumClientError,
};

// ---------------------
// | (De)serialization |
// ---------------------

/// Serializes a calldata element for a contract call
pub fn serialize_calldata<T: Serialize>(data: &T) -> Result<Bytes, ArbitrumClientError> {
    postcard::to_allocvec(data)
        .map(Bytes::from)
        .map_err(|e| ArbitrumClientError::Serde(e.to_string()))
}

/// Deserializes a return value from a contract call
pub fn deserialize_calldata<'de, T: Deserialize<'de>>(
    calldata: &'de [u8],
) -> Result<T, ArbitrumClientError> {
    postcard::from_bytes(calldata).map_err(|e| ArbitrumClientError::Serde(e.to_string()))
}

// ----------------
// | Parse Shares |
// ----------------

/// Parses wallet shares from the calldata of a `newWallet` call
pub fn parse_shares_from_new_wallet(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = newWalletCall::abi_decode(calldata)?;

    let statement = deserialize_calldata::<ContractValidWalletCreateStatement>(
        &call.valid_wallet_create_statement_bytes,
    )?;

    let mut shares = statement.public_wallet_shares.into_iter().map(Scalar::new);

    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of an `updateWallet` call
pub fn parse_shares_from_update_wallet(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = updateWalletCall::abi_decode(calldata)?;

    let statement = deserialize_calldata::<ContractValidWalletUpdateStatement>(
        &call.valid_wallet_update_statement_bytes,
    )?;

    let mut shares = statement.new_public_shares.into_iter().map(Scalar::new);

    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of a `processMatchSettle` call
pub fn parse_shares_from_process_match_settle(
    calldata: &[u8],
    public_blinder_share: Scalar,
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = processMatchSettleCall::abi_decode(calldata)?;

    let valid_match_settle_statement = deserialize_calldata::<ContractValidMatchSettleStatement>(
        &call.valid_match_settle_statement,
    )?;

    let party_0_shares = valid_match_settle_statement.party0_modified_shares;
    // The blinder is expected to be the last public wallet share
    let party_0_blinder_share = party_0_shares.last().unwrap();

    let party_1_shares = valid_match_settle_statement.party1_modified_shares;
    // The blinder is expected to be the last public wallet share
    let party_1_blinder_share = party_1_shares.last().unwrap();

    let target_share = public_blinder_share.inner();
    let selected_shares = if party_0_blinder_share == &target_share {
        party_0_shares
    } else if party_1_blinder_share == &target_share {
        party_1_shares
    } else {
        return Err(ArbitrumClientError::BlinderNotFound);
    };

    let mut shares = selected_shares.into_iter().map(Scalar::new);
    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of a `processAtomicMatchSettle` call
pub fn parse_shares_from_process_atomic_match_settle(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = processAtomicMatchSettleCall::abi_decode(calldata)?;
    let statement = deserialize_calldata::<ContractValidMatchSettleAtomicStatement>(
        &call.valid_match_settle_atomic_statement,
    )?;

    let mut shares = statement.internal_party_modified_shares.into_iter().map(Scalar::new);
    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of a
/// `processAtomicMatchSettleWithReceiver` call
pub fn parse_shares_from_process_atomic_match_settle_with_receiver(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = processAtomicMatchSettleWithReceiverCall::abi_decode(calldata)?;
    let statement = deserialize_calldata::<ContractValidMatchSettleAtomicStatement>(
        &call.valid_match_settle_atomic_statement,
    )?;

    let mut shares = statement.internal_party_modified_shares.into_iter().map(Scalar::new);
    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of a
/// `processMalleableAtomicMatchSettle` call
pub fn parse_shares_from_process_malleable_atomic_match_settle(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    // Parse the pre-update shares from the calldata
    let call = processMalleableAtomicMatchSettleCall::abi_decode(calldata)?;
    let statement = deserialize_calldata::<ContractValidMalleableMatchSettleAtomicStatement>(
        &call.valid_match_settle_statement,
    )?;
    let mut shares = statement.internal_party_public_shares.clone().into_iter().map(Scalar::new);
    let mut wallet_share = SizedWalletShare::from_scalars(&mut shares);

    // Update the shares with the match result
    let validity_proofs = deserialize_calldata::<MatchPayload>(&call.internal_party_match_payload)?;
    let indices =
        to_circuit_order_settlement_indices(&validity_proofs.valid_commitments_statement.indices);
    apply_malleable_match_result_to_wallet_share(
        &mut wallet_share,
        call.base_amount,
        indices,
        &statement,
    )?;

    Ok(wallet_share)
}

/// Parses wallet shares from the calldata of a
/// `processMalleableAtomicMatchSettleWithReceiver` call
pub fn parse_shares_from_process_malleable_atomic_match_settle_with_receiver(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = processMalleableAtomicMatchSettleWithReceiverCall::abi_decode(calldata)?;
    let statement = deserialize_calldata::<ContractValidMalleableMatchSettleAtomicStatement>(
        &call.valid_match_settle_statement,
    )?;

    let mut shares = statement.internal_party_public_shares.clone().into_iter().map(Scalar::new);
    let mut wallet_share = SizedWalletShare::from_scalars(&mut shares);

    // Update the shares with the match result
    let validity_proofs = deserialize_calldata::<MatchPayload>(&call.internal_party_match_payload)?;
    let indices =
        to_circuit_order_settlement_indices(&validity_proofs.valid_commitments_statement.indices);
    apply_malleable_match_result_to_wallet_share(
        &mut wallet_share,
        call.base_amount,
        indices,
        &statement,
    )?;

    Ok(wallet_share)
}

/// Parses wallet shares from the calldata of a `settleOnlineRelayerFee` call
pub fn parse_shares_from_settle_online_relayer_fee(
    calldata: &[u8],
    public_blinder_share: Scalar,
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = settleOnlineRelayerFeeCall::abi_decode(calldata)?;

    let valid_relayer_fee_settlement_statement =
        deserialize_calldata::<ContractValidRelayerFeeSettlementStatement>(
            &call.valid_relayer_fee_settlement_statement,
        )?;

    let sender_shares = valid_relayer_fee_settlement_statement.sender_updated_public_shares;
    // The blinder is expected to be the last public wallet share
    let sender_blinder_share = sender_shares.last().unwrap();

    let recipient_shares = valid_relayer_fee_settlement_statement.recipient_updated_public_shares;
    // The blinder is expected to be the last public wallet share
    let recipient_blinder_share = recipient_shares.last().unwrap();

    let target_share = public_blinder_share.inner();
    let selected_shares = if sender_blinder_share == &target_share {
        sender_shares
    } else if recipient_blinder_share == &target_share {
        recipient_shares
    } else {
        return Err(ArbitrumClientError::BlinderNotFound);
    };

    let mut shares = selected_shares.into_iter().map(Scalar::new);
    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of a `settleOfflineFee` call
pub fn parse_shares_from_settle_offline_fee(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = settleOfflineFeeCall::abi_decode(calldata)?;

    let statement = deserialize_calldata::<ContractValidOfflineFeeSettlementStatement>(
        &call.valid_offline_fee_settlement_statement,
    )?;

    let mut shares = statement.updated_wallet_public_shares.into_iter().map(Scalar::new);

    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of a `redeemFee` call
pub fn parse_shares_from_redeem_fee(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = redeemFeeCall::abi_decode(calldata)?;

    let statement = deserialize_calldata::<ContractValidFeeRedemptionStatement>(
        &call.valid_fee_redemption_statement,
    )?;

    let mut shares = statement.new_wallet_public_shares.into_iter().map(Scalar::new);

    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parse a note from calldata of a `settleOfflineFee` call
pub fn parse_note_ciphertext_from_settle_offline_fee(
    calldata: &[u8],
) -> Result<ElGamalCiphertext<NOTE_CIPHERTEXT_SIZE>, ArbitrumClientError> {
    let call = settleOfflineFeeCall::abi_decode(calldata)?;

    let statement = deserialize_calldata::<ContractValidOfflineFeeSettlementStatement>(
        &call.valid_offline_fee_settlement_statement,
    )?;
    let cipher = statement.note_ciphertext;
    let key_encryption = BabyJubJubPoint { x: Scalar::new(cipher.0.x), y: Scalar::new(cipher.0.y) };
    let symmetric_ciphertext =
        [Scalar::new(cipher.1), Scalar::new(cipher.2), Scalar::new(cipher.3)];

    Ok(ElGamalCiphertext { ephemeral_key: key_encryption, ciphertext: symmetric_ciphertext })
}

// ---------------------
// | Malleable Matches |
// ---------------------

/// Apply a malleable match result to a wallet share
///
/// We replicate this logic in the relayer for simplicity, though we could
/// conceivably log these updated shares in the contract as well
pub fn apply_malleable_match_result_to_wallet_share(
    wallet_share: &mut SizedWalletShare,
    base_amount: U256,
    indices: OrderSettlementIndices,
    statement: &ContractValidMalleableMatchSettleAtomicStatement,
) -> Result<(), ArbitrumClientError> {
    let base_amt: Amount = base_amount.try_into().expect("base amount too large");

    // Compute the amounts traded
    let bounded_match = to_circuit_bounded_match_result(&statement.match_result)?;
    let external_match_res = bounded_match.to_external_match_result(base_amt);
    let match_res = external_match_res.to_match_result();

    // Compute the fees due by the internal party
    let (_, recv_amount) = external_match_res.external_party_send();
    let fees = to_circuit_fee_rates(&statement.internal_fee_rates)?;
    let fee_take = fees.compute_fee_take(recv_amount);

    // Apply the match to the wallet share
    let side = external_match_res.internal_party_side();
    apply_match_to_shares(wallet_share, &indices, fee_take, &match_res, side);
    Ok(())
}
