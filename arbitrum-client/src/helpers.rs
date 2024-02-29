//! Various helpers for Arbitrum client execution

use alloy_sol_types::SolCall;
use circuit_types::{traits::BaseType, SizedWalletShare};
use constants::Scalar;
use contracts_common::types::{
    ValidMatchSettleStatement as ContractValidMatchSettleStatement,
    ValidRelayerFeeSettlementStatement as ContractValidRelayerFeeSettlementStatement,
    ValidWalletCreateStatement as ContractValidWalletCreateStatement,
    ValidWalletUpdateStatement as ContractValidWalletUpdateStatement,
};
use ethers::{
    abi::Detokenize,
    contract::ContractCall,
    types::{Bytes, TransactionReceipt},
};
use serde::{Deserialize, Serialize};

use crate::{
    abi::{newWalletCall, processMatchSettleCall, settleOnlineRelayerFeeCall, updateWalletCall},
    client::SignerHttpProvider,
    errors::ArbitrumClientError,
};

/// Serializes a calldata element for a contract call
pub fn serialize_calldata<T: Serialize>(data: &T) -> Result<Bytes, ArbitrumClientError> {
    postcard::to_allocvec(data)
        .map(Bytes::from)
        .map_err(|e| ArbitrumClientError::Serde(e.to_string()))
}

/// Deserializes a return value from a contract call
pub fn deserialize_calldata<'de, T: Deserialize<'de>>(
    calldata: &'de Bytes,
) -> Result<T, ArbitrumClientError> {
    postcard::from_bytes(calldata).map_err(|e| ArbitrumClientError::Serde(e.to_string()))
}

/// Sends a transaction, awaiting its confirmation and returning the receipt
pub async fn send_tx(
    tx: ContractCall<SignerHttpProvider, impl Detokenize>,
) -> Result<TransactionReceipt, ArbitrumClientError> {
    tx.send()
        .await
        .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
        .await
        .map_err(|e| ArbitrumClientError::ContractInteraction(e.to_string()))?
        .ok_or(ArbitrumClientError::TxDropped)
}

/// Parses wallet shares from the calldata of a `newWallet` call
pub fn parse_shares_from_new_wallet(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = newWalletCall::decode(calldata, true /* validate */)
        .map_err(|e| ArbitrumClientError::Serde(e.to_string()))?;

    let statement = deserialize_calldata::<ContractValidWalletCreateStatement>(
        &call.valid_wallet_create_statement_bytes.into(),
    )?;

    let mut shares = statement.public_wallet_shares.into_iter().map(Scalar::new);

    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of an `updateWallet` call
pub fn parse_shares_from_update_wallet(
    calldata: &[u8],
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = updateWalletCall::decode(calldata, true /* validate */)
        .map_err(|e| ArbitrumClientError::Serde(e.to_string()))?;

    let statement = deserialize_calldata::<ContractValidWalletUpdateStatement>(
        &call.valid_wallet_update_statement_bytes.into(),
    )?;

    let mut shares = statement.new_public_shares.into_iter().map(Scalar::new);

    Ok(SizedWalletShare::from_scalars(&mut shares))
}

/// Parses wallet shares from the calldata of a `processMatchSettle` call
pub fn parse_shares_from_process_match_settle(
    calldata: &[u8],
    public_blinder_share: Scalar,
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = processMatchSettleCall::decode(calldata, true /* validate */)
        .map_err(|e| ArbitrumClientError::Serde(e.to_string()))?;

    let valid_match_settle_statement = deserialize_calldata::<ContractValidMatchSettleStatement>(
        &call.valid_match_settle_statement.into(),
    )?;

    // The blinder is expected to be the last public wallet share
    let party_0_public_blinder_share =
        valid_match_settle_statement.party0_modified_shares.last().unwrap();

    // The blinder is expected to be the last public wallet share
    let party_1_public_blinder_share =
        valid_match_settle_statement.party1_modified_shares.last().unwrap();

    let target_share = public_blinder_share.inner();
    if party_0_public_blinder_share == &target_share {
        let mut shares =
            valid_match_settle_statement.party0_modified_shares.into_iter().map(Scalar::new);

        Ok(SizedWalletShare::from_scalars(&mut shares))
    } else if party_1_public_blinder_share == &target_share {
        let mut shares =
            valid_match_settle_statement.party1_modified_shares.into_iter().map(Scalar::new);

        Ok(SizedWalletShare::from_scalars(&mut shares))
    } else {
        Err(ArbitrumClientError::BlinderNotFound)
    }
}

/// Parses wallet shares from the calldata of a `settleOnlineRelayerFee` call
pub fn parse_shares_from_settle_online_relayer_fee(
    calldata: &[u8],
    public_blinder_share: Scalar,
) -> Result<SizedWalletShare, ArbitrumClientError> {
    let call = settleOnlineRelayerFeeCall::decode(calldata, true /* validate */)
        .map_err(|e| ArbitrumClientError::Serde(e.to_string()))?;

    let valid_relayer_fee_settlement_statement =
        deserialize_calldata::<ContractValidRelayerFeeSettlementStatement>(
            &call.valid_relayer_fee_settlement_statement.into(),
        )?;

    // The blinder is expected to be the last public wallet share
    let sender_public_blinder_share =
        valid_relayer_fee_settlement_statement.sender_updated_public_shares.last().unwrap();

    // The blinder is expected to be the last public wallet share
    let recipient_public_blinder_share =
        valid_relayer_fee_settlement_statement.recipient_updated_public_shares.last().unwrap();

    let target_share = public_blinder_share.inner();
    if sender_public_blinder_share == &target_share {
        let mut shares = valid_relayer_fee_settlement_statement
            .sender_updated_public_shares
            .into_iter()
            .map(Scalar::new);

        Ok(SizedWalletShare::from_scalars(&mut shares))
    } else if recipient_public_blinder_share == &target_share {
        let mut shares = valid_relayer_fee_settlement_statement
            .recipient_updated_public_shares
            .into_iter()
            .map(Scalar::new);

        Ok(SizedWalletShare::from_scalars(&mut shares))
    } else {
        Err(ArbitrumClientError::BlinderNotFound)
    }
}
