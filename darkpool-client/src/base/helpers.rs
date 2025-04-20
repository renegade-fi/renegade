//! Helpers for the Base darkpool implementation
//! Various helpers for darkpool client execution

use alloy::primitives::U256;
use alloy_sol_types::SolCall;
use circuit_types::{traits::BaseType, SizedWalletShare};
use constants::Scalar;
use util::matching_engine::apply_match_to_shares;

use crate::{
    conversion::{scalar_to_u256, u256_to_amount, u256_to_scalar},
    errors::DarkpoolClientError,
};

use super::conversion::ToCircuitType;

// ----------------
// | Parse Shares |
// ----------------

/// Parse a set of wallet shares from a `U256` vector
fn wallet_share_from_u256s(shares: Vec<U256>) -> SizedWalletShare {
    let mut shares = shares.into_iter().map(u256_to_scalar);
    SizedWalletShare::from_scalars(&mut shares)
}

/// Parses wallet shares from the calldata of a `newWallet` call
pub fn parse_shares_from_new_wallet(
    calldata: &[u8],
) -> Result<SizedWalletShare, DarkpoolClientError> {
    let call = createWalletCall::abi_decode(calldata)?;
    Ok(wallet_share_from_u256s(call.statement.publicShares))
}

/// Parses wallet shares from the calldata of an `updateWallet` call
pub fn parse_shares_from_update_wallet(
    calldata: &[u8],
) -> Result<SizedWalletShare, DarkpoolClientError> {
    let call = updateWalletCall::abi_decode(calldata)?;
    Ok(wallet_share_from_u256s(call.statement.newPublicShares))
}

/// Parses wallet shares from the calldata of a `processMatchSettle` call
pub fn parse_shares_from_process_match_settle(
    calldata: &[u8],
    public_blinder_share: Scalar,
) -> Result<SizedWalletShare, DarkpoolClientError> {
    let call = processMatchSettleCall::abi_decode(calldata)?;
    let party0_shares = &call.matchSettleStatement.firstPartyPublicShares;
    let party1_shares = &call.matchSettleStatement.secondPartyPublicShares;
    let party0_blinder = party0_shares.last().unwrap();
    let party1_blinder = party1_shares.last().unwrap();

    // Select the shares between the two parties
    let target_share = scalar_to_u256(public_blinder_share);
    let selected_shares = if party0_blinder == &target_share {
        party0_shares
    } else if party1_blinder == &target_share {
        party1_shares
    } else {
        return Err(DarkpoolClientError::BlinderNotFound);
    };

    Ok(wallet_share_from_u256s(selected_shares.clone()))
}

/// Parses wallet shares from the calldata of a `processAtomicMatchSettle` call
pub fn parse_shares_from_process_atomic_match_settle(
    calldata: &[u8],
) -> Result<SizedWalletShare, DarkpoolClientError> {
    let call = processAtomicMatchSettleCall::abi_decode(calldata)?;
    Ok(wallet_share_from_u256s(call.matchSettleStatement.internalPartyModifiedShares))
}

/// Parses wallet shares from the calldata of a
/// `processMalleableAtomicMatchSettle` call
pub fn parse_shares_from_process_malleable_atomic_match_settle(
    calldata: &[u8],
) -> Result<SizedWalletShare, DarkpoolClientError> {
    // Parse the pre-update shares from the calldata
    let call = processMalleableAtomicMatchSettleCall::abi_decode(calldata)?;
    let mut shares = wallet_share_from_u256s(call.matchSettleStatement.internalPartyPublicShares);

    // Update the shares with the match result
    let settlement_indices = call.internalPartyPayload.validCommitmentsStatement.indices;
    let indices = settlement_indices.to_circuit_type()?;

    // Compute the match result from the bounded match result and base amount
    let bounded_match = call.matchSettleStatement.matchResult.to_circuit_type()?;
    let base_amount = u256_to_amount(call.baseAmount)?;
    let external_match = bounded_match.to_external_match_result(base_amount);
    let (_, recv) = external_match.external_party_send();
    let side = external_match.internal_party_side();
    let match_res = external_match.to_match_result();

    // Compute the fees due by the internal party
    let fee_rate = call.matchSettleStatement.internalFeeRates.to_circuit_type()?;
    let fees = fee_rate.compute_fee_take(recv);

    // Apply the match to the wallet share
    apply_match_to_shares(&mut shares, &indices, fees, &match_res, side);
    Ok(shares)
}

/// Parses wallet shares from the calldata of a `settleOfflineFee` call
pub fn parse_shares_from_settle_offline_fee(
    calldata: &[u8],
) -> Result<SizedWalletShare, DarkpoolClientError> {
    let call = settleOfflineFeeCall::abi_decode(calldata)?;
    let shares = call.statement.updatedWalletPublicShares;
    Ok(wallet_share_from_u256s(shares))
}

/// Parses wallet shares from the calldata of a `redeemFee` call
pub fn parse_shares_from_redeem_fee(
    calldata: &[u8],
) -> Result<SizedWalletShare, DarkpoolClientError> {
    let call = redeemFeeCall::abi_decode(calldata)?;
    let shares = call.statement.newWalletPublicShares;
    Ok(wallet_share_from_u256s(shares))
}
