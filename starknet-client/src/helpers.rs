//! Various helpers for Starknet client execution

use circuit_types::{traits::BaseType, SizedWalletShare};
use mpc_stark::algebra::scalar::Scalar;
use renegade_crypto::fields::{starknet_felt_to_scalar, starknet_felt_to_usize};
use starknet::core::types::FieldElement as StarknetFieldElement;
use tracing::log;

use crate::{
    types::{CalldataDeserializable, MatchPayload},
    NEW_WALLET_SELECTOR,
};

use super::{error::StarknetClientError, MATCH_SELECTOR, UPDATE_WALLET_SELECTOR};

/// The index of the `party0_public_blinder_share` argument in `match` calldata
const MATCH_PARTY0_PUBLIC_BLINDER_SHARE_IDX: usize = 0;
/// The index of the `public_wallet_share_len` argument in `new_wallet` calldata
const NEW_WALLET_SHARE_LEN_IDX: usize = 2;
/// The index of the `external_transfers_len` argument in `update_wallet`
/// calldata
const UPDATE_WALLET_SHARE_LEN_IDX: usize = 3;

/// Error message emitted when a public blinder share is not found in calldata
const ERR_BLINDER_NOT_FOUND: &str = "public blinder share not found in calldata";
/// Error message emitted when an invalid selector is given in the transaction's
/// execution trace
const ERR_INVALID_SELECTOR: &str = "invalid selector received";

// --------------------
// | Calldata Parsing |
// --------------------

// InvokeV1 calldata is structured as follows:
//  0: `call_array_len`
//  1..4:
//      1: `contract_addr`
//      2: `selector`
//      3. `data_offset`
//      4. `data_len`
//  ... for `call_array_len` elements
//  `calldata_array_len` * 4 + 1: `calldata_len`
//  ... `raw_calldata`
/// The index of the `call_array_len` argument in InvokeV1 calldata
const CALL_ARRAY_LEN_IDX: usize = 0;
/// The length of each call array element's metadata in InvokeV1 calldata
const CALL_ARRAY_ELEMENT_METADATA_LEN: usize = 4;
/// The index of the contract address argument in a call array element's
/// metadata
const CALL_ARRAY_CONTRACT_ADDR_IDX: usize = 0;
/// The index of the selector argument in a call array element's metadata
const CALL_ARRAY_SELECTOR_IDX: usize = 1;
/// The index of the data offset argument in a call array element's metadata
const CALL_ARRAY_DATA_OFFSET_IDX: usize = 2;
/// The index of the data length argument in a call array element's metadata
const CALL_ARRAY_DATA_LEN_IDX: usize = 3;

/// Parses the first darkpool transaction in a call array
///
/// n.b. It is generally assumed that only one darkpool transaction exists in a
/// given call array, and the caller should take care to ensure this is the case
///
/// Returns the selector and calldata of the first darkpool transaction found
pub(crate) fn parse_first_darkpool_transaction(
    tx_call_array: Vec<StarknetFieldElement>,
    darkpool_contract_addr: &StarknetFieldElement,
) -> Option<(StarknetFieldElement, Vec<StarknetFieldElement>)> {
    // Parse the number of calls in the call array
    let n_calls = starknet_felt_to_usize(&tx_call_array[CALL_ARRAY_LEN_IDX]);

    // Find the first renegade transaction in the call array metadata
    let metadata_start = CALL_ARRAY_LEN_IDX + 1;
    let metadata_end = metadata_start + (n_calls * CALL_ARRAY_ELEMENT_METADATA_LEN);

    let (selector, data_offset, data_len) = find_first_darkpool_transaction(
        &tx_call_array[metadata_start..metadata_end],
        darkpool_contract_addr,
    )?;

    // Parse the calldata of the transaction
    let calldata_len_idx = metadata_end;
    let calldata_start = calldata_len_idx + 1;
    let calldata = tx_call_array[calldata_start..].to_vec();
    let darkpool_calldata = calldata[data_offset..(data_offset + data_len)].to_vec();

    Some((selector, darkpool_calldata))
}

/// Finds the first darkpool transaction and returns the selector, the
/// data offset, and the data length
fn find_first_darkpool_transaction(
    call_array_metadata: &[StarknetFieldElement],
    darkpool_contract_addr: &StarknetFieldElement,
) -> Option<(StarknetFieldElement, usize, usize)> {
    let mut cursor = 0;
    while cursor < call_array_metadata.len() {
        let contract_addr = call_array_metadata[cursor + CALL_ARRAY_CONTRACT_ADDR_IDX];
        let selector = call_array_metadata[cursor + CALL_ARRAY_SELECTOR_IDX];
        let data_offset = call_array_metadata[cursor + CALL_ARRAY_DATA_OFFSET_IDX];
        let data_len = call_array_metadata[cursor + CALL_ARRAY_DATA_LEN_IDX];

        if contract_addr == *darkpool_contract_addr {
            return Some((
                selector,
                starknet_felt_to_usize(&data_offset),
                starknet_felt_to_usize(&data_len),
            ));
        }

        cursor += CALL_ARRAY_ELEMENT_METADATA_LEN;
    }

    None
}

// -----------------
// | Share Parsing |
// -----------------

/// Parse wallet public secret shares from the calldata of a transaction based
/// on the selector invoked
///
/// Accept the public blinder share to disambiguate for transactions that update
/// two sets of secret shares in their calldata
pub(super) fn parse_shares_from_calldata(
    selector: StarknetFieldElement,
    calldata: &[StarknetFieldElement],
    public_blinder_share: StarknetFieldElement,
) -> Result<SizedWalletShare, StarknetClientError> {
    let scalar_blob = match selector {
        _ if selector == *NEW_WALLET_SELECTOR => parse_shares_from_new_wallet(calldata)?,
        _ if selector == *UPDATE_WALLET_SELECTOR => parse_shares_from_update_wallet(calldata)?,
        _ if selector == *MATCH_SELECTOR => {
            parse_shares_from_match(public_blinder_share, calldata)?
        },
        _ => {
            log::error!("invalid selector received: {selector}");
            return Err(StarknetClientError::NotFound(ERR_INVALID_SELECTOR.to_string()));
        },
    };

    // Convert to scalars and re-structure into a wallet share
    Ok(SizedWalletShare::from_scalars(&mut scalar_blob.into_iter()))
}

/// Parse wallet public shares from the calldata of a `new_wallet` transaction
fn parse_shares_from_new_wallet(
    calldata: &[StarknetFieldElement],
) -> Result<Vec<Scalar>, StarknetClientError> {
    Vec::<Scalar>::from_calldata(&mut calldata[NEW_WALLET_SHARE_LEN_IDX..].iter().copied())
}

/// Parse wallet public shares from the calldata of an `update_wallet`
/// transaction
fn parse_shares_from_update_wallet(
    calldata: &[StarknetFieldElement],
) -> Result<Vec<Scalar>, StarknetClientError> {
    Vec::<Scalar>::from_calldata(&mut calldata[UPDATE_WALLET_SHARE_LEN_IDX..].iter().copied())
}

/// Parse wallet public shares from the calldata of a `match` transaction
///
/// The calldata for `process_match` begins with two `MatchPayload` objects, one
/// for each party. We check the first one, the first element of which is the
/// public blinder share of the party; if it matches the desired share, we parse
/// public shares from the first match payload, otherwise we seek past the first
/// match payload to the second
fn parse_shares_from_match(
    public_blinder_share: StarknetFieldElement,
    calldata: &[StarknetFieldElement],
) -> Result<Vec<Scalar>, StarknetClientError> {
    let cursor = MATCH_PARTY0_PUBLIC_BLINDER_SHARE_IDX;

    // Parse two match payloads, one for each party
    let mut calldata_iter = calldata[cursor..].iter().copied();
    let party0_payload = MatchPayload::from_calldata(&mut calldata_iter)?;
    let party1_payload = MatchPayload::from_calldata(&mut calldata_iter)?;

    let target_share = starknet_felt_to_scalar(&public_blinder_share);
    if party0_payload.wallet_blinder_share == target_share {
        Ok(party0_payload.public_wallet_shares)
    } else if party1_payload.wallet_blinder_share == target_share {
        Ok(party1_payload.public_wallet_shares)
    } else {
        Err(StarknetClientError::NotFound(ERR_BLINDER_NOT_FOUND.to_string()))
    }
}
