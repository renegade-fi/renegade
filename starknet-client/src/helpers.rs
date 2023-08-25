//! Various helpers for Starknet client execution

use std::convert::TryInto;

use circuit_types::{traits::BaseType, SizedWalletShare};
use renegade_crypto::fields::{starknet_felt_to_scalar, starknet_felt_to_usize};
use starknet::core::types::FieldElement as StarknetFieldElement;
use tracing::log;

use crate::NEW_WALLET_SELECTOR;

use super::{error::StarknetClientError, MATCH_SELECTOR, UPDATE_WALLET_SELECTOR};

/// The number of field elements used to represent an external transfer struct
const EXTERNAL_TRANSFER_N_FELTS: usize = 5;
/// The index of the `party0_public_blinder_share` argument in `match` calldata
const MATCH_PARTY0_PUBLIC_BLINDER_SHARE_IDX: usize = 2;
/// The index of the `party0_public_share_len` argument in `match` calldata
const MATCH_PARTY0_PUBLIC_SHARES_IDX: usize = 8;
/// The index of the `public_wallet_share_len` argument in `new_wallet` calldata
const NEW_WALLET_SHARE_LEN_IDX: usize = 3;
/// The index of the `external_transfers_len` argument in `update_wallet` calldata
const UPDATE_WALLET_EXTERNAL_TRANSFER_LEN: usize = 4;

/// Error message emitted when a public blinder share is not found in calldata
const ERR_BLINDER_NOT_FOUND: &str = "public blinder share not found in calldata";
/// Error message emitted when an invalid selector is given in the transaction's execution trace
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
/// The index of the contract address argument in a call array element's metadata
const CALL_ARRAY_CONTRACT_ADDR_IDX: usize = 0;
/// The index of the selector argument in a call array element's metadata
const CALL_ARRAY_SELECTOR_IDX: usize = 1;
/// The index of the data offset argument in a call array element's metadata
const CALL_ARRAY_DATA_OFFSET_IDX: usize = 2;
/// The index of the data length argument in a call array element's metadata
const CALL_ARRAY_DATA_LEN_IDX: usize = 3;

/// Parses the first darkpool transaction in a call array
///
/// n.b. It is generally assumed that only one darkpool transaction exists in a given
/// call array, and the caller should take care to ensure this is the case
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
    let calldata_start = metadata_end;
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

/// Parse wallet public secret shares from the calldata of a transaction based on the
/// selector invoked
///
/// Accept the public blinder share to disambiguate for transactions that update two sets
/// of secret shares in their calldata
pub(super) fn parse_shares_from_calldata(
    selector: StarknetFieldElement,
    calldata: &[StarknetFieldElement],
    public_blinder_share: StarknetFieldElement,
) -> Result<SizedWalletShare, StarknetClientError> {
    let felt_blob = match selector {
        _ if selector == *NEW_WALLET_SELECTOR => parse_shares_from_new_wallet(calldata),
        _ if selector == *UPDATE_WALLET_SELECTOR => parse_shares_from_update_wallet(calldata),
        _ if selector == *MATCH_SELECTOR => {
            parse_shares_from_match(public_blinder_share, calldata)?
        }
        _ => {
            log::error!("invalid selector received: {selector}");
            return Err(StarknetClientError::NotFound(
                ERR_INVALID_SELECTOR.to_string(),
            ));
        }
    };

    // Convert to scalars and re-structure into a wallet share
    Ok(SizedWalletShare::from_scalars(
        &mut felt_blob.iter().map(starknet_felt_to_scalar),
    ))
}

/// Parse wallet public shares from the calldata of a `new_wallet` transaction
fn parse_shares_from_new_wallet(calldata: &[StarknetFieldElement]) -> Vec<StarknetFieldElement> {
    let wallet_shares_len: u64 = calldata[NEW_WALLET_SHARE_LEN_IDX].try_into().unwrap();
    let start_idx = NEW_WALLET_SHARE_LEN_IDX + 1;
    let end_idx = start_idx + (wallet_shares_len as usize);

    calldata[start_idx..end_idx].to_vec()
}

/// Parse wallet public shares from the calldata of an `update_wallet` transaction
fn parse_shares_from_update_wallet(calldata: &[StarknetFieldElement]) -> Vec<StarknetFieldElement> {
    // Scan up to the `external_transfers_len` argument to determine how far to jump past the transfer
    let mut cursor = UPDATE_WALLET_EXTERNAL_TRANSFER_LEN;
    let external_transfers_len: u64 = calldata[cursor].try_into().unwrap();
    cursor += (external_transfers_len as usize) * EXTERNAL_TRANSFER_N_FELTS + 1;

    // The next argument is the length of the public secret shares
    let wallet_shares_len: u64 = calldata[cursor].try_into().unwrap();
    let start_idx = cursor + 1;
    let end_idx = start_idx + (wallet_shares_len as usize);

    calldata[start_idx..end_idx].to_vec()
}

/// Parse wallet public shares from the calldata of a `match` transaction
fn parse_shares_from_match(
    public_blinder_share: StarknetFieldElement,
    calldata: &[StarknetFieldElement],
) -> Result<Vec<StarknetFieldElement>, StarknetClientError> {
    let mut cursor = MATCH_PARTY0_PUBLIC_BLINDER_SHARE_IDX;
    let party0_blinder_share = calldata[cursor];
    let party1_blinder_share = calldata[cursor + 1];

    let is_party0 = if public_blinder_share == party0_blinder_share {
        true
    } else if public_blinder_share == party1_blinder_share {
        false
    } else {
        return Err(StarknetClientError::NotFound(
            ERR_BLINDER_NOT_FOUND.to_string(),
        ));
    };

    cursor = MATCH_PARTY0_PUBLIC_SHARES_IDX;
    let party0_public_shares_len: u64 = calldata[cursor].try_into().unwrap();

    let (start_idx, end_idx) = if is_party0 {
        let start_idx = cursor + 1;
        (start_idx, start_idx + (party0_public_shares_len as usize))
    } else {
        // Scan cursor past party 0 shares
        cursor += party0_public_shares_len as usize + 1;
        let party1_public_shares_len: u64 = calldata[cursor].try_into().unwrap();
        let start_idx = cursor + 1;
        (start_idx, start_idx + (party1_public_shares_len as usize))
    };

    Ok(calldata[start_idx..end_idx].to_vec())
}
