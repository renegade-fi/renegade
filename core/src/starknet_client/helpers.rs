//! Various helpers for Starknet client execution

use std::{convert::TryInto, iter};

use crypto::fields::starknet_felt_to_scalar;
use itertools::Itertools;
use starknet::core::types::FieldElement as StarknetFieldElement;

use crate::{starknet_client::NEW_WALLET_SELECTOR, SizedWalletShare};

use super::{error::StarknetClientError, MATCH_SELECTOR, UPDATE_WALLET_SELECTOR};

/// The number of bytes we can pack into a given Starknet field element
///
/// The starknet field is of size 2 ** 251 + \delta, which fits at most
/// 31 bytes cleanly into a single felt
const BYTES_PER_FELT: usize = 31;

/// The number of field elements used to represent an external transfer struct
const EXTERNAL_TRANSFER_N_FELTS: usize = 5;
/// The index of the `party0_public_blinder_share` argument in `match` calldata
const MATCH_PARTY0_PUBLIC_BLINDER_SHARE_IDX: usize = 4;
/// The index of the `party0_public_share_len` argument in `match` calldata
const MATCH_PARTY0_PUBLIC_SHARES_IDX: usize = 10;
/// The index of the `public_wallet_share_len` argument in `new_wallet` calldata
const NEW_WALLET_SHARE_LEN_IDX: usize = 3;
/// The index of the `external_transfers_len` argument in `update_wallet` calldata
const UPDATE_WALLET_EXTERNAL_TRANSFER_LEN: usize = 5;

/// Error message emitted when a public blinder share is not found in calldata
const ERR_BLINDER_NOT_FOUND: &str = "public blinder share not found in calldata";
/// Error message emitted when an invalid selector is given in the transaction's execution trace
const ERR_INVALID_SELECTOR: &str = "invalid selector received";

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
    match selector {
        _ if selector == *NEW_WALLET_SELECTOR => Ok(parse_shares_from_new_wallet(calldata)),
        _ if selector == *UPDATE_WALLET_SELECTOR => Ok(parse_shares_from_update_wallet(calldata)),
        _ if selector == *MATCH_SELECTOR => parse_shares_from_match(public_blinder_share, calldata),
        _ => Err(StarknetClientError::NotFound(
            ERR_INVALID_SELECTOR.to_string(),
        )),
    }
}

/// Parse wallet public shares from the calldata of a `new_wallet` transaction
fn parse_shares_from_new_wallet(calldata: &[StarknetFieldElement]) -> SizedWalletShare {
    let wallet_shares_len: u64 = calldata[NEW_WALLET_SHARE_LEN_IDX].try_into().unwrap();
    let start_idx = NEW_WALLET_SHARE_LEN_IDX + 1;
    let end_idx = start_idx + (wallet_shares_len as usize);

    // Slice the calldata, cast to `Scalar`, then restructure into a wallet share
    let calldata_slice = calldata[start_idx..end_idx].to_vec();
    calldata_slice
        .iter()
        .map(starknet_felt_to_scalar)
        .collect_vec()
        .into()
}

/// Parse wallet public shares from the calldata of an `update_wallet` transaction
fn parse_shares_from_update_wallet(calldata: &[StarknetFieldElement]) -> SizedWalletShare {
    // Scan up to the `external_transfers_len` argument to determine how far to jump past the transfer
    let mut cursor = UPDATE_WALLET_EXTERNAL_TRANSFER_LEN;
    let external_transfers_len: u64 = calldata[cursor].try_into().unwrap();
    cursor += (external_transfers_len as usize) * EXTERNAL_TRANSFER_N_FELTS + 1;

    // The next argument is the length of the public secret shares
    let wallet_shares_len: u64 = calldata[cursor].try_into().unwrap();
    let start_idx = cursor + 1;
    let end_idx = start_idx + (wallet_shares_len as usize);

    // Slice the calldata, cast to `Scalar`, and restructure into a wallet share
    let calldata_slice = calldata[start_idx..end_idx].to_vec();
    calldata_slice
        .iter()
        .map(starknet_felt_to_scalar)
        .collect_vec()
        .into()
}

/// Parse wallet public shares from the calldata of a `match` transaction
fn parse_shares_from_match(
    public_blinder_share: StarknetFieldElement,
    calldata: &[StarknetFieldElement],
) -> Result<SizedWalletShare, StarknetClientError> {
    let mut cursor = MATCH_PARTY0_PUBLIC_BLINDER_SHARE_IDX;
    let party0_blinder_share = calldata[cursor];
    let party1_blinder_share = calldata[cursor];

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
        cursor += party0_public_shares_len as usize;
        let party1_public_shares_len: u64 = calldata[cursor].try_into().unwrap();
        let start_idx = cursor + 1;
        (start_idx, start_idx + (party1_public_shares_len as usize))
    };

    // Slice the calldata, cast to `Scalar`, and re-structure into a wallet share
    let calldata_slice = calldata[start_idx..end_idx].to_vec();
    Ok(calldata_slice
        .iter()
        .map(starknet_felt_to_scalar)
        .collect_vec()
        .into())
}

/// Pack bytes into Starknet field elements
pub(super) fn pack_bytes_into_felts(bytes: &[u8]) -> Vec<StarknetFieldElement> {
    // Run-length encoded
    let mut res = vec![StarknetFieldElement::from(bytes.len() as u64)];
    for i in (0..bytes.len()).step_by(BYTES_PER_FELT) {
        // Construct a felt from bytes [i..i+BYTES_PER_FELT], padding
        // to 32 in length
        let range_end = usize::min(i + BYTES_PER_FELT, bytes.len());
        let mut bytes_padded: Vec<u8> = bytes[i..range_end]
            .iter()
            .cloned()
            .chain(iter::repeat(0u8))
            .take(32)
            .collect_vec();

        // We pack into the felt in little endian format so that the felt does
        // not overflow the field size
        bytes_padded.reverse();

        // Cast to array
        let bytes_padded: [u8; 32] = bytes_padded.try_into().unwrap();
        res.push(StarknetFieldElement::from_bytes_be(&bytes_padded).unwrap());
    }

    res
}
