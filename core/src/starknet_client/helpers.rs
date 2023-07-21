//! Various helpers for Starknet client execution

use std::{
    convert::TryInto,
    io::{Cursor, Read},
    iter,
};

use ark_ff::{BigInteger, PrimeField};
use itertools::Itertools;
use mpc_stark::algebra::{
    scalar::Scalar,
    stark_curve::{StarkPoint, STARK_POINT_BYTES},
};
use serde::de::DeserializeOwned;
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
const MATCH_PARTY0_PUBLIC_BLINDER_SHARE_IDX: usize = 2;
/// The index of the `party0_public_share_len` argument in `match` calldata
const MATCH_PARTY0_PUBLIC_SHARES_IDX: usize = 8;
/// The index of the `public_wallet_share_len` argument in `new_wallet` calldata
const NEW_WALLET_SHARE_LEN_IDX: usize = 3;
/// The index of the `external_transfers_len` argument in `update_wallet` calldata
const UPDATE_WALLET_EXTERNAL_TRANSFER_LEN: usize = 4;

/// Error message emitted when a public blinder share is not found in calldata
const ERR_BLINDER_NOT_FOUND: &str = "public blinder share not found in calldata";
/// Error message emitted when a blob encoding is invalidly structured
const ERR_INVALID_BLOB_ENCODING: &str = "blob encoding incorrect";
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
    let felt_blob = match selector {
        _ if selector == *NEW_WALLET_SELECTOR => parse_shares_from_new_wallet(calldata),
        _ if selector == *UPDATE_WALLET_SELECTOR => parse_shares_from_update_wallet(calldata),
        _ if selector == *MATCH_SELECTOR => {
            parse_shares_from_match(public_blinder_share, calldata)?
        }
        _ => {
            return Err(StarknetClientError::NotFound(
                ERR_INVALID_SELECTOR.to_string(),
            ))
        }
    };

    unpack_bytes_from_blob(felt_blob)
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

/// Unpack bytes that were previously packed into felts
pub(super) fn unpack_bytes_from_blob<T: DeserializeOwned>(
    blob: Vec<StarknetFieldElement>,
) -> Result<T, StarknetClientError> {
    let n_bytes: u64 = blob[0]
        .try_into()
        .map_err(|_| StarknetClientError::Serde(ERR_INVALID_BLOB_ENCODING.to_string()))?;

    // Build a byte array from the calldata blob
    let mut byte_array: Vec<u8> = Vec::with_capacity(BYTES_PER_FELT * blob.len());
    for felt in blob[1..].iter() {
        let mut bytes = felt.to_bytes_be();
        // We pack bytes into the felts in little endian order to avoid
        // field overflows. So reverse into little endian then truncate
        bytes.reverse();

        byte_array.append(&mut bytes[..BYTES_PER_FELT].to_vec());
    }

    // Deserialize the byte array back into a ciphertext vector
    let truncated_bytes = &byte_array[..(n_bytes as usize)];
    serde_json::from_slice(truncated_bytes)
        .map_err(|err| StarknetClientError::Serde(err.to_string()))
}

struct DeserializationError;

impl From<DeserializationError> for String {
    fn from(value: DeserializationError) -> Self {
        String::from("error deserializing from bytes")
    }
}

pub(super) fn read_point(cursor: &mut Cursor<&[u8]>) -> Result<StarkPoint, DeserializationError> {
    let mut buf = [0u8; STARK_POINT_BYTES];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| DeserializationError)?;

    StarkPoint::from_bytes(&buf).map_err(|_| DeserializationError)
}

pub(super) fn read_scalar(cursor: &mut Cursor<&[u8]>) -> Result<Scalar, DeserializationError> {
    let mut buf = [0u8; 32];
    cursor
        .read_exact(&mut buf)
        .map_err(|_| DeserializationError)?;

    Ok(Scalar::from_be_bytes_mod_order(&buf))
}

struct SerializationError;

impl From<SerializationError> for String {
    fn from(value: SerializationError) -> Self {
        String::from("error serializing to calldata")
    }
}

pub(super) fn point_to_felts(
    point: &StarkPoint,
) -> Result<[StarknetFieldElement; 2], SerializationError> {
    if point.is_identity() {
        Ok([StarknetFieldElement::ZERO, StarknetFieldElement::ZERO])
    } else {
        let aff = point.to_affine();
        let x_bytes = aff.x.into_bigint().to_bytes_be();
        let y_bytes = aff.y.into_bigint().to_bytes_be();

        Ok([
            StarknetFieldElement::from_byte_slice_be(&x_bytes).map_err(|_| SerializationError)?,
            StarknetFieldElement::from_byte_slice_be(&y_bytes).map_err(|_| SerializationError)?,
        ])
    }
}

pub(super) fn serialize_points_to_calldata(
    points: &[StarkPoint],
    felts: &mut Vec<StarknetFieldElement>,
) -> Result<(), SerializationError> {
    points.iter().try_for_each(|point| {
        let point_ser = point_to_felts(point)?;
        felts.extend(point_ser);
        Ok(())
    })?;
    Ok(())
}

pub(super) fn serialize_scalars_to_calldata(
    scalars: &[Scalar],
    felts: &mut Vec<StarknetFieldElement>,
) -> Result<(), SerializationError> {
    scalars.iter().try_for_each(|scalar| {
        let felt = StarknetFieldElement::from_byte_slice_be(scalar.to_bytes_be().as_slice())
            .map_err(|_| SerializationError)?;
        felts.push(felt);
        Ok(())
    })?;
    Ok(())
}
