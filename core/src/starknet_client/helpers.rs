//! Various helpers for Starknet client execution

use std::{convert::TryInto, iter};

use crypto::elgamal::ElGamalCiphertext;
use itertools::Itertools;
use starknet::core::types::FieldElement as StarknetFieldElement;

use crate::starknet_client::{NEW_WALLET_SELECTOR, SETTLE_SELECTOR, UPDATE_WALLET_SELECTOR};

use super::error::StarknetClientError;

/// The number of bytes we can pack into a given Starknet field element
///
/// The starknet field is of size 2 ** 251 + \delta, which fits at most
/// 31 bytes cleanly into a single felt
const BYTES_PER_FELT: usize = 31;
/// The index of the `encryption_blob_len` parameter in the `new_wallet` calldata
const NEW_WALLET_ENCRYPTION_BLOB_IDX: usize = 2;
/// The index of the `internal_transfer_ciphertext_len` argument in the `update_wallet` calldata
const UPDATE_WALLET_INTERNAL_TRANSFER_IDX: usize = 4;
/// The index of the `wallet_ciphertext_len` argument in the `settle` calldata
const SETTLE_WALLET_CIPHERTEXT_IDX: usize = 6;

/// Error thrown when a blob is not properly encoded
const ERR_INVALID_BLOB_ENCODING: &str = "invalid blob encoding";
/// Error thrown when an invalid selector is encountered observing a transaction's details
const ERR_INVALID_SELECTOR: &str = "invalid selector received";

/// A helper to parse a ciphertext blob from transaction calldata
pub(super) fn parse_ciphertext_from_calldata(
    selector: StarknetFieldElement,
    calldata: &[StarknetFieldElement],
) -> Result<Vec<ElGamalCiphertext>, StarknetClientError> {
    // Parse the ciphertext blob from the calldata
    let blob = match selector {
        _ if selector == *NEW_WALLET_SELECTOR => parse_ciphertext_new_wallet(calldata),
        _ if selector == *UPDATE_WALLET_SELECTOR => parse_ciphertext_update_wallet(calldata),
        _ if selector == *SETTLE_SELECTOR => parse_ciphertext_settle(calldata),
        _ => {
            return Err(StarknetClientError::NotFound(
                ERR_INVALID_SELECTOR.to_string(),
            ));
        }
    };

    // Parse a packed ciphertext from the calldata
    ciphertext_vec_from_felt_blob(&blob)
}

/// Parse a ciphertext blob from a `new_wallet` transaction
fn parse_ciphertext_new_wallet(calldata: &[StarknetFieldElement]) -> Vec<StarknetFieldElement> {
    let blob_len: u64 = calldata[NEW_WALLET_ENCRYPTION_BLOB_IDX].try_into().unwrap();
    let start_idx = NEW_WALLET_ENCRYPTION_BLOB_IDX + 1;
    let end_idx = start_idx + (blob_len as usize);
    calldata[start_idx..end_idx].to_vec()
}

/// Parse a ciphertext blob from an `update_wallet` transaction
fn parse_ciphertext_update_wallet(calldata: &[StarknetFieldElement]) -> Vec<StarknetFieldElement> {
    // Read through the internal ciphertext
    let mut cursor = UPDATE_WALLET_INTERNAL_TRANSFER_IDX;
    let internal_wallet_ciphertext_len: u64 = calldata[cursor].try_into().unwrap();
    cursor += (internal_wallet_ciphertext_len as usize) + 1;

    // Read through the external transfers
    let external_transfers_len: u64 = calldata[cursor].try_into().unwrap();
    cursor += (external_transfers_len as usize) + 1;

    // The next argument is the ciphertext blob length
    let ciphertext_blob_len: u64 = calldata[cursor].try_into().unwrap();
    let start_idx: usize = cursor + 1;
    let end_idx: usize = start_idx + (ciphertext_blob_len as usize);

    calldata[start_idx..end_idx].to_vec()
}

/// Parse a ciphertext blob from a `settle` transaction
fn parse_ciphertext_settle(calldata: &[StarknetFieldElement]) -> Vec<StarknetFieldElement> {
    let blob_len: u64 = calldata[SETTLE_WALLET_CIPHERTEXT_IDX].try_into().unwrap();
    let start_idx = SETTLE_WALLET_CIPHERTEXT_IDX + 1;
    let end_idx = start_idx + (blob_len as usize);

    calldata[start_idx..end_idx].to_vec()
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

/// Deserialization from packed felts into a vector of ElGamal ciphertexts
///
/// When we pack the ciphertext into blob format for submission to the contract, we
/// byte serialize the ciphertext vector, then pack the bytes into felts. The
/// deserialization process is the opposite, chunk up the felts into byte windows,
/// then concatenate these and deserialize explicitly into a `Vec<ElGamalCiphertext>`
fn ciphertext_vec_from_felt_blob(
    blob: &[StarknetFieldElement],
) -> Result<Vec<ElGamalCiphertext>, StarknetClientError> {
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

#[cfg(test)]
mod tests {
    use crypto::elgamal::ElGamalCiphertext;
    use curve25519_dalek::scalar::Scalar;
    use rand_core::OsRng;

    use super::{ciphertext_vec_from_felt_blob, pack_bytes_into_felts};

    /// Tests serializing and deserializing a ciphertext blob as a packed array
    /// of felts
    #[test]
    fn test_serialize_deserialize_elgamal() {
        let n = 50;
        let mut rng = OsRng {};
        let mut ciphertexts = Vec::new();
        for _ in 0..n {
            ciphertexts.push(ElGamalCiphertext {
                partial_shared_secret: Scalar::random(&mut rng),
                encrypted_message: Scalar::random(&mut rng),
            })
        }

        // Serialize the ciphertexts
        let bytes = serde_json::to_vec(&ciphertexts).unwrap();
        let packed_calldata = pack_bytes_into_felts(&bytes);

        // Deserialize back into ciphertexts
        let recovered_ciphertexts = ciphertext_vec_from_felt_blob(&packed_calldata).unwrap();

        assert_eq!(ciphertexts, recovered_ciphertexts);
    }
}
