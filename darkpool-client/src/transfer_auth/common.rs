//! Common helpers across chains

use alloy::signers::{local::PrivateKeySigner, SignerSync};
use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{eip712_domain, SolStruct};
use circuit_types::{keychain::PublicSigningKey, traits::BaseType, transfers::ExternalTransfer};
use common::types::transfer_auth::{DepositAuth, ExternalTransferWithAuth};
use rand::RngCore;

use crate::{
    conversion::{amount_to_u256, biguint_to_address, scalar_to_u256, u256_to_biguint},
    errors::{ConversionError, DarkpoolClientError},
};

use super::permit2_abi::{
    DepositWitness, PermitWitnessTransferFrom, TokenPermissions, PERMIT2_EIP712_DOMAIN_NAME,
};

/// The number of scalars in a secp256k1 public key
const NUM_SCALARS_PK: usize = 4;

/// Generate a deposit payload with proper auth data
pub fn build_deposit_auth(
    wallet: &PrivateKeySigner,
    pk_root: &PublicSigningKey,
    transfer: ExternalTransfer,
    permit2_address: Address,
    darkpool_address: Address,
    chain_id: u64,
) -> Result<ExternalTransferWithAuth, DarkpoolClientError> {
    let transfer_mint = biguint_to_address(&transfer.mint)?;
    let transfer_amount = amount_to_u256(transfer.amount)?;
    let (permit_nonce, permit_deadline, permit_signature) = gen_permit_payload(
        wallet,
        transfer_mint,
        transfer_amount,
        pk_root,
        permit2_address,
        darkpool_address,
        chain_id,
    )?;

    let permit_nonce = u256_to_biguint(permit_nonce);
    let permit_deadline = u256_to_biguint(permit_deadline);

    Ok(ExternalTransferWithAuth::deposit(
        transfer.account_addr,
        transfer.mint,
        transfer.amount,
        DepositAuth { permit_nonce, permit_deadline, permit_signature },
    ))
}

/// Generates a permit payload for the given token and amount
fn gen_permit_payload(
    wallet: &PrivateKeySigner,
    token: Address,
    amount: U256,
    pk_root: &PublicSigningKey,
    permit2_address: Address,
    darkpool_address: Address,
    chain_id: u64,
) -> Result<(U256, U256, Vec<u8>), DarkpoolClientError> {
    let permitted = TokenPermissions { token, amount };

    // Set an effectively infinite deadline
    let nonce = gen_permit_nonce();
    let deadline = U256::from(u64::MAX);
    let witness = DepositWitness { pkRoot: pk_to_u256s(pk_root)? };
    let signable_permit = PermitWitnessTransferFrom {
        permitted,
        spender: darkpool_address,
        nonce,
        deadline,
        witness,
    };

    // Construct the EIP712 domain
    let permit_domain = eip712_domain!(
        name: PERMIT2_EIP712_DOMAIN_NAME,
        chain_id: chain_id,
        verifying_contract: permit2_address,
    );

    let msg_hash = signable_permit.eip712_signing_hash(&permit_domain);
    let signature = wallet.sign_hash_sync(&msg_hash).map_err(DarkpoolClientError::signing)?;
    let sig_bytes = signature.as_bytes().to_vec();
    Ok((nonce, deadline, sig_bytes))
}

/// Generate a permit nonce for a deposit
fn gen_permit_nonce() -> U256 {
    let mut rng = rand::thread_rng();
    let mut nonce_bytes = [0_u8; 32];
    rng.fill_bytes(&mut nonce_bytes);
    U256::from_be_slice(&nonce_bytes)
}

/// Sign a set of bytes with the given key
///
/// Returns the signature byte serialized
pub(crate) fn sign_bytes(
    wallet: &PrivateKeySigner,
    bytes: &[u8],
) -> Result<Vec<u8>, DarkpoolClientError> {
    let hash = B256::from_slice(keccak256(bytes).as_slice());
    let signature = wallet.sign_hash_sync(&hash).map_err(DarkpoolClientError::signing)?;
    Ok(signature.as_bytes().to_vec())
}

/// Converts a [`PublicSigningKey`] to a fixed-length array of [`AlloyU256`]
/// elements
fn pk_to_u256s(pk: &PublicSigningKey) -> Result<[U256; NUM_SCALARS_PK], ConversionError> {
    pk.to_scalars()
        .iter()
        .map(|s| scalar_to_u256(*s))
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ConversionError::InvalidLength)
}
