//! Test helpers for constructing auth data for external transfers
//! Much of this is ported over from https://github.com/renegade-fi/renegade-contracts/blob/main/integration/src/utils.rs

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{
    eip712_domain,
    sol_data::{Address as SolAddress, Uint as SolUint},
    Eip712Domain, SolStruct, SolType,
};
use arbitrum_client::{
    conversion::{pk_to_u256s, to_contract_external_transfer},
    helpers::serialize_calldata,
};
use circuit_types::{
    keychain::PublicSigningKey,
    transfers::{ExternalTransfer, ExternalTransferDirection},
};
use common::types::transfer_auth::{DepositAuth, ExternalTransferWithAuth, WithdrawalAuth};
use ethers::{signers::Wallet, types::H256};
use eyre::Result;
use k256::ecdsa::SigningKey;
use num_bigint::BigUint;
use rand::{thread_rng, RngCore};

use self::abi::{DepositWitness, PermitWitnessTransferFrom, TokenPermissions};

mod abi;

/// The name of the domain separator for Permit2 typed data
const PERMIT2_EIP712_DOMAIN_NAME: &str = "Permit2";

/// Generates an external transfer augmented with auth data
pub fn gen_transfer_with_auth(
    wallet: &Wallet<SigningKey>,
    pk_root: &PublicSigningKey,
    permit2_address: Address,
    darkpool_address: Address,
    chain_id: u64,
    transfer: ExternalTransfer,
) -> Result<ExternalTransferWithAuth> {
    match transfer.direction {
        ExternalTransferDirection::Deposit => gen_deposit_with_auth(
            wallet,
            pk_root,
            transfer,
            permit2_address,
            darkpool_address,
            chain_id,
        ),
        ExternalTransferDirection::Withdrawal => gen_withdrawal_with_auth(wallet, transfer),
    }
}

/// Generate a withdrawal payload with proper auth data
fn gen_withdrawal_with_auth(
    wallet: &Wallet<SigningKey>,
    transfer: ExternalTransfer,
) -> Result<ExternalTransferWithAuth> {
    let contract_transfer = to_contract_external_transfer(&transfer)?;
    let transfer_bytes = serialize_calldata(&contract_transfer)?;
    let transfer_hash = H256::from_slice(keccak256(&transfer_bytes).as_slice());
    let transfer_signature = wallet.sign_hash(transfer_hash)?.to_vec();

    Ok(ExternalTransferWithAuth::withdrawal(
        transfer.account_addr,
        transfer.mint,
        transfer.amount,
        WithdrawalAuth { external_transfer_signature: transfer_signature },
    ))
}

/// Generate a deposit payload with proper auth data
fn gen_deposit_with_auth(
    wallet: &Wallet<SigningKey>,
    pk_root: &PublicSigningKey,
    transfer: ExternalTransfer,
    permit2_address: Address,
    darkpool_address: Address,
    chain_id: u64,
) -> Result<ExternalTransferWithAuth> {
    let contract_transfer = to_contract_external_transfer(&transfer)?;
    let (permit_nonce, permit_deadline, permit_signature) = gen_permit_payload(
        wallet,
        contract_transfer.mint,
        contract_transfer.amount,
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
    wallet: &Wallet<SigningKey>,
    token: Address,
    amount: U256,
    pk_root: &PublicSigningKey,
    permit2_address: Address,
    darkpool_address: Address,
    chain_id: u64,
) -> Result<(U256, U256, Vec<u8>)> {
    let permitted = TokenPermissions { token, amount };

    // Generate a random nonce
    let mut nonce_bytes = [0_u8; 32];
    thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = U256::from_be_slice(&nonce_bytes);

    // Set an effectively infinite deadline
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

    let msg_hash =
        H256::from_slice(permit_signing_hash(&signable_permit, &permit_domain).as_slice());

    let signature = wallet.sign_hash(msg_hash)?.to_vec();

    Ok((nonce, deadline, signature))
}

/// This is a re-implementation of `eip712_signing_hash` (https://github.com/alloy-rs/core/blob/v0.3.1/crates/sol-types/src/types/struct.rs#L117)
/// which correctly encodes the data for the nested `TokenPermissions` struct.
///
/// We do so by mirroring the functionality implemented in the `sol!` macro (https://github.com/alloy-rs/core/blob/v0.3.1/crates/sol-macro/src/expand/struct.rs#L56)
/// but avoiding the (unintended) extra hash of the `TokenPermissions` struct's
/// EIP-712 struct hash.
///
/// This is fixed here: https://github.com/alloy-rs/core/pull/258
/// But the version of `alloy` used by `renegade-contracts` is not updated to
/// include this fix.
///
/// TODO: Remove this function when `renegade-contracts` uses `alloy >= 0.4.0`
fn permit_signing_hash(permit: &PermitWitnessTransferFrom, domain: &Eip712Domain) -> B256 {
    let domain_separator = domain.hash_struct();

    let mut type_hash = permit.eip712_type_hash().to_vec();
    let encoded_data = [
        permit.permitted.eip712_hash_struct().0,
        SolAddress::eip712_data_word(&permit.spender).0,
        SolUint::<256>::eip712_data_word(&permit.nonce).0,
        SolUint::<256>::eip712_data_word(&permit.deadline).0,
        permit.witness.eip712_hash_struct().0,
    ]
    .concat();
    type_hash.extend(encoded_data);
    let struct_hash = keccak256(&type_hash);

    let mut digest_input = [0u8; 2 + 32 + 32];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    digest_input[2..34].copy_from_slice(&domain_separator[..]);
    digest_input[34..66].copy_from_slice(&struct_hash[..]);
    keccak256(digest_input)
}

/// Convert a `U256` to a `BigUint`
fn u256_to_biguint(u: U256) -> BigUint {
    BigUint::from_bytes_le(u.as_le_slice())
}
