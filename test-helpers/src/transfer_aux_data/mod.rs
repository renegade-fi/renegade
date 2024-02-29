//! Test helpers for constructing auxiliary data for external transfers
//! Much of this is ported over from https://github.com/renegade-fi/renegade-contracts/blob/main/integration/src/utils.rs

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::{
    eip712_domain,
    sol_data::{Address as SolAddress, Uint as SolUint},
    Eip712Domain, SolStruct, SolType,
};
use arbitrum_client::{conversion::to_contract_external_transfer, helpers::serialize_calldata};
use circuit_types::transfers::ExternalTransfer;
use common::types::transfer_aux_data::{DepositAuxData, TransferAuxData, WithdrawalAuxData};
use ethers::{signers::Wallet, types::H256};
use eyre::Result;
use k256::ecdsa::SigningKey;
use num_bigint::BigUint;
use rand::{thread_rng, RngCore};

use self::abi::{PermitTransferFrom, TokenPermissions};

mod abi;

/// The name of the domain separator for Permit2 typed data
const PERMIT2_EIP712_DOMAIN_NAME: &str = "Permit2";

/// Generates the auxiliary data fpr the given external transfer,
/// including the Permit2 data & a signature over the transfer
pub fn gen_transfer_aux_data(
    wallet: Wallet<SigningKey>,
    transfer: &ExternalTransfer,
    permit2_address: Address,
    darkpool_address: Address,
    chain_id: u64,
) -> Result<TransferAuxData> {
    let transfer = to_contract_external_transfer(transfer)?;

    let res = if transfer.is_withdrawal {
        let transfer_bytes = serialize_calldata(&transfer)?;
        let transfer_hash = H256::from_slice(keccak256(&transfer_bytes).as_slice());
        let transfer_signature = wallet.sign_hash(transfer_hash)?.to_vec();

        TransferAuxData::Withdrawal(WithdrawalAuxData {
            external_transfer_signature: transfer_signature,
        })
    } else {
        let (permit_nonce, permit_deadline, permit_signature) = gen_permit_payload(
            wallet,
            transfer.mint,
            transfer.amount,
            permit2_address,
            darkpool_address,
            chain_id,
        )?;

        let permit_nonce = u256_to_biguint(permit_nonce);
        let permit_deadline = u256_to_biguint(permit_deadline);

        TransferAuxData::Deposit(DepositAuxData { permit_nonce, permit_deadline, permit_signature })
    };

    Ok(res)
}

/// Generates a permit payload for the given token and amount
fn gen_permit_payload(
    wallet: Wallet<SigningKey>,
    token: Address,
    amount: U256,
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

    let signable_permit =
        PermitTransferFrom { permitted, spender: darkpool_address, nonce, deadline };

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
fn permit_signing_hash(permit: &PermitTransferFrom, domain: &Eip712Domain) -> B256 {
    let domain_separator = domain.hash_struct();

    let mut type_hash = permit.eip712_type_hash().to_vec();
    let encoded_data = [
        permit.permitted.eip712_hash_struct().0,
        SolAddress::eip712_data_word(&permit.spender).0,
        SolUint::<256>::eip712_data_word(&permit.nonce).0,
        SolUint::<256>::eip712_data_word(&permit.deadline).0,
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
