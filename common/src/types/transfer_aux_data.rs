//! Type definitions for auxiliary data passed along from the client to the
//! contract to authorizing / authenticating ERC20 transfers

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// Auxiliary data for validating a deposit, namely a [Permit2 permitTransferFrom](https://docs.uniswap.org/contracts/permit2/reference/signature-transfer#single-permittransferfrom)
/// signature, and the signed fields that cannot be extracted from the external
/// transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositAuxData {
    /// The nonce used in the permit
    pub permit_nonce: BigUint,
    /// The deadline used in the permit
    pub permit_deadline: BigUint,
    /// The signature of the permit
    pub permit_signature: Vec<u8>,
}

/// Auxiliary data for validating a withdrawal, namely a signature
/// over the external transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalAuxData {
    /// The signature over the external transfer
    pub external_transfer_signature: Vec<u8>,
}

/// Auxiliary data for validating a transfer, which can be either a deposit or a
/// withdrawal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferAuxData {
    /// Auxiliary data for validating a deposit
    Deposit(DepositAuxData),
    /// Auxiliary data for validating a withdrawal
    Withdrawal(WithdrawalAuxData),
}
