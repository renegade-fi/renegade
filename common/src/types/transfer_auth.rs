//! Type definitions for auth data passed along from the client to the
//! contract to authorizing / authenticating ERC20 transfers

use circuit_types::{
    transfers::{ExternalTransfer, ExternalTransferDirection},
    Amount,
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// Auth data for validating a deposit
///
/// Namely a [Permit2 permitTransferFrom](https://docs.uniswap.org/contracts/permit2/reference/signature-transfer#single-permittransferfrom)
/// signature, and the signed fields that cannot be extracted from the external
/// transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositAuth {
    /// The nonce used in the permit
    pub permit_nonce: BigUint,
    /// The deadline used in the permit
    pub permit_deadline: BigUint,
    /// The signature of the permit
    pub permit_signature: Vec<u8>,
}

/// Auth data for validating a withdrawal, namely a signature
/// over the external transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalAuth {
    /// The signature over the external transfer
    pub external_transfer_signature: Vec<u8>,
}

/// Auth data for validating a transfer, which can be either a deposit or a
/// withdrawal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferAuth {
    /// Auth data for validating a deposit
    Deposit(DepositAuth),
    /// Auth data for validating a withdrawal
    Withdrawal(WithdrawalAuth),
}

/// An external transfer packed together with the necessary auth data to
/// validate it
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalTransferWithAuth {
    /// The external transfer
    pub external_transfer: ExternalTransfer,
    /// The auth data to validate the external transfer
    pub transfer_auth: TransferAuth,
}

impl ExternalTransferWithAuth {
    /// Create a new external transfer with auth data for a deposit
    pub fn deposit(
        account_addr: BigUint,
        mint: BigUint,
        amount: Amount,
        deposit_auth: DepositAuth,
    ) -> Self {
        Self {
            external_transfer: ExternalTransfer {
                account_addr,
                mint,
                amount,
                direction: ExternalTransferDirection::Deposit,
            },
            transfer_auth: TransferAuth::Deposit(deposit_auth),
        }
    }

    /// Create a new external transfer with auth data for a withdrawal
    pub fn withdrawal(
        account_addr: BigUint,
        mint: BigUint,
        amount: Amount,
        withdrawal_auth: WithdrawalAuth,
    ) -> Self {
        Self {
            external_transfer: ExternalTransfer {
                account_addr,
                mint,
                amount,
                direction: ExternalTransferDirection::Withdrawal,
            },
            transfer_auth: TransferAuth::Withdrawal(withdrawal_auth),
        }
    }
}
