//! Defines contract type bindings and helpers for interacting with them

use crypto::fields::biguint_to_starknet_felt;
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use starknet::core::types::FieldElement as StarknetFieldElement;

/// An external transfer tuple represents either a deposit or withdraw
/// to/from the darkpool
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExternalTransfer {
    /// The account contract address to deposit from or withdraw to
    pub sender_address: BigUint,
    /// The contract address of the ERC-20 token to deposit/withdraw
    pub mint: BigUint,
    /// The amount of the mint token to deposit/withdraw
    pub amount: BigUint,
    /// The direction of the transfer
    pub direction: ExternalTransferDirection,
}

impl ExternalTransfer {
    /// Constructor
    pub fn new(
        sender_address: BigUint,
        mint: BigUint,
        amount: BigUint,
        direction: ExternalTransferDirection,
    ) -> Self {
        Self {
            sender_address,
            mint,
            amount,
            direction,
        }
    }
}

/// A serialization implementation in the format that the Starknet client expects
impl From<ExternalTransfer> for Vec<StarknetFieldElement> {
    fn from(transfer: ExternalTransfer) -> Self {
        vec![
            biguint_to_starknet_felt(&transfer.sender_address),
            biguint_to_starknet_felt(&transfer.mint),
            biguint_to_starknet_felt(&transfer.amount),
            transfer.direction.into(),
        ]
    }
}

/// Represents the direction (deposit/withdraw) of a transfer
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ExternalTransferDirection {
    /// Deposit an ERC20 into the darkpool from an external address
    Deposit = 0,
    /// Withdraw an ERC20 from the darkpool to an external address
    Withdrawal,
}

impl From<ExternalTransferDirection> for StarknetFieldElement {
    fn from(dir: ExternalTransferDirection) -> Self {
        StarknetFieldElement::from(dir as u8)
    }
}
