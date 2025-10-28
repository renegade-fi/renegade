//! Defines native and circuit types for internal/external transfers
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use constants::{Scalar, ScalarField};
use renegade_crypto::fields::scalar_to_u64;
use serde::{Deserialize, Serialize};

use crate::{Address, Amount};

#[cfg(feature = "proof-system-types")]
use {
    crate::traits::{BaseType, CircuitBaseType, CircuitVarType},
    circuit_macros::circuit_type,
    mpc_relation::{BoolVar, Variable, traits::Circuit},
};

// ----------------------
// | External Transfers |
// ----------------------

/// The base external transfer type, not allocated in a constraint system
/// or an MPC circuit
#[cfg_attr(feature = "proof-system-types", circuit_type(serde, singleprover_circuit))]
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct ExternalTransfer {
    /// The address of the account contract to transfer to/from
    pub account_addr: Address,
    /// The mint (ERC20 address) of the token to transfer
    pub mint: Address,
    /// The amount of the token transferred
    pub amount: Amount,
    /// The direction of transfer
    pub direction: ExternalTransferDirection,
}

/// Represents the direction (deposit/withdraw) of a transfer
#[derive(Copy, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ExternalTransferDirection {
    /// Deposit an ERC20 into the darkpool from an external address
    Deposit = 0,
    /// Withdraw an ERC20 from the darkpool to an external address
    Withdrawal,
}

#[cfg(feature = "proof-system-types")]
impl BaseType for ExternalTransferDirection {
    const NUM_SCALARS: usize = 1;

    fn to_scalars(&self) -> Vec<Scalar> {
        vec![Scalar::from(*self as u8)]
    }

    fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
        match scalar_to_u64(&i.next().unwrap()) {
            0 => ExternalTransferDirection::Deposit,
            1 => ExternalTransferDirection::Withdrawal,
            _ => panic!("invalid value for ExternalTransferDirection"),
        }
    }
}

#[cfg(feature = "proof-system-types")]
impl CircuitBaseType for ExternalTransferDirection {
    type VarType = BoolVar;
}

impl Default for ExternalTransferDirection {
    fn default() -> Self {
        Self::Deposit
    }
}

impl From<ExternalTransferDirection> for Scalar {
    fn from(dir: ExternalTransferDirection) -> Self {
        Scalar::from(dir as u8)
    }
}

impl ExternalTransfer {
    /// Whether or not the instance is a default external transfer
    pub fn is_default(&self) -> bool {
        self.eq(&ExternalTransfer::default())
    }
}
