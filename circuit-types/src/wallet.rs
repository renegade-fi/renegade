//! Groups type definitions for a wallet and implements traits to allocate
//! the wallet
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::Add;

use constants::{Scalar, ScalarField};
use itertools::Itertools;
use serde::{Deserialize, Serialize};

use crate::{
    elgamal::EncryptionKey, fixed_point::FixedPoint, scalar_from_hex_string, scalar_to_hex_string,
};

use super::{
    balance::Balance, deserialize_array, keychain::PublicKeyChain, order::Order, serialize_array,
};

#[cfg(feature = "proof-system-types")]
use {
    crate::{
        traits::{
            BaseType, CircuitBaseType, CircuitVarType, MpcBaseType, MpcType,
            MultiproverCircuitBaseType, SecretShareBaseType, SecretShareType, SecretShareVarType,
        },
        Fabric,
    },
    circuit_macros::circuit_type,
    constants::AuthenticatedScalar,
    mpc_relation::{traits::Circuit, Variable},
};

/// A commitment to the wallet's secret shares that is entered into the global
/// state
pub type WalletShareStateCommitment = Scalar;
/// Commitment type alias for readability
pub type NoteCommitment = Scalar;
/// Nullifier type alias for readability
pub type Nullifier = Scalar;

// --------------------
// | Wallet Base Type |
// --------------------

/// Represents the base type of a wallet holding orders, balances, fees, keys
/// and cryptographic randomness
#[cfg_attr(
    feature = "proof-system-types",
    circuit_type(serde, singleprover_circuit, secret_share, mpc, multiprover_circuit)
)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wallet<const MAX_BALANCES: usize, const MAX_ORDERS: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// The list of balances in the wallet
    #[serde(serialize_with = "serialize_array", deserialize_with = "deserialize_array")]
    pub balances: [Balance; MAX_BALANCES],
    /// The list of open orders in the wallet
    #[serde(serialize_with = "serialize_array", deserialize_with = "deserialize_array")]
    pub orders: [Order; MAX_ORDERS],
    /// The key tuple used by the wallet; i.e. (pk_root, pk_match, pk_settle,
    /// pk_view)
    pub keys: PublicKeyChain,
    /// The match fee authorized by the wallet owner that the relayer may take
    /// on a match
    #[serde(alias = "match_fee")]
    pub max_match_fee: FixedPoint,
    /// The public key of the cluster that this wallet has been delegated to for
    /// matches
    ///
    /// Authorizes fees to be settled out of the wallet by the holder of the
    /// corresponding private key
    pub managing_cluster: EncryptionKey,
    /// key The wallet randomness used to blind secret shares
    #[serde(serialize_with = "scalar_to_hex_string", deserialize_with = "scalar_from_hex_string")]
    pub blinder: Scalar,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> Default
    for Wallet<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    fn default() -> Self {
        Self {
            balances: (0..MAX_BALANCES)
                .map(|_| Balance::default())
                .collect_vec()
                .try_into()
                .unwrap(),
            orders: (0..MAX_ORDERS).map(|_| Order::default()).collect_vec().try_into().unwrap(),
            keys: PublicKeyChain::default(),
            max_match_fee: FixedPoint::from_integer(0),
            managing_cluster: EncryptionKey::default(),
            blinder: Scalar::zero(),
        }
    }
}

#[cfg(feature = "proof-system-types")]
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> WalletShare<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// Blinds the wallet, but does not blind the blinder itself
    ///
    /// This is necessary because the default implementation of `blind` that is
    /// derived by the macro will blind the blinder as well as the shares,
    /// which is undesirable
    pub fn blind_shares(&self, blinder: Scalar) -> WalletShare<MAX_BALANCES, MAX_ORDERS> {
        let prev_blinder = self.blinder;
        let mut blinded = self.blind(blinder);
        blinded.blinder = prev_blinder;

        blinded
    }

    /// Unblinds the wallet, but does not unblind the blinder itself
    pub fn unblind_shares(&self, blinder: Scalar) -> WalletShare<MAX_BALANCES, MAX_ORDERS> {
        let prev_blinder = self.blinder;
        let mut unblinded = self.unblind(blinder);
        unblinded.blinder = prev_blinder;

        unblinded
    }
}

#[cfg(feature = "proof-system-types")]
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize> WalletShareVar<MAX_BALANCES, MAX_ORDERS>
where
    [(); MAX_BALANCES + MAX_ORDERS]: Sized,
{
    /// Blinds the wallet, but does not blind the blinder itself
    ///
    /// This is necessary because the default implementation of `blind` that is
    /// derived by the macro will blind the blinder as well as the shares,
    /// which is undesirable
    pub fn blind_shares<C: Circuit<ScalarField>>(
        self,
        blinder: Variable,
        circuit: &mut C,
    ) -> WalletShareVar<MAX_BALANCES, MAX_ORDERS> {
        let prev_blinder = self.blinder;
        let mut blinded = self.blind(blinder, circuit);
        blinded.blinder = prev_blinder;

        blinded
    }

    /// Unblinds the wallet, but does not unblind the blinder itself
    pub fn unblind_shares<C: Circuit<ScalarField>>(
        self,
        blinder: Variable,
        circuit: &mut C,
    ) -> WalletShareVar<MAX_BALANCES, MAX_ORDERS> {
        let prev_blinder = self.blinder;
        let mut unblinded = self.unblind(blinder, circuit);
        unblinded.blinder = prev_blinder;

        unblinded
    }
}
