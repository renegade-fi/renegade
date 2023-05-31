//! Groups type definitions for a wallet and implements traits to allocate
//! the wallet
#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use std::ops::Add;

use circuit_macros::circuit_type;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::r1cs::{LinearCombination, Variable};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    traits::{
        BaseType, CircuitBaseType, CircuitCommitmentType, CircuitVarType, LinearCombinationLike,
        LinkableBaseType, LinkableType, SecretShareBaseType, SecretShareType, SecretShareVarType,
    },
    types::{scalar_from_hex_string, scalar_to_hex_string},
};

use super::{
    balance::Balance, deserialize_array, fee::Fee, keychain::PublicKeyChain, order::Order,
    serialize_array,
};

/// A commitment to the wallet's secret shares that is entered into the global state
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
#[circuit_type(serde, singleprover_circuit, secret_share)]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Wallet<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The list of balances in the wallet
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub balances: [Balance; MAX_BALANCES],
    /// The list of open orders in the wallet
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub orders: [Order; MAX_ORDERS],
    /// The list of payable fees in the wallet
    #[serde(
        serialize_with = "serialize_array",
        deserialize_with = "deserialize_array"
    )]
    pub fees: [Fee; MAX_FEES],
    /// The key tuple used by the wallet; i.e. (pk_root, pk_match, pk_settle, pk_view)
    pub keys: PublicKeyChain,
    /// The wallet randomness used to blind secret shares
    #[serde(
        serialize_with = "scalar_to_hex_string",
        deserialize_with = "scalar_from_hex_string"
    )]
    pub blinder: Scalar,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> Default
    for Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    fn default() -> Self {
        Self {
            balances: (0..MAX_BALANCES)
                .map(|_| Balance::default())
                .collect_vec()
                .try_into()
                .unwrap(),
            orders: (0..MAX_ORDERS)
                .map(|_| Order::default())
                .collect_vec()
                .try_into()
                .unwrap(),
            fees: (0..MAX_FEES)
                .map(|_| Fee::default())
                .collect_vec()
                .try_into()
                .unwrap(),
            keys: PublicKeyChain::default(),
            blinder: Scalar::zero(),
        }
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Blinds the wallet, but does not blind the blinder itself
    ///
    /// This is necessary because the default implementation of `blind` that is derived
    /// by the macro will blind the blinder as well as the shares, which is undesirable
    pub fn blind_shares(self, blinder: Scalar) -> WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES> {
        let prev_blinder = self.blinder;
        let mut blinded = self.blind(blinder);
        blinded.blinder = prev_blinder;

        blinded
    }

    /// Unblinds the wallet, but does not unblind the blinder itself
    pub fn unblind_shares(
        self,
        blinder: Scalar,
    ) -> WalletShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES> {
        let prev_blinder = self.blinder;
        let mut unblinded = self.unblind(blinder);
        unblinded.blinder = prev_blinder;

        unblinded
    }
}

impl<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
        L: LinearCombinationLike,
    > WalletShareVar<L, MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// Blinds the wallet, but does not blind the blinder itself
    ///
    /// This is necessary because the default implementation of `blind` that is derived
    /// by the macro will blind the blinder as well as the shares, which is undesirable
    pub fn blind_shares<L1: LinearCombinationLike>(
        self,
        blinder: L1,
    ) -> WalletShareVar<LinearCombination, MAX_BALANCES, MAX_ORDERS, MAX_FEES> {
        let prev_blinder = self.blinder.clone();
        let mut blinded = self.blind(blinder);
        blinded.blinder = prev_blinder.into();

        blinded
    }

    /// Unblinds the wallet, but does not unblind the blinder itself
    pub fn unblind_shares<L1: LinearCombinationLike>(
        self,
        blinder: L1,
    ) -> WalletShareVar<LinearCombination, MAX_BALANCES, MAX_ORDERS, MAX_FEES> {
        let prev_blinder = self.blinder.clone();
        let mut unblinded = self.unblind(blinder);
        unblinded.blinder = prev_blinder.into();

        unblinded
    }
}
