//! Groups type definitions for a wallet and implements traits to allocate
//! the wallet

use std::ops::Add;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::r1cs::{LinearCombination, Prover, Variable, Verifier};
use mpc_ristretto::{beaver::SharedValueSource, error::MpcError, network::MpcNetwork};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::{
    mpc::SharedFabric,
    types::{scalar_from_hex_string, scalar_to_hex_string},
    CommitPublic, CommitVerifier, CommitWitness, LinkableCommitment, SharePublic,
};

use super::{
    balance::{
        Balance, BalanceSecretShare, BalanceSecretShareCommitment, BalanceSecretShareVar,
        BalanceVar, CommittedBalance, LinkableBalanceShareCommitment,
    },
    deserialize_array,
    fee::{
        CommittedFee, Fee, FeeSecretShare, FeeSecretShareCommitment, FeeSecretShareVar, FeeVar,
        LinkableFeeShareCommitment,
    },
    keychain::{
        CommittedPublicKeyChain, LinkablePublicKeyChainShareCommitment, PublicKeyChain,
        PublicKeyChainSecretShare, PublicKeyChainSecretShareCommitment,
        PublicKeyChainSecretShareVar, PublicKeyChainVar,
    },
    order::{
        CommittedOrder, LinkableOrderShareCommitment, Order, OrderSecretShare,
        OrderSecretShareCommitment, OrderSecretShareVar, OrderVar,
    },
    serialize_array,
};

/// Commitment type alias for readability
pub type WalletShareCommitment = Scalar;
/// Commitment type alias for readability
pub type NoteCommitment = Scalar;
/// Nullifier type alias for readability
pub type Nullifier = Scalar;

// --------------------
// | Wallet Base Type |
// --------------------

/// Represents the base type of a wallet holding orders, balances, fees, keys
/// and cryptographic randomness
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

/// Represents a wallet that has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct WalletVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
    L: Into<LinearCombination>,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The list of balances in the wallet
    pub balances: [BalanceVar<L>; MAX_BALANCES],
    /// The list of open orders in the wallet
    pub orders: [OrderVar<L>; MAX_ORDERS],
    /// The list of payable fees in the wallet
    pub fees: [FeeVar<L>; MAX_FEES],
    /// The key tuple used by the wallet; i.e. (pk_root, pk_match, pk_settle, pk_view)
    pub keys: PublicKeyChainVar<L>,
    /// The wallet randomness used to blind secret shares
    pub blinder: L,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type CommitType = CommittedWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type VarType = WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, Variable>;
    type ErrorType = ();

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (balance_vars, committed_balances): (Vec<BalanceVar<Variable>>, Vec<CommittedBalance>) =
            self.balances
                .iter()
                .map(|balance| balance.commit_witness(rng, prover).unwrap())
                .unzip();

        let (order_vars, committed_orders): (Vec<OrderVar<Variable>>, Vec<CommittedOrder>) = self
            .orders
            .iter()
            .map(|order| order.commit_witness(rng, prover).unwrap())
            .unzip();

        let (fee_vars, committed_fees): (Vec<FeeVar<Variable>>, Vec<CommittedFee>) = self
            .fees
            .iter()
            .map(|fee| fee.commit_witness(rng, prover).unwrap())
            .unzip();

        let (key_vars, key_comms) = self.keys.commit_witness(rng, prover).unwrap();
        let (blinder_comm, blinder_var) = prover.commit(self.blinder, Scalar::random(rng));

        Ok((
            WalletVar {
                balances: balance_vars.try_into().unwrap(),
                orders: order_vars.try_into().unwrap(),
                fees: fee_vars.try_into().unwrap(),
                keys: key_vars,
                blinder: blinder_var,
            },
            CommittedWallet {
                balances: committed_balances.try_into().unwrap(),
                orders: committed_orders.try_into().unwrap(),
                fees: committed_fees.try_into().unwrap(),
                keys: key_comms,
                blinder: blinder_comm,
            },
        ))
    }
}

/// Represents a commitment to a wallet in the constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedWallet<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    /// The list of balances in the wallet
    #[serde(with = "serde_arrays")]
    pub balances: [CommittedBalance; MAX_BALANCES],
    /// The list of open orders in the wallet
    #[serde(with = "serde_arrays")]
    pub orders: [CommittedOrder; MAX_ORDERS],
    /// The list of payable fees in the wallet
    #[serde(with = "serde_arrays")]
    pub fees: [CommittedFee; MAX_FEES],
    /// The key tuple used by the wallet; i.e. (pk_root, pk_match, pk_settle, pk_view)
    pub keys: CommittedPublicKeyChain,
    /// The wallet randomness used to blind secret shares
    pub blinder: CompressedRistretto,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for CommittedWallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type VarType = WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, Variable>;
    type ErrorType = ();

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let balance_vars = self
            .balances
            .iter()
            .map(|balance| balance.commit_verifier(verifier).unwrap())
            .collect_vec();
        let order_vars = self
            .orders
            .iter()
            .map(|order| order.commit_verifier(verifier).unwrap())
            .collect_vec();
        let fee_vars = self
            .fees
            .iter()
            .map(|fee| fee.commit_verifier(verifier).unwrap())
            .collect_vec();

        let key_vars = self.keys.commit_verifier(verifier).unwrap();
        let blinder_var = verifier.commit(self.blinder);

        Ok(WalletVar {
            balances: balance_vars.try_into().unwrap(),
            orders: order_vars.try_into().unwrap(),
            fees: fee_vars.try_into().unwrap(),
            keys: key_vars,
            blinder: blinder_var,
        })
    }
}

// ----------------------------
// | Wallet Secret Share Type |
// ----------------------------

/// Represents an additive secret share of a wallet
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletSecretShare<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The list of balances in the wallet
    #[serde(with = "serde_arrays")]
    pub balances: [BalanceSecretShare; MAX_BALANCES],
    /// The list of open orders in the wallet
    #[serde(with = "serde_arrays")]
    pub orders: [OrderSecretShare; MAX_ORDERS],
    /// The list of payable fees in the wallet
    #[serde(with = "serde_arrays")]
    pub fees: [FeeSecretShare; MAX_FEES],
    /// The key tuple used by the wallet; i.e. (pk_root, pk_match, pk_settle, pk_view)
    pub keys: PublicKeyChainSecretShare,
    /// The wallet randomness used to blind secret shares
    pub blinder: Scalar,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    /// The number of `Scalar` shares needed to fully represent a wallet
    pub const SHARES_PER_WALLET: usize = MAX_BALANCES * BalanceSecretShare::SHARES_PER_BALANCE
        + MAX_ORDERS * OrderSecretShare::SHARES_PER_ORDER
        + MAX_FEES * FeeSecretShare::SHARES_PER_FEE
        + PublicKeyChainSecretShare::SHARES_PER_KEYCHAIN
        + 1; // wallet blinder share

    /// Apply the wallet blinder to the secret shares
    pub fn blind(&mut self, blinder: Scalar) {
        self.balances.iter_mut().for_each(|b| b.blind(blinder));
        self.orders.iter_mut().for_each(|o| o.blind(blinder));
        self.fees.iter_mut().for_each(|f| f.blind(blinder));
        self.keys.blind(blinder);
    }

    /// Remove the wallet blinder from the secret shares
    pub fn unblind(&mut self, blinder: Scalar) {
        self.balances.iter_mut().for_each(|b| b.unblind(blinder));
        self.orders.iter_mut().for_each(|o| o.unblind(blinder));
        self.fees.iter_mut().for_each(|f| f.unblind(blinder));
        self.keys.unblind(blinder);
    }

    /// Clone the underlying shares and unblind them
    pub fn unblind_cloned(&self, blinder: Scalar) -> Self {
        let mut cloned = self.clone();
        cloned.unblind(blinder);
        cloned
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    Add<WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>
    for WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Output = Wallet<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;

    fn add(self, rhs: Self) -> Self::Output {
        let balances = self
            .balances
            .into_iter()
            .zip(rhs.balances.into_iter())
            .map(|(b1, b2)| b1 + b2)
            .collect_vec();

        let orders = self
            .orders
            .into_iter()
            .zip(rhs.orders.into_iter())
            .map(|(o1, o2)| o1 + o2)
            .collect_vec();

        let fees = self
            .fees
            .into_iter()
            .zip(rhs.fees.into_iter())
            .map(|(f1, f2)| f1 + f2)
            .collect_vec();

        let keys = self.keys + rhs.keys;
        let blinder = self.blinder + rhs.blinder;

        Self::Output {
            balances: balances.try_into().unwrap(),
            orders: orders.try_into().unwrap(),
            fees: fees.try_into().unwrap(),
            keys,
            blinder,
        }
    }
}

// Wallet share serialization
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    From<WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>> for Vec<Scalar>
{
    fn from(wallet: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>) -> Self {
        let mut wallet_shares: Vec<Scalar> = Vec::new();
        for balance in wallet.balances.into_iter() {
            wallet_shares.append(&mut balance.into())
        }

        for order in wallet.orders.into_iter() {
            wallet_shares.append(&mut order.into());
        }

        for fee in wallet.fees.into_iter() {
            wallet_shares.append(&mut fee.into());
        }

        wallet_shares.append(&mut wallet.keys.into());
        wallet_shares.push(wallet.blinder);

        wallet_shares
    }
}

// Wallet share deserialization
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> From<Vec<Scalar>>
    for WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    fn from(mut serialized: Vec<Scalar>) -> Self {
        // Deserialized balances
        let mut balances = Vec::with_capacity(MAX_BALANCES);
        for _ in 0..MAX_BALANCES {
            let next_vec = serialized
                .drain(..BalanceSecretShare::SHARES_PER_BALANCE)
                .collect_vec();
            balances.push(BalanceSecretShare::from(next_vec));
        }

        // Deserialize orders
        let mut orders = Vec::with_capacity(MAX_ORDERS);
        for _ in 0..MAX_ORDERS {
            let next_vec = serialized
                .drain(..OrderSecretShare::SHARES_PER_ORDER)
                .collect_vec();
            orders.push(OrderSecretShare::from(next_vec));
        }

        // Deserialize fees
        let mut fees = Vec::with_capacity(MAX_FEES);
        for _ in 0..MAX_FEES {
            let next_vec = serialized
                .drain(..FeeSecretShare::SHARES_PER_FEE)
                .collect_vec();
            fees.push(FeeSecretShare::from(next_vec));
        }

        // Pop the last element off for the blinder
        let blinder = serialized.pop().unwrap();

        // Deserialize the keychain from the rest of the elements
        let keychain = PublicKeyChainSecretShare::from(serialized);

        WalletSecretShare {
            balances: balances.try_into().unwrap(),
            orders: orders.try_into().unwrap(),
            fees: fees.try_into().unwrap(),
            keys: keychain,
            blinder,
        }
    }
}

impl<
        const MAX_BALANCES: usize,
        const MAX_ORDERS: usize,
        const MAX_FEES: usize,
        N: MpcNetwork + Send,
        S: SharedValueSource<Scalar>,
    > SharePublic<N, S> for WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type ErrorType = MpcError;

    fn share_public(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self, Self::ErrorType> {
        let shares_serialized: Vec<Scalar> = self.clone().into();
        let res = fabric
            .borrow_fabric()
            .batch_shared_plaintext_scalars(owning_party, &shares_serialized)?;
        Ok(res.into())
    }
}

/// Represents an additive secret share of a wallet that
/// has been allocated in a constraint system
#[derive(Clone, Debug)]
pub struct WalletSecretShareVar<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The list of balances in the wallet
    pub balances: [BalanceSecretShareVar; MAX_BALANCES],
    /// The list of open orders in the wallet
    pub orders: [OrderSecretShareVar; MAX_ORDERS],
    /// The list of payable fees in the wallet
    pub fees: [FeeSecretShareVar; MAX_FEES],
    /// The key tuple used by the wallet; i.e. (pk_root, pk_match, pk_settle, pk_view)
    pub keys: PublicKeyChainSecretShareVar,
    /// The wallet randomness used to blind secret shares
    pub blinder: LinearCombination,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    /// Apply the wallet blinder to the secret shares
    pub fn blind(&mut self, blinder: LinearCombination) {
        self.balances
            .iter_mut()
            .for_each(|b| b.blind(blinder.clone()));
        self.orders
            .iter_mut()
            .for_each(|o| o.blind(blinder.clone()));
        self.fees.iter_mut().for_each(|f| f.blind(blinder.clone()));
        self.keys.blind(blinder);
    }

    /// Remove the wallet blinder from the secret shares
    pub fn unblind(&mut self, blinder: LinearCombination) {
        self.balances
            .iter_mut()
            .for_each(|b| b.unblind(blinder.clone()));
        self.orders
            .iter_mut()
            .for_each(|o| o.unblind(blinder.clone()));
        self.fees
            .iter_mut()
            .for_each(|f| f.unblind(blinder.clone()));
        self.keys.unblind(blinder);
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    Add<WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>
    for WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
where
    [(); MAX_BALANCES + MAX_ORDERS + MAX_FEES]: Sized,
{
    type Output = WalletVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES, LinearCombination>;

    fn add(self, rhs: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>) -> Self::Output {
        let balances = self
            .balances
            .into_iter()
            .zip(rhs.balances.into_iter())
            .map(|(b1, b2)| b1 + b2)
            .collect_vec();

        let orders = self
            .orders
            .into_iter()
            .zip(rhs.orders.into_iter())
            .map(|(o1, o2)| o1 + o2)
            .collect_vec();

        let fees = self
            .fees
            .into_iter()
            .zip(rhs.fees.into_iter())
            .map(|(f1, f2)| f1 + f2)
            .collect_vec();

        let keys = self.keys + rhs.keys;
        let blinder = self.blinder + rhs.blinder;

        Self::Output {
            balances: balances.try_into().unwrap(),
            orders: orders.try_into().unwrap(),
            fees: fees.try_into().unwrap(),
            keys,
            blinder,
        }
    }
}

// Wallet share serialization
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    From<WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>> for Vec<LinearCombination>
{
    fn from(wallet: WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>) -> Self {
        let mut wallet_shares: Vec<LinearCombination> = Vec::new();
        wallet
            .balances
            .into_iter()
            .for_each(|b| wallet_shares.append(&mut b.into()));

        wallet
            .orders
            .into_iter()
            .for_each(|o| wallet_shares.append(&mut o.into()));

        wallet
            .fees
            .into_iter()
            .for_each(|f| wallet_shares.append(&mut f.into()));

        wallet_shares.append(&mut wallet.keys.into());
        wallet_shares.push(wallet.blinder);

        wallet_shares
    }
}

// Wallet share deserialization
impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    From<Vec<LinearCombination>> for WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    fn from(mut serialized: Vec<LinearCombination>) -> Self {
        let mut balances = Vec::with_capacity(MAX_BALANCES);
        for _ in 0..MAX_BALANCES {
            let next_vec = serialized
                .drain(..BalanceSecretShare::SHARES_PER_BALANCE)
                .collect_vec();
            balances.push(BalanceSecretShareVar::from(next_vec));
        }

        let mut orders = Vec::with_capacity(MAX_ORDERS);
        for _ in 0..MAX_ORDERS {
            let next_vec = serialized
                .drain(..OrderSecretShare::SHARES_PER_ORDER)
                .collect_vec();
            orders.push(OrderSecretShareVar::from(next_vec));
        }

        let mut fees = Vec::with_capacity(MAX_FEES);
        for _ in 0..MAX_FEES {
            let next_vec = serialized
                .drain(..FeeSecretShare::SHARES_PER_FEE)
                .collect_vec();
            fees.push(FeeSecretShareVar::from(next_vec));
        }

        let blinder = serialized.pop().unwrap();
        let keys = PublicKeyChainSecretShareVar::from(serialized);

        WalletSecretShareVar {
            balances: balances.try_into().unwrap(),
            orders: orders.try_into().unwrap(),
            fees: fees.try_into().unwrap(),
            keys,
            blinder,
        }
    }
}

/// Represents a commitment to an additive secret share of a wallet that
/// has been allocated in a constraint system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletSecretShareCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The list of balances in the wallet
    #[serde(with = "serde_arrays")]
    pub balances: [BalanceSecretShareCommitment; MAX_BALANCES],
    /// The list of open orders in the wallet
    #[serde(with = "serde_arrays")]
    pub orders: [OrderSecretShareCommitment; MAX_ORDERS],
    /// The list of payable fees in the wallet
    #[serde(with = "serde_arrays")]
    pub fees: [FeeSecretShareCommitment; MAX_FEES],
    /// The key tuple used by the wallet; i.e. (pk_root, pk_match, pk_settle, pk_view)
    pub keys: PublicKeyChainSecretShareCommitment,
    /// The wallet randomness used to blind secret shares
    pub blinder: CompressedRistretto,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type VarType = WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (balance_vars, balance_comms): (
            Vec<BalanceSecretShareVar>,
            Vec<BalanceSecretShareCommitment>,
        ) = self
            .balances
            .iter()
            .map(|b| b.commit_witness(rng, prover).unwrap())
            .unzip();

        let (order_vars, order_comms): (Vec<OrderSecretShareVar>, Vec<OrderSecretShareCommitment>) =
            self.orders
                .iter()
                .map(|o| o.commit_witness(rng, prover).unwrap())
                .unzip();

        let (fee_vars, fee_comms): (Vec<FeeSecretShareVar>, Vec<FeeSecretShareCommitment>) = self
            .fees
            .iter()
            .map(|f| f.commit_witness(rng, prover).unwrap())
            .unzip();

        let (key_var, key_comm) = self.keys.commit_witness(rng, prover).unwrap();
        let (blinder_var, blinder_comm) = self.blinder.commit_witness(rng, prover).unwrap();

        Ok((
            WalletSecretShareVar {
                balances: balance_vars.try_into().unwrap(),
                orders: order_vars.try_into().unwrap(),
                fees: fee_vars.try_into().unwrap(),
                keys: key_var,
                blinder: blinder_var.into(),
            },
            WalletSecretShareCommitment {
                balances: balance_comms.try_into().unwrap(),
                orders: order_comms.try_into().unwrap(),
                fees: fee_comms.try_into().unwrap(),
                keys: key_comm,
                blinder: blinder_comm,
            },
        ))
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitPublic
    for WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type VarType = WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_public<CS: mpc_bulletproof::r1cs::RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let balance_vars = self
            .balances
            .iter()
            .map(|b| b.commit_public(cs).unwrap())
            .collect_vec();

        let order_vars = self
            .orders
            .iter()
            .map(|o| o.commit_public(cs).unwrap())
            .collect_vec();

        let fee_vars = self
            .fees
            .iter()
            .map(|f| f.commit_public(cs).unwrap())
            .collect_vec();

        let key_var = self.keys.commit_public(cs).unwrap();
        let blinder_var = self.blinder.commit_public(cs).unwrap();

        Ok(WalletSecretShareVar {
            balances: balance_vars.try_into().unwrap(),
            orders: order_vars.try_into().unwrap(),
            fees: fee_vars.try_into().unwrap(),
            keys: key_var,
            blinder: blinder_var.into(),
        })
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitVerifier
    for WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type VarType = WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let balance_vars = self
            .balances
            .iter()
            .map(|b| b.commit_verifier(verifier).unwrap())
            .collect_vec();

        let order_vars = self
            .orders
            .iter()
            .map(|o| o.commit_verifier(verifier).unwrap())
            .collect_vec();

        let fee_vars = self
            .fees
            .iter()
            .map(|f| f.commit_verifier(verifier).unwrap())
            .collect_vec();

        let key_var = self.keys.commit_verifier(verifier).unwrap();
        let blinder_var = self.blinder.commit_verifier(verifier).unwrap();

        Ok(WalletSecretShareVar {
            balances: balance_vars.try_into().unwrap(),
            orders: order_vars.try_into().unwrap(),
            fees: fee_vars.try_into().unwrap(),
            keys: key_var,
            blinder: blinder_var.into(),
        })
    }
}

/// A wallet secret share that may be linked across proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkableWalletSecretShareCommitment<
    const MAX_BALANCES: usize,
    const MAX_ORDERS: usize,
    const MAX_FEES: usize,
> {
    /// The list of balances in the wallet
    #[serde(with = "serde_arrays")]
    pub balances: [LinkableBalanceShareCommitment; MAX_BALANCES],
    /// The list of open orders in the wallet
    #[serde(with = "serde_arrays")]
    pub orders: [LinkableOrderShareCommitment; MAX_ORDERS],
    /// The list of payable fees in the wallet
    #[serde(with = "serde_arrays")]
    pub fees: [LinkableFeeShareCommitment; MAX_FEES],
    /// The key tuple used by the wallet; i.e. (pk_root, pk_match, pk_settle, pk_view)
    pub keys: LinkablePublicKeyChainShareCommitment,
    /// The wallet randomness used to blind secret shares
    pub blinder: LinkableCommitment,
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize>
    From<WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>>
    for LinkableWalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    fn from(wallet: WalletSecretShare<MAX_BALANCES, MAX_ORDERS, MAX_FEES>) -> Self {
        LinkableWalletSecretShareCommitment {
            balances: wallet
                .balances
                .into_iter()
                .map(|b| b.into())
                .collect_vec()
                .try_into()
                .unwrap(),
            orders: wallet
                .orders
                .into_iter()
                .map(|o| o.into())
                .collect_vec()
                .try_into()
                .unwrap(),
            fees: wallet
                .fees
                .into_iter()
                .map(|f| f.into())
                .collect_vec()
                .try_into()
                .unwrap(),
            keys: wallet.keys.into(),
            blinder: wallet.blinder.into(),
        }
    }
}

impl<const MAX_BALANCES: usize, const MAX_ORDERS: usize, const MAX_FEES: usize> CommitWitness
    for LinkableWalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>
{
    type VarType = WalletSecretShareVar<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type CommitType = WalletSecretShareCommitment<MAX_BALANCES, MAX_ORDERS, MAX_FEES>;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (balance_vars, balance_comms): (
            Vec<BalanceSecretShareVar>,
            Vec<BalanceSecretShareCommitment>,
        ) = self
            .balances
            .iter()
            .map(|b| b.commit_witness(rng, prover).unwrap())
            .unzip();
        let (order_vars, order_comms): (Vec<OrderSecretShareVar>, Vec<OrderSecretShareCommitment>) =
            self.orders
                .iter()
                .map(|o| o.commit_witness(rng, prover).unwrap())
                .unzip();
        let (fee_vars, fee_comms): (Vec<FeeSecretShareVar>, Vec<FeeSecretShareCommitment>) = self
            .fees
            .iter()
            .map(|f| f.commit_witness(rng, prover).unwrap())
            .unzip();
        let (keychain_var, keychain_comm) = self.keys.commit_witness(rng, prover).unwrap();
        let (blinder_var, blinder_comm) = self.blinder.commit_witness(rng, prover).unwrap();

        Ok((
            WalletSecretShareVar {
                balances: balance_vars.try_into().unwrap(),
                orders: order_vars.try_into().unwrap(),
                fees: fee_vars.try_into().unwrap(),
                keys: keychain_var,
                blinder: blinder_var.into(),
            },
            WalletSecretShareCommitment {
                balances: balance_comms.try_into().unwrap(),
                orders: order_comms.try_into().unwrap(),
                fees: fee_comms.try_into().unwrap(),
                keys: keychain_comm,
                blinder: blinder_comm,
            },
        ))
    }
}
