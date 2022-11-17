//! Groups type definitons that are used throughout the mpc/zk circuitry
//!
//! Broadly each entity (e.g. balance, order, etc) has 4 types:
//!     1. Base type (e.g. `Balance`): this type is the most semanticly meaningful as the values
//!        take on their native types, u64, BigInt, etc.
//!     2. Var type (e.g. `BalanceVar`): this represents its base type after being committed to
//!        in a Dalek-style constraint system. The `Commit` trait converts from base type to var type
//!     3. Authenticated type (e.g. `AuthenticatedBalance`): this represents the type after it has
//!        been allocated in the MPC network and given a MAC (hence authenticated). These types are
//!        used for raw MPC computation. The `Allocate` trait converts base type to Authenticated type
//!     4. AuthenticatedVar type (e.g. `AuthenticatedBalanceVar`): this represents the base type after
//!        its values have been allocated in the network and committed to in a multi-prover constraint
//!        system. These types are used for collaborative proofs. The `CommitShared52Go` trait takes the
//!        base type to the AuthenticatedVar type.

use std::borrow::Borrow;

use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{Prover, Variable, Verifier},
    r1cs_mpc::{MpcProver, MpcVariable},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigInt;
use rand_core::{CryptoRng, RngCore};

use crate::{
    bigint_to_scalar,
    errors::{MpcError, TypeConversionError},
    mpc::SharedFabric,
    Allocate, CommitProver, CommitSharedProver, CommitVerifier, Open,
};

/**
 * Balance type
 */

/// Represents the base type of a balance in tuple holding a reference to the
/// ERC-20 token and its amount
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Balance {
    /// The mint (ERC-20 token address) of the token in the balance
    pub mint: u64,
    /// The amount of the given token stored in this balance
    pub amount: u64,
}

/// Convert a vector of u64s to a Balance
impl TryFrom<&[u64]> for Balance {
    type Error = TypeConversionError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        if values.len() != 2 {
            return Err(TypeConversionError(format!(
                "expected array of length 2, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            mint: values[0],
            amount: values[1],
        })
    }
}

impl From<&Balance> for Vec<u64> {
    fn from(balance: &Balance) -> Self {
        vec![balance.mint, balance.amount]
    }
}

/// Represents the constraint system allocated type of a balance in tuple holding a
/// reference to the ERC-20 token and its amount
#[derive(Clone, Debug)]
pub struct BalanceVar {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: Variable,
    /// the amount of the given token stored in this balance
    pub amount: Variable,
}

impl CommitProver for Balance {
    type VarType = BalanceVar;
    type CommitType = CommittedBalance;
    type ErrorType = (); // Does not error

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (mint_comm, mint_var) =
            prover.commit(Scalar::from(self.mint), Scalar::random(&mut rng));
        let (amount_comm, amount_var) =
            prover.commit(Scalar::from(self.amount), Scalar::random(&mut rng));

        Ok((
            BalanceVar {
                mint: mint_var,
                amount: amount_var,
            },
            CommittedBalance {
                mint: mint_comm,
                amount: amount_comm,
            },
        ))
    }
}

/// Represents the committed type of the balance tuple
#[derive(Clone, Debug)]
pub struct CommittedBalance {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: CompressedRistretto,
    /// the amount of the given token stored in this balance
    pub amount: CompressedRistretto,
}

impl CommitVerifier for CommittedBalance {
    type VarType = BalanceVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        Ok(BalanceVar {
            mint: verifier.commit(self.mint),
            amount: verifier.commit(self.amount),
        })
    }
}

/// Represents a balance that has been allocated in an MPC network
#[derive(Clone, Debug)]
pub struct AuthenticatedBalance<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: AuthenticatedScalar<N, S>,
    /// the amount of the given token stored in this balance
    pub amount: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for Balance {
    type SharedType = AuthenticatedBalance<N, S>;
    type ErrorType = MpcError;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType> {
        let shared_values = fabric
            .borrow_fabric()
            .batch_allocate_private_u64s(owning_party, &[self.amount, self.mint])
            .map_err(|err| MpcError::SharingError(err.to_string()))?
            .to_owned();

        Ok(Self::SharedType {
            mint: shared_values[0],
            amount: shared_values[1],
        })
    }
}

/// Represents a balance that has been allocated in an MPC network
/// and committed to in a multi-prover constraint system
#[derive(Clone, Debug)]
pub struct AuthenticatedBalanceVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: MpcVariable<N, S>,
    /// the amount of the given token stored in this balance
    pub amount: MpcVariable<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S> for Balance {
    type SharedVarType = AuthenticatedBalanceVar<N, S>;
    type CommitType = AuthenticatedCommittedBalance<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let blinders = &[Scalar::random(&mut rng), Scalar::random(&mut rng)];
        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[Scalar::from(self.mint), Scalar::from(self.amount)],
                blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            AuthenticatedBalanceVar {
                mint: shared_vars[0],
                amount: shared_vars[1],
            },
            AuthenticatedCommittedBalance {
                mint: shared_comm[0],
                amount: shared_comm[1],
            },
        ))
    }
}

/// A balance that has been authenticated and committed in the network
#[derive(Clone, Debug)]
pub struct AuthenticatedCommittedBalance<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// the mint (erc-20 token address) of the token in the balance
    pub mint: AuthenticatedCompressedRistretto<N, S>,
    /// the amount of the given token stored in this balance
    pub amount: AuthenticatedCompressedRistretto<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitVerifier
    for AuthenticatedCommittedBalance<N, S>
{
    type VarType = BalanceVar;
    type ErrorType = MpcError;

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        // Open the committments
        let opened_commit = AuthenticatedCompressedRistretto::batch_open_and_authenticate(&[
            self.mint,
            self.amount,
        ])
        .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let mint_var = verifier.commit(opened_commit[0].value());
        let amount_var = verifier.commit(opened_commit[1].value());

        Ok(BalanceVar {
            mint: mint_var,
            amount: amount_var,
        })
    }
}

/**
 * Orders
 */

/// Represents the base type of an open order, including the asset pair, the amount, price,
/// and direction
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: u64,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: u64,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: OrderSide,
    /// The limit price to be executed at, in units of quote
    pub price: u64,
    /// The amount of base currency to buy or sell
    pub amount: u64,
}

/// Convert a vector of u64s to an Order
impl TryFrom<&[u64]> for Order {
    type Error = TypeConversionError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        if value.len() != 5 {
            return Err(TypeConversionError(format!(
                "expected array of length 5, got {:?}",
                value.len()
            )));
        }

        // Check that the side is 0 or 1
        if !(value[2] == 0 || value[2] == 1) {
            return Err(TypeConversionError(format!(
                "Order side must be 0 or 1, got {:?}",
                value[2]
            )));
        }

        Ok(Self {
            quote_mint: value[0],
            base_mint: value[1],
            side: if value[2] == 0 {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            },
            price: value[3],
            amount: value[4],
        })
    }
}

/// Convert an order to a vector of u64s
///
/// Useful for allocating, sharing, serialization, etc
impl From<&Order> for Vec<u64> {
    fn from(o: &Order) -> Self {
        vec![o.quote_mint, o.base_mint, o.side.into(), o.price, o.amount]
    }
}

/// The side of the market a given order is on
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderSide {
    /// Buy side
    Buy = 0,
    /// Sell side
    Sell,
}

// Default for an empty order is buy
impl Default for OrderSide {
    fn default() -> Self {
        OrderSide::Buy
    }
}

impl From<OrderSide> for u64 {
    fn from(side: OrderSide) -> Self {
        match side {
            OrderSide::Buy => 0,
            OrderSide::Sell => 1,
        }
    }
}

/// An order with values allocated in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct OrderVar {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: Variable,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: Variable,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: Variable,
    /// The limit price to be executed at, in units of quote
    pub price: Variable,
    /// The amount of base currency to buy or sell
    pub amount: Variable,
}

impl CommitProver for Order {
    type VarType = OrderVar;
    type CommitType = CommittedOrder;
    type ErrorType = (); // Does not error

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (quote_comm, quote_var) =
            prover.commit(Scalar::from(self.quote_mint), Scalar::random(&mut rng));
        let (base_comm, base_var) =
            prover.commit(Scalar::from(self.base_mint), Scalar::random(&mut rng));
        let (side_comm, side_var) =
            prover.commit(Scalar::from(self.side as u64), Scalar::random(&mut rng));
        let (price_comm, price_var) =
            prover.commit(Scalar::from(self.price), Scalar::random(&mut rng));
        let (amount_comm, amount_var) =
            prover.commit(Scalar::from(self.amount), Scalar::random(&mut rng));

        Ok((
            OrderVar {
                quote_mint: quote_var,
                base_mint: base_var,
                side: side_var,
                price: price_var,
                amount: amount_var,
            },
            CommittedOrder {
                quote_mint: quote_comm,
                base_mint: base_comm,
                side: side_comm,
                price: price_comm,
                amount: amount_comm,
            },
        ))
    }
}

/// An order that has been committed to by a prover
#[derive(Clone, Debug)]
pub struct CommittedOrder {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: CompressedRistretto,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: CompressedRistretto,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: CompressedRistretto,
    /// The limit price to be executed at, in units of quote
    pub price: CompressedRistretto,
    /// The amount of base currency to buy or sell
    pub amount: CompressedRistretto,
}

impl CommitVerifier for CommittedOrder {
    type VarType = OrderVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let quote_var = verifier.commit(self.quote_mint);
        let base_var = verifier.commit(self.base_mint);
        let side_var = verifier.commit(self.side);
        let price_var = verifier.commit(self.price);
        let amount_var = verifier.commit(self.amount);

        Ok(OrderVar {
            quote_mint: quote_var,
            base_mint: base_var,
            side: side_var,
            price: price_var,
            amount: amount_var,
        })
    }
}

/// Represents an order that has been allocated in an MPC network
#[derive(Clone, Debug)]
pub struct AuthenticatedOrder<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: AuthenticatedScalar<N, S>,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: AuthenticatedScalar<N, S>,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: AuthenticatedScalar<N, S>,
    /// The limit price to be executed at, in units of quote
    pub price: AuthenticatedScalar<N, S>,
    /// The amount of base currency to buy or sell
    pub amount: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for Order {
    type SharedType = AuthenticatedOrder<N, S>;
    type ErrorType = MpcError;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType> {
        let shared_values = fabric
            .borrow_fabric()
            .batch_allocate_private_u64s(
                owning_party,
                &[
                    self.quote_mint,
                    self.base_mint,
                    self.side.into(),
                    self.price,
                    self.amount,
                ],
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self::SharedType {
            quote_mint: shared_values[0],
            base_mint: shared_values[1],
            side: shared_values[2],
            price: shared_values[3],
            amount: shared_values[4],
        })
    }
}

/// Represents an order that has been allocated in an MPC network and committed to
/// in a multi-prover constraint system
#[derive(Clone, Debug)]
pub struct AuthenticatedOrderVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: MpcVariable<N, S>,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: MpcVariable<N, S>,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: MpcVariable<N, S>,
    /// The limit price to be executed at, in units of quote
    pub price: MpcVariable<N, S>,
    /// The amount of base currency to buy or sell
    pub amount: MpcVariable<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S> for Order {
    type SharedVarType = AuthenticatedOrderVar<N, S>;
    type CommitType = AuthenticatedCommittedOrder<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let blinders = (0..5).map(|_| Scalar::random(&mut rng)).collect_vec();
        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    Scalar::from(self.quote_mint),
                    Scalar::from(self.base_mint),
                    Scalar::from(self.side as u64),
                    Scalar::from(self.price),
                    Scalar::from(self.amount),
                ],
                &blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            AuthenticatedOrderVar {
                quote_mint: shared_vars[0],
                base_mint: shared_vars[1],
                side: shared_vars[2],
                price: shared_vars[3],
                amount: shared_vars[4],
            },
            AuthenticatedCommittedOrder {
                quote_mint: shared_comm[0],
                base_mint: shared_comm[1],
                side: shared_comm[2],
                price: shared_comm[3],
                amount: shared_comm[4],
            },
        ))
    }
}

/// Represents an order that has been committed to in a multi-prover constraint system
#[derive(Clone, Debug)]
pub struct AuthenticatedCommittedOrder<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: AuthenticatedCompressedRistretto<N, S>,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: AuthenticatedCompressedRistretto<N, S>,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: AuthenticatedCompressedRistretto<N, S>,
    /// The limit price to be executed at, in units of quote
    pub price: AuthenticatedCompressedRistretto<N, S>,
    /// The amount of base currency to buy or sell
    pub amount: AuthenticatedCompressedRistretto<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitVerifier
    for AuthenticatedCommittedOrder<N, S>
{
    type VarType = OrderVar;
    type ErrorType = MpcError;

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let opened_commit = AuthenticatedCompressedRistretto::batch_open_and_authenticate(&[
            self.quote_mint,
            self.base_mint,
            self.side,
            self.price,
            self.amount,
        ])
        .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let quote_var = verifier.commit(opened_commit[0].value());
        let base_var = verifier.commit(opened_commit[1].value());
        let side_var = verifier.commit(opened_commit[2].value());
        let price_var = verifier.commit(opened_commit[3].value());
        let amount_var = verifier.commit(opened_commit[4].value());

        Ok(OrderVar {
            quote_mint: quote_var,
            base_mint: base_var,
            side: side_var,
            price: price_var,
            amount: amount_var,
        })
    }
}

/**
 * Fees
 */

/// Represents a fee-tuple in the state, i.e. a commitment to pay a relayer for a given
/// match
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Fee {
    /// The public settle key of the cluster collecting fees
    pub settle_key: BigInt,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: BigInt,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: u64,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: u64,
}

impl TryFrom<&[u64]> for Fee {
    type Error = TypeConversionError;

    fn try_from(values: &[u64]) -> Result<Self, Self::Error> {
        if values.len() != 4 {
            return Err(TypeConversionError(format!(
                "expected array of length 4, got {:?}",
                values.len()
            )));
        }

        Ok(Self {
            settle_key: BigInt::from(values[0]),
            gas_addr: BigInt::from(values[1]),
            gas_token_amount: values[2],
            percentage_fee: values[3],
        })
    }
}

impl From<&Fee> for Vec<u64> {
    fn from(fee: &Fee) -> Self {
        vec![
            fee.settle_key.clone().try_into().unwrap(),
            fee.gas_addr.clone().try_into().unwrap(),
            fee.gas_token_amount,
            fee.percentage_fee,
        ]
    }
}

/// A fee with values allocated in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct FeeVar {
    /// The public settle key of the cluster collecting fees
    pub settle_key: Variable,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: Variable,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: Variable,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: Variable,
}

impl CommitProver for Fee {
    type VarType = FeeVar;
    type CommitType = CommittedFee;
    type ErrorType = (); // Does not error

    fn commit_prover<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (settle_comm, settle_var) =
            prover.commit(bigint_to_scalar(&self.settle_key), Scalar::random(&mut rng));
        let (addr_comm, addr_var) =
            prover.commit(bigint_to_scalar(&self.gas_addr), Scalar::random(&mut rng));
        let (amount_comm, amount_var) = prover.commit(
            Scalar::from(self.gas_token_amount),
            Scalar::random(&mut rng),
        );
        let (percent_comm, percent_var) =
            prover.commit(Scalar::from(self.percentage_fee), Scalar::random(&mut rng));

        Ok((
            FeeVar {
                settle_key: settle_var,
                gas_addr: addr_var,
                gas_token_amount: amount_var,
                percentage_fee: percent_var,
            },
            CommittedFee {
                settle_key: settle_comm,
                gas_addr: addr_comm,
                gas_token_amount: amount_comm,
                percentage_fee: percent_comm,
            },
        ))
    }
}

/// A fee that has been committed to in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct CommittedFee {
    /// The public settle key of the cluster collecting fees
    pub settle_key: CompressedRistretto,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: CompressedRistretto,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: CompressedRistretto,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: CompressedRistretto,
}

/// A fee with values that have been allocated in an MPC network
#[derive(Clone, Debug)]
pub struct AuthenticatedFee<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The public settle key of the cluster collecting fees
    pub settle_key: AuthenticatedScalar<N, S>,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: AuthenticatedScalar<N, S>,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: AuthenticatedScalar<N, S>,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for Fee {
    type SharedType = AuthenticatedFee<N, S>;
    type ErrorType = MpcError;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType> {
        let shared_values = fabric
            .borrow_fabric()
            .batch_allocate_private_scalars(
                owning_party,
                &[
                    bigint_to_scalar(&self.settle_key),
                    bigint_to_scalar(&self.gas_addr),
                    Scalar::from(self.gas_token_amount),
                    Scalar::from(self.percentage_fee),
                ],
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(AuthenticatedFee {
            settle_key: shared_values[0],
            gas_addr: shared_values[1],
            gas_token_amount: shared_values[2],
            percentage_fee: shared_values[3],
        })
    }
}

/// Represents a fee that has been allocated in an MPC network and committed to in
/// a multi-prover constraint system
#[derive(Clone, Debug)]
pub struct AuthenticatedFeeVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The public settle key of the cluster collecting fees
    pub settle_key: MpcVariable<N, S>,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: MpcVariable<N, S>,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: MpcVariable<N, S>,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: MpcVariable<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S> for Fee {
    type SharedVarType = AuthenticatedFeeVar<N, S>;
    type CommitType = AuthenticatedCommittedFee<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let blinders = (0..4).map(|_| Scalar::random(&mut rng)).collect_vec();
        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    bigint_to_scalar(&self.settle_key),
                    bigint_to_scalar(&self.gas_addr),
                    Scalar::from(self.gas_token_amount),
                    Scalar::from(self.percentage_fee),
                ],
                &blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            AuthenticatedFeeVar {
                settle_key: shared_vars[0],
                gas_addr: shared_vars[1],
                gas_token_amount: shared_vars[2],
                percentage_fee: shared_vars[3],
            },
            AuthenticatedCommittedFee {
                settle_key: shared_comm[0],
                gas_addr: shared_comm[1],
                gas_token_amount: shared_comm[2],
                percentage_fee: shared_comm[3],
            },
        ))
    }
}

/// Represents a fee that has been committed to in a multi-prover constraint system
#[derive(Clone, Debug)]
pub struct AuthenticatedCommittedFee<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The public settle key of the cluster collecting fees
    pub settle_key: AuthenticatedCompressedRistretto<N, S>,
    /// The mint (ERC-20 Address) of the token used to pay gas
    pub gas_addr: AuthenticatedCompressedRistretto<N, S>,
    /// The amount of the mint token to use for gas
    pub gas_token_amount: AuthenticatedCompressedRistretto<N, S>,
    /// The percentage fee that the cluster may take upon match
    /// For now this is encoded as a u64, which represents a
    /// fixed point rational under the hood
    pub percentage_fee: AuthenticatedCompressedRistretto<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitVerifier
    for AuthenticatedCommittedFee<N, S>
{
    type VarType = FeeVar;
    type ErrorType = MpcError;

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let opened_values = AuthenticatedCompressedRistretto::batch_open_and_authenticate(&[
            self.settle_key,
            self.gas_addr,
            self.gas_token_amount,
            self.percentage_fee,
        ])
        .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let settle_var = verifier.commit(opened_values[0].value());
        let addr_var = verifier.commit(opened_values[1].value());
        let amount_var = verifier.commit(opened_values[2].value());
        let percentage_var = verifier.commit(opened_values[3].value());

        Ok(FeeVar {
            settle_key: settle_var,
            gas_addr: addr_var,
            gas_token_amount: amount_var,
            percentage_fee: percentage_var,
        })
    }
}

/**
 * Tuple structs
 */

/// Allocate an (order, balance, fee) handshake tuple in the network for a multiprover setting
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
    for (Order, Balance, Fee)
{
    type SharedVarType = (
        AuthenticatedOrderVar<N, S>,
        AuthenticatedBalanceVar<N, S>,
        AuthenticatedFeeVar<N, S>,
    );
    type CommitType = (
        AuthenticatedCommittedOrder<N, S>,
        AuthenticatedCommittedBalance<N, S>,
        AuthenticatedCommittedFee<N, S>,
    );
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let order = self.0;
        let balance = self.1;
        let fee = self.2;

        let num_committed_elements = 5 /* order */ + 2 /* balance */ + 4 /* fee */;
        let blinders = (0..num_committed_elements)
            .map(|_| Scalar::random(&mut rng))
            .collect_vec();

        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    Scalar::from(order.quote_mint),
                    Scalar::from(order.base_mint),
                    Scalar::from(order.side as u64),
                    Scalar::from(order.price),
                    Scalar::from(order.amount),
                    Scalar::from(balance.mint),
                    Scalar::from(balance.amount),
                    bigint_to_scalar(&fee.settle_key),
                    bigint_to_scalar(&fee.gas_addr),
                    Scalar::from(fee.gas_token_amount),
                    Scalar::from(fee.percentage_fee),
                ],
                &blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let vars = (
            AuthenticatedOrderVar {
                quote_mint: shared_vars[0],
                base_mint: shared_vars[1],
                side: shared_vars[2],
                price: shared_vars[3],
                amount: shared_vars[4],
            },
            AuthenticatedBalanceVar {
                mint: shared_vars[5],
                amount: shared_vars[6],
            },
            AuthenticatedFeeVar {
                settle_key: shared_vars[7],
                gas_addr: shared_vars[8],
                gas_token_amount: shared_vars[9],
                percentage_fee: shared_vars[10],
            },
        );

        let comms = (
            AuthenticatedCommittedOrder {
                quote_mint: shared_comm[0],
                base_mint: shared_comm[1],
                side: shared_comm[2],
                price: shared_comm[3],
                amount: shared_comm[4],
            },
            AuthenticatedCommittedBalance {
                mint: shared_comm[5],
                amount: shared_comm[6],
            },
            AuthenticatedCommittedFee {
                settle_key: shared_comm[7],
                gas_addr: shared_comm[8],
                gas_token_amount: shared_comm[9],
                percentage_fee: shared_comm[10],
            },
        );

        Ok((vars, comms))
    }
}

/**
 * Matches
 */

/// Represents a match on a single set of orders overlapping
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SingleMatchResult {
    /// Specifies the asset party 1 buys
    pub buy_side1: Match,
    /// Specifies the asset party 1 sell
    pub sell_side1: Match,
    /// Specifies the asset party 2 buys
    pub buy_side2: Match,
    /// Specifies the asset party 2 sells
    pub sell_side2: Match,
}

impl TryFrom<&[u64]> for SingleMatchResult {
    type Error = MpcError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        // 4 matches, 3 values each
        if value.len() != 3 * 4 {
            return Err(MpcError::SerializationError(format!(
                "Expected 12 values, got {:?}",
                value.len()
            )));
        }

        Ok(SingleMatchResult {
            buy_side1: Match::try_from(&value[..3])?,
            sell_side1: Match::try_from(&value[3..6])?,
            buy_side2: Match::try_from(&value[6..9])?,
            sell_side2: Match::try_from(&value[9..])?,
        })
    }
}

/// Represents a single match on a set of overlapping orders
/// with values authenticated in an MPC network
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedSingleMatchResult<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// Specifies the asset party 1 buys
    pub buy_side1: AuthenticatedMatch<N, S>,
    /// Specifies the asset party 1 sell
    pub sell_side1: AuthenticatedMatch<N, S>,
    /// Specifies the asset party 2 buys
    pub buy_side2: AuthenticatedMatch<N, S>,
    /// Specifies the asset party 2 sells
    pub sell_side2: AuthenticatedMatch<N, S>,
}

/// Serialization to a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<&AuthenticatedSingleMatchResult<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(match_res: &AuthenticatedSingleMatchResult<N, S>) -> Self {
        let mut res = Vec::with_capacity(3 * 4 /* 3 scalars for 4 matches */);
        res.append(&mut match_res.buy_side1.borrow().into());
        res.append(&mut match_res.sell_side1.borrow().into());
        res.append(&mut match_res.buy_side2.borrow().into());
        res.append(&mut match_res.sell_side2.borrow().into());

        res
    }
}

/// Deserialization from a vector of authenticated scalars
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedSingleMatchResult<N, S>
{
    type Error = MpcError;

    fn try_from(value: &[AuthenticatedScalar<N, S>]) -> Result<Self, Self::Error> {
        // 4 matches, 3 elements each
        if value.len() != 3 * 4 {
            return Err(MpcError::SerializationError(format!(
                "Expected 12 elements, got {:?}",
                value.len()
            )));
        }

        Ok(Self {
            buy_side1: AuthenticatedMatch::try_from(&value[..3])?,
            sell_side1: AuthenticatedMatch::try_from(&value[3..6])?,
            buy_side2: AuthenticatedMatch::try_from(&value[8..9])?,
            sell_side2: AuthenticatedMatch::try_from(&value[9..])?,
        })
    }
}

/// Implementation of opening for the single match result
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Open
    for AuthenticatedSingleMatchResult<N, S>
{
    type Output = SingleMatchResult;
    type Error = MpcError;

    fn open(&self) -> Result<Self::Output, Self::Error> {
        // Flatten the values into a shape that can be batch opened
        let flattened_self: Vec<AuthenticatedScalar<_, _>> = self.into();
        // Open the values and cast them to u64
        let opened_values = AuthenticatedScalar::batch_open(&flattened_self)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .iter()
            .map(|val| scalar_to_u64(&val.to_scalar()))
            .collect::<Vec<_>>();

        // Deserialize back into result type
        TryFrom::<&[u64]>::try_from(&opened_values)
    }

    fn open_and_authenticate(&self) -> Result<Self::Output, Self::Error> {
        // Flatten the values into a shape that can be batch opened
        let flattened_self: Vec<AuthenticatedScalar<_, _>> = self.into();
        // Open the values and cast them to u64
        let opened_values = AuthenticatedScalar::batch_open_and_authenticate(&flattened_self)
            .map_err(|err| MpcError::OpeningError(err.to_string()))?
            .iter()
            .map(|val| scalar_to_u64(&val.to_scalar()))
            .collect::<Vec<_>>();

        // Deserialize back into result type
        TryFrom::<&[u64]>::try_from(&opened_values)
    }
}

/// A single match which specifies the token transferred, amount, and direction of transfer
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Match {
    /// The mint (ERC-20) of the token transferred by this match
    pub mint: u64,
    /// The amount of the token transferred by this match
    pub amount: u64,
    /// The direction (buy or sell) of the transfer that this match results in
    pub side: OrderSide,
}

/// Deserialization from a list of u64s to a Match
impl TryFrom<&[u64]> for Match {
    type Error = MpcError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        if value.len() != 3 {
            return Err(MpcError::SerializationError(format!(
                "Expected 3 elements, got {:?}",
                value.len()
            )));
        }

        if value[2] != 0 && value[2] != 1 {
            return Err(MpcError::SerializationError(format!(
                "Expected order side to be 0 or 1, got {:?}",
                value[2]
            )));
        }

        Ok(Match {
            mint: value[0],
            amount: value[1],
            side: if value[2] == 0 {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            },
        })
    }
}

/// Represents a match on one side of the order that is backed by authenticated,
/// network allocated values
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedMatch<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 token) that this match result swaps
    pub mint: AuthenticatedScalar<N, S>,
    /// The amount of the mint token to swap
    pub amount: AuthenticatedScalar<N, S>,
    /// The side (0 is buy, 1 is sell)
    pub side: AuthenticatedScalar<N, S>,
}

/// Serialization for opening and sending across the MPC network
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<&AuthenticatedMatch<N, S>>
    for Vec<AuthenticatedScalar<N, S>>
{
    fn from(val: &AuthenticatedMatch<N, S>) -> Self {
        vec![val.mint.clone(), val.amount.clone(), val.side.clone()]
    }
}

/// Deserialization from a list of shared values
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> TryFrom<&[AuthenticatedScalar<N, S>]>
    for AuthenticatedMatch<N, S>
{
    type Error = MpcError;

    fn try_from(value: &[AuthenticatedScalar<N, S>]) -> Result<Self, Self::Error> {
        if value.len() != 3 {
            return Err(MpcError::SerializationError(format!(
                "Expected 3 values, got {:?}",
                value.len()
            )));
        }

        Ok(AuthenticatedMatch {
            mint: value[0].clone(),
            amount: value[1].clone(),
            side: value[2].clone(),
        })
    }
}
