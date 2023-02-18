//! Groups the base type and derived types for the `Order` entity
use crate::{
    errors::{MpcError, TypeConversionError},
    mpc::SharedFabric,
    zk_gadgets::fixed_point::{
        AuthenticatedCommittedFixedPoint, AuthenticatedFixedPoint, AuthenticatedFixedPointVar,
        CommittedFixedPoint, FixedPoint, FixedPointVar,
    },
    Allocate, CommitProver, CommitSharedProver, CommitVerifier,
};
use crypto::fields::biguint_to_scalar;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, Prover, Variable, Verifier},
    r1cs_mpc::{MpcLinearCombination, MpcProver, MpcVariable},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Represents the base type of an open order, including the asset pair, the amount, price,
/// and direction
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: BigUint,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: BigUint,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: OrderSide,
    /// The limit price to be executed at, in units of quote per base
    pub price: FixedPoint,
    /// The amount of base currency to buy or sell
    pub amount: u64,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: u64,
}

/// Convert a vector of u64s to an Order
impl TryFrom<&[u64]> for Order {
    type Error = TypeConversionError;

    fn try_from(value: &[u64]) -> Result<Self, Self::Error> {
        if value.len() != 6 {
            return Err(TypeConversionError(format!(
                "expected array of length 6, got {:?}",
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
            quote_mint: value[0].into(),
            base_mint: value[1].into(),
            side: if value[2] == 0 {
                OrderSide::Buy
            } else {
                OrderSide::Sell
            },
            price: Scalar::from(value[3]).into(),
            amount: value[4],
            timestamp: value[5],
        })
    }
}

/// The side of the market a given order is on
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    /// Buy side
    Buy = 0,
    /// Sell side
    Sell,
}

impl OrderSide {
    /// Return the opposite direction to self
    pub fn opposite(&self) -> OrderSide {
        match self {
            OrderSide::Buy => OrderSide::Sell,
            OrderSide::Sell => OrderSide::Buy,
        }
    }
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

impl From<u64> for OrderSide {
    fn from(val: u64) -> Self {
        match val {
            0 => OrderSide::Buy,
            1 => OrderSide::Sell,
            _ => panic!("invalid order side"),
        }
    }
}

impl From<OrderSide> for Scalar {
    fn from(side: OrderSide) -> Self {
        Scalar::from(side as u8)
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
    pub price: FixedPointVar,
    /// The amount of base currency to buy or sell
    pub amount: Variable,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: Variable,
}

impl From<OrderVar> for Vec<LinearCombination> {
    fn from(order: OrderVar) -> Self {
        vec![
            order.quote_mint.into(),
            order.base_mint.into(),
            order.side.into(),
            order.price.repr,
            order.amount.into(),
            order.timestamp.into(),
        ]
    }
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
            prover.commit(biguint_to_scalar(&self.quote_mint), Scalar::random(rng));
        let (base_comm, base_var) =
            prover.commit(biguint_to_scalar(&self.base_mint), Scalar::random(rng));
        let (side_comm, side_var) =
            prover.commit(Scalar::from(self.side as u64), Scalar::random(rng));
        let (price_var, price_comm) = self.price.commit_prover(rng, prover).unwrap();
        let (amount_comm, amount_var) =
            prover.commit(Scalar::from(self.amount), Scalar::random(rng));
        let (timestamp_comm, timestamp_var) =
            prover.commit(Scalar::from(self.timestamp), Scalar::random(rng));

        Ok((
            OrderVar {
                quote_mint: quote_var,
                base_mint: base_var,
                side: side_var,
                price: price_var,
                amount: amount_var,
                timestamp: timestamp_var,
            },
            CommittedOrder {
                quote_mint: quote_comm,
                base_mint: base_comm,
                side: side_comm,
                price: price_comm,
                amount: amount_comm,
                timestamp: timestamp_comm,
            },
        ))
    }
}

/// An order that has been committed to by a prover
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommittedOrder {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: CompressedRistretto,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: CompressedRistretto,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: CompressedRistretto,
    /// The limit price to be executed at, in units of quote
    pub price: CommittedFixedPoint,
    /// The amount of base currency to buy or sell
    pub amount: CompressedRistretto,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: CompressedRistretto,
}

impl CommitVerifier for CommittedOrder {
    type VarType = OrderVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let quote_var = verifier.commit(self.quote_mint);
        let base_var = verifier.commit(self.base_mint);
        let side_var = verifier.commit(self.side);
        let price_var = self.price.commit_verifier(verifier).unwrap();
        let amount_var = verifier.commit(self.amount);
        let timestamp_var = verifier.commit(self.timestamp);

        Ok(OrderVar {
            quote_mint: quote_var,
            base_mint: base_var,
            side: side_var,
            price: price_var,
            amount: amount_var,
            timestamp: timestamp_var,
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
    pub price: AuthenticatedFixedPoint<N, S>,
    /// The amount of base currency to buy or sell
    pub amount: AuthenticatedScalar<N, S>,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: AuthenticatedScalar<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Allocate<N, S> for Order {
    type SharedType = AuthenticatedOrder<N, S>;
    type ErrorType = MpcError;

    fn allocate(
        &self,
        owning_party: u64,
        fabric: SharedFabric<N, S>,
    ) -> Result<Self::SharedType, Self::ErrorType> {
        // Convert all elements of the order to a scalar, then share
        let field_scalars = vec![
            biguint_to_scalar(&self.quote_mint),
            biguint_to_scalar(&self.base_mint),
            self.side.into(),
            self.price.repr,
            self.amount.into(),
            self.timestamp.into(),
        ];
        let shared_values = fabric
            .borrow_fabric()
            .batch_allocate_private_scalars(owning_party, &field_scalars)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok(Self::SharedType {
            quote_mint: shared_values[0].to_owned(),
            base_mint: shared_values[1].to_owned(),
            side: shared_values[2].to_owned(),
            price: AuthenticatedFixedPoint {
                repr: shared_values[3].to_owned(),
            },
            amount: shared_values[4].to_owned(),
            timestamp: shared_values[5].to_owned(),
        })
    }
}

/// Represents an order that has been allocated in an MPC network and committed to
/// in a multi-prover constraint system
#[derive(Debug)]
pub struct AuthenticatedOrderVar<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: MpcVariable<N, S>,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: MpcVariable<N, S>,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: MpcVariable<N, S>,
    /// The limit price to be executed at, in units of quote
    pub price: AuthenticatedFixedPointVar<N, S>,
    /// The amount of base currency to buy or sell
    pub amount: MpcVariable<N, S>,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: MpcVariable<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone for AuthenticatedOrderVar<N, S> {
    fn clone(&self) -> Self {
        Self {
            quote_mint: self.quote_mint.clone(),
            base_mint: self.base_mint.clone(),
            side: self.side.clone(),
            price: self.price.clone(),
            amount: self.amount.clone(),
            timestamp: self.timestamp.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedOrderVar<N, S>>
    for Vec<MpcLinearCombination<N, S>>
{
    fn from(order: AuthenticatedOrderVar<N, S>) -> Self {
        vec![
            order.quote_mint.into(),
            order.base_mint.into(),
            order.side.into(),
            order.price.repr.to_owned(),
            order.amount.into(),
            order.timestamp.into(),
        ]
    }
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
        let blinders = (0..6).map(|_| Scalar::random(rng)).collect_vec();
        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    biguint_to_scalar(&self.quote_mint),
                    biguint_to_scalar(&self.base_mint),
                    Scalar::from(self.side as u64),
                    Scalar::from(self.price.to_owned()),
                    Scalar::from(self.amount),
                    Scalar::from(self.timestamp),
                ],
                &blinders,
            )
            .map_err(|err| MpcError::SharingError(err.to_string()))?;

        Ok((
            AuthenticatedOrderVar {
                quote_mint: shared_vars[0].to_owned(),
                base_mint: shared_vars[1].to_owned(),
                side: shared_vars[2].to_owned(),
                price: AuthenticatedFixedPointVar {
                    repr: shared_vars[3].to_owned().into(),
                },
                amount: shared_vars[4].to_owned(),
                timestamp: shared_vars[5].to_owned(),
            },
            AuthenticatedCommittedOrder {
                quote_mint: shared_comm[0].to_owned(),
                base_mint: shared_comm[1].to_owned(),
                side: shared_comm[2].to_owned(),
                price: AuthenticatedCommittedFixedPoint {
                    repr: shared_comm[3].to_owned(),
                },
                amount: shared_comm[4].to_owned(),
                timestamp: shared_comm[5].to_owned(),
            },
        ))
    }
}

/// Represents an order that has been committed to in a multi-prover constraint system
#[derive(Debug)]
pub struct AuthenticatedCommittedOrder<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: AuthenticatedCompressedRistretto<N, S>,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: AuthenticatedCompressedRistretto<N, S>,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: AuthenticatedCompressedRistretto<N, S>,
    /// The limit price to be executed at, in units of quote
    pub price: AuthenticatedCommittedFixedPoint<N, S>,
    /// The amount of base currency to buy or sell
    pub amount: AuthenticatedCompressedRistretto<N, S>,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: AuthenticatedCompressedRistretto<N, S>,
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
    for AuthenticatedCommittedOrder<N, S>
{
    fn clone(&self) -> Self {
        Self {
            quote_mint: self.quote_mint.clone(),
            base_mint: self.base_mint.clone(),
            side: self.side.clone(),
            price: self.price.clone(),
            amount: self.amount.clone(),
            timestamp: self.timestamp.clone(),
        }
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> From<AuthenticatedCommittedOrder<N, S>>
    for Vec<AuthenticatedCompressedRistretto<N, S>>
{
    fn from(order: AuthenticatedCommittedOrder<N, S>) -> Self {
        vec![
            order.quote_mint,
            order.base_mint,
            order.side,
            order.price.repr,
            order.amount,
            order.timestamp,
        ]
    }
}

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitVerifier
    for AuthenticatedCommittedOrder<N, S>
{
    type VarType = OrderVar;
    type ErrorType = MpcError;

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let opened_commit = AuthenticatedCompressedRistretto::batch_open_and_authenticate(&Into::<
            Vec<AuthenticatedCompressedRistretto<N, S>>,
        >::into(
            self.clone(),
        ))
        .map_err(|err| MpcError::SharingError(err.to_string()))?;

        let quote_var = verifier.commit(opened_commit[0].value());
        let base_var = verifier.commit(opened_commit[1].value());
        let side_var = verifier.commit(opened_commit[2].value());
        let price_var = verifier.commit(opened_commit[3].value());
        let amount_var = verifier.commit(opened_commit[4].value());
        let timestamp_var = verifier.commit(opened_commit[5].value());

        Ok(OrderVar {
            quote_mint: quote_var,
            base_mint: base_var,
            side: side_var,
            price: FixedPointVar {
                repr: price_var.into(),
            },
            amount: amount_var,
            timestamp: timestamp_var,
        })
    }
}
