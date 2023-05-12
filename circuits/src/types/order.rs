//! Groups the base type and derived types for the `Order` entity
use std::ops::Add;

use crate::{
    errors::{MpcError, TypeConversionError},
    mpc::SharedFabric,
    types::{biguint_from_hex_string, biguint_to_hex_string},
    zk_gadgets::fixed_point::{
        AuthenticatedCommittedFixedPoint, AuthenticatedFixedPoint, AuthenticatedFixedPointVar,
        CommittedFixedPoint, FixedPoint, FixedPointVar, LinkableFixedPointCommitment,
    },
    Allocate, CommitPublic, CommitSharedProver, CommitVerifier, CommitWitness, LinkableCommitment,
};
use crypto::fields::{biguint_to_scalar, scalar_to_biguint};
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use itertools::Itertools;
use mpc_bulletproof::{
    r1cs::{LinearCombination, Prover, Variable, Verifier},
    r1cs_mpc::{MpcLinearCombination, MpcProver, MpcVariable},
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    mpc_scalar::scalar_to_u64, network::MpcNetwork,
};
use num_bigint::BigUint;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// --------------------
// | Base Order Types |
// --------------------

/// Represents the base type of an open order, including the asset pair, the amount, price,
/// and direction
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Order {
    /// The mint (ERC-20 contract address) of the quote token
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
    pub quote_mint: BigUint,
    /// The mint (ERC-20 contract address) of the base token
    #[serde(
        serialize_with = "biguint_to_hex_string",
        deserialize_with = "biguint_from_hex_string"
    )]
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

impl Order {
    /// Whether or not this is the zero'd order
    pub fn is_default(&self) -> bool {
        self.eq(&Self::default())
    }
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
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OrderSide {
    /// Buy side
    #[default]
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

impl From<Scalar> for OrderSide {
    fn from(side: Scalar) -> Self {
        if side == Scalar::zero() {
            OrderSide::Buy
        } else if side == Scalar::one() {
            OrderSide::Sell
        } else {
            panic!(
                "unexpected order side encoded as scalar: {}",
                scalar_to_u64(&side)
            )
        }
    }
}

/// An order with values allocated in a single-prover constraint system
#[derive(Clone, Debug)]
pub struct OrderVar<L: Into<LinearCombination>> {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: L,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: L,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: L,
    /// The limit price to be executed at, in units of quote
    pub price: FixedPointVar,
    /// The amount of base currency to buy or sell
    pub amount: L,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: L,
}

impl CommitWitness for Order {
    type VarType = OrderVar<Variable>;
    type CommitType = CommittedOrder;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
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
        let (price_var, price_comm) = self.price.commit_witness(rng, prover).unwrap();
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
    type VarType = OrderVar<Variable>;
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

// --------------------------------
// | Commitment Linked Order Type |
// --------------------------------

/// A linkable commitment to an Order that may be used across proofs
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkableOrderCommitment {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: LinkableCommitment,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: LinkableCommitment,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: LinkableCommitment,
    /// The limit price to be executed at, in units of quote
    pub price: LinkableFixedPointCommitment,
    /// The amount of base currency to buy or sell
    pub amount: LinkableCommitment,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: LinkableCommitment,
}

/// Implement From<Order> by choosing commitment randomness
impl From<Order> for LinkableOrderCommitment {
    fn from(order: Order) -> Self {
        Self {
            quote_mint: LinkableCommitment::new(biguint_to_scalar(&order.quote_mint)),
            base_mint: LinkableCommitment::new(biguint_to_scalar(&order.base_mint)),
            side: LinkableCommitment::new(order.side.into()),
            price: order.price.into(),
            amount: LinkableCommitment::new(order.amount.into()),
            timestamp: LinkableCommitment::new(order.timestamp.into()),
        }
    }
}

impl From<LinkableOrderCommitment> for Order {
    fn from(order: LinkableOrderCommitment) -> Self {
        Self {
            quote_mint: scalar_to_biguint(&order.quote_mint.val),
            base_mint: scalar_to_biguint(&order.base_mint.val),
            side: order.side.val.into(),
            price: order.price.into(),
            amount: scalar_to_u64(&order.amount.val),
            timestamp: scalar_to_u64(&order.timestamp.val),
        }
    }
}

impl CommitWitness for LinkableOrderCommitment {
    type VarType = OrderVar<Variable>;
    type CommitType = CommittedOrder;
    type ErrorType = ();

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (quote_var, quote_comm) = self.quote_mint.commit_witness(rng, prover).unwrap();
        let (base_var, base_comm) = self.base_mint.commit_witness(rng, prover).unwrap();
        let (side_var, side_comm) = self.side.commit_witness(rng, prover).unwrap();
        let (price_var, price_comm) = self.price.commit_witness(rng, prover).unwrap();
        let (amount_var, amount_comm) = self.amount.commit_witness(rng, prover).unwrap();
        let (timestamp_var, timestamp_comm) = self.timestamp.commit_witness(rng, prover).unwrap();

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

// -------------------
// | MPC Order Types |
// -------------------

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

impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
    for LinkableOrderCommitment
{
    type SharedVarType = AuthenticatedOrderVar<N, S>;
    type CommitType = AuthenticatedCommittedOrder<N, S>;
    type ErrorType = MpcError;

    fn commit<R: RngCore + CryptoRng>(
        &self,
        owning_party: u64,
        _rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let (shared_comm, shared_vars) = prover
            .batch_commit(
                owning_party,
                &[
                    self.quote_mint.val,
                    self.base_mint.val,
                    self.side.val,
                    self.price.repr.val,
                    self.amount.val,
                    self.timestamp.val,
                ],
                &[
                    self.quote_mint.randomness,
                    self.base_mint.randomness,
                    self.side.randomness,
                    self.price.repr.randomness,
                    self.amount.randomness,
                    self.timestamp.randomness,
                ],
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
    type VarType = OrderVar<Variable>;
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

// -----------------------------
// | Secret Shared Order Types |
// -----------------------------

/// Represents an additive secret share of an order
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OrderSecretShare {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: Scalar,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: Scalar,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: Scalar,
    /// The limit price to be executed at, in units of quote per base
    pub price: Scalar,
    /// The amount of base currency to buy or sell
    pub amount: Scalar,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: Scalar,
}

impl OrderSecretShare {
    /// The number of `Scalar`s needed to represent an order
    pub const SHARES_PER_ORDER: usize = 6;

    /// Apply a blinder to the secret shares
    pub fn blind(&mut self, blinder: Scalar) {
        self.quote_mint += blinder;
        self.base_mint += blinder;
        self.side += blinder;
        self.price += blinder;
        self.amount += blinder;
        self.timestamp += blinder;
    }

    /// Remove a blinder from the secret shares
    pub fn unblind(&mut self, blinder: Scalar) {
        self.quote_mint -= blinder;
        self.base_mint -= blinder;
        self.side -= blinder;
        self.price -= blinder;
        self.amount -= blinder;
        self.timestamp -= blinder;
    }
}

impl Add<OrderSecretShare> for OrderSecretShare {
    type Output = Order;

    fn add(self, rhs: OrderSecretShare) -> Self::Output {
        let quote_mint = scalar_to_biguint(&(self.quote_mint + rhs.quote_mint));
        let base_mint = scalar_to_biguint(&(self.base_mint + rhs.base_mint));
        let side = OrderSide::from(self.side + rhs.side);
        let price = FixedPoint::from(self.price + rhs.price);
        let amount = scalar_to_u64(&(self.amount + rhs.amount));
        let timestamp = scalar_to_u64(&(self.timestamp + rhs.timestamp));

        Order {
            quote_mint,
            base_mint,
            side,
            price,
            amount,
            timestamp,
        }
    }
}

// Order serialization
impl From<OrderSecretShare> for Vec<Scalar> {
    fn from(share: OrderSecretShare) -> Self {
        vec![
            share.quote_mint,
            share.base_mint,
            share.side,
            share.price,
            share.amount,
            share.timestamp,
        ]
    }
}

// Order deserialization
impl From<Vec<Scalar>> for OrderSecretShare {
    fn from(mut serialized: Vec<Scalar>) -> Self {
        let mut drain = serialized.drain(..);
        OrderSecretShare {
            quote_mint: drain.next().unwrap(),
            base_mint: drain.next().unwrap(),
            side: drain.next().unwrap(),
            price: drain.next().unwrap(),
            amount: drain.next().unwrap(),
            timestamp: drain.next().unwrap(),
        }
    }
}

/// Represents an additive secret share of an order committed into a constraint system
#[derive(Clone, Debug)]
pub struct OrderSecretShareVar {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: LinearCombination,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: LinearCombination,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: LinearCombination,
    /// The limit price to be executed at, in units of quote per base
    pub price: LinearCombination,
    /// The amount of base currency to buy or sell
    pub amount: LinearCombination,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: LinearCombination,
}

impl OrderSecretShareVar {
    /// Apply a blinder to the secret shares
    pub fn blind(&mut self, blinder: LinearCombination) {
        self.quote_mint += blinder.clone();
        self.base_mint += blinder.clone();
        self.side += blinder.clone();
        self.price += blinder.clone();
        self.amount += blinder.clone();
        self.timestamp += blinder;
    }

    /// Remove a blinder from the secret shares
    pub fn unblind(&mut self, blinder: LinearCombination) {
        self.quote_mint -= blinder.clone();
        self.base_mint -= blinder.clone();
        self.side -= blinder.clone();
        self.price -= blinder.clone();
        self.amount -= blinder.clone();
        self.timestamp -= blinder;
    }
}

impl Add<OrderSecretShareVar> for OrderSecretShareVar {
    type Output = OrderVar<LinearCombination>;

    fn add(self, rhs: OrderSecretShareVar) -> Self::Output {
        let quote_mint = self.quote_mint + rhs.quote_mint;
        let base_mint = self.base_mint + rhs.base_mint;
        let side = self.side + rhs.side;
        let price = self.price + rhs.price;
        let amount = self.amount + rhs.amount;
        let timestamp = self.timestamp + rhs.timestamp;

        OrderVar {
            quote_mint,
            base_mint,
            side,
            price: FixedPointVar { repr: price },
            amount,
            timestamp,
        }
    }
}

// Order serialization
impl From<OrderSecretShareVar> for Vec<LinearCombination> {
    fn from(share: OrderSecretShareVar) -> Self {
        vec![
            share.quote_mint,
            share.base_mint,
            share.side,
            share.price,
            share.amount,
            share.timestamp,
        ]
    }
}

// Order deserialization
impl<L: Into<LinearCombination>> From<Vec<L>> for OrderSecretShareVar {
    fn from(mut serialized: Vec<L>) -> Self {
        let mut drain = serialized.drain(..);
        OrderSecretShareVar {
            quote_mint: drain.next().unwrap().into(),
            base_mint: drain.next().unwrap().into(),
            side: drain.next().unwrap().into(),
            price: drain.next().unwrap().into(),
            amount: drain.next().unwrap().into(),
            timestamp: drain.next().unwrap().into(),
        }
    }
}

/// Represents a commitment to an additive secret share of an order committed into a constraint system
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct OrderSecretShareCommitment {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: CompressedRistretto,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: CompressedRistretto,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: CompressedRistretto,
    /// The limit price to be executed at, in units of quote per base
    pub price: CompressedRistretto,
    /// The amount of base currency to buy or sell
    pub amount: CompressedRistretto,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: CompressedRistretto,
}

impl CommitWitness for OrderSecretShare {
    type VarType = OrderSecretShareVar;
    type CommitType = OrderSecretShareCommitment;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (quote_var, quote_comm) = self.quote_mint.commit_witness(rng, prover).unwrap();
        let (base_var, base_comm) = self.base_mint.commit_witness(rng, prover).unwrap();
        let (side_var, side_comm) = self.side.commit_witness(rng, prover).unwrap();
        let (price_var, price_comm) = self.price.commit_witness(rng, prover).unwrap();
        let (amount_var, amount_comm) = self.amount.commit_witness(rng, prover).unwrap();
        let (timestamp_var, timestamp_comm) = self.timestamp.commit_witness(rng, prover).unwrap();

        Ok((
            OrderSecretShareVar {
                quote_mint: quote_var.into(),
                base_mint: base_var.into(),
                side: side_var.into(),
                price: price_var.into(),
                amount: amount_var.into(),
                timestamp: timestamp_var.into(),
            },
            OrderSecretShareCommitment {
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

impl CommitPublic for OrderSecretShare {
    type VarType = OrderSecretShareVar;
    type ErrorType = (); // Does not error

    fn commit_public<CS: mpc_bulletproof::r1cs::RandomizableConstraintSystem>(
        &self,
        cs: &mut CS,
    ) -> Result<Self::VarType, Self::ErrorType> {
        let quote_var = self.quote_mint.commit_public(cs).unwrap();
        let base_var = self.base_mint.commit_public(cs).unwrap();
        let side_var = self.side.commit_public(cs).unwrap();
        let price_var = self.price.commit_public(cs).unwrap();
        let amount_var = self.amount.commit_public(cs).unwrap();
        let timestamp_var = self.timestamp.commit_public(cs).unwrap();

        Ok(OrderSecretShareVar {
            quote_mint: quote_var.into(),
            base_mint: base_var.into(),
            side: side_var.into(),
            price: price_var.into(),
            amount: amount_var.into(),
            timestamp: timestamp_var.into(),
        })
    }
}

impl CommitVerifier for OrderSecretShareCommitment {
    type VarType = OrderSecretShareVar;
    type ErrorType = (); // Does not error

    fn commit_verifier(&self, verifier: &mut Verifier) -> Result<Self::VarType, Self::ErrorType> {
        let quote_var = self.quote_mint.commit_verifier(verifier).unwrap();
        let base_var = self.base_mint.commit_verifier(verifier).unwrap();
        let side_var = self.side.commit_verifier(verifier).unwrap();
        let price_var = self.price.commit_verifier(verifier).unwrap();
        let amount_var = self.amount.commit_verifier(verifier).unwrap();
        let timestamp_var = self.timestamp.commit_verifier(verifier).unwrap();

        Ok(OrderSecretShareVar {
            quote_mint: quote_var.into(),
            base_mint: base_var.into(),
            side: side_var.into(),
            price: price_var.into(),
            amount: amount_var.into(),
            timestamp: timestamp_var.into(),
        })
    }
}

/// An order secret share type that may be linked between proofs
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LinkableOrderShare {
    /// The mint (ERC-20 contract address) of the quote token
    pub quote_mint: LinkableCommitment,
    /// The mint (ERC-20 contract address) of the base token
    pub base_mint: LinkableCommitment,
    /// The side this order is for (0 = buy, 1 = sell)
    pub side: LinkableCommitment,
    /// The limit price to be executed at, in units of quote per base
    pub price: LinkableCommitment,
    /// The amount of base currency to buy or sell
    pub amount: LinkableCommitment,
    /// A timestamp indicating when the order was placed, set by the user
    pub timestamp: LinkableCommitment,
}

impl From<OrderSecretShare> for LinkableOrderShare {
    fn from(order: OrderSecretShare) -> Self {
        LinkableOrderShare {
            quote_mint: order.quote_mint.into(),
            base_mint: order.base_mint.into(),
            side: order.side.into(),
            price: order.price.into(),
            amount: order.amount.into(),
            timestamp: order.timestamp.into(),
        }
    }
}

impl From<LinkableOrderShare> for OrderSecretShare {
    fn from(order: LinkableOrderShare) -> Self {
        OrderSecretShare {
            quote_mint: order.quote_mint.val,
            base_mint: order.base_mint.val,
            side: order.side.val,
            price: order.price.val,
            amount: order.amount.val,
            timestamp: order.timestamp.val,
        }
    }
}

impl CommitWitness for LinkableOrderShare {
    type VarType = OrderSecretShareVar;
    type CommitType = OrderSecretShareCommitment;
    type ErrorType = (); // Does not error

    fn commit_witness<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        prover: &mut Prover,
    ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
        let (quote_var, quote_comm) = self.quote_mint.commit_witness(rng, prover).unwrap();
        let (base_var, base_comm) = self.base_mint.commit_witness(rng, prover).unwrap();
        let (side_var, side_comm) = self.side.commit_witness(rng, prover).unwrap();
        let (price_var, price_comm) = self.price.commit_witness(rng, prover).unwrap();
        let (amount_var, amount_comm) = self.amount.commit_witness(rng, prover).unwrap();
        let (timestamp_var, timestamp_comm) = self.timestamp.commit_witness(rng, prover).unwrap();

        Ok((
            OrderSecretShareVar {
                quote_mint: quote_var.into(),
                base_mint: base_var.into(),
                side: side_var.into(),
                price: price_var.into(),
                amount: amount_var.into(),
                timestamp: timestamp_var.into(),
            },
            OrderSecretShareCommitment {
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

// ---------
// | Tests |
// ---------

#[cfg(test)]
mod test {
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{LinearCombination, Prover},
        PedersenGens,
    };

    use crate::{
        test_helpers::{assert_lcs_equal, random_scalar},
        types::order::OrderSecretShareVar,
        CommitPublic,
    };

    use super::OrderSecretShare;

    /// Tests serialization of the order secret share types
    #[test]
    fn test_order_share_serde() {
        let order_share = OrderSecretShare {
            quote_mint: random_scalar(),
            base_mint: random_scalar(),
            side: random_scalar(),
            price: random_scalar(),
            amount: random_scalar(),
            timestamp: random_scalar(),
        };

        // Serialize then deserialize
        let serialized: Vec<Scalar> = order_share.into();
        let deserialized: OrderSecretShare = serialized.into();

        assert_eq!(deserialized, order_share);

        // Convert to a constraint-system allocated type
        let pc_gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"test");
        let mut prover = Prover::new(&pc_gens, &mut transcript);

        let share_var = order_share.commit_public(&mut prover).unwrap();

        // Serialize then deserialize the variable
        let serialized: Vec<LinearCombination> = share_var.clone().into();
        let deserialized: OrderSecretShareVar = serialized.into();

        assert_lcs_equal(&share_var.quote_mint, &deserialized.quote_mint, &prover);
        assert_lcs_equal(&share_var.base_mint, &deserialized.base_mint, &prover);
        assert_lcs_equal(&share_var.side, &deserialized.side, &prover);
        assert_lcs_equal(&share_var.price, &deserialized.price, &prover);
        assert_lcs_equal(&share_var.amount, &deserialized.amount, &prover);
        assert_lcs_equal(&share_var.timestamp, &deserialized.timestamp, &prover);
    }
}
