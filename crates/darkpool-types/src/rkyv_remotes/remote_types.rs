//! Remote type shims for rkyv serialization
//!
//! These types are used with `#[rkyv(with = ...)]` to serialize types
//! that don't natively support rkyv.

use std::{hash::Hash, marker::PhantomData};

use alloy_primitives::{Address, Uint};
use ark_bn254::FrConfig;
use ark_ed_on_bn254::FrConfig as EmbeddedFrConfig;
use ark_ff::{BigInt, Fp, MontBackend};
use circuit_types::{
    fixed_point::FixedPoint,
    primitives::{
        baby_jubjub::BabyJubJubPoint,
        schnorr::{SchnorrPublicKey, SchnorrSignature},
    },
};

// Share types are only available when proof-system-types feature is enabled
#[cfg(feature = "proof-system-types")]
use circuit_types::{
    fixed_point::FixedPointShare,
    primitives::{baby_jubjub::BabyJubJubPointShare, schnorr::SchnorrPublicKeyShare},
};
use constants::{EmbeddedScalarField, Scalar};
use rkyv::{Archive, Deserialize, Serialize};

/// The number of u64 limbs which arkworks uses to represent an element of the
/// BN254 scalar field
const SCALAR_LIMBS: usize = 4;

// --- Address --- //

/// Remote type shim for `alloy_primitives::Address`
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
#[rkyv(derive(Debug), compare(PartialEq))]
#[rkyv(remote = alloy_primitives::Address)]
#[rkyv(archived = ArchivedAddress)]
pub struct AddressDef(pub [u8; 20]);

impl From<AddressDef> for Address {
    fn from(value: AddressDef) -> Self {
        Address::from(value.0)
    }
}

impl From<Address> for AddressDef {
    fn from(value: Address) -> Self {
        AddressDef(value.0.0)
    }
}

impl PartialEq<Address> for ArchivedAddress {
    fn eq(&self, other: &Address) -> bool {
        self.0 == other.0.0
    }
}

impl PartialEq for ArchivedAddress {
    fn eq(&self, other: &ArchivedAddress) -> bool {
        self.0 == other.0
    }
}
impl Eq for ArchivedAddress {}

impl Hash for ArchivedAddress {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

// --- Scalar --- //

// BigIntDef matches BigInt<4> structure
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = BigInt<SCALAR_LIMBS>)]
pub(crate) struct BigIntDef(pub [u64; SCALAR_LIMBS]);

impl From<BigIntDef> for BigInt<SCALAR_LIMBS> {
    fn from(value: BigIntDef) -> Self {
        BigInt(value.0)
    }
}

// ScalarFieldDef matches ScalarField (Fp<MontBackend<FrConfig, 4>, 4>)
// structure
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = Fp<MontBackend<FrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>)]
pub(crate) struct ScalarFieldDef(
    #[rkyv(with = BigIntDef)] pub BigInt<SCALAR_LIMBS>,
    pub PhantomData<MontBackend<FrConfig, SCALAR_LIMBS>>,
);

impl From<ScalarFieldDef> for Fp<MontBackend<FrConfig, SCALAR_LIMBS>, SCALAR_LIMBS> {
    fn from(value: ScalarFieldDef) -> Self {
        Fp(value.0, value.1)
    }
}

/// Remote type shim for `constants::Scalar`
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = constants::Scalar)]
#[rkyv(archived = ArchivedScalar)]
pub struct ScalarDef(
    #[rkyv(with = ScalarFieldDef)] pub Fp<MontBackend<FrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>,
);

impl From<ScalarDef> for Scalar {
    fn from(value: ScalarDef) -> Self {
        Scalar::new(value.0)
    }
}

impl From<Scalar> for ScalarDef {
    fn from(value: Scalar) -> Self {
        ScalarDef(value.0)
    }
}

impl PartialEq<Scalar> for ArchivedScalar {
    fn eq(&self, other: &Scalar) -> bool {
        self.0.0.0 == other.0.0.0
    }
}

// --- EmbeddedScalarField --- //

// EmbeddedScalarFieldDef matches EmbeddedScalarField
// (Fp<MontBackend<EmbeddedFrConfig, 4>, 4>) structure
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = Fp<MontBackend<EmbeddedFrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>)]
pub struct EmbeddedScalarFieldDef(
    #[rkyv(with = BigIntDef)] pub BigInt<SCALAR_LIMBS>,
    pub PhantomData<MontBackend<EmbeddedFrConfig, SCALAR_LIMBS>>,
);

impl From<EmbeddedScalarFieldDef>
    for Fp<MontBackend<EmbeddedFrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>
{
    fn from(value: EmbeddedScalarFieldDef) -> Self {
        Fp(value.0, value.1)
    }
}

impl From<Fp<MontBackend<EmbeddedFrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>>
    for EmbeddedScalarFieldDef
{
    fn from(value: Fp<MontBackend<EmbeddedFrConfig, SCALAR_LIMBS>, SCALAR_LIMBS>) -> Self {
        EmbeddedScalarFieldDef(value.0, value.1)
    }
}

impl PartialEq<EmbeddedScalarField> for ArchivedEmbeddedScalarFieldDef {
    fn eq(&self, other: &EmbeddedScalarField) -> bool {
        // Compare the BigInt limbs directly
        self.0.0 == other.0.0
    }
}

// --- BabyJubJubPoint --- //

/// Remote type shim for
/// `circuit_types::primitives::baby_jubjub::BabyJubJubPoint`
#[derive(Archive, Clone, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = BabyJubJubPoint)]
#[rkyv(archived = ArchivedBabyJubJubPoint)]
pub struct BabyJubJubPointDef {
    /// The x coordinate of the point
    #[rkyv(with = ScalarDef)]
    pub x: Scalar,
    /// The y coordinate of the point
    #[rkyv(with = ScalarDef)]
    pub y: Scalar,
}

impl From<BabyJubJubPointDef> for BabyJubJubPoint {
    fn from(value: BabyJubJubPointDef) -> Self {
        BabyJubJubPoint { x: value.x, y: value.y }
    }
}

impl From<BabyJubJubPoint> for BabyJubJubPointDef {
    fn from(value: BabyJubJubPoint) -> Self {
        BabyJubJubPointDef { x: value.x, y: value.y }
    }
}

impl PartialEq<BabyJubJubPoint> for ArchivedBabyJubJubPoint {
    fn eq(&self, other: &BabyJubJubPoint) -> bool {
        self.x == other.x && self.y == other.y
    }
}

// --- SchnorrPublicKey --- //

/// Remote type shim for `circuit_types::primitives::schnorr::SchnorrPublicKey`
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = SchnorrPublicKey)]
#[rkyv(derive(Debug))]
#[rkyv(archived = ArchivedSchnorrPublicKey)]
pub struct SchnorrPublicKeyDef {
    /// The curve point representing the public key
    #[rkyv(with = BabyJubJubPointDef)]
    pub point: BabyJubJubPoint,
}

impl From<SchnorrPublicKeyDef> for SchnorrPublicKey {
    fn from(value: SchnorrPublicKeyDef) -> Self {
        SchnorrPublicKey { point: value.point }
    }
}

impl PartialEq<SchnorrPublicKey> for ArchivedSchnorrPublicKey {
    fn eq(&self, other: &SchnorrPublicKey) -> bool {
        self.point == other.point
    }
}

// --- SchnorrSignature --- //

/// Remote type shim for `circuit_types::primitives::schnorr::SchnorrSignature`
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = SchnorrSignature)]
#[rkyv(derive(Debug))]
#[rkyv(archived = ArchivedSchnorrSignature)]
pub struct SchnorrSignatureDef {
    /// The s-value of the signature
    ///
    /// s = H(M || r) * private_key + k
    #[rkyv(with = EmbeddedScalarFieldDef)]
    pub s: EmbeddedScalarField,
    /// The R-value of the signature
    ///
    /// r = k * G for random k; though practically k is made deterministic via
    /// the transcript.
    #[rkyv(with = BabyJubJubPointDef)]
    pub r: BabyJubJubPoint,
}

impl From<SchnorrSignatureDef> for SchnorrSignature {
    fn from(value: SchnorrSignatureDef) -> Self {
        SchnorrSignature { s: value.s, r: value.r }
    }
}

impl From<SchnorrSignature> for SchnorrSignatureDef {
    fn from(value: SchnorrSignature) -> Self {
        SchnorrSignatureDef { s: value.s, r: value.r }
    }
}

impl PartialEq<SchnorrSignature> for ArchivedSchnorrSignature {
    fn eq(&self, other: &SchnorrSignature) -> bool {
        self.s == other.s && self.r == other.r
    }
}

// --- BabyJubJubPointShare --- //
// Only available when proof-system-types feature is enabled

/// Remote type shim for
/// `circuit_types::primitives::baby_jubjub::BabyJubJubPointShare`
///
/// The share type has `x: Scalar, y: Scalar` fields.
#[cfg(feature = "proof-system-types")]
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = BabyJubJubPointShare)]
#[rkyv(derive(Debug))]
#[rkyv(archived = ArchivedBabyJubJubPointShare)]
pub struct BabyJubJubPointShareDef {
    /// The x coordinate share
    #[rkyv(with = ScalarDef)]
    pub x: Scalar,
    /// The y coordinate share
    #[rkyv(with = ScalarDef)]
    pub y: Scalar,
}

#[cfg(feature = "proof-system-types")]
impl From<BabyJubJubPointShareDef> for BabyJubJubPointShare {
    fn from(value: BabyJubJubPointShareDef) -> Self {
        BabyJubJubPointShare { x: value.x, y: value.y }
    }
}

#[cfg(feature = "proof-system-types")]
impl PartialEq<BabyJubJubPointShare> for ArchivedBabyJubJubPointShare {
    fn eq(&self, other: &BabyJubJubPointShare) -> bool {
        self.x == other.x && self.y == other.y
    }
}

// --- SchnorrPublicKeyShare --- //
// Only available when proof-system-types feature is enabled

/// Remote type shim for
/// `circuit_types::primitives::schnorr::SchnorrPublicKeyShare`
///
/// The share type has a `point: BabyJubJubPointShare` field.
#[cfg(feature = "proof-system-types")]
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(remote = SchnorrPublicKeyShare)]
#[rkyv(derive(Debug))]
#[rkyv(archived = ArchivedSchnorrPublicKeyShare)]
pub struct SchnorrPublicKeyShareDef {
    /// The curve point share representing the public key
    #[rkyv(with = BabyJubJubPointShareDef)]
    pub point: BabyJubJubPointShare,
}

#[cfg(feature = "proof-system-types")]
impl From<SchnorrPublicKeyShareDef> for SchnorrPublicKeyShare {
    fn from(value: SchnorrPublicKeyShareDef) -> Self {
        SchnorrPublicKeyShare { point: value.point }
    }
}

#[cfg(feature = "proof-system-types")]
impl PartialEq<SchnorrPublicKeyShare> for ArchivedSchnorrPublicKeyShare {
    fn eq(&self, other: &SchnorrPublicKeyShare) -> bool {
        self.point == other.point
    }
}

// --- FixedPoint --- //

/// Remote type shim for `circuit_types::fixed_point::FixedPoint`
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = FixedPoint)]
#[rkyv(archived = ArchivedFixedPoint)]
pub struct FixedPointDef {
    /// The underlying scalar representing the fixed point variable
    #[rkyv(with = ScalarDef)]
    pub repr: Scalar,
}

impl From<FixedPointDef> for FixedPoint {
    fn from(value: FixedPointDef) -> Self {
        FixedPoint::from_repr(value.repr)
    }
}

impl PartialEq<FixedPoint> for ArchivedFixedPoint {
    fn eq(&self, other: &FixedPoint) -> bool {
        self.repr == other.repr
    }
}

// --- FixedPointShare --- //
// Only available when proof-system-types feature is enabled

/// Remote type shim for `circuit_types::fixed_point::FixedPointShare`
///
/// The share type has `repr: Scalar` field.
#[cfg(feature = "proof-system-types")]
#[derive(Archive, Deserialize, Serialize)]
#[rkyv(derive(Debug))]
#[rkyv(remote = FixedPointShare)]
#[rkyv(archived = ArchivedFixedPointShare)]
pub struct FixedPointShareDef {
    /// The underlying scalar share
    #[rkyv(with = ScalarDef)]
    pub repr: Scalar,
}

#[cfg(feature = "proof-system-types")]
impl From<FixedPointShareDef> for FixedPointShare {
    fn from(value: FixedPointShareDef) -> Self {
        FixedPointShare { repr: value.repr }
    }
}

#[cfg(feature = "proof-system-types")]
impl PartialEq<FixedPointShare> for ArchivedFixedPointShare {
    fn eq(&self, other: &FixedPointShare) -> bool {
        self.repr == other.repr
    }
}

// --- U256 --- //

/// Remote type shim for `alloy_primitives::Uint<256, 4>` (U256)
#[derive(Archive, Deserialize, Serialize, Debug, PartialEq, Eq)]
#[rkyv(derive(Debug), compare(PartialEq))]
#[rkyv(remote = alloy_primitives::U256)]
#[rkyv(archived = ArchivedU256)]
pub struct U256Def {
    /// The 4 u64 limbs representing the 256-bit integer
    #[rkyv(getter = Uint::as_limbs)]
    pub limbs: [u64; 4],
}

impl From<U256Def> for Uint<256, 4> {
    fn from(value: U256Def) -> Self {
        Uint::from_limbs(value.limbs)
    }
}

impl PartialEq<Uint<256, 4>> for ArchivedU256 {
    fn eq(&self, other: &Uint<256, 4>) -> bool {
        self.limbs == *other.as_limbs()
    }
}

impl PartialEq for ArchivedU256 {
    fn eq(&self, other: &ArchivedU256) -> bool {
        self.limbs == other.limbs
    }
}
impl Eq for ArchivedU256 {}

#[cfg(test)]
mod tests {
    #![allow(unsafe_code)]

    use alloy_primitives::Address;
    use constants::Scalar;
    use rand::{RngCore, thread_rng};
    use rkyv::{Archive, Deserialize, Serialize};

    use super::{AddressDef, ScalarDef};

    /// Test wrapper for Address to test rkyv serialization
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    struct AddressWrapper(#[rkyv(with = AddressDef)] Address);

    /// Test wrapper for Scalar to test rkyv serialization
    #[derive(Archive, Deserialize, Serialize, Debug, PartialEq)]
    struct ScalarWrapper(#[rkyv(with = ScalarDef)] Scalar);

    #[test]
    fn test_address_def_round_trip() {
        let mut rng = thread_rng();
        let mut address_bytes = [0u8; 20];
        rng.fill_bytes(&mut address_bytes);
        let original = AddressWrapper(Address::from(address_bytes));

        // Serialize
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&original).expect("Failed to serialize");

        // Deserialize
        let archived = unsafe { rkyv::access_unchecked::<ArchivedAddressWrapper>(&bytes) };
        let round_trip: AddressWrapper =
            rkyv::deserialize::<_, rkyv::rancor::Error>(archived).expect("Failed to deserialize");

        assert_eq!(original, round_trip);
    }

    #[test]
    fn test_scalar_def_round_trip() {
        let mut rng = thread_rng();
        let original = ScalarWrapper(Scalar::random(&mut rng));

        // Serialize
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&original).expect("Failed to serialize");

        // Deserialize
        let archived = unsafe { rkyv::access_unchecked::<ArchivedScalarWrapper>(&bytes) };
        let round_trip: ScalarWrapper =
            rkyv::deserialize::<_, rkyv::rancor::Error>(archived).expect("Failed to deserialize");

        assert_eq!(original, round_trip);
    }
}
