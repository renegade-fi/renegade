//! Types & trait implementations to enable deriving serde::{Serialize,
//! Deserialize} on the foreign Arkworks, Alloy, and other types that we compose
//! into complex structs.

use alloy_primitives::{Address, FixedBytes, Uint};
use ark_bn254::{Fq2Config, FqConfig, FrConfig, g1::Config as G1Config, g2::Config as G2Config};
use ark_ec::short_weierstrass::Affine;
use ark_ff::{BigInt, Fp, Fp2ConfigWrapper, FpConfig, MontBackend, QuadExtField};
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeAs, SerializeAs, serde_as};

use super::types::{G1Affine, G1BaseField, G2Affine, G2BaseField, ScalarField};

/// This macro implements the `SerializeAs` and `DeserializeAs` traits for a
/// given type, allowing it to be serialized / deserialized as the remote type
/// it mirrors.
macro_rules! impl_serde_as {
    ($remote_type:ty, $def_type:ty, $($generics:tt)*) => {
        impl<$($generics)*> SerializeAs<$remote_type> for $def_type {
            fn serialize_as<S>(source: &$remote_type, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                <$def_type>::serialize(source, serializer)
            }
        }

        impl<'de, $($generics)*> DeserializeAs<'de, $remote_type> for $def_type {
            fn deserialize_as<D>(deserializer: D) -> Result<$remote_type, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                <$def_type>::deserialize(deserializer)
            }
        }
    };
}

/// A serde-compatible type mirroring [`BigInt`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "BigInt")]
pub struct BigIntDef<const N: usize>(#[serde_as(as = "[_; N]")] pub [u64; N]);

impl_serde_as!(BigInt<N>, BigIntDef<N>, const N: usize);

/// A serde-compatible type mirroring [`Fp`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Fp")]
pub struct FpDef<P: FpConfig<N>, const N: usize>(
    #[serde_as(as = "BigIntDef<N>")] pub BigInt<N>,
    pub PhantomData<P>,
);

impl_serde_as!(Fp<P, N>, FpDef<P, N>, P: FpConfig<N>, const N: usize);

/// A serde-compatible type alias mirroring [`ScalarField`]
pub type ScalarFieldDef = FpDef<MontBackend<FrConfig, 4>, 4>;

/// A serde-compatible type alias mirroring [`G1BaseField`]
pub(crate) type G1BaseFieldDef = FpDef<MontBackend<FqConfig, 4>, 4>;

/// A serde-compatible wrapper type around [`ScalarField`],
/// allowing direct access to the underlying type
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct SerdeScalarField(#[serde_as(as = "ScalarFieldDef")] pub ScalarField);

/// A serde-compatible type mirroring [`G2BaseField`],
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "QuadExtField<Fp2ConfigWrapper<Fq2Config>>")]
pub(crate) struct G2BaseFieldDef {
    #[doc(hidden)]
    #[serde_as(as = "G1BaseFieldDef")]
    pub c0: G1BaseField,
    #[doc(hidden)]
    #[serde_as(as = "G1BaseFieldDef")]
    pub c1: G1BaseField,
}

impl_serde_as!(G2BaseField, G2BaseFieldDef,);

/// A serde-compatible type mirroring [`G1Affine`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Affine<G1Config>")]
pub(crate) struct G1AffineDef {
    #[doc(hidden)]
    #[serde_as(as = "G1BaseFieldDef")]
    x: G1BaseField,
    #[doc(hidden)]
    #[serde_as(as = "G1BaseFieldDef")]
    y: G1BaseField,
    #[doc(hidden)]
    infinity: bool,
}

impl_serde_as!(G1Affine, G1AffineDef,);

/// A serde-compatible wrapper type around [`G1Affine`],
/// allowing direct access to the underlying type
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SerdeG1Affine(#[serde_as(as = "G1AffineDef")] pub G1Affine);

/// A serde-compatible type mirroring [`G2Affine`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Affine<G2Config>")]
pub(crate) struct G2AffineDef {
    #[doc(hidden)]
    #[serde_as(as = "G2BaseFieldDef")]
    x: G2BaseField,
    #[doc(hidden)]
    #[serde_as(as = "G2BaseFieldDef")]
    y: G2BaseField,
    #[doc(hidden)]
    infinity: bool,
}

impl_serde_as!(G2Affine, G2AffineDef,);

/// A serde-compatible wrapper type around [`G2Affine`],
/// allowing direct access to the underlying type
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SerdeG2Affine(#[serde_as(as = "G2AffineDef")] pub G2Affine);

/// A serde-compatible type mirroring [`FixedBytes`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "FixedBytes")]
pub(crate) struct FixedBytesDef<const N: usize>(#[serde_as(as = "[_; N]")] pub [u8; N]);

impl_serde_as!(FixedBytes<N>, FixedBytesDef<N>, const N: usize);

/// A serde-compatible type mirroring [`Address`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Address")]
pub struct AddressDef(#[serde_as(as = "FixedBytesDef<20>")] FixedBytes<20>);

impl_serde_as!(Address, AddressDef,);

/// A serde-compatible type mirroring [`Uint`]
#[serde_as]
#[derive(Serialize, Deserialize)]
#[serde(remote = "Uint")]
pub(crate) struct UintDef<const BITS: usize, const LIMBS: usize> {
    #[doc(hidden)]
    #[serde_as(as = "[_; LIMBS]")]
    #[serde(getter = "Uint::as_limbs")]
    limbs: [u64; LIMBS],
}

impl<const BITS: usize, const LIMBS: usize> From<UintDef<BITS, LIMBS>> for Uint<BITS, LIMBS> {
    fn from(value: UintDef<BITS, LIMBS>) -> Self {
        Uint::from_limbs(value.limbs)
    }
}

impl_serde_as!(Uint<BITS, LIMBS>, UintDef<BITS, LIMBS>, const BITS: usize, const LIMBS: usize);

/// A serde-compatible type alias mirroring [`U256`]
pub(crate) type U256Def = UintDef<256, 4>;
