//! Trait and impls for validity proof bundles and witnesses that can be
//! persisted in state.
//!
//! Each bundle type is paired with its rkyv remote type shim and a storage key
//! prefix so that `RkyvWith<Self, Self::RkyvRemote>` satisfies the `Value`
//! trait required by the state DB layer.

use circuits_core::zk_circuits::validity_proofs::{
    intent_and_balance::SizedIntentAndBalanceValidityWitness,
    intent_and_balance_first_fill::SizedIntentAndBalanceFirstFillValidityWitness,
    intent_only::SizedIntentOnlyValidityWitness,
    intent_only_first_fill::IntentOnlyFirstFillValidityWitness,
    new_output_balance::SizedNewOutputBalanceValidityWitness,
    output_balance::SizedOutputBalanceValidityWitness,
};

use crate::bundles::{
    IntentAndBalanceFirstFillValidityBundle, IntentAndBalanceValidityBundle,
    IntentOnlyFirstFillValidityBundle, IntentOnlyValidityBundle, NewOutputBalanceValidityBundle,
    OutputBalanceValidityBundle,
};
use crate::rkyv_impls::{
    IntentAndBalanceFirstFillValidityBundleDef, IntentAndBalanceFirstFillValidityWitnessDef,
    IntentAndBalanceValidityBundleDef, IntentAndBalanceValidityWitnessDef,
    IntentOnlyFirstFillValidityBundleDef, IntentOnlyFirstFillValidityWitnessDef,
    IntentOnlyValidityBundleDef, IntentOnlyValidityWitnessDef, NewOutputBalanceValidityBundleDef,
    NewOutputBalanceValidityWitnessDef, OutputBalanceValidityBundleDef,
    OutputBalanceValidityWitnessDef,
};

/// Marker trait for validity proof bundles that can be persisted.
///
/// Each bundle type is paired with its rkyv remote type shim so that
/// `RkyvWith<Self, Self::RkyvRemote>` satisfies the `Value` trait
/// required by `DbTxn::read`/`write`.
pub trait StoredValidityProof: Sized {
    /// The rkyv remote type that provides Archive/Serialize/Deserialize
    type RkyvRemote;
    /// The key prefix identifying this proof type in storage
    const PROOF_TYPE_KEY: &'static str;
}

impl StoredValidityProof for IntentOnlyFirstFillValidityBundle {
    type RkyvRemote = IntentOnlyFirstFillValidityBundleDef;
    const PROOF_TYPE_KEY: &'static str = "intent-only-first-fill";
}

impl StoredValidityProof for IntentOnlyValidityBundle {
    type RkyvRemote = IntentOnlyValidityBundleDef;
    const PROOF_TYPE_KEY: &'static str = "intent-only";
}

impl StoredValidityProof for IntentAndBalanceFirstFillValidityBundle {
    type RkyvRemote = IntentAndBalanceFirstFillValidityBundleDef;
    const PROOF_TYPE_KEY: &'static str = "intent-and-balance-first-fill";
}

impl StoredValidityProof for IntentAndBalanceValidityBundle {
    type RkyvRemote = IntentAndBalanceValidityBundleDef;
    const PROOF_TYPE_KEY: &'static str = "intent-and-balance";
}

impl StoredValidityProof for NewOutputBalanceValidityBundle {
    type RkyvRemote = NewOutputBalanceValidityBundleDef;
    const PROOF_TYPE_KEY: &'static str = "new-output-balance";
}

impl StoredValidityProof for OutputBalanceValidityBundle {
    type RkyvRemote = OutputBalanceValidityBundleDef;
    const PROOF_TYPE_KEY: &'static str = "output-balance";
}

/// All validity proof key prefixes, for bulk delete operations.
pub const ALL_VALIDITY_PROOF_KEYS: [&str; 6] = [
    IntentOnlyFirstFillValidityBundle::PROOF_TYPE_KEY,
    IntentOnlyValidityBundle::PROOF_TYPE_KEY,
    IntentAndBalanceFirstFillValidityBundle::PROOF_TYPE_KEY,
    IntentAndBalanceValidityBundle::PROOF_TYPE_KEY,
    NewOutputBalanceValidityBundle::PROOF_TYPE_KEY,
    OutputBalanceValidityBundle::PROOF_TYPE_KEY,
];

/// Output balance validity proof key prefixes.
///
/// Used to check whether any output balance proof (new or existing) is stored
/// for a given locator.
pub const OUTPUT_BALANCE_VALIDITY_PROOF_KEYS: [&str; 2] =
    [NewOutputBalanceValidityBundle::PROOF_TYPE_KEY, OutputBalanceValidityBundle::PROOF_TYPE_KEY];

// ----------------------
// | Validity Witnesses |
// ----------------------

/// Marker trait for validity proof witnesses that can be persisted.
///
/// Each witness type is paired with its rkyv remote type shim so that
/// `RkyvWith<Self, Self::RkyvRemote>` satisfies the `Value` trait
/// required by `DbTxn::read`/`write`.
pub trait StoredValidityWitness: Sized {
    /// The rkyv remote type that provides Archive/Serialize/Deserialize
    type RkyvRemote;
    /// The key prefix identifying this witness type in storage
    const WITNESS_TYPE_KEY: &'static str;
}

impl StoredValidityWitness for IntentOnlyFirstFillValidityWitness {
    type RkyvRemote = IntentOnlyFirstFillValidityWitnessDef;
    const WITNESS_TYPE_KEY: &'static str = "intent-only-first-fill-witness";
}

impl StoredValidityWitness for SizedIntentOnlyValidityWitness {
    type RkyvRemote = IntentOnlyValidityWitnessDef;
    const WITNESS_TYPE_KEY: &'static str = "intent-only-witness";
}

impl StoredValidityWitness for SizedIntentAndBalanceFirstFillValidityWitness {
    type RkyvRemote = IntentAndBalanceFirstFillValidityWitnessDef;
    const WITNESS_TYPE_KEY: &'static str = "intent-and-balance-first-fill-witness";
}

impl StoredValidityWitness for SizedIntentAndBalanceValidityWitness {
    type RkyvRemote = IntentAndBalanceValidityWitnessDef;
    const WITNESS_TYPE_KEY: &'static str = "intent-and-balance-witness";
}

impl StoredValidityWitness for SizedNewOutputBalanceValidityWitness {
    type RkyvRemote = NewOutputBalanceValidityWitnessDef;
    const WITNESS_TYPE_KEY: &'static str = "new-output-balance-witness";
}

impl StoredValidityWitness for SizedOutputBalanceValidityWitness {
    type RkyvRemote = OutputBalanceValidityWitnessDef;
    const WITNESS_TYPE_KEY: &'static str = "output-balance-witness";
}

/// All validity witness key prefixes, for bulk delete operations.
pub const ALL_VALIDITY_WITNESS_KEYS: [&str; 6] = [
    IntentOnlyFirstFillValidityWitness::WITNESS_TYPE_KEY,
    SizedIntentOnlyValidityWitness::WITNESS_TYPE_KEY,
    SizedIntentAndBalanceFirstFillValidityWitness::WITNESS_TYPE_KEY,
    SizedIntentAndBalanceValidityWitness::WITNESS_TYPE_KEY,
    SizedNewOutputBalanceValidityWitness::WITNESS_TYPE_KEY,
    SizedOutputBalanceValidityWitness::WITNESS_TYPE_KEY,
];
