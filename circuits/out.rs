#![feature(prelude_import)]
//! Groups circuits for MPC and zero knowledge execution
#![feature(generic_const_exprs)]
#![feature(negative_impls)]
#![allow(incomplete_features)]
#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]
#[prelude_import]
use std::prelude::rust_2021::*;
#[macro_use]
extern crate std;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use errors::{MpcError, ProverError, VerifierError};
use itertools::Itertools;
use merlin::Transcript;
use mpc::SharedFabric;
use mpc_bulletproof::{
    r1cs::{Prover, R1CSProof, Verifier},
    r1cs_mpc::{MpcProver, MpcVariable, SharedR1CSProof},
    PedersenGens,
};
use mpc_ristretto::{
    authenticated_ristretto::AuthenticatedCompressedRistretto,
    authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
    network::MpcNetwork,
};
use serde::{Deserialize, Serialize};
use rand_core::{CryptoRng, OsRng, RngCore};
pub mod errors {
    //! Groups error types for the circuits crate
    use std::fmt::{Display, Formatter, Result};
    use mpc_bulletproof::r1cs_mpc::{MultiproverError, R1CSError};
    /// Represents an error during the course of an MPC circuit execution
    pub enum MpcError {
        /// Represents an error during the course of an arithmetic operation
        ArithmeticError(String),
        /// Error opening a value during circuit evaluation
        OpeningError(String),
        /// Error serializing and deserializing network values
        SerializationError(String),
        /// Error when setting up an MPC
        SetupError(String),
        /// Error sharing a privately held value
        SharingError(String),
    }
    #[automatically_derived]
    impl ::core::clone::Clone for MpcError {
        #[inline]
        fn clone(&self) -> MpcError {
            match self {
                MpcError::ArithmeticError(__self_0) => {
                    MpcError::ArithmeticError(::core::clone::Clone::clone(__self_0))
                }
                MpcError::OpeningError(__self_0) => {
                    MpcError::OpeningError(::core::clone::Clone::clone(__self_0))
                }
                MpcError::SerializationError(__self_0) => {
                    MpcError::SerializationError(::core::clone::Clone::clone(__self_0))
                }
                MpcError::SetupError(__self_0) => {
                    MpcError::SetupError(::core::clone::Clone::clone(__self_0))
                }
                MpcError::SharingError(__self_0) => {
                    MpcError::SharingError(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for MpcError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                MpcError::ArithmeticError(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "ArithmeticError",
                        &__self_0,
                    )
                }
                MpcError::OpeningError(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "OpeningError",
                        &__self_0,
                    )
                }
                MpcError::SerializationError(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "SerializationError",
                        &__self_0,
                    )
                }
                MpcError::SetupError(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "SetupError",
                        &__self_0,
                    )
                }
                MpcError::SharingError(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "SharingError",
                        &__self_0,
                    )
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for MpcError {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for MpcError {
        #[inline]
        fn eq(&self, other: &MpcError) -> bool {
            let __self_tag = ::core::intrinsics::discriminant_value(self);
            let __arg1_tag = ::core::intrinsics::discriminant_value(other);
            __self_tag == __arg1_tag
                && match (self, other) {
                    (
                        MpcError::ArithmeticError(__self_0),
                        MpcError::ArithmeticError(__arg1_0),
                    ) => *__self_0 == *__arg1_0,
                    (
                        MpcError::OpeningError(__self_0),
                        MpcError::OpeningError(__arg1_0),
                    ) => *__self_0 == *__arg1_0,
                    (
                        MpcError::SerializationError(__self_0),
                        MpcError::SerializationError(__arg1_0),
                    ) => *__self_0 == *__arg1_0,
                    (MpcError::SetupError(__self_0), MpcError::SetupError(__arg1_0)) => {
                        *__self_0 == *__arg1_0
                    }
                    (
                        MpcError::SharingError(__self_0),
                        MpcError::SharingError(__arg1_0),
                    ) => *__self_0 == *__arg1_0,
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralEq for MpcError {}
    #[automatically_derived]
    impl ::core::cmp::Eq for MpcError {
        #[inline]
        #[doc(hidden)]
        #[no_coverage]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<String>;
        }
    }
    impl Display for MpcError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.write_fmt(format_args!("{0:?}", self))
        }
    }
    /// Represents an error during the course of proving a statement
    pub enum ProverError {
        /// An error during the course of a multi-prover execution that results
        /// from the MPC network itself
        Mpc(MpcError),
        /// An error that occurs from the execution of a collaborative proof
        Collaborative(MultiproverError),
        /// An error that occurs from an R1CS error directly
        R1CS(R1CSError),
    }
    #[automatically_derived]
    impl ::core::clone::Clone for ProverError {
        #[inline]
        fn clone(&self) -> ProverError {
            match self {
                ProverError::Mpc(__self_0) => {
                    ProverError::Mpc(::core::clone::Clone::clone(__self_0))
                }
                ProverError::Collaborative(__self_0) => {
                    ProverError::Collaborative(::core::clone::Clone::clone(__self_0))
                }
                ProverError::R1CS(__self_0) => {
                    ProverError::R1CS(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ProverError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                ProverError::Mpc(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Mpc",
                        &__self_0,
                    )
                }
                ProverError::Collaborative(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "Collaborative",
                        &__self_0,
                    )
                }
                ProverError::R1CS(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "R1CS",
                        &__self_0,
                    )
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for ProverError {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for ProverError {
        #[inline]
        fn eq(&self, other: &ProverError) -> bool {
            let __self_tag = ::core::intrinsics::discriminant_value(self);
            let __arg1_tag = ::core::intrinsics::discriminant_value(other);
            __self_tag == __arg1_tag
                && match (self, other) {
                    (ProverError::Mpc(__self_0), ProverError::Mpc(__arg1_0)) => {
                        *__self_0 == *__arg1_0
                    }
                    (
                        ProverError::Collaborative(__self_0),
                        ProverError::Collaborative(__arg1_0),
                    ) => *__self_0 == *__arg1_0,
                    (ProverError::R1CS(__self_0), ProverError::R1CS(__arg1_0)) => {
                        *__self_0 == *__arg1_0
                    }
                    _ => unsafe { ::core::intrinsics::unreachable() }
                }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralEq for ProverError {}
    #[automatically_derived]
    impl ::core::cmp::Eq for ProverError {
        #[inline]
        #[doc(hidden)]
        #[no_coverage]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<MpcError>;
            let _: ::core::cmp::AssertParamIsEq<MultiproverError>;
            let _: ::core::cmp::AssertParamIsEq<R1CSError>;
        }
    }
    impl Display for ProverError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.write_fmt(format_args!("{0:?}", self))
        }
    }
    /// Represents an error during proof verification
    pub enum VerifierError {
        /// An error that occurs as a result of R1CS non-satisfaction
        R1CS(R1CSError),
    }
    #[automatically_derived]
    impl ::core::clone::Clone for VerifierError {
        #[inline]
        fn clone(&self) -> VerifierError {
            match self {
                VerifierError::R1CS(__self_0) => {
                    VerifierError::R1CS(::core::clone::Clone::clone(__self_0))
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for VerifierError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            match self {
                VerifierError::R1CS(__self_0) => {
                    ::core::fmt::Formatter::debug_tuple_field1_finish(
                        f,
                        "R1CS",
                        &__self_0,
                    )
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for VerifierError {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for VerifierError {
        #[inline]
        fn eq(&self, other: &VerifierError) -> bool {
            match (self, other) {
                (VerifierError::R1CS(__self_0), VerifierError::R1CS(__arg1_0)) => {
                    *__self_0 == *__arg1_0
                }
            }
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralEq for VerifierError {}
    #[automatically_derived]
    impl ::core::cmp::Eq for VerifierError {
        #[inline]
        #[doc(hidden)]
        #[no_coverage]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<R1CSError>;
        }
    }
    impl Display for VerifierError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.write_fmt(format_args!("{0:?}", self))
        }
    }
    /// Represents an error in converting to/from this package's types
    pub struct TypeConversionError(pub(crate) String);
    #[automatically_derived]
    impl ::core::clone::Clone for TypeConversionError {
        #[inline]
        fn clone(&self) -> TypeConversionError {
            TypeConversionError(::core::clone::Clone::clone(&self.0))
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for TypeConversionError {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "TypeConversionError",
                &&self.0,
            )
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for TypeConversionError {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for TypeConversionError {
        #[inline]
        fn eq(&self, other: &TypeConversionError) -> bool {
            self.0 == other.0
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralEq for TypeConversionError {}
    #[automatically_derived]
    impl ::core::cmp::Eq for TypeConversionError {
        #[inline]
        #[doc(hidden)]
        #[no_coverage]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<String>;
        }
    }
    impl Display for TypeConversionError {
        fn fmt(&self, f: &mut Formatter<'_>) -> Result {
            f.write_fmt(format_args!("{0:?}", self.0))
        }
    }
}
mod macro_tests {
    //! Defines tests for macros in the `circuit_macros` crate. We do this so that we may define the
    //! bulk of the traits, data structures, etc outside of the `circuit-macros` crate; as a proc-macro
    //! crate cannot export non proc-macro items
    #[allow(clippy::missing_docs_in_private_items)]
    #[cfg(test)]
    mod test {
        use circuit_macros::circuit_type;
        use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
        use integration_helpers::mpc_network::mocks::{MockMpcNet, PartyIDBeaverSource};
        use merlin::Transcript;
        use mpc_bulletproof::{
            r1cs::{Prover, Variable, Verifier},
            r1cs_mpc::MpcVariable, PedersenGens,
        };
        use mpc_ristretto::{
            authenticated_ristretto::AuthenticatedCompressedRistretto,
            authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
            network::MpcNetwork,
        };
        use rand_core::OsRng;
        use serde::{Deserialize, Serialize};
        use std::{cell::RefCell, rc::Rc};
        use crate::{
            mpc::{MpcFabric, SharedFabric},
            traits::{
                Allocate, BaseType, CircuitBaseType, CircuitCommitmentType,
                CircuitVarType, CommitPublic, CommitVerifier, CommitWitness, MpcBaseType,
                MpcType, MultiproverCircuitBaseType, MultiproverCircuitCommitmentType,
                MultiproverCircuitVariableType, Open,
            },
        };
        struct TestType {
            val: Scalar,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for TestType {
            #[inline]
            fn clone(&self) -> TestType {
                TestType {
                    val: ::core::clone::Clone::clone(&self.val),
                }
            }
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for TestType {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field1_finish(
                    f,
                    "TestType",
                    "val",
                    &&self.val,
                )
            }
        }
        #[automatically_derived]
        impl ::core::marker::StructuralPartialEq for TestType {}
        #[automatically_derived]
        impl ::core::cmp::PartialEq for TestType {
            #[inline]
            fn eq(&self, other: &TestType) -> bool {
                self.val == other.val
            }
        }
        #[automatically_derived]
        impl ::core::marker::StructuralEq for TestType {}
        #[automatically_derived]
        impl ::core::cmp::Eq for TestType {
            #[inline]
            #[doc(hidden)]
            #[no_coverage]
            fn assert_receiver_is_total_eq(&self) -> () {
                let _: ::core::cmp::AssertParamIsEq<Scalar>;
            }
        }
        impl BaseType for TestType {
            fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
                Self {
                    val: <Scalar as BaseType>::from_scalars(i),
                }
            }
            fn to_scalars(self) -> Vec<Scalar> {
                <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([self.val]))
            }
        }
        impl CircuitBaseType for TestType {
            type VarType = TestTypeVar;
            type CommitmentType = TestTypeCommitment;
        }
        struct TestTypeVar {
            val: <Scalar as CircuitBaseType>::VarType,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for TestTypeVar {
            #[inline]
            fn clone(&self) -> TestTypeVar {
                TestTypeVar {
                    val: ::core::clone::Clone::clone(&self.val),
                }
            }
        }
        impl CircuitVarType for TestTypeVar {
            fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self {
                Self {
                    val: <<Scalar as CircuitBaseType>::VarType as CircuitVarType>::from_vars(
                        i,
                    ),
                }
            }
        }
        struct TestTypeCommitment {
            val: <Scalar as CircuitBaseType>::CommitmentType,
        }
        #[automatically_derived]
        impl ::core::clone::Clone for TestTypeCommitment {
            #[inline]
            fn clone(&self) -> TestTypeCommitment {
                TestTypeCommitment {
                    val: ::core::clone::Clone::clone(&self.val),
                }
            }
        }
        impl CircuitCommitmentType for TestTypeCommitment {
            type VarType = TestTypeVar;
            fn from_commitments<I: Iterator<Item = CompressedRistretto>>(
                i: &mut I,
            ) -> Self {
                Self {
                    val: <<Scalar as CircuitBaseType>::CommitmentType as CircuitCommitmentType>::from_commitments(
                        i,
                    ),
                }
            }
            fn to_commitments(self) -> Vec<CompressedRistretto> {
                <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([self.val]))
            }
        }
        impl<
            N: MpcNetwork + Send + Clone,
            S: SharedValueSource<Scalar> + Clone,
        > MpcBaseType<N, S> for TestType {
            type AllocatedType = AuthenticatedTestType<N, S>;
        }
        struct AuthenticatedTestType<
            N: MpcNetwork + Send + Clone,
            S: SharedValueSource<Scalar> + Clone,
        > {
            val: <Scalar as MpcBaseType<N, S>>::AllocatedType,
        }
        #[automatically_derived]
        impl<
            N: ::core::clone::Clone + MpcNetwork + Send + Clone,
            S: ::core::clone::Clone + SharedValueSource<Scalar> + Clone,
        > ::core::clone::Clone for AuthenticatedTestType<N, S> {
            #[inline]
            fn clone(&self) -> AuthenticatedTestType<N, S> {
                AuthenticatedTestType {
                    val: ::core::clone::Clone::clone(&self.val),
                }
            }
        }
        impl<
            N: MpcNetwork + Send + Clone,
            S: SharedValueSource<Scalar> + Clone,
        > MpcType<N, S> for AuthenticatedTestType<N, S> {
            type NativeType = TestType;
            fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar<N, S>>>(
                i: &mut I,
            ) -> Self {
                Self {
                    val: <<Scalar as MpcBaseType<
                        N,
                        S,
                    >>::AllocatedType as MpcType<N, S>>::from_authenticated_scalars(i),
                }
            }
            fn to_authenticated_scalars(self) -> Vec<AuthenticatedScalar<N, S>> {
                <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([self.val]))
            }
        }
        impl<
            N: MpcNetwork + Send + Clone,
            S: SharedValueSource<Scalar> + Clone,
        > MultiproverCircuitBaseType<N, S> for TestType {
            type MultiproverVarType = AuthenticatedTestTypeVar;
            type MultiproverCommType = AuthenticatedTestTypeCommitment;
        }
        struct AuthenticatedTestTypeVar<
            N: MpcNetwork + Send + Clone,
            S: SharedValueSource<Scalar> + Clone,
        > {
            val: <Scalar as MultiproverCircuitBaseType<N, S>>::MultiproverVarType,
        }
        #[automatically_derived]
        impl<
            N: ::core::clone::Clone + MpcNetwork + Send + Clone,
            S: ::core::clone::Clone + SharedValueSource<Scalar> + Clone,
        > ::core::clone::Clone for AuthenticatedTestTypeVar<N, S> {
            #[inline]
            fn clone(&self) -> AuthenticatedTestTypeVar<N, S> {
                AuthenticatedTestTypeVar {
                    val: ::core::clone::Clone::clone(&self.val),
                }
            }
        }
        impl<
            N: MpcNetwork + Send + Clone,
            S: SharedValueSource<Scalar> + Clone,
        > MultiproverCircuitVariableType<N, S> for AuthenticatedTestTypeVar<N, S> {
            fn from_mpc_vars<I: Iterator<Item = MpcVariable<N, S>>>(i: &mut I) -> Self {
                Self {
                    val: <<Scalar as MultiproverCircuitBaseType<
                        N,
                        S,
                    >>::MultiproverVarType as MultiproverCircuitVariableType<
                        N,
                        S,
                    >>::from_mpc_vars(i),
                }
            }
        }
        struct AuthenticatedTestTypeCommitment<
            N: MpcNetwork + Send + Clone,
            S: SharedValueSource<Scalar> + Clone,
        > {
            val: <Scalar as MultiproverCircuitBaseType<N, S>>::MultiproverCommType,
        }
        #[automatically_derived]
        impl<
            N: ::core::clone::Clone + MpcNetwork + Send + Clone,
            S: ::core::clone::Clone + SharedValueSource<Scalar> + Clone,
        > ::core::clone::Clone for AuthenticatedTestTypeCommitment<N, S> {
            #[inline]
            fn clone(&self) -> AuthenticatedTestTypeCommitment<N, S> {
                AuthenticatedTestTypeCommitment {
                    val: ::core::clone::Clone::clone(&self.val),
                }
            }
        }
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<
                N: MpcNetwork + Send + Clone,
                S: SharedValueSource<Scalar> + Clone,
            > _serde::Serialize for AuthenticatedTestTypeCommitment<N, S>
            where
                N: _serde::Serialize,
                S: _serde::Serialize,
            {
                fn serialize<__S>(
                    &self,
                    __serializer: __S,
                ) -> _serde::__private::Result<__S::Ok, __S::Error>
                where
                    __S: _serde::Serializer,
                {
                    let mut __serde_state = match _serde::Serializer::serialize_struct(
                        __serializer,
                        "AuthenticatedTestTypeCommitment",
                        false as usize + 1,
                    ) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    };
                    match _serde::ser::SerializeStruct::serialize_field(
                        &mut __serde_state,
                        "val",
                        &self.val,
                    ) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    };
                    _serde::ser::SerializeStruct::end(__serde_state)
                }
            }
        };
        #[doc(hidden)]
        #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
        const _: () = {
            #[allow(unused_extern_crates, clippy::useless_attribute)]
            extern crate serde as _serde;
            #[automatically_derived]
            impl<
                'de,
                N: MpcNetwork + Send + Clone,
                S: SharedValueSource<Scalar> + Clone,
            > _serde::Deserialize<'de> for AuthenticatedTestTypeCommitment<N, S>
            where
                N: _serde::Deserialize<'de>,
                S: _serde::Deserialize<'de>,
            {
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    #[allow(non_camel_case_types)]
                    #[doc(hidden)]
                    enum __Field {
                        __field0,
                        __ignore,
                    }
                    #[doc(hidden)]
                    struct __FieldVisitor;
                    impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                        type Value = __Field;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "field identifier",
                            )
                        }
                        fn visit_u64<__E>(
                            self,
                            __value: u64,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                0u64 => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_str<__E>(
                            self,
                            __value: &str,
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                "val" => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                        fn visit_bytes<__E>(
                            self,
                            __value: &[u8],
                        ) -> _serde::__private::Result<Self::Value, __E>
                        where
                            __E: _serde::de::Error,
                        {
                            match __value {
                                b"val" => _serde::__private::Ok(__Field::__field0),
                                _ => _serde::__private::Ok(__Field::__ignore),
                            }
                        }
                    }
                    impl<'de> _serde::Deserialize<'de> for __Field {
                        #[inline]
                        fn deserialize<__D>(
                            __deserializer: __D,
                        ) -> _serde::__private::Result<Self, __D::Error>
                        where
                            __D: _serde::Deserializer<'de>,
                        {
                            _serde::Deserializer::deserialize_identifier(
                                __deserializer,
                                __FieldVisitor,
                            )
                        }
                    }
                    #[doc(hidden)]
                    struct __Visitor<
                        'de,
                        N: MpcNetwork + Send + Clone,
                        S: SharedValueSource<Scalar> + Clone,
                    >
                    where
                        N: _serde::Deserialize<'de>,
                        S: _serde::Deserialize<'de>,
                    {
                        marker: _serde::__private::PhantomData<
                            AuthenticatedTestTypeCommitment<N, S>,
                        >,
                        lifetime: _serde::__private::PhantomData<&'de ()>,
                    }
                    impl<
                        'de,
                        N: MpcNetwork + Send + Clone,
                        S: SharedValueSource<Scalar> + Clone,
                    > _serde::de::Visitor<'de> for __Visitor<'de, N, S>
                    where
                        N: _serde::Deserialize<'de>,
                        S: _serde::Deserialize<'de>,
                    {
                        type Value = AuthenticatedTestTypeCommitment<N, S>;
                        fn expecting(
                            &self,
                            __formatter: &mut _serde::__private::Formatter,
                        ) -> _serde::__private::fmt::Result {
                            _serde::__private::Formatter::write_str(
                                __formatter,
                                "struct AuthenticatedTestTypeCommitment",
                            )
                        }
                        #[inline]
                        fn visit_seq<__A>(
                            self,
                            mut __seq: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::SeqAccess<'de>,
                        {
                            let __field0 = match match _serde::de::SeqAccess::next_element::<
                                <Scalar as MultiproverCircuitBaseType<
                                    N,
                                    S,
                                >>::MultiproverCommType,
                            >(&mut __seq) {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            } {
                                _serde::__private::Some(__value) => __value,
                                _serde::__private::None => {
                                    return _serde::__private::Err(
                                        _serde::de::Error::invalid_length(
                                            0usize,
                                            &"struct AuthenticatedTestTypeCommitment with 1 element",
                                        ),
                                    );
                                }
                            };
                            _serde::__private::Ok(AuthenticatedTestTypeCommitment {
                                val: __field0,
                            })
                        }
                        #[inline]
                        fn visit_map<__A>(
                            self,
                            mut __map: __A,
                        ) -> _serde::__private::Result<Self::Value, __A::Error>
                        where
                            __A: _serde::de::MapAccess<'de>,
                        {
                            let mut __field0: _serde::__private::Option<
                                <Scalar as MultiproverCircuitBaseType<
                                    N,
                                    S,
                                >>::MultiproverCommType,
                            > = _serde::__private::None;
                            while let _serde::__private::Some(__key)
                                = match _serde::de::MapAccess::next_key::<
                                    __Field,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                } {
                                match __key {
                                    __Field::__field0 => {
                                        if _serde::__private::Option::is_some(&__field0) {
                                            return _serde::__private::Err(
                                                <__A::Error as _serde::de::Error>::duplicate_field("val"),
                                            );
                                        }
                                        __field0 = _serde::__private::Some(
                                            match _serde::de::MapAccess::next_value::<
                                                <Scalar as MultiproverCircuitBaseType<
                                                    N,
                                                    S,
                                                >>::MultiproverCommType,
                                            >(&mut __map) {
                                                _serde::__private::Ok(__val) => __val,
                                                _serde::__private::Err(__err) => {
                                                    return _serde::__private::Err(__err);
                                                }
                                            },
                                        );
                                    }
                                    _ => {
                                        let _ = match _serde::de::MapAccess::next_value::<
                                            _serde::de::IgnoredAny,
                                        >(&mut __map) {
                                            _serde::__private::Ok(__val) => __val,
                                            _serde::__private::Err(__err) => {
                                                return _serde::__private::Err(__err);
                                            }
                                        };
                                    }
                                }
                            }
                            let __field0 = match __field0 {
                                _serde::__private::Some(__field0) => __field0,
                                _serde::__private::None => {
                                    match _serde::__private::de::missing_field("val") {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    }
                                }
                            };
                            _serde::__private::Ok(AuthenticatedTestTypeCommitment {
                                val: __field0,
                            })
                        }
                    }
                    #[doc(hidden)]
                    const FIELDS: &'static [&'static str] = &["val"];
                    _serde::Deserializer::deserialize_struct(
                        __deserializer,
                        "AuthenticatedTestTypeCommitment",
                        FIELDS,
                        __Visitor {
                            marker: _serde::__private::PhantomData::<
                                AuthenticatedTestTypeCommitment<N, S>,
                            >,
                            lifetime: _serde::__private::PhantomData,
                        },
                    )
                }
            }
        };
        impl<
            N: MpcNetwork + Send + Clone,
            S: SharedValueSource<Scalar> + Clone,
        > MultiproverCircuitCommitmentType<N, S>
        for AuthenticatedTestTypeCommitment<N, S> {
            fn from_mpc_commitments<
                I: Iterator<Item = AuthenticatedCompressedRistretto<N, S>>,
            >(i: &mut I) -> Self {
                Self {
                    val: <<Scalar as MultiproverCircuitBaseType<
                        N,
                        S,
                    >>::MultiproverCommType as MultiproverCircuitCommitmentType<
                        N,
                        S,
                    >>::from_mpc_commitments(i),
                }
            }
        }
        impl TestType {
            fn check_equal(&self, val: Scalar) -> bool {
                self.val.eq(&val)
            }
        }
        extern crate test;
        #[cfg(test)]
        #[rustc_test_marker = "macro_tests::test::test_base_type_preserved"]
        pub const test_base_type_preserved: test::TestDescAndFn = test::TestDescAndFn {
            desc: test::TestDesc {
                name: test::StaticTestName(
                    "macro_tests::test::test_base_type_preserved",
                ),
                ignore: false,
                ignore_message: ::core::option::Option::None,
                compile_fail: false,
                no_run: false,
                should_panic: test::ShouldPanic::No,
                test_type: test::TestType::UnitTest,
            },
            testfn: test::StaticTestFn(|| test::assert_test_result(
                test_base_type_preserved(),
            )),
        };
        fn test_base_type_preserved() {
            let a = TestType { val: Scalar::one() };
            if !a.check_equal(Scalar::one()) {
                ::core::panicking::panic(
                    "assertion failed: a.check_equal(Scalar::one())",
                )
            }
        }
        extern crate test;
        #[cfg(test)]
        #[rustc_test_marker = "macro_tests::test::test_base_type_implementation"]
        pub const test_base_type_implementation: test::TestDescAndFn = test::TestDescAndFn {
            desc: test::TestDesc {
                name: test::StaticTestName(
                    "macro_tests::test::test_base_type_implementation",
                ),
                ignore: false,
                ignore_message: ::core::option::Option::None,
                compile_fail: false,
                no_run: false,
                should_panic: test::ShouldPanic::No,
                test_type: test::TestType::UnitTest,
            },
            testfn: test::StaticTestFn(|| test::assert_test_result(
                test_base_type_implementation(),
            )),
        };
        fn test_base_type_implementation() {
            let a = TestType { val: Scalar::from(2u8) };
            let serialized = a.clone().to_scalars();
            let deserialized = TestType::from_scalars(&mut serialized.into_iter());
            match (&a, &deserialized) {
                (left_val, right_val) => {
                    if !(*left_val == *right_val) {
                        let kind = ::core::panicking::AssertKind::Eq;
                        ::core::panicking::assert_failed(
                            kind,
                            &*left_val,
                            &*right_val,
                            ::core::option::Option::None,
                        );
                    }
                }
            }
        }
        extern crate test;
        #[cfg(test)]
        #[rustc_test_marker = "macro_tests::test::test_circuit_base_type_implementation"]
        pub const test_circuit_base_type_implementation: test::TestDescAndFn = test::TestDescAndFn {
            desc: test::TestDesc {
                name: test::StaticTestName(
                    "macro_tests::test::test_circuit_base_type_implementation",
                ),
                ignore: false,
                ignore_message: ::core::option::Option::None,
                compile_fail: false,
                no_run: false,
                should_panic: test::ShouldPanic::No,
                test_type: test::TestType::UnitTest,
            },
            testfn: test::StaticTestFn(|| test::assert_test_result(
                test_circuit_base_type_implementation(),
            )),
        };
        fn test_circuit_base_type_implementation() {
            let a = TestType { val: Scalar::one() };
            let mut rng = OsRng {};
            let pedersen_gens = PedersenGens::default();
            let mut transcript = Transcript::new(b"test");
            let mut prover = Prover::new(&pedersen_gens, &mut transcript);
            let (_, comm) = a.commit_witness(&mut rng, &mut prover).unwrap();
            a.commit_public(&mut prover).unwrap();
            let mut transcript = Transcript::new(b"test");
            let mut verifier = Verifier::new(&pedersen_gens, &mut transcript);
            comm.commit_verifier(&mut verifier).unwrap();
        }
        extern crate test;
        #[cfg(test)]
        #[rustc_test_marker = "macro_tests::test::test_circuit_base_type_derived_types"]
        pub const test_circuit_base_type_derived_types: test::TestDescAndFn = test::TestDescAndFn {
            desc: test::TestDesc {
                name: test::StaticTestName(
                    "macro_tests::test::test_circuit_base_type_derived_types",
                ),
                ignore: false,
                ignore_message: ::core::option::Option::None,
                compile_fail: false,
                no_run: false,
                should_panic: test::ShouldPanic::No,
                test_type: test::TestType::UnitTest,
            },
            testfn: test::StaticTestFn(|| test::assert_test_result(
                test_circuit_base_type_derived_types(),
            )),
        };
        fn test_circuit_base_type_derived_types() {
            let callback = |_: TestTypeCommitment| {};
            let a = TestType { val: Scalar::one() };
            let mut rng = OsRng {};
            let pedersen_gens = PedersenGens::default();
            let mut transcript = Transcript::new(b"test");
            let mut prover = Prover::new(&pedersen_gens, &mut transcript);
            let (_, comm) = a.commit_witness(&mut rng, &mut prover).unwrap();
            callback(comm);
        }
        extern crate test;
        #[cfg(test)]
        #[rustc_test_marker = "macro_tests::test::test_mpc_derived_type"]
        pub const test_mpc_derived_type: test::TestDescAndFn = test::TestDescAndFn {
            desc: test::TestDesc {
                name: test::StaticTestName("macro_tests::test::test_mpc_derived_type"),
                ignore: false,
                ignore_message: ::core::option::Option::None,
                compile_fail: false,
                no_run: false,
                should_panic: test::ShouldPanic::No,
                test_type: test::TestType::UnitTest,
            },
            testfn: test::StaticTestFn(|| test::assert_test_result(
                test_mpc_derived_type(),
            )),
        };
        fn test_mpc_derived_type() {
            let body = async {
                let handle = tokio::task::spawn_blocking(|| {
                    let dummy = TestType { val: Scalar::from(2u8) };
                    let dummy_network = Rc::new(RefCell::new(MockMpcNet::new()));
                    let dummy_network_data = ::alloc::vec::from_elem(Scalar::one(), 100);
                    dummy_network.borrow_mut().add_mock_scalars(dummy_network_data);
                    let dummy_beaver_source = Rc::new(
                        RefCell::new(PartyIDBeaverSource::new(0)),
                    );
                    let dummy_fabric = MpcFabric::new_with_network(
                        0,
                        dummy_network,
                        dummy_beaver_source,
                    );
                    let shared_fabric = SharedFabric::new(dummy_fabric);
                    let allocated = dummy.allocate(1, shared_fabric.clone()).unwrap();
                    allocated.open(shared_fabric).unwrap();
                });
                handle.await.unwrap();
            };
            let mut body = body;
            #[allow(unused_mut)]
            let mut body = unsafe {
                ::tokio::macros::support::Pin::new_unchecked(&mut body)
            };
            let body: ::std::pin::Pin<&mut dyn ::std::future::Future<Output = ()>> = body;
            #[allow(clippy::expect_used, clippy::diverging_sub_expression)]
            {
                return tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("Failed building the Runtime")
                    .block_on(body);
            }
        }
    }
}
pub mod mpc {
    //! Groups logic around MPC structure
    use std::{
        cell::{Ref, RefCell},
        net::SocketAddr, rc::Rc,
    };
    use curve25519_dalek::scalar::Scalar;
    use mpc_ristretto::{
        beaver::SharedValueSource, fabric::AuthenticatedMpcFabric,
        network::{MpcNetwork, QuicTwoPartyNet},
        BeaverSource,
    };
    use crate::errors::MpcError;
    /**
 * Types
 */
    /// Type alias that curries one generic out of the concern of this implementation
    #[allow(type_alias_bounds)]
    pub type MpcFabric<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> = AuthenticatedMpcFabric<
        N,
        S,
    >;
    /// A shared fabric for multi-owner mutability
    pub struct SharedFabric<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>(
        pub Rc<RefCell<MpcFabric<N, S>>>,
    );
    #[automatically_derived]
    impl<
        N: ::core::fmt::Debug + MpcNetwork + Send,
        S: ::core::fmt::Debug + SharedValueSource<Scalar>,
    > ::core::fmt::Debug for SharedFabric<N, S> {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_tuple_field1_finish(
                f,
                "SharedFabric",
                &&self.0,
            )
        }
    }
    impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> SharedFabric<N, S> {
        /// Wrap an existing fabric in a shared mutability struct
        pub fn new(fabric: AuthenticatedMpcFabric<N, S>) -> Self {
            Self(Rc::new(RefCell::new(fabric)))
        }
        /// Borrow the shared MPC fabric as an immutable reference
        pub fn borrow_fabric(&self) -> Ref<MpcFabric<N, S>> {
            self.0.as_ref().borrow()
        }
    }
    impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
    for SharedFabric<N, S> {
        fn clone(&self) -> Self {
            Self(self.0.clone())
        }
    }
    /**
 * Generic, module level helpers
 */
    /// Create a new MPC fabric from a high level beaver source
    pub fn new_mpc_fabric<S: SharedValueSource<Scalar>>(
        party_id: u64,
        peer_addr: SocketAddr,
        beaver_source: BeaverSource<S>,
    ) -> Result<AuthenticatedMpcFabric<QuicTwoPartyNet, S>, MpcError> {
        let local_addr: SocketAddr = "192.168.0.1"
            .parse()
            .map_err(|_| MpcError::SetupError("invalid peer addr".to_string()))?;
        let fabric = AuthenticatedMpcFabric::new(
                local_addr,
                peer_addr,
                beaver_source,
                party_id,
            )
            .map_err(|_| MpcError::SetupError("error connecting to peer".to_string()))?;
        Ok(fabric)
    }
}
pub mod traits {
    //! Defines traits which groups types of types and translations between them
    //!
    //! We strongly type inputs to our ZK(MPC) circuits to gain circuit readability
    //! and inherit safety properties from the type checker and linters (i.e. unused
    //! witness elements)
    //!
    //! We group types of types by traits which associate with other types. For example, types
    //! allocated in an MPC circuit implement different traits than ZK circuit types do, due to
    //! their different underlying primitives
    //!
    //! At a high level the types are:
    //!     - Base types: application level types that have semantically meaningful values
    //!     - Single-prover variable types: base types allocated in a single-prover constraint system
    //!     - Single-prover commitment types: commitments to base types in a single-prover system
    //!     - MPC types: base types that have been allocated in an MPC fabric
    //!     - Multi-prover variable types: base types allocated in a multi-prover constraint system
    //!     - Multi-prover commitment types: commitments to base types in a multi-prover system
    use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
    use itertools::Itertools;
    use mpc_bulletproof::{
        r1cs::{Prover, R1CSProof, RandomizableConstraintSystem, Variable, Verifier},
        r1cs_mpc::{MpcProver, MpcVariable, SharedR1CSProof},
    };
    use mpc_ristretto::{
        authenticated_ristretto::AuthenticatedCompressedRistretto,
        authenticated_scalar::AuthenticatedScalar, beaver::SharedValueSource,
        network::MpcNetwork,
    };
    use rand_core::{CryptoRng, RngCore};
    use crate::{
        errors::{MpcError, ProverError, VerifierError},
        mpc::SharedFabric, LinkableCommitment,
    };
    /// Implementing types are base (application level) types that define serialization to/from `Scalars`
    ///
    /// Commitment, variable, MPC, etc types are implemented automatically from serialization and deserialization
    pub trait BaseType: Clone {
        /// Convert the base type to its serialized scalar representation in the circuit
        fn to_scalars(self) -> Vec<Scalar>;
        /// Convert from a serialized scalar representation to the base type
        fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self;
    }
    /// The base type that may be allocated in a single-prover circuit
    pub trait CircuitBaseType: BaseType {
        /// The variable type for this base type
        type VarType: CircuitVarType;
        /// The commitment type for this base type
        type CommitmentType: CircuitCommitmentType;
    }
    /// Implementing types are variable types that may appear in constraints in
    /// a constraint system
    pub trait CircuitVarType {
        /// Convert from an iterable of variables representing the serialized type
        fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self;
    }
    /// Implementing types are commitments to base types that have an analogous variable
    /// type allocated with them
    pub trait CircuitCommitmentType: Clone {
        /// The variable type that this type is a commitment to
        type VarType: CircuitVarType;
        /// Convert from an iterable of compressed ristretto points, each representing
        /// a commitment to an underlying variable
        fn from_commitments<I: Iterator<Item = CompressedRistretto>>(i: &mut I) -> Self;
        /// Convert to a vector of compressed ristretto points
        fn to_commitments(self) -> Vec<CompressedRistretto>;
    }
    /// A base type for allocating into an MPC network
    pub trait MpcBaseType<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
    >: BaseType {
        /// The type that results from allocating the base type into an MPC network
        type AllocatedType: MpcType<N, S>;
    }
    /// An implementing type is the representation of a `BaseType` in an MPC circuit
    /// *outside* of a multiprover constraint system
    pub trait MpcType<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
    >: Clone {
        /// The native type when the value is opened out of a circuit
        type NativeType: BaseType;
        /// Convert from an iterable of authenticated scalars: scalars that have been
        /// allocated in an MPC fabric
        fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar<N, S>>>(
            i: &mut I,
        ) -> Self;
        /// Convert to a vector of authenticated scalars
        fn to_authenticated_scalars(self) -> Vec<AuthenticatedScalar<N, S>>;
    }
    /// A base type for allocating within a multiprover constraint system
    pub trait MultiproverCircuitBaseType<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
    >: BaseType {
        /// The multiprover constraint system variable type that results when committing
        /// to the base type in a multiprover constraint system
        type MultiproverVarType;
        /// The shared commitment type that results when committing to the base type in a multiprover
        /// constraint system
        type MultiproverCommType;
    }
    /// A multiprover circuit variable type
    pub trait MultiproverCircuitVariableType<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
    > {
        /// Deserialization from an iterator over MPC allocated variables
        fn from_mpc_vars<I: Iterator<Item = MpcVariable<N, S>>>(i: &mut I) -> Self;
    }
    /// A multiprover circuit commitment type
    pub trait MultiproverCircuitCommitmentType<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
    > {
        /// The multi-prover variable type that this type is a commitment to
        type VariableType: MultiproverCircuitVariableType<N, S>;
        /// Deserialization form an iterator over MPC allocated commitments
        fn from_mpc_commitments<
            I: Iterator<Item = AuthenticatedCompressedRistretto<N, S>>,
        >(i: &mut I) -> Self;
    }
    impl BaseType for Scalar {
        fn to_scalars(self) -> Vec<Scalar> {
            <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([self]))
        }
        fn from_scalars<I: Iterator<Item = Scalar>>(i: &mut I) -> Self {
            i.next().unwrap()
        }
    }
    impl CircuitBaseType for Scalar {
        type VarType = Variable;
        type CommitmentType = CompressedRistretto;
    }
    impl CircuitVarType for Variable {
        fn from_vars<I: Iterator<Item = Variable>>(i: &mut I) -> Self {
            i.next().unwrap()
        }
    }
    impl CircuitCommitmentType for CompressedRistretto {
        type VarType = Variable;
        fn from_commitments<I: Iterator<Item = CompressedRistretto>>(i: &mut I) -> Self {
            i.next().unwrap()
        }
        fn to_commitments(self) -> Vec<CompressedRistretto> {
            <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([self]))
        }
    }
    impl<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
    > MpcBaseType<N, S> for Scalar {
        type AllocatedType = AuthenticatedScalar<N, S>;
    }
    impl<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
    > MpcType<N, S> for AuthenticatedScalar<N, S> {
        type NativeType = Scalar;
        fn from_authenticated_scalars<I: Iterator<Item = AuthenticatedScalar<N, S>>>(
            i: &mut I,
        ) -> Self {
            i.next().unwrap()
        }
        fn to_authenticated_scalars(self) -> Vec<AuthenticatedScalar<N, S>> {
            <[_]>::into_vec(#[rustc_box] ::alloc::boxed::Box::new([self]))
        }
    }
    /// Defines functionality to allocate a witness value within a single-prover constraint system
    pub trait CommitWitness {
        /// The type that results from committing to the base type
        type VarType;
        /// The type that consists of Pedersen commitments to the base type
        type CommitType;
        /// The error thrown by the commit method
        type ErrorType;
        /// Commit to the base type in the constraint system
        ///
        /// Returns a tuple holding both the var type (used for operations)
        /// within the constraint system, and the commit type; which is passed
        /// to the verifier to use as hidden values
        fn commit_witness<R: RngCore + CryptoRng>(
            &self,
            rng: &mut R,
            prover: &mut Prover,
        ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType>;
    }
    /// Defines functionality to allocate a public variable within a single-prover constraint system
    pub trait CommitPublic {
        /// The type that results from committing to the base type
        type VarType;
        /// The error thrown by the commit method
        type ErrorType;
        /// Commit to the base type in the constraint system
        fn commit_public<CS: RandomizableConstraintSystem>(
            &self,
            cs: &mut CS,
        ) -> Result<Self::VarType, Self::ErrorType>;
    }
    /// Defines functionality to commit to a value in a verifier's constraint system
    pub trait CommitVerifier {
        /// The type that results from committing to the implementation types
        type VarType;
        /// The type of error thrown when committing fails
        type ErrorType;
        /// Commit to a hidden value in the Verifier
        fn commit_verifier(
            &self,
            verifier: &mut Verifier,
        ) -> Result<Self::VarType, Self::ErrorType>;
    }
    /// Defines functionality to allocate a value within an MPC network
    pub trait Allocate<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
        /// The output type that results from allocating the value in the network
        type SharedType;
        /// The type of error thrown when allocation fails
        type ErrorType;
        /// Allocates the raw type in the network as a shared value
        fn allocate(
            &self,
            owning_party: u64,
            fabric: SharedFabric<N, S>,
        ) -> Result<Self::SharedType, Self::ErrorType>;
    }
    /// Defines functionality to allocate a value as a public, shared value in an MPC network
    pub trait SharePublic<N: MpcNetwork + Send, S: SharedValueSource<Scalar>>: Sized {
        /// The type of error thrown when sharing fails
        type ErrorType;
        /// Share the value with the counterparty
        fn share_public(
            &self,
            owning_party: u64,
            fabric: SharedFabric<N, S>,
        ) -> Result<Self, Self::ErrorType>;
    }
    /// Defines functionality to allocate a base type as a shared commitment in a multi-prover
    /// constraint system
    pub trait CommitSharedProver<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
        /// The type that results from committing to the base type
        type SharedVarType;
        /// The type consisting of Pedersen commitments to the base type
        type CommitType;
        /// The type of error that is thrown when committing fails
        type ErrorType;
        /// Commit to the base type in the constraint system
        fn commit<R: RngCore + CryptoRng>(
            &self,
            owning_party: u64,
            rng: &mut R,
            prover: &mut MpcProver<N, S>,
        ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType>;
    }
    /// Defines functionality for a shared, allocated type to be opened to another type
    ///
    /// The type this is implemented for is assumed to be a secret sharing of some MPC
    /// network allocated value.
    pub trait Open<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> {
        /// The output type that results from opening this value
        type OpenOutput;
        /// The error type that results if opening fails
        type Error;
        /// Opens the shared type without authenticating
        fn open(
            self,
            fabric: SharedFabric<N, S>,
        ) -> Result<Self::OpenOutput, Self::Error>;
        /// Opens the shared type and authenticates the result
        fn open_and_authenticate(
            self,
            fabric: SharedFabric<N, S>,
        ) -> Result<Self::OpenOutput, Self::Error>;
    }
    /// Defines the abstraction of a Circuit.
    ///
    /// A circuit represents a provable unit, a complete NP statement that takes as input
    /// a series of values, commits to them, and applies constraints
    ///
    /// The input types are broken out into the witness type and the statement type.
    /// The witness type represents the secret witness that the prover has access to but
    /// that the verifier does not. The statement is the set of public inputs and any
    /// other circuit meta-parameters that both prover and verifier have access to.
    pub trait SingleProverCircuit {
        /// The witness type, given only to the prover, which generates a blinding commitment
        /// that can be given to the verifier
        type Witness;
        /// The statement type, given to both the prover and verifier, parameterizes the underlying
        /// NP statement being proven
        type Statement: Clone;
        /// The data type of the output commitment from the prover.
        ///
        /// The prover commits to the witness and sends this commitment to the verifier, this type
        /// is the structure in which that commitment is sent
        type WitnessCommitment;
        /// The size of the bulletproof generators that must be allocated
        /// to fully compute a proof or verification of the statement
        ///
        /// This is a function of circuit depth, one generator is needed per
        /// multiplication gate (roughly)
        const BP_GENS_CAPACITY: usize;
        /// Generate a proof of the statement represented by the circuit
        ///
        /// Returns both the commitment to the inputs, as well as the proof itself
        fn prove(
            witness: Self::Witness,
            statement: Self::Statement,
            prover: Prover,
        ) -> Result<(Self::WitnessCommitment, R1CSProof), ProverError>;
        /// Verify a proof of the statement represented by the circuit
        ///
        /// The verifier has access to the statement variables, but only hiding (and binding)
        /// commitments to the witness variables
        fn verify(
            witness_commitment: Self::WitnessCommitment,
            statement: Self::Statement,
            proof: R1CSProof,
            verifier: Verifier,
        ) -> Result<(), VerifierError>;
    }
    /// Defines the abstraction of a Circuit that is evaluated in a multiprover setting
    ///
    /// A circuit represents a provable unit, a complete NP statement that takes as input
    /// a series of values, commits to them, and applies constraints.
    ///
    /// The input types are broken out into the witness type and the statement type.
    /// The witness type represents the secret witness that the prover has access to but
    /// that the verifier does not. The statement is the set of public inputs and any
    /// other circuit meta-parameters that both prover and verifier have access to.
    pub trait MultiProverCircuit<
        'a,
        N: 'a + MpcNetwork + Send,
        S: 'a + SharedValueSource<Scalar>,
    > {
        /// The witness type, given only to the prover, which generates a blinding commitment
        /// that can be given to the verifier
        type Witness;
        /// The statement type, given to both the prover and verifier, parameterizes the underlying
        /// NP statement being proven
        type Statement: Clone;
        /// The data type of the output commitment from the prover.
        ///
        /// The prover commits to the witness and sends this commitment to the verifier, this type
        /// is the structure in which that commitment is sent
        type WitnessCommitment: Open<N, S>;
        /// The size of the bulletproof generators that must be allocated
        /// to fully compute a proof or verification of the statement
        ///
        /// This is a function of circuit depth, one generator is needed per
        /// multiplication gate (roughly)
        const BP_GENS_CAPACITY: usize;
        /// Generate a proof of the statement represented by the circuit
        ///
        /// Returns both the commitment to the inputs, as well as the proof itself
        #[allow(clippy::type_complexity)]
        fn prove(
            witness: Self::Witness,
            statement: Self::Statement,
            prover: MpcProver<'a, '_, '_, N, S>,
            fabric: SharedFabric<N, S>,
        ) -> Result<(Self::WitnessCommitment, SharedR1CSProof<N, S>), ProverError>;
        /// Verify a proof of the statement represented by the circuit
        ///
        /// The verifier has access to the statement variables, but only hiding (and binding)
        /// commitments to the witness variables
        ///
        /// The verifier in this case provides the same interface as the single prover case.
        /// The proof and commitments to the witness should be "opened" by having the MPC
        /// parties reconstruct the underlying secret from their shares. Then the opened
        /// proof and commitments can be passed to the verifier.
        fn verify(
            witness_commitments: <Self::WitnessCommitment as Open<N, S>>::OpenOutput,
            statement: Self::Statement,
            proof: R1CSProof,
            verifier: Verifier,
        ) -> Result<(), VerifierError>;
    }
    impl<T: CircuitBaseType> CommitWitness for T {
        type VarType = <Self as CircuitBaseType>::VarType;
        type CommitType = <Self as CircuitBaseType>::CommitmentType;
        type ErrorType = ();
        fn commit_witness<R: RngCore + CryptoRng>(
            &self,
            rng: &mut R,
            prover: &mut Prover,
        ) -> Result<(Self::VarType, Self::CommitType), Self::ErrorType> {
            let scalars: Vec<Scalar> = self.clone().to_scalars();
            let (comms, vars): (Vec<CompressedRistretto>, Vec<Variable>) = scalars
                .into_iter()
                .map(|s| prover.commit(s, Scalar::random(rng)))
                .unzip();
            Ok((
                Self::VarType::from_vars(&mut vars.into_iter()),
                Self::CommitType::from_commitments(&mut comms.into_iter()),
            ))
        }
    }
    impl<T: CircuitBaseType> CommitPublic for T {
        type VarType = <Self as CircuitBaseType>::VarType;
        type ErrorType = ();
        fn commit_public<CS: RandomizableConstraintSystem>(
            &self,
            cs: &mut CS,
        ) -> Result<Self::VarType, Self::ErrorType> {
            let self_scalars = self.clone().to_scalars();
            let vars = self_scalars
                .into_iter()
                .map(|s| cs.commit_public(s))
                .collect_vec();
            Ok(Self::VarType::from_vars(&mut vars.into_iter()))
        }
    }
    impl<T: CircuitCommitmentType> CommitVerifier for T {
        type VarType = T::VarType;
        type ErrorType = ();
        fn commit_verifier(
            &self,
            verifier: &mut Verifier,
        ) -> Result<Self::VarType, Self::ErrorType> {
            let comms = self.clone().to_commitments();
            let vars = comms.into_iter().map(|c| verifier.commit(c)).collect_vec();
            Ok(Self::VarType::from_vars(&mut vars.into_iter()))
        }
    }
    impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> SharePublic<N, S>
    for LinkableCommitment {
        type ErrorType = MpcError;
        fn share_public(
            &self,
            owning_party: u64,
            fabric: SharedFabric<N, S>,
        ) -> Result<Self, Self::ErrorType> {
            let shared_values = fabric
                .borrow_fabric()
                .batch_share_plaintext_scalars(
                    owning_party,
                    &[self.val, self.randomness],
                )
                .map_err(|err| MpcError::SharingError(err.to_string()))?;
            Ok(Self {
                val: shared_values[0],
                randomness: shared_values[1],
            })
        }
    }
    impl<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        T: MpcBaseType<N, S>,
    > Allocate<N, S> for T {
        type SharedType = T::AllocatedType;
        type ErrorType = MpcError;
        fn allocate(
            &self,
            owning_party: u64,
            fabric: SharedFabric<N, S>,
        ) -> Result<Self::SharedType, Self::ErrorType> {
            let self_scalars = self.clone().to_scalars();
            let shared_scalars = fabric
                .borrow_fabric()
                .batch_allocate_private_scalars(owning_party, &self_scalars)
                .map_err(|err| MpcError::SharingError(err.to_string()))?;
            Ok(
                Self::SharedType::from_authenticated_scalars(
                    &mut shared_scalars.into_iter(),
                ),
            )
        }
    }
    impl<
        N: MpcNetwork + Send + Clone,
        S: SharedValueSource<Scalar> + Clone,
        T: MpcType<N, S>,
    > Open<N, S> for T {
        type OpenOutput = T::NativeType;
        type Error = MpcError;
        fn open(self, _: SharedFabric<N, S>) -> Result<Self::OpenOutput, Self::Error> {
            let self_authenticated_scalars = self.to_authenticated_scalars();
            let opened_scalars = AuthenticatedScalar::batch_open(
                    &self_authenticated_scalars,
                )
                .map_err(|err| MpcError::OpeningError(err.to_string()))?
                .into_iter()
                .map(|auth_scalar| auth_scalar.to_scalar())
                .collect_vec();
            Ok(T::NativeType::from_scalars(&mut opened_scalars.into_iter()))
        }
        fn open_and_authenticate(
            self,
            _: SharedFabric<N, S>,
        ) -> Result<Self::OpenOutput, Self::Error> {
            let self_authenticated_scalars = self.to_authenticated_scalars();
            let opened_scalars = AuthenticatedScalar::batch_open_and_authenticate(
                    &self_authenticated_scalars,
                )
                .map_err(|err| MpcError::OpeningError(err.to_string()))?
                .into_iter()
                .map(|auth_scalar| auth_scalar.to_scalar())
                .collect_vec();
            Ok(T::NativeType::from_scalars(&mut opened_scalars.into_iter()))
        }
    }
}
mod tracing {
    //! Groups the global static data structures used for tracing circuit execution
    //!
    //! The types used here are copied over from the circuit-macros crate. Due to the restriction
    //! on procedural macros to own their crate, these two crates cannot share these types.
    #![allow(unused)]
    use lazy_static::lazy_static;
    use std::{
        collections::{hash_map::Entry, HashMap},
        sync::Mutex,
    };
    /// A type used for scoping trace metrics
    pub struct Scope {
        /// The path the current scope takes through its calling gadgets
        pub path: Vec<String>,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for Scope {
        #[inline]
        fn clone(&self) -> Scope {
            Scope {
                path: ::core::clone::Clone::clone(&self.path),
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for Scope {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "Scope",
                "path",
                &&self.path,
            )
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralPartialEq for Scope {}
    #[automatically_derived]
    impl ::core::cmp::PartialEq for Scope {
        #[inline]
        fn eq(&self, other: &Scope) -> bool {
            self.path == other.path
        }
    }
    #[automatically_derived]
    impl ::core::marker::StructuralEq for Scope {}
    #[automatically_derived]
    impl ::core::cmp::Eq for Scope {
        #[inline]
        #[doc(hidden)]
        #[no_coverage]
        fn assert_receiver_is_total_eq(&self) -> () {
            let _: ::core::cmp::AssertParamIsEq<Vec<String>>;
        }
    }
    #[automatically_derived]
    impl ::core::hash::Hash for Scope {
        fn hash<__H: ::core::hash::Hasher>(&self, state: &mut __H) -> () {
            ::core::hash::Hash::hash(&self.path, state)
        }
    }
    impl Scope {
        /// Build a new scope
        pub fn new() -> Self {
            Self {
                path: ::alloc::vec::Vec::new(),
            }
        }
        /// Parse a scope from a path
        pub fn from_path(path: Vec<String>) -> Self {
            Self { path }
        }
        /// Append a value to the scope
        pub fn scope_in(&mut self, scope: String) {
            self.path.push(scope)
        }
        /// Pop the latest scope from the path
        pub fn scope_out(&mut self) -> String {
            self.path.pop().unwrap()
        }
    }
    /// Represents a list of metrics collected via a trace
    pub struct ScopedMetrics {
        /// A list of metrics, represented as named tuples
        pub(crate) data: HashMap<String, u64>,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for ScopedMetrics {
        #[inline]
        fn clone(&self) -> ScopedMetrics {
            ScopedMetrics {
                data: ::core::clone::Clone::clone(&self.data),
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ScopedMetrics {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "ScopedMetrics",
                "data",
                &&self.data,
            )
        }
    }
    impl ScopedMetrics {
        /// Create a new, empty list of metrics
        pub fn new() -> Self {
            Self { data: HashMap::new() }
        }
        /// Add a metric to the list, aggregating if the metric already exists
        ///
        /// Returns the value if a previous value existed
        pub fn add_metric(&mut self, name: String, value: u64) -> Option<u64> {
            if let Some(curr_val) = self.data.get(&name) {
                self.data.insert(name, curr_val + value)
            } else {
                self.data.insert(name, value);
                None
            }
        }
    }
    /// A set of metrics captured by the execution of the tracer on a circuit
    pub struct MetricsCapture {
        /// A mapping from scope to the metrics captured at that scope
        pub(crate) metrics: HashMap<Scope, ScopedMetrics>,
    }
    #[automatically_derived]
    impl ::core::clone::Clone for MetricsCapture {
        #[inline]
        fn clone(&self) -> MetricsCapture {
            MetricsCapture {
                metrics: ::core::clone::Clone::clone(&self.metrics),
            }
        }
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for MetricsCapture {
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "MetricsCapture",
                "metrics",
                &&self.metrics,
            )
        }
    }
    impl MetricsCapture {
        /// Create a new MetricsCapture instance
        pub fn new() -> Self {
            Self { metrics: HashMap::new() }
        }
        /// Record a scoped metric, if the metric already exists for the scope, aggregate it
        pub fn record_metric(&mut self, scope: Scope, metric_name: String, value: u64) {
            if let Entry::Vacant(e) = self.metrics.entry(scope.clone()) {
                e.insert(ScopedMetrics::new());
            }
            self.metrics.get_mut(&scope).unwrap().add_metric(metric_name, value);
        }
        /// Get the metric for the given scope and metric name
        pub fn get_metric(&mut self, scope: Scope, metric_name: String) -> Option<u64> {
            self.metrics.get(&scope)?.data.get(&metric_name).cloned()
        }
    }
    #[allow(missing_copy_implementations)]
    #[allow(non_camel_case_types)]
    #[allow(dead_code)]
    pub(crate) struct SCOPED_METRICS {
        __private_field: (),
    }
    #[doc(hidden)]
    pub(crate) static SCOPED_METRICS: SCOPED_METRICS = SCOPED_METRICS {
        __private_field: (),
    };
    impl ::lazy_static::__Deref for SCOPED_METRICS {
        type Target = Mutex<MetricsCapture>;
        fn deref(&self) -> &Mutex<MetricsCapture> {
            #[inline(always)]
            fn __static_ref_initialize() -> Mutex<MetricsCapture> {
                Mutex::new(MetricsCapture::new())
            }
            #[inline(always)]
            fn __stability() -> &'static Mutex<MetricsCapture> {
                static LAZY: ::lazy_static::lazy::Lazy<Mutex<MetricsCapture>> = ::lazy_static::lazy::Lazy::INIT;
                LAZY.get(__static_ref_initialize)
            }
            __stability()
        }
    }
    impl ::lazy_static::LazyStatic for SCOPED_METRICS {
        fn initialize(lazy: &Self) {
            let _ = &**lazy;
        }
    }
    #[allow(missing_copy_implementations)]
    #[allow(non_camel_case_types)]
    #[allow(dead_code)]
    pub(crate) struct CURR_SCOPE {
        __private_field: (),
    }
    #[doc(hidden)]
    pub(crate) static CURR_SCOPE: CURR_SCOPE = CURR_SCOPE { __private_field: () };
    impl ::lazy_static::__Deref for CURR_SCOPE {
        type Target = Mutex<Scope>;
        fn deref(&self) -> &Mutex<Scope> {
            #[inline(always)]
            fn __static_ref_initialize() -> Mutex<Scope> {
                Mutex::new(Scope::new())
            }
            #[inline(always)]
            fn __stability() -> &'static Mutex<Scope> {
                static LAZY: ::lazy_static::lazy::Lazy<Mutex<Scope>> = ::lazy_static::lazy::Lazy::INIT;
                LAZY.get(__static_ref_initialize)
            }
            __stability()
        }
    }
    impl ::lazy_static::LazyStatic for CURR_SCOPE {
        fn initialize(lazy: &Self) {
            let _ = &**lazy;
        }
    }
    /// We define the macro tests here to avoid duplicating the above data structures
    #[cfg(test)]
    pub mod test {
        use circuit_macros::circuit_trace;
        use curve25519_dalek::scalar::Scalar;
        use lazy_static::lazy_static;
        use merlin::Transcript;
        use mpc_bulletproof::{
            r1cs::{ConstraintSystem, Prover, Variable},
            PedersenGens,
        };
        use rand_core::OsRng;
        use std::{
            collections::{hash_map::Entry, HashMap},
            sync::Mutex, thread, time::Duration,
        };
        use crate::tracing::{MetricsCapture, Scope};
        #[allow(missing_copy_implementations)]
        #[allow(non_camel_case_types)]
        #[allow(dead_code)]
        struct SCOPED_METRICS {
            __private_field: (),
        }
        #[doc(hidden)]
        static SCOPED_METRICS: SCOPED_METRICS = SCOPED_METRICS {
            __private_field: (),
        };
        impl ::lazy_static::__Deref for SCOPED_METRICS {
            type Target = Mutex<MetricsCapture>;
            fn deref(&self) -> &Mutex<MetricsCapture> {
                #[inline(always)]
                fn __static_ref_initialize() -> Mutex<MetricsCapture> {
                    Mutex::new(MetricsCapture::new())
                }
                #[inline(always)]
                fn __stability() -> &'static Mutex<MetricsCapture> {
                    static LAZY: ::lazy_static::lazy::Lazy<Mutex<MetricsCapture>> = ::lazy_static::lazy::Lazy::INIT;
                    LAZY.get(__static_ref_initialize)
                }
                __stability()
            }
        }
        impl ::lazy_static::LazyStatic for SCOPED_METRICS {
            fn initialize(lazy: &Self) {
                let _ = &**lazy;
            }
        }
        #[allow(missing_copy_implementations)]
        #[allow(non_camel_case_types)]
        #[allow(dead_code)]
        struct CURR_SCOPE {
            __private_field: (),
        }
        #[doc(hidden)]
        static CURR_SCOPE: CURR_SCOPE = CURR_SCOPE { __private_field: () };
        impl ::lazy_static::__Deref for CURR_SCOPE {
            type Target = Mutex<Scope>;
            fn deref(&self) -> &Mutex<Scope> {
                #[inline(always)]
                fn __static_ref_initialize() -> Mutex<Scope> {
                    Mutex::new(Scope::new())
                }
                #[inline(always)]
                fn __stability() -> &'static Mutex<Scope> {
                    static LAZY: ::lazy_static::lazy::Lazy<Mutex<Scope>> = ::lazy_static::lazy::Lazy::INIT;
                    LAZY.get(__static_ref_initialize)
                }
                __stability()
            }
        }
        impl ::lazy_static::LazyStatic for CURR_SCOPE {
            fn initialize(lazy: &Self) {
                let _ = &**lazy;
            }
        }
        #[allow(missing_copy_implementations)]
        #[allow(non_camel_case_types)]
        #[allow(dead_code)]
        /// Used to synchronize the tests in this module in specific, because the tracer does not
        /// allow concurrent access to these global state elements
        struct TEST_LOCK {
            __private_field: (),
        }
        #[doc(hidden)]
        static TEST_LOCK: TEST_LOCK = TEST_LOCK { __private_field: () };
        impl ::lazy_static::__Deref for TEST_LOCK {
            type Target = Mutex<()>;
            fn deref(&self) -> &Mutex<()> {
                #[inline(always)]
                fn __static_ref_initialize() -> Mutex<()> {
                    Mutex::new(())
                }
                #[inline(always)]
                fn __stability() -> &'static Mutex<()> {
                    static LAZY: ::lazy_static::lazy::Lazy<Mutex<()>> = ::lazy_static::lazy::Lazy::INIT;
                    LAZY.get(__static_ref_initialize)
                }
                __stability()
            }
        }
        impl ::lazy_static::LazyStatic for TEST_LOCK {
            fn initialize(lazy: &Self) {
                let _ = &**lazy;
            }
        }
        /// A dummy gadget whose constraint generation is done through an associated function, used to
        /// test the trace macro on an associated function
        pub struct Gadget {}
        impl Gadget {
            #[cfg(not(feature = "bench"))]
            pub fn apply_constraints(cs: &mut Prover) {
                Self::apply_constraints_impl(cs)
            }
            fn apply_constraints_impl(cs: &mut Prover) {
                let mut rng = OsRng {};
                let (_, var) = cs.commit(Scalar::one(), Scalar::random(&mut rng));
                let (_, _, mul_out) = cs.multiply(var.into(), Variable::Zero().into());
                cs.constrain(mul_out.into());
                thread::sleep(Duration::from_millis(100));
            }
        }
        /// A dummy macro target that is not an associated function of any abstract gadget, used to
        /// test the non-associated macro arg
        #[cfg(not(feature = "bench"))]
        fn non_associated_gadget(cs: &mut Prover) {
            non_associated_gadget_impl(cs)
        }
        /// A dummy macro target that is not an associated function of any abstract gadget, used to
        /// test the non-associated macro arg
        fn non_associated_gadget_impl(cs: &mut Prover) {
            let mut rng = OsRng {};
            let (_, var) = cs.commit(Scalar::one(), Scalar::random(&mut rng));
            let (_, _, mul_out) = cs.multiply(var.into(), Variable::Zero().into());
            cs.constrain(mul_out.into());
            thread::sleep(Duration::from_millis(100));
        }
        extern crate test;
        #[cfg(test)]
        #[rustc_test_marker = "tracing::test::test_macro_associated"]
        pub const test_macro_associated: test::TestDescAndFn = test::TestDescAndFn {
            desc: test::TestDesc {
                name: test::StaticTestName("tracing::test::test_macro_associated"),
                ignore: false,
                ignore_message: ::core::option::Option::None,
                compile_fail: false,
                no_run: false,
                should_panic: test::ShouldPanic::No,
                test_type: test::TestType::UnitTest,
            },
            testfn: test::StaticTestFn(|| test::assert_test_result(
                test_macro_associated(),
            )),
        };
        /// Tests the tracer macro on an associated function when the tracer is disabled
        #[cfg(not(feature = "bench"))]
        fn test_macro_associated() {
            let mut prover_transcript = Transcript::new("test".as_bytes());
            let pc_gens = PedersenGens::default();
            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
            Gadget::apply_constraints(&mut prover);
            let gadget_scope = Scope::from_path(
                <[_]>::into_vec(
                    #[rustc_box]
                    ::alloc::boxed::Box::new(["apply_constraints".to_string()]),
                ),
            );
            let mut locked_metrics = SCOPED_METRICS.lock().unwrap();
            if !locked_metrics
                .get_metric(gadget_scope.clone(), "latency".to_string())
                .is_none()
            {
                ::core::panicking::panic(
                    "assertion failed: locked_metrics.get_metric(gadget_scope.clone(),\\n        \\\"latency\\\".to_string()).is_none()",
                )
            }
            if !locked_metrics
                .get_metric(gadget_scope.clone(), "n_constraints".to_string())
                .is_none()
            {
                ::core::panicking::panic(
                    "assertion failed: locked_metrics.get_metric(gadget_scope.clone(),\\n        \\\"n_constraints\\\".to_string()).is_none()",
                )
            }
            if !locked_metrics
                .get_metric(gadget_scope, "n_multipliers".to_string())
                .is_none()
            {
                ::core::panicking::panic(
                    "assertion failed: locked_metrics.get_metric(gadget_scope, \\\"n_multipliers\\\".to_string()).is_none()",
                )
            }
        }
        extern crate test;
        #[cfg(test)]
        #[rustc_test_marker = "tracing::test::test_macro_non_associated"]
        pub const test_macro_non_associated: test::TestDescAndFn = test::TestDescAndFn {
            desc: test::TestDesc {
                name: test::StaticTestName("tracing::test::test_macro_non_associated"),
                ignore: false,
                ignore_message: ::core::option::Option::None,
                compile_fail: false,
                no_run: false,
                should_panic: test::ShouldPanic::No,
                test_type: test::TestType::UnitTest,
            },
            testfn: test::StaticTestFn(|| test::assert_test_result(
                test_macro_non_associated(),
            )),
        };
        /// Tests the tracer macro on a non-associated function when the tracer is disabled
        #[cfg(not(feature = "bench"))]
        fn test_macro_non_associated() {
            let mut prover_transcript = Transcript::new("test".as_bytes());
            let pc_gens = PedersenGens::default();
            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);
            non_associated_gadget(&mut prover);
            let gadget_scope = Scope::from_path(
                <[_]>::into_vec(
                    #[rustc_box]
                    ::alloc::boxed::Box::new(["non_associated_gadget".to_string()]),
                ),
            );
            let mut locked_metrics = SCOPED_METRICS.lock().unwrap();
            if !locked_metrics
                .get_metric(gadget_scope.clone(), "latency".to_string())
                .is_none()
            {
                ::core::panicking::panic(
                    "assertion failed: locked_metrics.get_metric(gadget_scope.clone(),\\n        \\\"latency\\\".to_string()).is_none()",
                )
            }
            if !locked_metrics
                .get_metric(gadget_scope.clone(), "n_constraints".to_string())
                .is_none()
            {
                ::core::panicking::panic(
                    "assertion failed: locked_metrics.get_metric(gadget_scope.clone(),\\n        \\\"n_constraints\\\".to_string()).is_none()",
                )
            }
            if !locked_metrics
                .get_metric(gadget_scope, "n_multipliers".to_string())
                .is_none()
            {
                ::core::panicking::panic(
                    "assertion failed: locked_metrics.get_metric(gadget_scope, \\\"n_multipliers\\\".to_string()).is_none()",
                )
            }
        }
    }
}
/// The maximum number of balances allowed in a wallet
pub const MAX_BALANCES: usize = 5;
/// The maximum number of fees a wallet may hold
pub const MAX_FEES: usize = 5;
/// The maximum number of orders allowed in a wallet
pub const MAX_ORDERS: usize = 5;
/// The highest possible set bit for a positive scalar
pub(crate) const POSITIVE_SCALAR_MAX_BITS: usize = 251;
/// The highest possible set bit in the Dalek scalar field
pub(crate) const SCALAR_MAX_BITS: usize = 253;
/// The seed for a fiat-shamir transcript
pub(crate) const TRANSCRIPT_SEED: &str = "merlin seed";
#[allow(unused)]
pub(crate) use print_mpc_wire;
#[allow(unused)]
pub(crate) use print_multiprover_wire;
#[allow(unused)]
pub(crate) use print_wire;
use traits::{CommitSharedProver, MultiProverCircuit, Open, SingleProverCircuit};
/// Represents 2^m as a scalar
pub fn scalar_2_to_m(m: usize) -> Scalar {
    if m >= SCALAR_MAX_BITS {
        return Scalar::zero();
    }
    if (128..SCALAR_MAX_BITS).contains(&m) {
        Scalar::from(1u128 << 127) * Scalar::from(1u128 << (m - 127))
    } else {
        Scalar::from(1u128 << m)
    }
}
/// Abstracts over the flow of proving a single-prover circuit
pub fn singleprover_prove<C: SingleProverCircuit>(
    witness: C::Witness,
    statement: C::Statement,
) -> Result<(C::WitnessCommitment, R1CSProof), ProverError> {
    let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = Prover::new(&pc_gens, &mut transcript);
    C::prove(witness, statement, prover)
}
/// Abstracts over the flow of collaboratively proving a generic circuit
pub fn multiprover_prove<'a, N, S, C>(
    witness: C::Witness,
    statement: C::Statement,
    fabric: SharedFabric<N, S>,
) -> Result<(C::WitnessCommitment, SharedR1CSProof<N, S>), ProverError>
where
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
    C: MultiProverCircuit<'a, N, S>,
{
    let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let prover = MpcProver::new_with_fabric(fabric.0.clone(), &mut transcript, &pc_gens);
    C::prove(witness, statement.clone(), prover, fabric)
}
/// Abstracts over the flow of verifying a proof for a single-prover proved circuit
pub fn verify_singleprover_proof<C: SingleProverCircuit>(
    statement: C::Statement,
    witness_commitment: C::WitnessCommitment,
    proof: R1CSProof,
) -> Result<(), VerifierError> {
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);
    C::verify(witness_commitment, statement, proof, verifier)
}
/// Abstracts over the flow of verifying a proof for a collaboratively proved circuit
pub fn verify_collaborative_proof<'a, N, S, C>(
    statement: C::Statement,
    witness_commitment: <C::WitnessCommitment as Open<N, S>>::OpenOutput,
    proof: R1CSProof,
) -> Result<(), VerifierError>
where
    C: MultiProverCircuit<'a, N, S>,
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
{
    let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
    let pc_gens = PedersenGens::default();
    let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);
    C::verify(witness_commitment, statement, proof, verifier)
}
/// A linkable commitment is a commitment used in multiple proofs. We split the constraints
/// of the matching engine into roughly 3 pieces:
///     1. Input validity checks, done offline by managing relayers (`VALID COMMITMENTS`)
///     2. The matching engine execution, proved collaboratively over an MPC fabric (`VALID MATCH MPC`)
///     3. Output validity checks: i.e. note construction and encryption (`VALID MATCH ENCRYPTION`)
/// These components are split to remove as many constraints from the bottleneck (the collaborative proof)
/// as possible.
///
/// However, we need to ensure that -- for example -- the order used in the proof of `VALID COMMITMENTS`
/// is the same order as the order used in `VALID MATCH MPC`. This can be done by constructing the Pedersen
/// commitments to the orders using the same randomness across proofs. That way, the verified may use the
/// shared Pedersen commitment as an implicit constraint that witness values are equal across proofs.
///
/// The `LinkableCommitment` type allows this from the prover side by storing the randomness used in the
/// original commitment along with the value itself.
pub struct LinkableCommitment {
    /// The underlying value committed to
    pub val: Scalar,
    /// The randomness used to blind the commitment
    randomness: Scalar,
}
#[automatically_derived]
impl ::core::marker::Copy for LinkableCommitment {}
#[automatically_derived]
impl ::core::clone::Clone for LinkableCommitment {
    #[inline]
    fn clone(&self) -> LinkableCommitment {
        let _: ::core::clone::AssertParamIsClone<Scalar>;
        *self
    }
}
#[automatically_derived]
impl ::core::fmt::Debug for LinkableCommitment {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "LinkableCommitment",
            "val",
            &self.val,
            "randomness",
            &&self.randomness,
        )
    }
}
#[automatically_derived]
impl ::core::marker::StructuralEq for LinkableCommitment {}
#[automatically_derived]
impl ::core::cmp::Eq for LinkableCommitment {
    #[inline]
    #[doc(hidden)]
    #[no_coverage]
    fn assert_receiver_is_total_eq(&self) -> () {
        let _: ::core::cmp::AssertParamIsEq<Scalar>;
    }
}
#[automatically_derived]
impl ::core::marker::StructuralPartialEq for LinkableCommitment {}
#[automatically_derived]
impl ::core::cmp::PartialEq for LinkableCommitment {
    #[inline]
    fn eq(&self, other: &LinkableCommitment) -> bool {
        self.val == other.val && self.randomness == other.randomness
    }
}
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl _serde::Serialize for LinkableCommitment {
        fn serialize<__S>(
            &self,
            __serializer: __S,
        ) -> _serde::__private::Result<__S::Ok, __S::Error>
        where
            __S: _serde::Serializer,
        {
            let mut __serde_state = match _serde::Serializer::serialize_struct(
                __serializer,
                "LinkableCommitment",
                false as usize + 1 + 1,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "val",
                &self.val,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            match _serde::ser::SerializeStruct::serialize_field(
                &mut __serde_state,
                "randomness",
                &self.randomness,
            ) {
                _serde::__private::Ok(__val) => __val,
                _serde::__private::Err(__err) => {
                    return _serde::__private::Err(__err);
                }
            };
            _serde::ser::SerializeStruct::end(__serde_state)
        }
    }
};
#[doc(hidden)]
#[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
const _: () = {
    #[allow(unused_extern_crates, clippy::useless_attribute)]
    extern crate serde as _serde;
    #[automatically_derived]
    impl<'de> _serde::Deserialize<'de> for LinkableCommitment {
        fn deserialize<__D>(
            __deserializer: __D,
        ) -> _serde::__private::Result<Self, __D::Error>
        where
            __D: _serde::Deserializer<'de>,
        {
            #[allow(non_camel_case_types)]
            #[doc(hidden)]
            enum __Field {
                __field0,
                __field1,
                __ignore,
            }
            #[doc(hidden)]
            struct __FieldVisitor;
            impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                type Value = __Field;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "field identifier",
                    )
                }
                fn visit_u64<__E>(
                    self,
                    __value: u64,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        0u64 => _serde::__private::Ok(__Field::__field0),
                        1u64 => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_str<__E>(
                    self,
                    __value: &str,
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        "val" => _serde::__private::Ok(__Field::__field0),
                        "randomness" => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
                fn visit_bytes<__E>(
                    self,
                    __value: &[u8],
                ) -> _serde::__private::Result<Self::Value, __E>
                where
                    __E: _serde::de::Error,
                {
                    match __value {
                        b"val" => _serde::__private::Ok(__Field::__field0),
                        b"randomness" => _serde::__private::Ok(__Field::__field1),
                        _ => _serde::__private::Ok(__Field::__ignore),
                    }
                }
            }
            impl<'de> _serde::Deserialize<'de> for __Field {
                #[inline]
                fn deserialize<__D>(
                    __deserializer: __D,
                ) -> _serde::__private::Result<Self, __D::Error>
                where
                    __D: _serde::Deserializer<'de>,
                {
                    _serde::Deserializer::deserialize_identifier(
                        __deserializer,
                        __FieldVisitor,
                    )
                }
            }
            #[doc(hidden)]
            struct __Visitor<'de> {
                marker: _serde::__private::PhantomData<LinkableCommitment>,
                lifetime: _serde::__private::PhantomData<&'de ()>,
            }
            impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                type Value = LinkableCommitment;
                fn expecting(
                    &self,
                    __formatter: &mut _serde::__private::Formatter,
                ) -> _serde::__private::fmt::Result {
                    _serde::__private::Formatter::write_str(
                        __formatter,
                        "struct LinkableCommitment",
                    )
                }
                #[inline]
                fn visit_seq<__A>(
                    self,
                    mut __seq: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::SeqAccess<'de>,
                {
                    let __field0 = match match _serde::de::SeqAccess::next_element::<
                        Scalar,
                    >(&mut __seq) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    } {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(
                                _serde::de::Error::invalid_length(
                                    0usize,
                                    &"struct LinkableCommitment with 2 elements",
                                ),
                            );
                        }
                    };
                    let __field1 = match match _serde::de::SeqAccess::next_element::<
                        Scalar,
                    >(&mut __seq) {
                        _serde::__private::Ok(__val) => __val,
                        _serde::__private::Err(__err) => {
                            return _serde::__private::Err(__err);
                        }
                    } {
                        _serde::__private::Some(__value) => __value,
                        _serde::__private::None => {
                            return _serde::__private::Err(
                                _serde::de::Error::invalid_length(
                                    1usize,
                                    &"struct LinkableCommitment with 2 elements",
                                ),
                            );
                        }
                    };
                    _serde::__private::Ok(LinkableCommitment {
                        val: __field0,
                        randomness: __field1,
                    })
                }
                #[inline]
                fn visit_map<__A>(
                    self,
                    mut __map: __A,
                ) -> _serde::__private::Result<Self::Value, __A::Error>
                where
                    __A: _serde::de::MapAccess<'de>,
                {
                    let mut __field0: _serde::__private::Option<Scalar> = _serde::__private::None;
                    let mut __field1: _serde::__private::Option<Scalar> = _serde::__private::None;
                    while let _serde::__private::Some(__key)
                        = match _serde::de::MapAccess::next_key::<__Field>(&mut __map) {
                            _serde::__private::Ok(__val) => __val,
                            _serde::__private::Err(__err) => {
                                return _serde::__private::Err(__err);
                            }
                        } {
                        match __key {
                            __Field::__field0 => {
                                if _serde::__private::Option::is_some(&__field0) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field("val"),
                                    );
                                }
                                __field0 = _serde::__private::Some(
                                    match _serde::de::MapAccess::next_value::<
                                        Scalar,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    },
                                );
                            }
                            __Field::__field1 => {
                                if _serde::__private::Option::is_some(&__field1) {
                                    return _serde::__private::Err(
                                        <__A::Error as _serde::de::Error>::duplicate_field(
                                            "randomness",
                                        ),
                                    );
                                }
                                __field1 = _serde::__private::Some(
                                    match _serde::de::MapAccess::next_value::<
                                        Scalar,
                                    >(&mut __map) {
                                        _serde::__private::Ok(__val) => __val,
                                        _serde::__private::Err(__err) => {
                                            return _serde::__private::Err(__err);
                                        }
                                    },
                                );
                            }
                            _ => {
                                let _ = match _serde::de::MapAccess::next_value::<
                                    _serde::de::IgnoredAny,
                                >(&mut __map) {
                                    _serde::__private::Ok(__val) => __val,
                                    _serde::__private::Err(__err) => {
                                        return _serde::__private::Err(__err);
                                    }
                                };
                            }
                        }
                    }
                    let __field0 = match __field0 {
                        _serde::__private::Some(__field0) => __field0,
                        _serde::__private::None => {
                            match _serde::__private::de::missing_field("val") {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        }
                    };
                    let __field1 = match __field1 {
                        _serde::__private::Some(__field1) => __field1,
                        _serde::__private::None => {
                            match _serde::__private::de::missing_field("randomness") {
                                _serde::__private::Ok(__val) => __val,
                                _serde::__private::Err(__err) => {
                                    return _serde::__private::Err(__err);
                                }
                            }
                        }
                    };
                    _serde::__private::Ok(LinkableCommitment {
                        val: __field0,
                        randomness: __field1,
                    })
                }
            }
            #[doc(hidden)]
            const FIELDS: &'static [&'static str] = &["val", "randomness"];
            _serde::Deserializer::deserialize_struct(
                __deserializer,
                "LinkableCommitment",
                FIELDS,
                __Visitor {
                    marker: _serde::__private::PhantomData::<LinkableCommitment>,
                    lifetime: _serde::__private::PhantomData,
                },
            )
        }
    }
};
impl LinkableCommitment {
    /// Create a new linkable commitment from a given value
    pub fn new(val: Scalar) -> Self {
        let mut rng = OsRng {};
        let randomness = Scalar::random(&mut rng);
        Self { val, randomness }
    }
    /// Get the Pedersen commitment to this value
    pub fn compute_commitment(&self) -> CompressedRistretto {
        let pedersen_generators = PedersenGens::default();
        pedersen_generators.commit(self.val, self.randomness).compress()
    }
}
impl From<Scalar> for LinkableCommitment {
    fn from(val: Scalar) -> Self {
        LinkableCommitment::new(val)
    }
}
impl From<LinkableCommitment> for Scalar {
    fn from(comm: LinkableCommitment) -> Self {
        comm.val
    }
}
/// A linkable commitment that has been allocated inside of an MPC fabric
pub struct AuthenticatedLinkableCommitment<
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
> {
    /// The underlying shared scalar
    val: AuthenticatedScalar<N, S>,
    /// The randomness used to blind the commitment
    randomness: Scalar,
}
#[automatically_derived]
impl<
    N: ::core::fmt::Debug + MpcNetwork + Send,
    S: ::core::fmt::Debug + SharedValueSource<Scalar>,
> ::core::fmt::Debug for AuthenticatedLinkableCommitment<N, S> {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
        ::core::fmt::Formatter::debug_struct_field2_finish(
            f,
            "AuthenticatedLinkableCommitment",
            "val",
            &self.val,
            "randomness",
            &&self.randomness,
        )
    }
}
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> Clone
for AuthenticatedLinkableCommitment<N, S> {
    fn clone(&self) -> Self {
        Self {
            val: self.val.clone(),
            randomness: self.randomness,
        }
    }
}
/// Flattening operation for serialization to share over an MPC fabric
impl<
    N: MpcNetwork + Send,
    S: SharedValueSource<Scalar>,
> AuthenticatedLinkableCommitment<N, S> {
    /// Create a linkable commitment from a shared scalar by sampling a shared
    /// blinder
    pub fn new(val: AuthenticatedScalar<N, S>) -> Self {
        let mut rng = OsRng {};
        let randomness = Scalar::random(&mut rng);
        Self { val, randomness }
    }
}
impl<N: MpcNetwork + Send, S: SharedValueSource<Scalar>> CommitSharedProver<N, S>
for AuthenticatedLinkableCommitment<N, S> {
    type SharedVarType = MpcVariable<N, S>;
    type CommitType = AuthenticatedCompressedRistretto<N, S>;
    type ErrorType = MpcError;
    fn commit<R: RngCore + CryptoRng>(
        &self,
        _owning_party: u64,
        _rng: &mut R,
        prover: &mut MpcProver<N, S>,
    ) -> Result<(Self::SharedVarType, Self::CommitType), Self::ErrorType> {
        let (comm, var) = prover
            .commit_preshared(&self.val, self.randomness)
            .map_err(|err| MpcError::SharingError(err.to_string()))?;
        Ok((var, comm))
    }
}
#[cfg(test)]
pub(crate) mod test_helpers {
    use crypto::fields::{prime_field_to_bigint, scalar_to_bigint, DalekRistrettoField};
    use curve25519_dalek::scalar::Scalar;
    use env_logger::{Builder, Env, Target};
    use merlin::Transcript;
    use mpc_bulletproof::{
        r1cs::{LinearCombination, Prover, RandomizableConstraintSystem, Verifier},
        PedersenGens,
    };
    use rand_core::OsRng;
    use crate::{errors::VerifierError, traits::SingleProverCircuit};
    const TRANSCRIPT_SEED: &str = "test";
    /// Constructor to initialize logging in tests
    extern fn setup() {
        init_logger()
    }
    #[used]
    #[allow(non_upper_case_globals)]
    #[doc(hidden)]
    #[link_section = "__DATA,__mod_init_func"]
    static setup___rust_ctor___ctor: unsafe extern "C" fn() = {
        unsafe extern "C" fn setup___rust_ctor___ctor() {
            setup()
        }
        setup___rust_ctor___ctor
    };
    pub fn init_logger() {
        let env = Env::default().filter_or("MY_CRATE_LOG", "trace");
        let mut builder = Builder::from_env(env);
        builder.target(Target::Stdout);
        builder.init();
    }
    /// Construct a random scalar
    pub(crate) fn random_scalar() -> Scalar {
        let mut rng = OsRng {};
        Scalar::random(&mut rng)
    }
    /// Assert that two linear combinations are equal in the given constraint system
    pub(crate) fn assert_lcs_equal<CS: RandomizableConstraintSystem>(
        lc1: &LinearCombination,
        lc2: &LinearCombination,
        cs: &CS,
    ) {
        let eval1 = cs.eval(lc1);
        let eval2 = cs.eval(lc2);
        match (&eval1, &eval2) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    let kind = ::core::panicking::AssertKind::Eq;
                    ::core::panicking::assert_failed(
                        kind,
                        &*left_val,
                        &*right_val,
                        ::core::option::Option::None,
                    );
                }
            }
        };
    }
    /// Compares a Dalek Scalar to an Arkworks field element
    pub(crate) fn compare_scalar_to_felt(
        scalar: &Scalar,
        felt: &DalekRistrettoField,
    ) -> bool {
        scalar_to_bigint(scalar).eq(&prime_field_to_bigint(felt))
    }
    /// Abstracts over the flow of proving and verifying a circuit given
    /// a valid statement + witness assignment
    pub fn bulletproof_prove_and_verify<C: SingleProverCircuit>(
        witness: C::Witness,
        statement: C::Statement,
    ) -> Result<(), VerifierError> {
        let mut transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let pc_gens = PedersenGens::default();
        let prover = Prover::new(&pc_gens, &mut transcript);
        let (witness_commitment, proof) = C::prove(witness, statement.clone(), prover)
            .unwrap();
        let mut verifier_transcript = Transcript::new(TRANSCRIPT_SEED.as_bytes());
        let verifier = Verifier::new(&pc_gens, &mut verifier_transcript);
        C::verify(witness_commitment, statement, proof, verifier)
    }
}
/// Groups helpers that operate on native types; which correspond to circuitry
/// defined in this library
///
/// For example; when computing witnesses, wallet commitments, note commitments,
/// nullifiers, etc are all useful helpers
pub mod native_helpers {
    use ark_crypto_primitives::sponge::{poseidon::PoseidonSponge, CryptographicSponge};
    use crypto::{
        fields::{
            biguint_to_scalar, prime_field_to_scalar, scalar_to_prime_field,
            DalekRistrettoField,
        },
        hash::{default_poseidon_params, evaluate_hash_chain},
    };
    use curve25519_dalek::scalar::Scalar;
    use itertools::Itertools;
}
#[cfg(test)]
mod circuits_test {
    use crypto::fields::bigint_to_scalar;
    use num_bigint::BigInt;
    use rand::{thread_rng, Rng};
    use crate::scalar_2_to_m;
    extern crate test;
    #[cfg(test)]
    #[rustc_test_marker = "circuits_test::test_scalar_2_to_m"]
    pub const test_scalar_2_to_m: test::TestDescAndFn = test::TestDescAndFn {
        desc: test::TestDesc {
            name: test::StaticTestName("circuits_test::test_scalar_2_to_m"),
            ignore: false,
            ignore_message: ::core::option::Option::None,
            compile_fail: false,
            no_run: false,
            should_panic: test::ShouldPanic::No,
            test_type: test::TestType::UnitTest,
        },
        testfn: test::StaticTestFn(|| test::assert_test_result(test_scalar_2_to_m())),
    };
    fn test_scalar_2_to_m() {
        let rand_m: usize = thread_rng().gen_range(0..256);
        let res = scalar_2_to_m(rand_m);
        let expected = bigint_to_scalar(&(BigInt::from(1u64) << rand_m));
        match (&res, &expected) {
            (left_val, right_val) => {
                if !(*left_val == *right_val) {
                    let kind = ::core::panicking::AssertKind::Eq;
                    ::core::panicking::assert_failed(
                        kind,
                        &*left_val,
                        &*right_val,
                        ::core::option::Option::None,
                    );
                }
            }
        };
    }
}
#[rustc_main]
pub fn main() -> () {
    extern crate test;
    test::test_main_static(
        &[
            &test_scalar_2_to_m,
            &test_base_type_implementation,
            &test_base_type_preserved,
            &test_circuit_base_type_derived_types,
            &test_circuit_base_type_implementation,
            &test_mpc_derived_type,
            &test_macro_associated,
            &test_macro_non_associated,
        ],
    )
}
