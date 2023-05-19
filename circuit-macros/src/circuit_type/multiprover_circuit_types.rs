//! Type definitions and trait implementations for multi-prover ZK circuits

use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{parse_quote, ItemImpl, ItemStruct};

use crate::circuit_type::{
    build_deserialize_method, build_modified_struct_from_associated_types, ident_with_prefix,
    ident_with_suffix,
    mpc_types::{build_mpc_generics, with_mpc_generics},
    new_ident,
};

use super::build_serialize_method;

/// The name of the trait that multiprover circuit base types implement
const MULTIPROVER_BASE_TRAIT_NAME: &str = "MultiproverCircuitBaseType";
/// The name of the associated variable type on the base trait
const MULTIPROVER_BASE_VAR_ASSOCIATED_NAME: &str = "MultiproverVarType";
/// The name of the trait that multiprover circuit variable types implement
const MULTIPROVER_VAR_TRAIT_NAME: &str = "MultiproverCircuitVariableType";
/// The name of the associated variable type on the base trait
const MULTIPROVER_BASE_COMM_ASSOCIATED_NAME: &str = "MultiproverCommType";
/// The name of the trait that multiprover circuit commitment types implement
const MULTIPROVER_COMM_TRAIT_NAME: &str = "MultiproverCircuitCommitmentType";
/// The name of the associated base commitment type for a shared commitment type
const BASE_COMM_TYPE_ASSOCIATED_NAME: &str = "BaseCommitType";

/// The `from_mpc_vars` method on the `MultiproverCircuitVariableType` trait
const FROM_MPC_VARS_METHOD: &str = "from_mpc_vars";
/// The `from_mpc_commitments` method on the `MultiproverCircuitCommitmentType` trait
const FROM_MPC_COMMS_METHOD: &str = "from_mpc_commitments";
/// The `to_mpc_commitments` method on the `MultiproverCircuitCommitmentType` trait
const TO_MPC_COMMS_METHOD: &str = "to_mpc_commitments";

/// The `MpcVariable` type name
const MPC_VAR_TYPE_NAME: &str = "MpcVariable";
/// The `AuthenticatedCompressedRistretto` type
const MPC_COMM_TYPE_NAME: &str = "AuthenticatedCompressedRistretto";

/// The prefix that is prepended to all authenticated MPC types
const AUTHENTICATED_PREFIX: &str = "Authenticated";
/// The suffix that is appended to variable types
const VAR_SUFFIX: &str = "Var";
/// The suffix that is appended to commitment types
const COMM_SUFFIX: &str = "Commitment";

/// Build the multiprover circuit types from a base type
pub(crate) fn build_multiprover_circuit_types(base_struct: &ItemStruct) -> TokenStream2 {
    // Build the variable and commitment types and the trait implementations
    // for committing to the base type in an MPC circuit
    let mut res = build_base_type_impl(base_struct);
    res.extend(build_authenticated_var_type(base_struct));
    res.extend(build_authenticated_comm_type(base_struct));

    res
}

/// Build an `impl MultiproverCircuitBaseType` block
fn build_base_type_impl(base_struct: &ItemStruct) -> TokenStream2 {
    let mpc_generics = build_mpc_generics();
    let trait_name = with_mpc_generics(new_ident(MULTIPROVER_BASE_TRAIT_NAME));
    let base_struct_name = base_struct.ident.clone();

    let var_type_associated_name = new_ident(MULTIPROVER_BASE_VAR_ASSOCIATED_NAME);
    let comm_type_associated_name = new_ident(MULTIPROVER_BASE_COMM_ASSOCIATED_NAME);

    let auth_prefixed_type =
        ident_with_prefix(&base_struct.ident.to_string(), AUTHENTICATED_PREFIX);
    let derived_var_type_ident = with_mpc_generics(ident_with_suffix(
        &auth_prefixed_type.to_string(),
        VAR_SUFFIX,
    ));
    let derived_comm_type_ident = with_mpc_generics(ident_with_suffix(
        &auth_prefixed_type.to_string(),
        COMM_SUFFIX,
    ));

    let impl_block: ItemImpl = parse_quote! {
        impl #mpc_generics #trait_name for #base_struct_name {
            type #var_type_associated_name = #derived_var_type_ident;
            type #comm_type_associated_name = #derived_comm_type_ident;
        }
    };
    impl_block.to_token_stream()
}

/// Build the multiprover circuit variable type
fn build_authenticated_var_type(base_struct: &ItemStruct) -> TokenStream2 {
    let base_struct_name = base_struct.ident.clone();
    let new_name = ident_with_prefix(&base_struct_name.to_string(), AUTHENTICATED_PREFIX);
    let new_name = ident_with_suffix(&new_name.to_string(), VAR_SUFFIX);

    let multiprover_base_trait_name = with_mpc_generics(new_ident(MULTIPROVER_BASE_TRAIT_NAME));
    let base_type_var_associated_name = new_ident(MULTIPROVER_BASE_VAR_ASSOCIATED_NAME);

    let multiprover_var_type = build_modified_struct_from_associated_types(
        base_struct,
        new_name,
        vec![parse_quote!(#[derive(Clone)])],
        build_mpc_generics(),
        multiprover_base_trait_name,
        base_type_var_associated_name,
    );

    // Impl `MultiproverCircuitVariableType` for the newly constructed type
    let multiprover_var_type_impl = build_multiprover_var_type_impl(&multiprover_var_type);
    let mut res = multiprover_var_type.to_token_stream();
    res.extend(multiprover_var_type_impl);

    res
}

/// Build a `impl MultiproverCircuitVariableType` block
fn build_multiprover_var_type_impl(var_type: &ItemStruct) -> TokenStream2 {
    let mpc_generics = build_mpc_generics();
    let trait_name = with_mpc_generics(new_ident(MULTIPROVER_VAR_TRAIT_NAME));
    let var_type_name = with_mpc_generics(var_type.ident.clone());

    let mpc_variable_type = with_mpc_generics(new_ident(MPC_VAR_TYPE_NAME));

    let from_mpc_vars_method = build_deserialize_method(
        new_ident(FROM_MPC_VARS_METHOD),
        mpc_variable_type,
        trait_name.clone(),
        var_type,
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #mpc_generics #trait_name for #var_type_name {
            #from_mpc_vars_method
        }
    };
    impl_block.to_token_stream()
}

/// Build the multiprover circuit commitment type
fn build_authenticated_comm_type(base_struct: &ItemStruct) -> TokenStream2 {
    let base_struct_name = base_struct.ident.clone();
    let new_name = ident_with_prefix(&base_struct_name.to_string(), AUTHENTICATED_PREFIX);
    let new_name = ident_with_suffix(&new_name.to_string(), COMM_SUFFIX);

    let multiprover_base_trait_name = with_mpc_generics(new_ident(MULTIPROVER_BASE_TRAIT_NAME));
    let base_type_comm_associated_name = new_ident(MULTIPROVER_BASE_COMM_ASSOCIATED_NAME);

    let multiprover_comm_type = build_modified_struct_from_associated_types(
        base_struct,
        new_name,
        vec![parse_quote!(#[derive(Clone)])],
        build_mpc_generics(),
        multiprover_base_trait_name,
        base_type_comm_associated_name,
    );

    // Impl `MultiproverCircuitVariableType` for the newly constructed type
    let multiprover_comm_type_impl = build_multiprover_comm_type_impl(&multiprover_comm_type);
    let mut res = multiprover_comm_type.to_token_stream();
    res.extend(multiprover_comm_type_impl);

    res
}

/// Build a `impl MultiproverCircuitCommitmentType` block
fn build_multiprover_comm_type_impl(comm_type: &ItemStruct) -> TokenStream2 {
    let mpc_generics = build_mpc_generics();
    let trait_name = with_mpc_generics(new_ident(MULTIPROVER_COMM_TRAIT_NAME));
    let comm_type_name = with_mpc_generics(comm_type.ident.clone());

    let base_commitment_type = &comm_type.ident.to_string();
    let base_commitment_type = base_commitment_type
        .strip_prefix(AUTHENTICATED_PREFIX)
        .unwrap_or(base_commitment_type);

    let base_commitment_type = new_ident(base_commitment_type);
    let associated_comm_type_name = new_ident(BASE_COMM_TYPE_ASSOCIATED_NAME);

    // Build a deserialization method from a list of shared commitments
    let mpc_comm_type = with_mpc_generics(new_ident(MPC_COMM_TYPE_NAME));
    let from_mpc_comms_method = build_deserialize_method(
        new_ident(FROM_MPC_COMMS_METHOD),
        mpc_comm_type.clone(),
        trait_name.clone(),
        comm_type,
    );

    // Build a serialization method to a list of shared commitments
    let to_mpc_comms_method =
        build_serialize_method(new_ident(TO_MPC_COMMS_METHOD), mpc_comm_type, comm_type);

    let impl_block: ItemImpl = parse_quote! {
        impl #mpc_generics #trait_name for #comm_type_name {
            type #associated_comm_type_name = #base_commitment_type;

            #from_mpc_comms_method
            #to_mpc_comms_method
        }
    };
    impl_block.to_token_stream()
}
