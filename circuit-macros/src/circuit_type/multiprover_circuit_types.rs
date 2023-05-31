//! Type definitions and trait implementations for multi-prover ZK circuits

use proc_macro2::{Ident, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{parse_quote, Generics, ItemImpl, ItemStruct, Path};

use crate::circuit_type::{
    build_deserialize_method, build_modified_struct_from_associated_types, ident_with_suffix,
    mpc_types::{build_mpc_generics, with_mpc_generics},
    new_ident,
};

use super::{
    build_commitment_randomness_method, build_serialize_method, filter_generics,
    ident_strip_prefix, ident_with_generics, impl_clone_by_fields, merge_generics,
    mpc_types::MPC_TYPE_PREFIX, path_from_ident,
};

/// The name of the trait that multiprover circuit base types implement
pub(crate) const MULTIPROVER_BASE_TRAIT_NAME: &str = "MultiproverCircuitBaseType";
/// The name of the associated variable type on the base trait
pub(crate) const MULTIPROVER_BASE_VAR_ASSOCIATED_NAME: &str = "MultiproverVarType";
/// The name of the associated base type on the multiprover base trait
pub(crate) const MULTIPROVER_BASE_TYPE_ASSOCIATED_NAME: &str = "BaseType";
/// The name of the trait that multiprover circuit variable types implement
const MULTIPROVER_VAR_TRAIT_NAME: &str = "MultiproverCircuitVariableType";
/// The name of the associated variable type on the base trait
pub(crate) const MULTIPROVER_BASE_COMM_ASSOCIATED_NAME: &str = "MultiproverCommType";
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

/// The `AuthenticatedCompressedRistretto` type
const MPC_COMM_TYPE_NAME: &str = "AuthenticatedCompressedRistretto";

/// The suffix that is appended to variable types
pub(crate) const VAR_SUFFIX: &str = "Var";
/// The suffix that is appended to commitment types
pub(crate) const COMM_SUFFIX: &str = "Commitment";

// -----------
// | Helpers |
// -----------

/// Build the generic used for the variable type
pub(crate) fn build_multiprover_var_generics() -> Generics {
    parse_quote!(<L: MpcLinearCombinationLike<N, S>>)
}

/// Build the multiprover generics to attach to an implementation
pub(crate) fn build_multiprover_generics() -> Generics {
    parse_quote!(<N: MpcNetwork + Send, S: SharedValueSource<Scalar>, L: MpcLinearCombinationLike<N, S>>)
}

/// Add multiprover variable generics to a given identifier
pub(crate) fn with_multiprover_var_generics(ident: Ident) -> Path {
    parse_quote!(#ident<L>)
}

/// Add multiprover generics to a given identifier
pub(crate) fn with_multiprover_generics(ident: Ident) -> Path {
    parse_quote!(#ident<N, S, L>)
}

// --------------------------
// | Multiprover Types Impl |
// --------------------------

/// Build the multiprover circuit types from a base type
pub(crate) fn build_multiprover_circuit_types(
    mpc_type: &ItemStruct,
    multiprover_base_only: bool,
) -> TokenStream2 {
    // Build the variable and commitment types and the trait implementations
    // for committing to the base type in an MPC circuit
    let mut res = build_base_type_impl(mpc_type);
    if multiprover_base_only {
        return res;
    }

    res.extend(build_authenticated_var_type(mpc_type));
    res.extend(build_authenticated_comm_type(mpc_type));

    res
}

/// Build an `impl MultiproverCircuitBaseType` block
fn build_base_type_impl(mpc_type: &ItemStruct) -> TokenStream2 {
    let base_generics = mpc_type.generics.clone();
    let base_type_generics = filter_generics(base_generics.clone(), build_mpc_generics());
    let var_associated_generics = build_multiprover_var_generics();
    let var_type_generics = merge_generics(build_mpc_generics(), build_multiprover_var_generics());
    let where_clause = mpc_type.generics.where_clause.clone();

    let trait_name = with_mpc_generics(new_ident(MULTIPROVER_BASE_TRAIT_NAME));
    let mpc_type_name = ident_with_generics(mpc_type.ident.clone(), base_generics.clone());

    let base_type_associated_name = new_ident(MULTIPROVER_BASE_TYPE_ASSOCIATED_NAME);
    let var_type_associated_name = new_ident(MULTIPROVER_BASE_VAR_ASSOCIATED_NAME);
    let comm_type_associated_name = new_ident(MULTIPROVER_BASE_COMM_ASSOCIATED_NAME);

    let derived_base_type_ident = ident_with_generics(
        ident_strip_prefix(&mpc_type.ident.to_string(), MPC_TYPE_PREFIX),
        base_type_generics,
    );

    let derived_var_type_ident = ident_with_generics(
        ident_with_suffix(&mpc_type.ident.to_string(), VAR_SUFFIX),
        merge_generics(var_type_generics, base_generics.clone()),
    );
    let derived_comm_type_ident = ident_with_generics(
        ident_with_suffix(&mpc_type.ident.to_string(), COMM_SUFFIX),
        base_generics.clone(),
    );

    // Build the `commitment_randomness` method
    let commitment_randomness_method =
        build_commitment_randomness_method(mpc_type, trait_name.clone());

    let impl_block: ItemImpl = parse_quote! {
        impl #base_generics #trait_name for #mpc_type_name
            #where_clause
        {
            type #base_type_associated_name = #derived_base_type_ident;
            type #var_type_associated_name #var_associated_generics = #derived_var_type_ident;
            type #comm_type_associated_name = #derived_comm_type_ident;

            #commitment_randomness_method
        }
    };
    impl_block.to_token_stream()
}

/// Build the multiprover circuit variable type
fn build_authenticated_var_type(mpc_type: &ItemStruct) -> TokenStream2 {
    let generics = mpc_type.generics.clone();
    let new_name = ident_with_suffix(&mpc_type.ident.to_string(), VAR_SUFFIX);

    let multiprover_base_trait_name = with_mpc_generics(new_ident(MULTIPROVER_BASE_TRAIT_NAME));
    let base_type_var_associated_name =
        with_multiprover_var_generics(new_ident(MULTIPROVER_BASE_VAR_ASSOCIATED_NAME));

    let multiprover_var_type = build_modified_struct_from_associated_types(
        mpc_type,
        new_name,
        vec![],
        merge_generics(build_multiprover_generics(), generics),
        multiprover_base_trait_name,
        base_type_var_associated_name,
    );

    // Impl `MultiproverCircuitVariableType` for the newly constructed type
    let multiprover_var_type_impl = build_multiprover_var_type_impl(&multiprover_var_type);
    let mut res = multiprover_var_type.to_token_stream();
    res.extend(multiprover_var_type_impl);
    res.extend(impl_clone_by_fields(&multiprover_var_type));

    res
}

/// Build a `impl MultiproverCircuitVariableType` block
fn build_multiprover_var_type_impl(var_type: &ItemStruct) -> TokenStream2 {
    let impl_generics = var_type.generics.clone();
    let where_clause = var_type.generics.where_clause.clone();

    let trait_name = with_multiprover_generics(new_ident(MULTIPROVER_VAR_TRAIT_NAME));
    let var_type_name = ident_with_generics(var_type.ident.clone(), impl_generics.clone());

    let mpc_variable_type: Path = parse_quote!(L);
    let from_mpc_vars_method = build_deserialize_method(
        new_ident(FROM_MPC_VARS_METHOD),
        mpc_variable_type,
        trait_name.clone(),
        var_type,
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #impl_generics #trait_name for #var_type_name
            #where_clause
        {
            #from_mpc_vars_method
        }
    };
    impl_block.to_token_stream()
}

/// Build the multiprover circuit commitment type
fn build_authenticated_comm_type(mpc_type: &ItemStruct) -> TokenStream2 {
    let generics = merge_generics(build_mpc_generics(), mpc_type.generics.clone());
    let new_name = ident_with_suffix(&mpc_type.ident.to_string(), COMM_SUFFIX);

    let multiprover_base_trait_name = with_mpc_generics(new_ident(MULTIPROVER_BASE_TRAIT_NAME));
    let base_type_comm_associated_name = new_ident(MULTIPROVER_BASE_COMM_ASSOCIATED_NAME);

    let multiprover_comm_type = build_modified_struct_from_associated_types(
        mpc_type,
        new_name,
        vec![],
        generics,
        multiprover_base_trait_name,
        path_from_ident(base_type_comm_associated_name),
    );

    // Impl `MultiproverCircuitVariableType` for the newly constructed type
    let multiprover_comm_type_impl =
        build_multiprover_comm_type_impl(&multiprover_comm_type, mpc_type);
    let mut res = multiprover_comm_type.to_token_stream();
    res.extend(multiprover_comm_type_impl);
    res.extend(impl_clone_by_fields(&multiprover_comm_type));

    res
}

/// Build a `impl MultiproverCircuitCommitmentType` block
fn build_multiprover_comm_type_impl(comm_type: &ItemStruct, mpc_type: &ItemStruct) -> TokenStream2 {
    let impl_generics = merge_generics(build_mpc_generics(), mpc_type.generics.clone());
    let where_clause = mpc_type.generics.where_clause.clone();

    let trait_name = with_mpc_generics(new_ident(MULTIPROVER_COMM_TRAIT_NAME));
    let comm_type_name = ident_with_generics(comm_type.ident.clone(), impl_generics.clone());

    let base_commitment_type = ident_with_generics(
        ident_strip_prefix(&comm_type.ident.to_string(), MPC_TYPE_PREFIX),
        filter_generics(mpc_type.generics.clone(), build_mpc_generics()),
    );
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
        impl #impl_generics #trait_name for #comm_type_name
            #where_clause
        {
            type #associated_comm_type_name = #base_commitment_type;

            #from_mpc_comms_method
            #to_mpc_comms_method
        }
    };
    impl_block.to_token_stream()
}
