//! This file groups type definitions for proof-linkable commitments

use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{parse_quote, Attribute, Generics, ItemImpl, ItemStruct};

use crate::circuit_type::{
    build_deserialize_method, build_serialize_method, ident_strip_prefix, ident_with_prefix,
    ident_with_suffix, new_ident,
    singleprover_circuit_types::{COMM_TYPE_SUFFIX, VAR_TYPE_SUFFIX},
    FROM_SCALARS_METHOD_NAME, SCALAR_TYPE_IDENT, TO_SCALARS_METHOD_NAME,
};

use super::{
    build_modified_struct_from_associated_types, path_from_ident,
    singleprover_circuit_types::{
        build_commitment_randomness_method, CIRCUIT_BASE_TYPE_TRAIT_NAME,
        COMM_TYPE_ASSOCIATED_NAME, VAR_TYPE_ASSOCIATED_NAME,
    },
    BASE_TYPE_TRAIT_NAME,
};

/// The name of the trait that linkable base types implement
const LINKABLE_BASE_TYPE_TRAIT_NAME: &str = "LinkableBaseType";
/// The associated type of the linkable type on the base type
const LINKABLE_TYPE_ASSOCIATED_NAME: &str = "Linkable";
/// The name of the trait that derived linkable types implement
const LINKABLE_TYPE_TRAIT_NAME: &str = "LinkableType";
/// The associated type of the base type on the linkable type
const BASE_TYPE_ASSOCIATED_NAME: &str = "BaseType";

/// The prefix prepended to linkable types derived from a base type
const LINKABLE_PREFIX: &str = "Linkable";

/// Build commitment linkable type definitions for the given struct
pub(crate) fn build_linkable_types(base_type: &ItemStruct) -> TokenStream2 {
    let mut res = build_linkable_base_type_impl(base_type);
    res.extend(build_linkable_struct(base_type));

    res
}

/// Build an implementation of the `LinkableBaseType` trait for the base struct
fn build_linkable_base_type_impl(base_type: &ItemStruct) -> TokenStream2 {
    let base_name = base_type.ident.clone();
    let associated_name = new_ident(LINKABLE_TYPE_ASSOCIATED_NAME);
    let linkable_type_name = ident_with_prefix(&base_name.to_string(), LINKABLE_PREFIX);

    let trait_name = new_ident(LINKABLE_BASE_TYPE_TRAIT_NAME);

    let impl_block: ItemImpl = parse_quote! {
        impl #trait_name for #base_name {
            type #associated_name = #linkable_type_name;
        }
    };
    impl_block.to_token_stream()
}

/// Build the modified version of the struct that replaces each field with its commitment
/// linkable analog
fn build_linkable_struct(base_type: &ItemStruct) -> TokenStream2 {
    let linkable_name = ident_with_prefix(&base_type.ident.to_string(), LINKABLE_PREFIX);
    let derive_clone: Attribute = parse_quote!(#[derive(Clone)]);

    let trait_name = new_ident(LINKABLE_BASE_TYPE_TRAIT_NAME);
    let associated_name = new_ident(LINKABLE_TYPE_ASSOCIATED_NAME);

    // Build the linkable type
    let linkable_type = build_modified_struct_from_associated_types(
        base_type,
        linkable_name,
        vec![derive_clone],
        Generics::default(),
        path_from_ident(trait_name),
        associated_name,
    );
    let mut res = linkable_type.to_token_stream();

    // Implement `LinkableType`
    res.extend(build_linkable_type_impl(&linkable_type));

    // Implement `BaseType`
    res.extend(build_base_type_impl(&linkable_type));

    // Implement `CircuitBaseType
    res.extend(build_circuit_base_type_impl(&linkable_type));

    res
}

/// Build the linkable type's implementation of the `LinkableType` trait
fn build_linkable_type_impl(linkable_type: &ItemStruct) -> TokenStream2 {
    let trait_name = new_ident(LINKABLE_TYPE_TRAIT_NAME);
    let struct_name = linkable_type.ident.clone();

    let associated_name = new_ident(BASE_TYPE_ASSOCIATED_NAME);
    let base_type_name = ident_strip_prefix(&linkable_type.ident.to_string(), LINKABLE_PREFIX);

    let impl_block: ItemImpl = parse_quote! {
        impl #trait_name for #struct_name {
            type #associated_name = #base_type_name;
        }
    };
    impl_block.to_token_stream()
}

/// Build the `BaseType` implementation for the linkable type so that it may be committed to in a
/// constraint system
fn build_base_type_impl(linkable_type: &ItemStruct) -> TokenStream2 {
    // Build the serialize method
    let linkable_type_name = linkable_type.ident.clone();
    let base_type_trait_name = path_from_ident(new_ident(BASE_TYPE_TRAIT_NAME));

    // Build the `to_scalars` serialization method
    let to_scalars_method_name = new_ident(TO_SCALARS_METHOD_NAME);
    let scalar_type = path_from_ident(new_ident(SCALAR_TYPE_IDENT));
    let to_scalars_method =
        build_serialize_method(to_scalars_method_name, scalar_type.clone(), linkable_type);

    // Build the `from_scalars` deserialization method
    let from_scalars_method_name = new_ident(FROM_SCALARS_METHOD_NAME);
    let from_scalars_method = build_deserialize_method(
        from_scalars_method_name,
        scalar_type,
        base_type_trait_name.clone(),
        linkable_type,
    );

    // Build the impl block
    let impl_block: ItemImpl = parse_quote! {
        impl #base_type_trait_name for #linkable_type_name {
            #to_scalars_method
            #from_scalars_method
        }
    };
    impl_block.to_token_stream()
}

/// Build the `CircuitBaseType` implementation of the linkable type so that it may be committed
/// to within a constraint system
///
/// Assumes that a base type exists for the non-linkable implementation
fn build_circuit_base_type_impl(linkable_type: &ItemStruct) -> TokenStream2 {
    // Build the trait metadata
    let trait_name = new_ident(CIRCUIT_BASE_TYPE_TRAIT_NAME);
    let type_name = linkable_type.ident.clone();

    // Build the associated `VarType` and `CommitmentType` fields
    let var_type_associated = new_ident(VAR_TYPE_ASSOCIATED_NAME);
    let comm_type_associated = new_ident(COMM_TYPE_ASSOCIATED_NAME);

    // Build the associated types
    let base_type_ident = ident_strip_prefix(&linkable_type.ident.to_string(), LINKABLE_PREFIX);
    let var_type_ident = ident_with_suffix(&base_type_ident.to_string(), VAR_TYPE_SUFFIX);
    let comm_type_ident = ident_with_suffix(&base_type_ident.to_string(), COMM_TYPE_SUFFIX);

    // Build the implementation of `commitment_randomness`
    let commitment_randomness_fn = build_commitment_randomness_method(linkable_type);

    let impl_block: ItemImpl = parse_quote! {
        impl #trait_name for #type_name {
            type #var_type_associated = #var_type_ident;
            type #comm_type_associated = #comm_type_ident;

            #commitment_randomness_fn
        }
    };
    impl_block.to_token_stream()
}
