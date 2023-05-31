//! This file groups type definitions for proof-linkable commitments

use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{
    parse_quote, punctuated::Punctuated, token::Comma, Attribute, FieldValue, ItemImpl, ItemStruct,
};

use crate::circuit_type::{
    ident_strip_prefix, ident_with_prefix, ident_with_suffix,
    multiprover_circuit_types::with_multiprover_generics,
    new_ident,
    singleprover_circuit_types::{COMM_TYPE_SUFFIX, VAR_TYPE_SUFFIX},
};

use super::{
    build_base_type_impl, build_commitment_randomness_method,
    build_modified_struct_from_associated_types, build_serde_methods, ident_with_generics,
    merge_generics,
    mpc_types::{build_mpc_generics, build_mpc_types, with_mpc_generics, MPC_TYPE_PREFIX},
    multiprover_circuit_types::build_multiprover_generics,
    path_from_ident,
    singleprover_circuit_types::{
        build_var_type_generics, CIRCUIT_BASE_TYPE_TRAIT_NAME, COMM_TYPE_ASSOCIATED_NAME,
        VAR_TYPE_ASSOCIATED_NAME,
    },
    FROM_SCALARS_METHOD_NAME, SCALAR_TYPE_IDENT, TO_SCALARS_LINKING_METHOD_NAME,
};

/// The name of the trait that linkable base types implement
const LINKABLE_BASE_TYPE_TRAIT_NAME: &str = "LinkableBaseType";
/// The associated type of the linkable type on the base type
const LINKABLE_TYPE_ASSOCIATED_NAME: &str = "Linkable";
/// The name of the trait that derived linkable types implement
const LINKABLE_TYPE_TRAIT_NAME: &str = "LinkableType";
/// The `to_linkable` method name
const TO_LINKABLE_METHOD_NAME: &str = "to_linkable";
/// The associated type of the base type on the linkable type
const BASE_TYPE_ASSOCIATED_NAME: &str = "BaseType";

/// The prefix prepended to linkable types derived from a base type
const LINKABLE_PREFIX: &str = "Linkable";

/// Build commitment linkable type definitions for the given struct
pub(crate) fn build_linkable_types(
    base_type: &ItemStruct,
    include_multiprover: bool,
    serde: bool,
) -> TokenStream2 {
    let mut res = build_linkable_base_type_impl(base_type);
    res.extend(build_linkable_struct(base_type, include_multiprover, serde));

    res
}

/// Build an implementation of the `LinkableBaseType` trait for the base struct
fn build_linkable_base_type_impl(base_type: &ItemStruct) -> TokenStream2 {
    let generics = base_type.generics.clone();
    let where_clause = generics.where_clause.clone();

    let base_name = ident_with_generics(base_type.ident.clone(), generics.clone());
    let associated_name = new_ident(LINKABLE_TYPE_ASSOCIATED_NAME);
    let linkable_type_name = ident_with_generics(
        ident_with_prefix(&base_type.ident.to_string(), LINKABLE_PREFIX),
        generics.clone(),
    );

    let trait_name = new_ident(LINKABLE_BASE_TYPE_TRAIT_NAME);

    // Build the `to_linkable` method implementation
    let mut field_exprs: Punctuated<FieldValue, Comma> = Punctuated::new();
    base_type.fields.iter().for_each(|field| {
        let field_name = field.ident.as_ref().unwrap();
        field_exprs.push(parse_quote! {
            #field_name: self.#field_name.to_linkable()
        })
    });
    let to_linkable_name = new_ident(TO_LINKABLE_METHOD_NAME);

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_name for #base_name
            #where_clause
        {
            type #associated_name = #linkable_type_name;

            fn #to_linkable_name(&self) -> Self::#associated_name {
                Self::#associated_name {
                    #field_exprs
                }
            }
        }
    };
    impl_block.to_token_stream()
}

/// Build the modified version of the struct that replaces each field with its commitment
/// linkable analog
fn build_linkable_struct(
    base_type: &ItemStruct,
    include_multiprover: bool,
    serde: bool,
) -> TokenStream2 {
    let generics = base_type.generics.clone();
    let linkable_name = ident_with_prefix(&base_type.ident.to_string(), LINKABLE_PREFIX);
    let derive: Attribute = parse_quote!(#[derive(Clone, Debug, Eq, PartialEq)]);

    let trait_name = new_ident(LINKABLE_BASE_TYPE_TRAIT_NAME);
    let associated_name = new_ident(LINKABLE_TYPE_ASSOCIATED_NAME);

    // Build the linkable type
    let linkable_type = build_modified_struct_from_associated_types(
        base_type,
        linkable_name,
        vec![derive],
        generics,
        path_from_ident(trait_name),
        path_from_ident(associated_name),
    );
    let mut res = linkable_type.to_token_stream();

    // Implement `LinkableType`
    res.extend(build_linkable_type_impl(&linkable_type));

    // Implement `BaseType`
    res.extend(build_base_type_impl(&linkable_type));

    // Implement `CircuitBaseType
    res.extend(build_circuit_base_type_impl(&linkable_type));

    // Build MPC types and Multiprover types for the linkable type
    if include_multiprover {
        // Add type aliases to the commitment and var types from the linkable type
        res.extend(build_multiprover_type(&linkable_type));
    }

    // Build `serde` impls for the linkable type
    if serde {
        res.extend(build_serde_methods(
            &linkable_type,
            path_from_ident(new_ident(SCALAR_TYPE_IDENT)),
            new_ident(TO_SCALARS_LINKING_METHOD_NAME),
            new_ident(FROM_SCALARS_METHOD_NAME),
        ));
    }

    res
}

/// Build the linkable type's implementation of the `LinkableType` trait
fn build_linkable_type_impl(linkable_type: &ItemStruct) -> TokenStream2 {
    let generics = linkable_type.generics.clone();
    let where_clause = generics.where_clause.clone();

    let trait_name = new_ident(LINKABLE_TYPE_TRAIT_NAME);
    let struct_name = ident_with_generics(linkable_type.ident.clone(), generics.clone());

    let associated_name = new_ident(BASE_TYPE_ASSOCIATED_NAME);
    let base_type_name = ident_with_generics(
        ident_strip_prefix(&linkable_type.ident.to_string(), LINKABLE_PREFIX),
        generics.clone(),
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_name for #struct_name
            #where_clause
        {
            type #associated_name = #base_type_name;
        }
    };
    impl_block.to_token_stream()
}

/// Build the `CircuitBaseType` implementation of the linkable type so that it may be committed
/// to within a constraint system
///
/// Assumes that a base type exists for the non-linkable implementation
fn build_circuit_base_type_impl(linkable_type: &ItemStruct) -> TokenStream2 {
    let generics = linkable_type.generics.clone();
    let where_clause = generics.where_clause.clone();

    // Build the trait metadata
    let trait_name = new_ident(CIRCUIT_BASE_TYPE_TRAIT_NAME);
    let type_name = ident_with_generics(linkable_type.ident.clone(), generics.clone());

    // Build the associated `VarType` and `CommitmentType` fields
    let var_type_associated = new_ident(VAR_TYPE_ASSOCIATED_NAME);
    let var_type_generics = build_var_type_generics();
    let comm_type_associated = new_ident(COMM_TYPE_ASSOCIATED_NAME);

    // Build the associated types
    let base_type_ident = ident_strip_prefix(&linkable_type.ident.to_string(), LINKABLE_PREFIX);
    let var_type_ident = ident_with_generics(
        ident_with_suffix(&base_type_ident.to_string(), VAR_TYPE_SUFFIX),
        merge_generics(build_var_type_generics(), generics.clone()),
    );
    let comm_type_ident = ident_with_generics(
        ident_with_suffix(&base_type_ident.to_string(), COMM_TYPE_SUFFIX),
        generics.clone(),
    );

    // Build the implementation of `commitment_randomness`
    let commitment_randomness_fn =
        build_commitment_randomness_method(linkable_type, path_from_ident(trait_name.clone()));

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_name for #type_name
            #where_clause
        {
            type #var_type_associated #var_type_generics = #var_type_ident;
            type #comm_type_associated = #comm_type_ident;

            #commitment_randomness_fn
        }
    };
    impl_block.to_token_stream()
}

/// Build a multiprover type for the linkable type
fn build_multiprover_type(linkable_type: &ItemStruct) -> TokenStream2 {
    // Add type aliases for the allocated linkable commitment and variable types
    // to the non-linkable ones, the MPC types will allocate multiprover var types
    // as AuthenticatedLinkableTypeVar and AuthenticatedLinkableTypeCommitment, whereas we would prefer them
    // to be AuthenticatedTypeVar and AuthenticatedTypeCommitment
    let var_generics = build_multiprover_generics();
    let comm_generics = build_mpc_generics();
    let authenticated_linkable_name =
        ident_with_prefix(&linkable_type.ident.to_string(), MPC_TYPE_PREFIX);
    let linkable_var_name =
        ident_with_suffix(&authenticated_linkable_name.to_string(), VAR_TYPE_SUFFIX);
    let linkable_comm_name =
        ident_with_suffix(&authenticated_linkable_name.to_string(), COMM_TYPE_SUFFIX);

    let base_type_name = ident_with_prefix(
        &ident_strip_prefix(&linkable_type.ident.to_string(), LINKABLE_PREFIX).to_string(),
        MPC_TYPE_PREFIX,
    );
    let base_var_type = with_multiprover_generics(ident_with_suffix(
        &base_type_name.to_string(),
        VAR_TYPE_SUFFIX,
    ));
    let base_comm_type = with_mpc_generics(ident_with_suffix(
        &base_type_name.to_string(),
        COMM_TYPE_SUFFIX,
    ));

    // We do not construct new multiprover types, we instead implement `MulitproverCircuitBaseType` directly
    // and target the types already constructed
    let mpc_type_impl = build_mpc_types(
        linkable_type,
        true, /* include_multiprover */
        true, /* multiprover_base_only */
    );
    // let multiprover_impl = build_multiprover_base_type_impl(linkable_type);

    parse_quote! {
        type #linkable_var_name #var_generics = #base_var_type;
        type #linkable_comm_name #comm_generics = #base_comm_type;

        #mpc_type_impl
    }
}
