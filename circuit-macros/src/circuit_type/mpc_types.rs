//! Builds MPC-related types from a base type and implements relevant traits

use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{parse_quote, ImplItemMethod, ItemImpl, ItemStruct};

use crate::circuit_type::{
    build_deserialize_method, build_serialize_method, ident_with_generics, ident_with_prefix,
    new_ident,
};

use super::{
    build_modified_struct_from_associated_types, impl_clone_by_fields,
    multiprover_circuit_types::build_multiprover_circuit_types, path_from_ident,
};

/// The prefix used in an MPC type of a given base type
pub(crate) const MPC_TYPE_PREFIX: &str = "Authenticated";

/// The name of the trait that specifies an MPC base type name
const MPC_BASE_TYPE_TRAIT_NAME: &str = "MpcBaseType";
/// The name of the associated type representing the allocated type of a base
/// type
const MPC_ALLOCATED_TYPE_ASSOCIATED_NAME: &str = "AllocatedType";
/// The name of the trait that specifies an allocated MPC type
const MPC_ALLOC_TYPE_TRAIT_NAME: &str = "MpcType";
/// The name of the associated type representing the native type of an MPC type
const MPC_NATIVE_TYPE_ASSOCIATED_NAME: &str = "NativeType";

/// The method name that deserializes an authenticated type from a serialized
/// Scalar repr
const FROM_AUTHENTICATED_SCALARS_METHOD_NAME: &str = "from_authenticated_scalars";
/// The type that is deserialized from for an MPC type
const MPC_TYPE_SERIALIZED_IDENT: &str = "AuthenticatedScalar";
/// The method name that serializes an authenticated type to a vector of
/// allocated Scalars
const TO_AUTHENTICATED_SCALARS_METHOD_NAME: &str = "to_authenticated_scalars";

/// Build the MPC types from a base type
///
/// If `include_multiprover` is set, the MPC types will also implement
/// `MultiproverBaseType` and multi-prover circuit types will be allocated for
/// the struct
pub(crate) fn build_mpc_types(base_struct: &ItemStruct, include_multiprover: bool) -> TokenStream2 {
    // Implement `MpcBaseType` for the base struct
    let mut res = build_mpc_base_type_impl(base_struct);
    // Build the MPC type and implementations
    res.extend(build_mpc_type(base_struct, include_multiprover));

    res
}

/// Build an `impl MpcBaseType` struct for the base type
fn build_mpc_base_type_impl(base_struct: &ItemStruct) -> TokenStream2 {
    let generics = base_struct.generics.clone();
    let where_clause = generics.where_clause.clone();

    let base_struct_ident = ident_with_generics(&base_struct.ident, generics.clone());
    let mpc_type_name = ident_with_prefix(&base_struct.ident.to_string(), MPC_TYPE_PREFIX);
    let mpc_type_name = ident_with_generics(&mpc_type_name, generics.clone());

    let mpc_base_type_trait = new_ident(MPC_BASE_TYPE_TRAIT_NAME);
    let mpc_allocated_type = new_ident(MPC_ALLOCATED_TYPE_ASSOCIATED_NAME);

    parse_quote! {
        impl #generics #mpc_base_type_trait for #base_struct_ident
            #where_clause
        {
            type #mpc_allocated_type = #mpc_type_name;
        }
    }
}

/// Build the core `Authenticated` type that implements `MpcType`
fn build_mpc_type(base_struct: &ItemStruct, include_multiprover: bool) -> TokenStream2 {
    let base_type_name = base_struct.ident.clone();
    let new_name_ident = ident_with_prefix(&base_type_name.to_string(), MPC_TYPE_PREFIX);

    let mpc_base_trait_ident = new_ident(MPC_BASE_TYPE_TRAIT_NAME);
    let mpc_type_associated_ident = new_ident(MPC_ALLOCATED_TYPE_ASSOCIATED_NAME);

    let generics = base_struct.generics.clone();
    let mpc_type = build_modified_struct_from_associated_types(
        base_struct,
        new_name_ident,
        vec![],
        generics,
        &path_from_ident(&mpc_base_trait_ident),
        &path_from_ident(&mpc_type_associated_ident),
    );

    // Impl `MpcType` for the newly constructed type
    let mpc_type_impl_block = build_mpc_type_impl(&mpc_type, base_struct);
    let mut res = mpc_type.to_token_stream();
    res.extend(mpc_type_impl_block);
    res.extend(impl_clone_by_fields(&mpc_type));

    // Implement multiprover types
    if include_multiprover {
        res.extend(build_multiprover_circuit_types(&mpc_type));
    }

    res
}

/// Build an `impl MpcType` block for a given type
fn build_mpc_type_impl(mpc_type: &ItemStruct, base_type: &ItemStruct) -> TokenStream2 {
    let generics = base_type.generics.clone();
    let where_clause = generics.where_clause.clone();

    let mpc_type_trait_name = path_from_ident(&new_ident(MPC_ALLOC_TYPE_TRAIT_NAME));
    let mpc_type_ident = ident_with_generics(&mpc_type.ident, generics.clone());

    // This ident is used for the `type NativeType` associated type
    let native_type_ident = new_ident(MPC_NATIVE_TYPE_ASSOCIATED_NAME);
    let base_type_ident = ident_with_generics(&base_type.ident, generics.clone());

    let authenticated_scalar_type = path_from_ident(&new_ident(MPC_TYPE_SERIALIZED_IDENT));
    let from_auth_scalars_method = build_deserialize_method(
        &new_ident(FROM_AUTHENTICATED_SCALARS_METHOD_NAME),
        &authenticated_scalar_type,
        &mpc_type_trait_name,
        mpc_type,
    );

    // Build a `fabric` method
    // TODO: Fold the `fabric` method into the `MpcType` trait and call out to its
    // implementation
    let first_element = &mpc_type.fields.iter().next().unwrap().ident.clone().unwrap();
    let fabric_method: ImplItemMethod = parse_quote! {
        fn fabric(&self) -> &Fabric {
            &self.#first_element.fabric()
        }
    };

    // Build a `to_authenticated_scalars` method
    let to_auth_scalars_method = build_serialize_method(
        &new_ident(TO_AUTHENTICATED_SCALARS_METHOD_NAME),
        &authenticated_scalar_type,
        mpc_type,
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #mpc_type_trait_name for #mpc_type_ident
            #where_clause
        {
            type #native_type_ident = #base_type_ident;

            #fabric_method
            #from_auth_scalars_method
            #to_auth_scalars_method
        }
    };
    impl_block.to_token_stream()
}
