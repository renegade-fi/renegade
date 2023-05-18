//! Groups type and trait definitions built when the `singleprover_circuit`
//! argument is given to the macro

use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{parse_quote, Attribute, Generics, ItemImpl, ItemStruct};

use super::{
    build_deserialize_method, build_modified_struct_from_associated_types, build_serialize_method,
    path_from_ident,
};

// -------------
// | Constants |
// -------------

/// The name of the trait that base types implement
const BASE_TYPE_TRAIT_NAME: &str = "CircuitBaseType";
/// The name of the trait that the var type implements
const VAR_TYPE_TRAIT_NAME: &str = "CircuitVarType";
/// The name of the trait that the commitment type implements
const COMM_TYPE_TRAIT_NAME: &str = "CircuitCommitmentType";

/// The name of the associated type for variables
const VAR_TYPE_ASSOCIATED_NAME: &str = "VarType";
/// The name of the associated type for commitments
const COMM_TYPE_ASSOCIATED_NAME: &str = "CommitmentType";

/// The method name for converting from serialized commitments to a commitment type
const FROM_COMMS_METHOD_NAME: &str = "from_commitments";
/// The method name for converting a commitment type to a serialized commitment vector
const TO_COMMS_METHOD_NAME: &str = "to_commitments";
/// The type that a `from_commitments` method implementation converts from
const FROM_COMMS_ITER_TYPE: &str = "CompressedRistretto";
/// The method name for converting from serialized variables to a variable type
const FROM_VARS_METHOD_NAME: &str = "from_vars";
/// The type that a `from_vars` method implementation converts from
const FROM_VARS_ITER_TYPE: &str = "Variable";

/// The suffix appended to a variable type of a base type
const VAR_TYPE_SUFFIX: &str = "Var";
/// The suffix appended to a commitment type of a base type
const COMM_TYPE_SUFFIX: &str = "Commitment";

// ------------------
// | Implementation |
// ------------------

/// Build single-prover circuit types for the base type, these are variable and commitment types
pub(crate) fn build_circuit_types(base_type: &ItemStruct) -> TokenStream2 {
    let mut res_stream = TokenStream2::default();

    // Build an implementation of `CircuitBaseType` for the
    let circuit_base_type_stream = build_circuit_base_type_impl(base_type);
    res_stream.extend(circuit_base_type_stream);

    // Build a variable type
    let var_type_stream = build_var_type(base_type);
    res_stream.extend(var_type_stream);

    // Build a commitment types
    let comm_type_stream = build_commitment_type(base_type);
    res_stream.extend(comm_type_stream);

    res_stream
}

/// Build an `impl CircuitBaseType` block for the base type
fn build_circuit_base_type_impl(base_type: &ItemStruct) -> TokenStream2 {
    let base_name = base_type.ident.clone();
    let trait_ident = Ident::new(BASE_TYPE_TRAIT_NAME, Span::call_site());

    let var_type_associated = Ident::new(VAR_TYPE_ASSOCIATED_NAME, Span::call_site());
    let var_type_name = Ident::new(&format!("{base_name}{VAR_TYPE_SUFFIX}"), Span::call_site());
    let comm_type_associated = Ident::new(COMM_TYPE_ASSOCIATED_NAME, Span::call_site());
    let comm_type_name = Ident::new(&format!("{base_name}{COMM_TYPE_SUFFIX}"), Span::call_site());

    parse_quote! {
        impl #trait_ident for #base_name {
            type #var_type_associated = #var_type_name;
            type #comm_type_associated = #comm_type_name;
        }
    }
}

/// Build a variable type; the type of the base allocated in a constraint system
fn build_var_type(base_type: &ItemStruct) -> TokenStream2 {
    let base_name = base_type.ident.clone();
    let var_name: Ident = Ident::new(&format!("{base_name}{VAR_TYPE_SUFFIX}"), Span::call_site());
    let derive_clone: Attribute = parse_quote!(#[derive(Clone)]);

    let var_struct = build_modified_struct_from_associated_types(
        base_type,
        var_name,
        vec![derive_clone],
        Generics::default(),
        path_from_ident(Ident::new(BASE_TYPE_TRAIT_NAME, Span::call_site())),
        Ident::new(VAR_TYPE_ASSOCIATED_NAME, Span::call_site()),
    );

    // Implement `CircuitVarType` for this struct and append to the result
    let circuit_var_impl = build_var_type_impl(&var_struct);
    let mut res = var_struct.to_token_stream();
    res.extend(circuit_var_impl);

    res
}

/// Build an implementation of the `CircuitVarType` trait for the new var type
fn build_var_type_impl(var_struct: &ItemStruct) -> TokenStream2 {
    let trait_ident = Ident::new(VAR_TYPE_TRAIT_NAME, Span::call_site());
    let var_struct_ident = var_struct.ident.clone();

    let deserialize_method_expr = build_deserialize_method(
        Ident::new(FROM_VARS_METHOD_NAME, Span::call_site()),
        path_from_ident(Ident::new(FROM_VARS_ITER_TYPE, Span::call_site())),
        path_from_ident(trait_ident.clone()),
        var_struct,
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #trait_ident for #var_struct_ident {
            #deserialize_method_expr
        }
    };

    impl_block.to_token_stream()
}

/// Build a commitment type; the type of a commitment to the base type that has been allocated
fn build_commitment_type(base_type: &ItemStruct) -> TokenStream2 {
    let base_name = base_type.ident.clone();
    let comm_name = Ident::new(&format!("{base_name}{COMM_TYPE_SUFFIX}"), Span::call_site());
    let derive_clone: Attribute = parse_quote!(#[derive(Clone)]);

    let comm_struct = build_modified_struct_from_associated_types(
        base_type,
        comm_name,
        vec![derive_clone],
        Generics::default(),
        path_from_ident(Ident::new(BASE_TYPE_TRAIT_NAME, Span::call_site())),
        Ident::new(COMM_TYPE_ASSOCIATED_NAME, Span::call_site()),
    );

    let mut res = comm_struct.to_token_stream();
    res.extend(build_comm_type_impl(&comm_struct));
    res
}

/// Build the `impl CircuitCommitmentType for ...` block fo the commitment struct
fn build_comm_type_impl(comm_struct: &ItemStruct) -> TokenStream2 {
    let trait_ident = Ident::new(COMM_TYPE_TRAIT_NAME, Span::call_site());
    let comm_struct_ident = comm_struct.ident.clone();

    // Strip the commitment suffix and add in the var suffix
    let base_struct_name = comm_struct_ident.to_string();
    let stripped = base_struct_name
        .strip_suffix(COMM_TYPE_SUFFIX)
        .unwrap_or(&base_struct_name);

    let var_type_ident = Ident::new(&format!("{stripped}{VAR_TYPE_SUFFIX}"), Span::call_site());
    let associated_type_ident = Ident::new(VAR_TYPE_ASSOCIATED_NAME, Span::call_site());

    // Implement `from_commitments`
    let deserialize_expr = build_deserialize_method(
        Ident::new(FROM_COMMS_METHOD_NAME, Span::call_site()),
        path_from_ident(Ident::new(FROM_COMMS_ITER_TYPE, Span::call_site())),
        path_from_ident(trait_ident.clone()),
        comm_struct,
    );

    // Implement `to_commitments`
    let serialize_expr = build_serialize_method(
        Ident::new(TO_COMMS_METHOD_NAME, Span::call_site()),
        path_from_ident(Ident::new(FROM_COMMS_ITER_TYPE, Span::call_site())),
        comm_struct,
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #trait_ident for #comm_struct_ident {
            type #associated_type_ident = #var_type_ident;
            #deserialize_expr
            #serialize_expr
        }
    };
    impl_block.to_token_stream()
}
