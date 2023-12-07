//! Groups type and trait definitions built when the `singleprover_circuit`
//! argument is given to the macro

use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{
    parse_quote,
    punctuated::Punctuated,
    token::{Colon, Comma},
    Attribute, Expr, FieldValue, ItemImpl, ItemStruct, Member, Path,
};

use crate::circuit_type::{ident_with_suffix, new_ident};

use super::{
    build_modified_struct_from_associated_types, build_serialize_method, ident_with_generics,
    params_from_generics, str_to_path, BASE_TYPE_TRAIT_NAME,
};

// -------------
// | Constants |
// -------------

/// The name of the trait that base types implement
pub(crate) const CIRCUIT_BASE_TYPE_TRAIT_NAME: &str = "CircuitBaseType";
/// The name of the trait that the var type implements
const VAR_TYPE_TRAIT_NAME: &str = "CircuitVarType";

/// The name of the associated type for variables
pub(crate) const VAR_TYPE_ASSOCIATED_NAME: &str = "VarType";

/// The type underlying every variable type
pub(crate) const VARIABLE_TYPE: &str = "Variable";
/// The method name for converting from serialized variables to a variable type
const FROM_VARS_METHOD_NAME: &str = "from_vars";
/// The method name for converting to serialized variables from a variable type
const TO_VARS_METHOD_NAME: &str = "to_vars";

/// The suffix appended to a variable type of a base type
pub(crate) const VAR_TYPE_SUFFIX: &str = "Var";

// ------------------
// | Implementation |
// ------------------

/// Build single-prover circuit types for the base type, these are variable and
/// commitment types
pub(crate) fn build_circuit_types(base_type: &ItemStruct) -> TokenStream2 {
    let mut res_stream = TokenStream2::default();

    // Build an implementation of `CircuitBaseType` for the base type
    let circuit_base_type_stream = build_circuit_base_type_impl(base_type);
    res_stream.extend(circuit_base_type_stream);

    // Build a variable type
    let var_type_stream = build_var_type(base_type);
    res_stream.extend(var_type_stream);

    res_stream
}

/// Build an `impl CircuitBaseType` block for the base type
fn build_circuit_base_type_impl(base_type: &ItemStruct) -> TokenStream2 {
    let generics = base_type.generics.clone();
    let where_clause = generics.where_clause.clone();

    let trait_ident = new_ident(CIRCUIT_BASE_TYPE_TRAIT_NAME);
    let base_name = base_type.ident.clone();
    let base_type_params = params_from_generics(generics.clone());

    let var_type_associated = new_ident(VAR_TYPE_ASSOCIATED_NAME);
    let var_type_name = ident_with_generics(
        &ident_with_suffix(&base_name.to_string(), VAR_TYPE_SUFFIX),
        generics.clone(),
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_ident for #base_name <#base_type_params>
            #where_clause
        {
            type #var_type_associated = #var_type_name;
        }
    };
    impl_block.to_token_stream()
}

/// Build a variable type; the type of the base allocated in a constraint system
pub(crate) fn build_var_type(base_type: &ItemStruct) -> TokenStream2 {
    let base_name = base_type.ident.clone();
    let var_name = ident_with_suffix(&base_name.to_string(), VAR_TYPE_SUFFIX);
    let derive_clone: Attribute = parse_quote!(#[derive(Clone, Debug)]);

    let generics = base_type.generics.clone();
    let var_struct = build_modified_struct_from_associated_types(
        base_type,
        var_name,
        vec![derive_clone],
        generics.clone(),
        &str_to_path(CIRCUIT_BASE_TYPE_TRAIT_NAME),
        &str_to_path(VAR_TYPE_ASSOCIATED_NAME),
    );

    // Implement `CircuitVarType` for this struct and append to the result
    let circuit_var_impl =
        build_var_type_impl(&var_struct, &ident_with_generics(&base_name, generics));
    let mut res = var_struct.to_token_stream();
    res.extend(circuit_var_impl);

    res
}

/// Build an implementation of the `CircuitVarType` trait for the new var type
fn build_var_type_impl(var_struct: &ItemStruct, base_name: &Path) -> TokenStream2 {
    // Build the impl prelude
    let generics = var_struct.generics.clone();
    let trait_ident = str_to_path(VAR_TYPE_TRAIT_NAME);
    let where_clause = generics.where_clause.clone();

    let var_struct_ident = ident_with_generics(&var_struct.ident, generics.clone());

    let base_type_associated_name = new_ident(BASE_TYPE_TRAIT_NAME);

    let serialized_type = str_to_path(VARIABLE_TYPE);
    let serialize_method_expr =
        build_serialize_method(&new_ident(TO_VARS_METHOD_NAME), &serialized_type, var_struct);

    let deserialize_method_expr = build_from_vars(var_struct);

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_ident for #var_struct_ident
            #where_clause
        {
            type #base_type_associated_name = #base_name;

            #serialize_method_expr
            #deserialize_method_expr
        }
    };
    impl_block.to_token_stream()
}

/// Builds the `from_vars` method on a circuit type, this method cannot use the
/// `build_deserialize_method` as it takes an extra parameter in the form of a
/// circuit
fn build_from_vars(self_struct: &ItemStruct) -> TokenStream2 {
    let method_name = new_ident(FROM_VARS_METHOD_NAME);
    let from_type = new_ident(VARIABLE_TYPE);
    let trait_ident = new_ident(VAR_TYPE_TRAIT_NAME);

    let mut fields_expr: Punctuated<FieldValue, Comma> = Punctuated::new();

    for field in self_struct.fields.iter().cloned() {
        let ident = field.ident.expect("only named fields supported");
        let field_type = field.ty;

        // The parse field expr recursively calls `#method_name` on the field type
        let parse_field_expr: Expr = parse_quote! {
            <#field_type as #trait_ident>::#method_name(i, cs)
        };

        fields_expr.push(FieldValue {
            attrs: Vec::new(),
            member: Member::Named(ident),
            colon_token: Some(Colon::default()),
            expr: parse_field_expr,
        });
    }

    parse_quote! {
        fn #method_name<I: Iterator<Item = #from_type>, C: Circuit<ScalarField>>(i: &mut I, cs: &mut C) -> Self {
            Self {
                #fields_expr
            }
        }
    }
}
