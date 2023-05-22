//! Groups type and trait definitions built when the `singleprover_circuit`
//! argument is given to the macro

use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{parse_quote, Attribute, Generics, ItemFn, ItemImpl, ItemStruct, Stmt};

use crate::circuit_type::{ident_with_suffix, new_ident};

use super::{
    build_deserialize_method, build_modified_struct_from_associated_types, build_serialize_method,
    path_from_ident, str_to_path,
};

// -------------
// | Constants |
// -------------

/// The name of the trait that base types implement
pub(crate) const CIRCUIT_BASE_TYPE_TRAIT_NAME: &str = "CircuitBaseType";
/// The name of the trait that the var type implements
const VAR_TYPE_TRAIT_NAME: &str = "CircuitVarType";
/// The name of the trait that the commitment type implements
const COMM_TYPE_TRAIT_NAME: &str = "CircuitCommitmentType";

/// The name of the associated type for variables
pub(crate) const VAR_TYPE_ASSOCIATED_NAME: &str = "VarType";
/// The name of the associated type for commitments
pub(crate) const COMM_TYPE_ASSOCIATED_NAME: &str = "CommitmentType";

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
/// The method name for creating commitment randomness to a base type
const COMMITMENT_RANDOMNESS_METHOD_NAME: &str = "commitment_randomness";

/// The suffix appended to a variable type of a base type
pub(crate) const VAR_TYPE_SUFFIX: &str = "Var";
/// The suffix appended to a commitment type of a base type
pub(crate) const COMM_TYPE_SUFFIX: &str = "Commitment";

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
    let trait_ident = new_ident(CIRCUIT_BASE_TYPE_TRAIT_NAME);

    let var_type_associated = new_ident(VAR_TYPE_ASSOCIATED_NAME);
    let var_type_name = ident_with_suffix(&base_name.to_string(), VAR_TYPE_SUFFIX);
    let comm_type_associated = new_ident(COMM_TYPE_ASSOCIATED_NAME);
    let comm_type_name = ident_with_suffix(&base_name.to_string(), COMM_TYPE_SUFFIX);

    // Build the body of the `commitment_randomness` method
    let commitment_randomness_impl = build_commitment_randomness_method(base_type);
    let impl_block: ItemImpl = parse_quote! {
        impl #trait_ident for #base_name {
            type #var_type_associated = #var_type_name;
            type #comm_type_associated = #comm_type_name;

            #commitment_randomness_impl
        }
    };
    impl_block.to_token_stream()
}

/// Build an implementation of the `commitment_randomness` method that calls out to each
/// field's implementation
pub(crate) fn build_commitment_randomness_method(base_type: &ItemStruct) -> TokenStream2 {
    // Build the body of the `commitment_randomness` method
    let commitment_randomness_ident = new_ident(COMMITMENT_RANDOMNESS_METHOD_NAME);
    let mut field_stmts: Vec<Stmt> = Vec::new();
    for field in base_type.fields.iter() {
        let field_ident = field.ident.clone();
        field_stmts.push(parse_quote! {
            res.extend(self.#field_ident.#commitment_randomness_ident(r));
        });
    }

    let fn_def: ItemFn = parse_quote! {
        fn #commitment_randomness_ident <R: RngCore + CryptoRng>(&self, r: &mut R) -> Vec<Scalar> {
            let mut res = Vec::new();
            #(#field_stmts)*

            res
        }
    };
    fn_def.to_token_stream()
}

/// Build a variable type; the type of the base allocated in a constraint system
pub(crate) fn build_var_type(base_type: &ItemStruct) -> TokenStream2 {
    let base_name = base_type.ident.clone();
    let var_name = ident_with_suffix(&base_name.to_string(), VAR_TYPE_SUFFIX);
    let derive_clone: Attribute = parse_quote!(#[derive(Clone)]);

    let var_struct = build_modified_struct_from_associated_types(
        base_type,
        var_name,
        vec![derive_clone],
        Generics::default(),
        str_to_path(CIRCUIT_BASE_TYPE_TRAIT_NAME),
        new_ident(VAR_TYPE_ASSOCIATED_NAME),
    );

    // Implement `CircuitVarType` for this struct and append to the result
    let circuit_var_impl = build_var_type_impl(&var_struct);
    let mut res = var_struct.to_token_stream();
    res.extend(circuit_var_impl);

    res
}

/// Build an implementation of the `CircuitVarType` trait for the new var type
fn build_var_type_impl(var_struct: &ItemStruct) -> TokenStream2 {
    let var_struct_ident = var_struct.ident.clone();
    let trait_ident = new_ident(VAR_TYPE_TRAIT_NAME);

    let deserialize_method_expr = build_deserialize_method(
        new_ident(FROM_VARS_METHOD_NAME),
        str_to_path(FROM_VARS_ITER_TYPE),
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
pub(crate) fn build_commitment_type(base_type: &ItemStruct) -> TokenStream2 {
    let base_name = base_type.ident.clone();
    let comm_name = ident_with_suffix(&base_name.to_string(), COMM_TYPE_SUFFIX);
    let derive_clone: Attribute = parse_quote!(#[derive(Clone)]);

    let comm_struct = build_modified_struct_from_associated_types(
        base_type,
        comm_name,
        vec![derive_clone],
        Generics::default(),
        str_to_path(CIRCUIT_BASE_TYPE_TRAIT_NAME),
        new_ident(COMM_TYPE_ASSOCIATED_NAME),
    );

    let mut res = comm_struct.to_token_stream();
    res.extend(build_comm_type_impl(&comm_struct));
    res
}

/// Build the `impl CircuitCommitmentType for ...` block fo the commitment struct
fn build_comm_type_impl(comm_struct: &ItemStruct) -> TokenStream2 {
    let trait_ident = new_ident(COMM_TYPE_TRAIT_NAME);
    let comm_struct_ident = comm_struct.ident.clone();

    // Strip the commitment suffix and add in the var suffix
    let base_struct_name = comm_struct_ident.to_string();
    let stripped = base_struct_name
        .strip_suffix(COMM_TYPE_SUFFIX)
        .unwrap_or(&base_struct_name);

    let var_type_ident = ident_with_suffix(stripped, VAR_TYPE_SUFFIX);
    let associated_type_ident = new_ident(VAR_TYPE_ASSOCIATED_NAME);

    // Implement `from_commitments`
    let deserialize_expr = build_deserialize_method(
        new_ident(FROM_COMMS_METHOD_NAME),
        str_to_path(FROM_COMMS_ITER_TYPE),
        path_from_ident(trait_ident.clone()),
        comm_struct,
    );

    // Implement `to_commitments`
    let serialize_expr = build_serialize_method(
        new_ident(TO_COMMS_METHOD_NAME),
        str_to_path(FROM_COMMS_ITER_TYPE),
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
