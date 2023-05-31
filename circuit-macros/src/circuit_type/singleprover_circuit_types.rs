//! Groups type and trait definitions built when the `singleprover_circuit`
//! argument is given to the macro

use proc_macro2::{Ident, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{parse_quote, Attribute, Generics, ItemImpl, ItemStruct, Path};

use crate::circuit_type::{ident_with_suffix, new_ident};

use super::{
    build_commitment_randomness_method, build_deserialize_method,
    build_modified_struct_from_associated_types, build_serde_methods, build_serialize_method,
    ident_strip_suffix, ident_with_generics, merge_generics, params_from_generics, path_from_ident,
    str_to_path,
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
/// The method name for converting to serialized variables from a variable type
const TO_VARS_METHOD_NAME: &str = "to_vars";

/// The suffix appended to a variable type of a base type
pub(crate) const VAR_TYPE_SUFFIX: &str = "Var";
/// The suffix appended to a commitment type of a base type
pub(crate) const COMM_TYPE_SUFFIX: &str = "Commitment";

/// The generic type used to represent a `LinearCombinationLike` type
const LINEAR_COMBINATION_LIKE_GENERIC: &str = "L";
/// The name of the `LinearCombination` type
const LINEAR_COMBINATION_TYPE: &str = "LinearCombination";
/// The name of the associated type `LinearCombinationType`
const LINEAR_COMBINATION_ASSOCIATED_TYPE_NAME: &str = "LinearCombinationType";

// -----------
// | Helpers |
// -----------

/// Build generic bounds for variable types which abstract over the functional differences
/// of `Variable`s and `LinearCombination`s
pub(crate) fn build_var_type_generics() -> Generics {
    let l_ident = new_ident(LINEAR_COMBINATION_LIKE_GENERIC);
    parse_quote!(<#l_ident: LinearCombinationLike>)
}

/// Attach variable type generics to the given identifier
pub(crate) fn with_var_type_generics(ident: Ident) -> Path {
    let l_ident = new_ident(LINEAR_COMBINATION_LIKE_GENERIC);
    parse_quote!(#ident <#l_ident>)
}

// ------------------
// | Implementation |
// ------------------

/// Build single-prover circuit types for the base type, these are variable and commitment types
pub(crate) fn build_circuit_types(base_type: &ItemStruct, serde: bool) -> TokenStream2 {
    let mut res_stream = TokenStream2::default();

    // Build an implementation of `CircuitBaseType` for the base type
    let circuit_base_type_stream = build_circuit_base_type_impl(base_type);
    res_stream.extend(circuit_base_type_stream);

    // Build a variable type
    let var_type_stream = build_var_type(base_type);
    res_stream.extend(var_type_stream);

    // Build a commitment types
    let comm_type_stream = build_commitment_type(base_type, serde);
    res_stream.extend(comm_type_stream);

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
    let var_type_generics = build_var_type_generics();

    let var_type_name = ident_with_generics(
        ident_with_suffix(&base_name.to_string(), VAR_TYPE_SUFFIX),
        merge_generics(var_type_generics.clone(), generics.clone()),
    );

    let comm_type_associated = new_ident(COMM_TYPE_ASSOCIATED_NAME);
    let comm_type_name = ident_with_generics(
        ident_with_suffix(&base_name.to_string(), COMM_TYPE_SUFFIX),
        generics.clone(),
    );

    // Build the body of the `commitment_randomness` method
    let commitment_randomness_impl =
        build_commitment_randomness_method(base_type, path_from_ident(trait_ident.clone()));
    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_ident for #base_name <#base_type_params>
            #where_clause
        {
            type #var_type_associated #var_type_generics = #var_type_name;
            type #comm_type_associated = #comm_type_name;

            #commitment_randomness_impl
        }
    };
    impl_block.to_token_stream()
}

/// Build a variable type; the type of the base allocated in a constraint system
pub(crate) fn build_var_type(base_type: &ItemStruct) -> TokenStream2 {
    let base_name = base_type.ident.clone();
    let var_name = ident_with_suffix(&base_name.to_string(), VAR_TYPE_SUFFIX);
    let derive_clone: Attribute = parse_quote!(#[derive(Clone, Debug)]);

    let generics = merge_generics(build_var_type_generics(), base_type.generics.clone());
    let var_struct = build_modified_struct_from_associated_types(
        base_type,
        var_name,
        vec![derive_clone],
        generics,
        str_to_path(CIRCUIT_BASE_TYPE_TRAIT_NAME),
        with_var_type_generics(new_ident(VAR_TYPE_ASSOCIATED_NAME)),
    );

    // Implement `CircuitVarType` for this struct and append to the result
    let circuit_var_impl = build_var_type_impl(&var_struct, base_type);
    let mut res = var_struct.to_token_stream();
    res.extend(circuit_var_impl);

    res
}

/// Build an implementation of the `CircuitVarType` trait for the new var type
fn build_var_type_impl(var_struct: &ItemStruct, base_type: &ItemStruct) -> TokenStream2 {
    // Build the impl prelude
    let generics = var_struct.generics.clone();
    let where_clause = generics.where_clause.clone();

    let var_struct_ident = ident_with_generics(var_struct.ident.clone(), generics.clone());
    let trait_ident = with_var_type_generics(new_ident(VAR_TYPE_TRAIT_NAME));

    // Build the generics for the `LinearCombinationType` associated
    let mut lc_associated_params = params_from_generics(base_type.generics.clone());
    lc_associated_params.insert(0, new_ident(LINEAR_COMBINATION_TYPE));
    let lc_type_associated = new_ident(LINEAR_COMBINATION_ASSOCIATED_TYPE_NAME);
    let lc_type_name = var_struct.ident.clone();

    let serialized_type = str_to_path(LINEAR_COMBINATION_LIKE_GENERIC);
    let serialize_method_expr = build_serialize_method(
        new_ident(TO_VARS_METHOD_NAME),
        serialized_type.clone(),
        var_struct,
    );

    let deserialize_method_expr = build_deserialize_method(
        new_ident(FROM_VARS_METHOD_NAME),
        serialized_type,
        trait_ident.clone(),
        var_struct,
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_ident for #var_struct_ident
            #where_clause
        {
            type #lc_type_associated = #lc_type_name <#lc_associated_params>;
            #serialize_method_expr
            #deserialize_method_expr
        }
    };
    impl_block.to_token_stream()
}

/// Build a commitment type; the type of a commitment to the base type that has been allocated
pub(crate) fn build_commitment_type(base_type: &ItemStruct, serde: bool) -> TokenStream2 {
    let generics = base_type.generics.clone();
    let base_name = base_type.ident.clone();
    let comm_name = ident_with_suffix(&base_name.to_string(), COMM_TYPE_SUFFIX);
    let derive: Attribute = parse_quote!(#[derive(Clone, Debug, Eq, PartialEq)]);

    let comm_struct = build_modified_struct_from_associated_types(
        base_type,
        comm_name,
        vec![derive],
        generics,
        str_to_path(CIRCUIT_BASE_TYPE_TRAIT_NAME),
        path_from_ident(new_ident(COMM_TYPE_ASSOCIATED_NAME)),
    );

    let mut res = comm_struct.to_token_stream();
    res.extend(build_comm_type_impl(&comm_struct));
    if serde {
        res.extend(build_serde_methods(
            &comm_struct,
            path_from_ident(new_ident(FROM_COMMS_ITER_TYPE)),
            new_ident(TO_COMMS_METHOD_NAME),
            new_ident(FROM_COMMS_METHOD_NAME),
        ));
    }

    res
}

/// Build the `impl CircuitCommitmentType for ...` block fo the commitment struct
fn build_comm_type_impl(comm_struct: &ItemStruct) -> TokenStream2 {
    let generics = comm_struct.generics.clone();
    let where_clause = generics.where_clause.clone();

    let trait_ident = new_ident(COMM_TYPE_TRAIT_NAME);
    let comm_struct_ident = ident_with_generics(comm_struct.ident.clone(), generics.clone());

    // Strip the commitment suffix and add in the var suffix
    let stripped = ident_strip_suffix(&comm_struct.ident.to_string(), COMM_TYPE_SUFFIX);
    let var_type_ident = ident_with_generics(
        ident_with_suffix(&stripped.to_string(), VAR_TYPE_SUFFIX),
        merge_generics(parse_quote!(<Variable>), generics.clone()),
    );
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
        impl #generics #trait_ident for #comm_struct_ident
            #where_clause
        {
            type #associated_type_ident = #var_type_ident;
            #deserialize_expr
            #serialize_expr
        }
    };
    impl_block.to_token_stream()
}
