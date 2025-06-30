//! Type definitions and trait implementations for multi-prover ZK circuits

use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{ItemImpl, ItemStruct, parse_quote};

use crate::circuit_type::{ident_with_suffix, new_ident};

use super::{
    ident_strip_prefix, ident_with_generics,
    mpc_types::MPC_TYPE_PREFIX,
    path_from_ident,
    proof_linking::{build_create_shared_witness_method, requires_proof_linking},
    singleprover_circuit_types::VAR_TYPE_ASSOCIATED_NAME,
};

/// The name of the trait that multiprover circuit base types implement
pub(crate) const MULTIPROVER_BASE_TRAIT_NAME: &str = "MultiproverCircuitBaseType";
/// The name of the associated base type on the multiprover base trait
pub(crate) const MULTIPROVER_BASE_TYPE_ASSOCIATED_NAME: &str = "BaseType";

/// The suffix that is appended to variable types
pub(crate) const VAR_SUFFIX: &str = "Var";

// --------------------------
// | Multiprover Types Impl |
// --------------------------

/// Build the multiprover circuit types from a base type
pub(crate) fn build_multiprover_circuit_types(
    mpc_type: &ItemStruct,
    base_type: &ItemStruct,
) -> TokenStream2 {
    // Build the variable and commitment types and the trait implementations
    // for committing to the base type in an MPC circuit
    build_base_type_impl(mpc_type, base_type)
}

/// Build an `impl MultiproverCircuitBaseType` block
fn build_base_type_impl(mpc_type: &ItemStruct, base_type: &ItemStruct) -> TokenStream2 {
    let base_generics = mpc_type.generics.clone();
    let where_clause = mpc_type.generics.where_clause.clone();

    let trait_name = path_from_ident(&new_ident(MULTIPROVER_BASE_TRAIT_NAME));
    let mpc_type_name = ident_with_generics(&mpc_type.ident, base_generics.clone());

    let base_type_associated_name = new_ident(MULTIPROVER_BASE_TYPE_ASSOCIATED_NAME);
    let var_type_associated_name = new_ident(VAR_TYPE_ASSOCIATED_NAME);

    let derived_base_type_ident = ident_with_generics(
        &ident_strip_prefix(&mpc_type.ident.to_string(), MPC_TYPE_PREFIX),
        base_generics.clone(),
    );

    let base_ident = mpc_type.ident.to_string();
    let var_type_ident = ident_strip_prefix(
        &ident_with_suffix(&base_ident, VAR_SUFFIX).to_string(),
        MPC_TYPE_PREFIX,
    );
    let derived_var_type_ident = ident_with_generics(&var_type_ident, base_generics.clone());

    // Maybe build a `create_shared_witness method`
    let mut create_shared_witness_method = TokenStream2::new();
    if requires_proof_linking(base_type) {
        create_shared_witness_method = build_create_shared_witness_method(mpc_type, base_type);
    }

    let impl_block: ItemImpl = parse_quote! {
        impl #base_generics #trait_name for #mpc_type_name
            #where_clause
        {
            type #base_type_associated_name = #derived_base_type_ident;
            type #var_type_associated_name = #derived_var_type_ident;

            #create_shared_witness_method
        }
    };
    impl_block.to_token_stream()
}
