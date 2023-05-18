//! Type definitions and trait implementations for multi-prover ZK circuits

use proc_macro2::TokenStream as TokenStream2;
use syn::{token::Token, ItemStruct};

pub(crate) fn build_multiprover_circuit_types(base_type: &ItemStruct) -> TokenStream2 {
    // Build the variable and commitment types and the trait implementations
    // for committing to the base type in an MPC circuit
    let mut res = build_authenticated_var_type(base_type);
    res.extend(build_authenticated_comm_type(base_type));

    res
}

fn build_authenticated_var_type(base_type: &ItemStruct) -> TokenStream2 {
    unimplemented!()
}

fn build_authenticated_comm_type(base_type: &ItemStruct) -> TokenStream2 {
    unimplemented!()
}
