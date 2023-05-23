//! Groups type derivations for secret share types

use proc_macro2::TokenStream as TokenStream2;
use quote::ToTokens;
use syn::{
    parse_quote,
    punctuated::Punctuated,
    token::{Comma, Semi},
    Attribute, FieldValue, Generics, ItemImpl, ItemStruct, Stmt,
};

use crate::circuit_type::{
    build_modified_struct_from_associated_types, ident_strip_suffix, ident_with_suffix, new_ident,
    path_from_ident,
};

use super::{
    build_base_type_impl, linkable_types::build_linkable_types,
    singleprover_circuit_types::build_circuit_types,
};

/// The trait name of the base type
const SECRET_SHARE_BASE_TYPE_TRAIT_NAME: &str = "SecretShareBaseType";
/// The associated constant of the secret share type on the base type
const SHARE_TYPE_ASSOCIATED_NAME: &str = "ShareType";
/// The trait name of the secret share type
const SECRET_SHARE_TYPE_TRAIT_NAME: &str = "SecretShareType";
/// The associated constant of the base type on the secret share type
const SECRET_SHARE_BASE_ASSOCIATED_NAME: &str = "Base";

/// The suffix appended to secret share types
const SHARE_SUFFIX: &str = "Share";

/// Build the secret share types for the base type
pub fn build_secret_share_types(base_type: &ItemStruct) -> TokenStream2 {
    // Implement `SecretShareBaseType`
    let mut res = build_secret_share_base_type_impl(base_type);
    res.extend(build_secret_share_type(base_type));

    res
}

/// Build the `impl SecretShareBaseType` block
fn build_secret_share_base_type_impl(base_type: &ItemStruct) -> TokenStream2 {
    let trait_name = new_ident(SECRET_SHARE_BASE_TYPE_TRAIT_NAME);
    let base_struct_name = base_type.ident.clone();

    let associated_type_name = new_ident(SHARE_TYPE_ASSOCIATED_NAME);
    let derived_share_type_name = ident_with_suffix(&base_struct_name.to_string(), SHARE_SUFFIX);

    let impl_block: ItemImpl = parse_quote! {
        impl #trait_name for #base_struct_name {
            type #associated_type_name = #derived_share_type_name;
        }
    };
    impl_block.to_token_stream()
}

/// Build the secret share type
fn build_secret_share_type(base_type: &ItemStruct) -> TokenStream2 {
    // Build the derived struct
    let new_name = ident_with_suffix(&base_type.ident.to_string(), SHARE_SUFFIX);
    let derive_clone: Attribute = parse_quote!(#[derive(Clone)]);

    let base_type_trait = path_from_ident(new_ident(SECRET_SHARE_BASE_TYPE_TRAIT_NAME));
    let associated_share_name = new_ident(SHARE_TYPE_ASSOCIATED_NAME);

    let secret_share_type = build_modified_struct_from_associated_types(
        base_type,
        new_name,
        vec![derive_clone],
        Generics::default(),
        base_type_trait,
        path_from_ident(associated_share_name),
    );

    // Implement addition between share types
    let mut res = build_addition_impl(base_type);

    // Implement `BaseType` for the new type
    res.extend(build_base_type_impl(&secret_share_type));

    // Implement `SecretShareType` for the new type
    res.extend(build_secret_share_type_impl(&secret_share_type));

    // Build singleprover circuit types for the secret shares
    res.extend(build_circuit_types(&secret_share_type));

    // Build linkable commitment types for the secret shares
    res.extend(build_linkable_types(
        &secret_share_type,
        false, /* include_multiprover */
    ));
    res.extend(secret_share_type.to_token_stream());

    res
}

/// Build an addition implementation between secret share types
///
/// This is equivalent to recovering the plaintext by adding two secret shares, hence the
/// addition target is the base type
fn build_addition_impl(base_type: &ItemStruct) -> TokenStream2 {
    let secret_share_type_name = ident_with_suffix(&base_type.ident.to_string(), SHARE_SUFFIX);
    let base_type_name = base_type.ident.clone();

    let mut field_exprs: Punctuated<FieldValue, Comma> = Punctuated::new();
    for field in base_type.fields.iter() {
        let field_ident = field.ident.clone().unwrap();
        field_exprs.push(parse_quote! {
            #field_ident: self.#field_ident + rhs.#field_ident
        });
    }

    // Implementation adds each field element-wise
    let impl_block: ItemImpl = parse_quote! {
        impl Add<#secret_share_type_name> for #secret_share_type_name {
            type Output = #base_type_name;

            fn add(self, rhs: #secret_share_type_name) -> Self::Output {
                #base_type_name {
                    #field_exprs
                }
            }
        }
    };
    impl_block.to_token_stream()
}

/// Build an `impl SecretShareType` block for the secret share type
fn build_secret_share_type_impl(secret_share_type: &ItemStruct) -> TokenStream2 {
    let trait_name = new_ident(SECRET_SHARE_TYPE_TRAIT_NAME);
    let secret_share_type_name = secret_share_type.ident.clone();

    // The associated base type
    let base_type_associated_name = new_ident(SECRET_SHARE_BASE_ASSOCIATED_NAME);
    let base_type_name = ident_strip_suffix(&secret_share_type_name.to_string(), SHARE_SUFFIX);

    let mut blind_stmts: Punctuated<Stmt, Semi> = Punctuated::new();
    let mut unblind_stmts: Punctuated<Stmt, Semi> = Punctuated::new();
    for field in secret_share_type.fields.iter() {
        let field_ident = field.ident.clone();
        blind_stmts.push(parse_quote!(self.#field_ident.blind(blinder);));
        unblind_stmts.push(parse_quote!(self.#field_ident.unblind(blinder);));
    }

    let impl_block: ItemImpl = parse_quote! {
        impl #trait_name for #secret_share_type_name {
            type #base_type_associated_name = #base_type_name;

            fn blind(&mut self, blinder: Scalar) {
                #blind_stmts
            }

            fn unblind(&mut self, blinder: Scalar) {
                #unblind_stmts
            }
        }
    };
    impl_block.to_token_stream()
}
