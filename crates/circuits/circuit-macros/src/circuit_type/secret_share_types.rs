//! Groups type derivations for secret share types

use itertools::Itertools;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{
    Attribute, Field, Fields, FieldsNamed, ItemImpl, ItemStruct, Path, Type, TypePath, parse_quote,
    punctuated::Punctuated,
    token::{Brace, Comma},
};

use crate::circuit_type::{ident_strip_suffix, ident_with_suffix, new_ident, path_from_ident};

use super::{
    FROM_SCALARS_METHOD_NAME, SCALAR_TYPE_IDENT, TO_SCALARS_METHOD_NAME, build_base_type_impl,
    build_serde_methods, ident_with_generics, mpc_types::build_mpc_types,
    multiprover_circuit_types::VAR_SUFFIX, singleprover_circuit_types::build_circuit_types,
    str_to_path,
};

/// The trait name of the base type
const SECRET_SHARE_BASE_TYPE_TRAIT_NAME: &str = "SecretShareBaseType";
/// The associated constant of the secret share type on the base type
const SHARE_TYPE_ASSOCIATED_NAME: &str = "ShareType";
/// The trait name of the secret share type
const SECRET_SHARE_TYPE_TRAIT_NAME: &str = "SecretShareType";
/// The associated constant of the base type on the secret share type
const SECRET_SHARE_BASE_ASSOCIATED_NAME: &str = "Base";
/// The trait name of the secret share var trait
const SECRET_SHARE_VAR_TRAIT_NAME: &str = "SecretShareVarType";

/// The suffix appended to secret share types
const SHARE_SUFFIX: &str = "Share";

/// The attribute name for share-type rkyv field attributes
const SHARE_RKYV_ATTR: &str = "share_rkyv";

// ----------------------
// | Share Type Builder |
// ----------------------

/// Build the secret share types for the base type
pub fn build_secret_share_types(
    base_type: &ItemStruct,
    mpc: bool,
    serde: bool,
    rkyv: bool,
) -> TokenStream2 {
    // Implement `SecretShareBaseType`
    let mut res = build_secret_share_base_type_impl(base_type);
    res.extend(build_secret_share_type(base_type, mpc, serde, rkyv));

    res
}

/// Build the `impl SecretShareBaseType` block
fn build_secret_share_base_type_impl(base_type: &ItemStruct) -> TokenStream2 {
    let generics = base_type.generics.clone();
    let where_clause = base_type.generics.where_clause.clone();

    let trait_name = new_ident(SECRET_SHARE_BASE_TYPE_TRAIT_NAME);
    let base_struct_name = ident_with_generics(&base_type.ident.clone(), generics.clone());

    let associated_type_name = new_ident(SHARE_TYPE_ASSOCIATED_NAME);
    let derived_share_type_name = ident_with_generics(
        &ident_with_suffix(&base_type.ident.to_string(), SHARE_SUFFIX),
        generics.clone(),
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_name for #base_struct_name
            #where_clause
        {
            type #associated_type_name = #derived_share_type_name;
        }
    };
    impl_block.to_token_stream()
}

/// Build the secret share type
fn build_secret_share_type(
    base_type: &ItemStruct,
    mpc: bool,
    serde: bool,
    rkyv: bool,
) -> TokenStream2 {
    // Build the derived struct
    let new_name = ident_with_suffix(&base_type.ident.to_string(), SHARE_SUFFIX);

    // Build struct-level attributes
    let mut attributes = Vec::new();

    // Derive attribute
    let derive: Attribute = if rkyv {
        parse_quote!(#[derive(Clone, Debug, Eq, PartialEq, rkyv::Archive, rkyv::Deserialize, rkyv::Serialize)])
    } else {
        parse_quote!(#[derive(Clone, Debug, Eq, PartialEq)])
    };
    attributes.push(derive);

    // Add rkyv struct-level attribute if enabled
    if rkyv {
        attributes.push(parse_quote!(#[rkyv(derive(Debug))]));
    }

    let base_type_trait = path_from_ident(&new_ident(SECRET_SHARE_BASE_TYPE_TRAIT_NAME));
    let associated_share_name = new_ident(SHARE_TYPE_ASSOCIATED_NAME);

    let secret_share_type = build_share_struct_from_associated_types(
        base_type,
        new_name,
        attributes,
        base_type.generics.clone(),
        &base_type_trait,
        &path_from_ident(&associated_share_name),
        rkyv,
    );

    // Implement addition between share types
    let mut res = build_addition_impl(base_type);

    // Implement `BaseType` for the new type
    res.extend(build_base_type_impl(&secret_share_type));

    // Implement `SecretShareType` for the new type
    res.extend(build_secret_share_type_impl(&secret_share_type));

    // Build singleprover circuit types for the secret shares
    res.extend(build_circuit_types(&secret_share_type));
    res.extend(build_share_var_impl(&secret_share_type));

    // Build MPC and multiprover base types
    if mpc {
        res.extend(build_mpc_types(
            &secret_share_type,
            true, // multiprover
        ));
    }

    res.extend(secret_share_type.to_token_stream());

    // Implement serialization
    if serde {
        res.extend(build_serde_methods(
            &secret_share_type,
            &path_from_ident(&new_ident(SCALAR_TYPE_IDENT)),
            &new_ident(TO_SCALARS_METHOD_NAME),
            &new_ident(FROM_SCALARS_METHOD_NAME),
        ));
    }

    res
}

/// Build an addition implementation between secret share types
///
/// This is equivalent to recovering the plaintext by adding two secret shares,
/// hence the addition target is the base type
///
/// We explicitly dispatch to `add_shares` which is implementable generically.
/// The macro handles implementations on local traits, as their generic versions
/// are often not able to have `Add` implemented
fn build_addition_impl(base_type: &ItemStruct) -> TokenStream2 {
    let generics = base_type.generics.clone();
    let where_clause = base_type.generics.where_clause.clone();

    let secret_share_type_name = ident_with_generics(
        &ident_with_suffix(&base_type.ident.to_string(), SHARE_SUFFIX),
        generics.clone(),
    );

    let output_type_name = ident_with_generics(&base_type.ident, generics.clone());

    // Implementation calls out to the `add_shares`
    let impl_block: ItemImpl = parse_quote! {
        impl #generics Add<#secret_share_type_name> for #secret_share_type_name
            #where_clause
        {
            type Output = #output_type_name;

            fn add(self, rhs: #secret_share_type_name) -> Self::Output {
                self.add_shares(&rhs)
            }
        }
    };
    impl_block.to_token_stream()
}

/// Build an `impl SecretShareType` block for the secret share type
fn build_secret_share_type_impl(secret_share_type: &ItemStruct) -> TokenStream2 {
    let generics = secret_share_type.generics.clone();
    let where_clause = secret_share_type.generics.where_clause.clone();

    let trait_name = new_ident(SECRET_SHARE_TYPE_TRAIT_NAME);
    let secret_share_type_name = ident_with_generics(&secret_share_type.ident, generics.clone());

    // The associated base type
    let base_type_associated_name = new_ident(SECRET_SHARE_BASE_ASSOCIATED_NAME);
    let base_type_name = ident_with_generics(
        &ident_strip_suffix(&secret_share_type.ident.to_string(), SHARE_SUFFIX),
        generics.clone(),
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #generics #trait_name for #secret_share_type_name
            #where_clause
        {
            type #base_type_associated_name = #base_type_name;
        }
    };
    impl_block.to_token_stream()
}

/// Build an `impl SecretShareVarType` block
fn build_share_var_impl(secret_share_type: &ItemStruct) -> TokenStream2 {
    let generics = secret_share_type.generics.clone();
    let where_clause = secret_share_type.generics.where_clause.clone();

    let trait_name = str_to_path(SECRET_SHARE_VAR_TRAIT_NAME);
    let impl_generics = generics.clone();

    let var_type_name = ident_with_suffix(&secret_share_type.ident.to_string(), VAR_SUFFIX);
    let var_type_with_generics = ident_with_generics(&var_type_name, impl_generics.clone());

    let base_type_associated_name = new_ident(SECRET_SHARE_BASE_ASSOCIATED_NAME);
    let base_type_name = ident_with_suffix(
        &ident_strip_suffix(&secret_share_type.ident.to_string(), SHARE_SUFFIX).to_string(),
        VAR_SUFFIX,
    );
    let base_type_with_generics: Path = ident_with_generics(&base_type_name, generics.clone());

    let impl_block: ItemImpl = parse_quote! {
        impl #impl_generics #trait_name for #var_type_with_generics
            #where_clause
        {
            type #base_type_associated_name = #base_type_with_generics;
        }
    };
    impl_block.to_token_stream()
}

// ----------------------
// | Share Rkyv Helpers |
// ----------------------

/// Returns whether an attribute is a `share_rkyv` attribute
fn is_share_rkyv_attr(attr: &Attribute) -> bool {
    attr.path.segments.iter().any(|seg| seg.ident == SHARE_RKYV_ATTR)
}

/// Extract `#[share_rkyv(...)]` attributes from a field and convert them to
/// `#[rkyv(...)]` attributes for the share type
fn extract_share_rkyv_attrs(field: &Field) -> Vec<Attribute> {
    field
        .attrs
        .iter()
        .filter(|attr| is_share_rkyv_attr(attr))
        .map(|attr| {
            // Convert share_rkyv(...) to rkyv(...)
            let tokens = attr.tokens.clone();
            parse_quote!(#[rkyv #tokens])
        })
        .collect()
}

/// Remove `#[share_rkyv(...)]` attributes from a struct
///
/// These attributes should not appear in the output base type
pub fn remove_share_rkyv_attributes(base_type: &ItemStruct) -> ItemStruct {
    let mut res = base_type.clone();
    res.fields.iter_mut().for_each(|f| {
        f.attrs.retain(|a| !is_share_rkyv_attr(a));
    });
    res
}

// -----------
// | Helpers |
// -----------

/// Build a replica of the given struct with field types replaced by associated
/// types, and optionally transform `#[share_rkyv(...)]` attributes to
/// `#[rkyv(...)]`
fn build_share_struct_from_associated_types(
    base_type: &ItemStruct,
    new_name: Ident,
    attributes: Vec<Attribute>,
    generics: syn::Generics,
    type_derivation_trait_ident: &Path,
    associated_type_ident: &Path,
    include_share_rkyv_attrs: bool,
) -> ItemStruct {
    // Build the fields of the share struct
    let new_fields = base_type
        .fields
        .iter()
        .map(|f| {
            let name = f.ident.clone();
            let curr_type = f.ty.clone();

            // Construct the fully-qualified path type expression
            let base_trait = type_derivation_trait_ident.clone();
            let associated = associated_type_ident.clone();
            let type_path: TypePath = parse_quote!(
                <#curr_type as #base_trait>::#associated
            );

            // Extract share_rkyv attributes and convert to rkyv attributes if enabled
            let field_attrs =
                if include_share_rkyv_attrs { extract_share_rkyv_attrs(f) } else { Vec::new() };

            Field {
                vis: f.vis.clone(),
                attrs: field_attrs,
                ident: name,
                colon_token: f.colon_token,
                ty: Type::Path(type_path),
            }
        })
        .collect_vec();

    let mut named = Punctuated::<Field, Comma>::new();
    for field in new_fields.into_iter() {
        named.push(field);
    }

    let named_fields = FieldsNamed { brace_token: Brace::default(), named };

    ItemStruct {
        attrs: attributes,
        vis: base_type.vis.clone(),
        struct_token: syn::Token![struct](Span::call_site()),
        ident: new_name,
        generics,
        fields: Fields::Named(named_fields),
        semi_token: None,
    }
}
