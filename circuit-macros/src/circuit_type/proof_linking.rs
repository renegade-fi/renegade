//! Helpers for generating proof linking helper methods, i.e. implementations of
//! variable allocation that use proof linking groups
//!
//! Linking groups are specified by annotating fields in a struct with the
//! `link_groups` attribute. For example, the following struct will
//! allocate `field1` into groups `group1` and `group2` and `field2` into group
//! `group3`:
//!
//! ```
//! #[circuit-type(singleprover)]
//! struct MyCircuit {
//!    #[link_groups = "group1, group2")]
//!    field1: Scalar,
//!    #[link_groups = "group3"]
//!    field2: Scalar,
//! }

use proc_macro2::{Literal, TokenStream, TokenTree};
use quote::quote;
use syn::{
    parse_quote,
    punctuated::Punctuated,
    token::{Colon, Comma},
    Attribute, Expr, Field, FieldValue, ItemStruct, LitStr, Member,
};

use crate::circuit_type::{
    new_ident,
    singleprover_circuit_types::{CIRCUIT_BASE_TYPE_TRAIT_NAME, VAR_TYPE_ASSOCIATED_NAME},
};

/// The link group attribute name
const LINKING_GROUP_IDS_ATTR: &str = "link_groups";

/// The method used to create a witness
const CREATE_WITNESS_METHOD_NAME: &str = "create_witness";

/// Returns whether the given type uses any proof linking groups
///
/// This is done by checking whether any of the fields in the type have the
/// `link_groups` attribute
pub fn requires_proof_linking(base_type: &ItemStruct) -> bool {
    base_type.fields.iter().any(|f| f.attrs.iter().any(is_link_group_attr))
}

/// Returns a copy of the target struct with link group attributes removed
pub fn remove_link_group_attributes(base_type: &ItemStruct) -> ItemStruct {
    let mut res = base_type.clone();
    res.fields.iter_mut().for_each(|f| {
        f.attrs.retain(|a| !is_link_group_attr(a));
    });

    res
}

/// Generate a `create_witness` method that allocates appropriate fields into
/// their proof linking groups
pub fn build_create_witness_method(base_type: &ItemStruct) -> TokenStream {
    // For each field, construct a list of link group ids and allocate the field
    // into the circuit with these group ids
    let var_type = new_ident(VAR_TYPE_ASSOCIATED_NAME);
    let circuit_base_type = new_ident(CIRCUIT_BASE_TYPE_TRAIT_NAME);

    let mut fields_expr: Punctuated<FieldValue, Comma> = Punctuated::new();
    for field in base_type.fields.iter().cloned() {
        let ident = field.ident.clone().expect("only named fields are supported");
        let field_type = field.ty.clone();

        // This block expression represents the allocation of the current field into the
        // constraint system
        let group_expr = parse_linking_groups_for_field(&field);
        let field_expr: Expr = parse_quote! {{
            let groups = #group_expr;
            let vars = self.#ident
                .to_scalars()
                .into_iter()
                .map(|s| cs.create_variable_with_link_groups(s.inner(), &groups).unwrap())
                .collect::<Vec<_>>();

            <#field_type as #circuit_base_type>::#var_type::from_vars(&mut vars.into_iter(), cs)
        }};

        fields_expr.push(FieldValue {
            attrs: Vec::new(),
            member: Member::Named(ident),
            colon_token: Some(Colon::default()),
            expr: field_expr,
        });
    }

    let method_name = new_ident(CREATE_WITNESS_METHOD_NAME);
    let var_type = new_ident(VAR_TYPE_ASSOCIATED_NAME);

    quote! {
        fn #method_name(&self, cs: &mut PlonkCircuit) -> Self::#var_type {
            Self::#var_type {
                #fields_expr
            }
        }
    }
}

/// Returns whether an attribute is a `linking_group_ids` attribute
fn is_link_group_attr(attr: &Attribute) -> bool {
    // Search the path segments
    for seg in attr.path.segments.iter() {
        if seg.ident == LINKING_GROUP_IDS_ATTR {
            return true;
        }
    }

    false
}

/// Parse a linking group expr of the form `["group1", "group2", ...]`
///
/// This allows us to quickly assign a field into groups
fn parse_linking_groups_for_field(field: &Field) -> Expr {
    for attr in field.attrs.iter() {
        if is_link_group_attr(attr) {
            return parse_linking_groups(attr);
        }
    }

    // If no attribute was found, the field is a member of no link groups
    parse_quote! { [] }
}

/// Parse a list of groups from a `link_groups` attribute
fn parse_linking_groups(attr: &Attribute) -> Expr {
    // Expected format is an "=" followed by a string literal that we can parse
    // directly, i.e. `link_groups = "group1, group2, group3"`
    let mut token_iter = attr.tokens.clone().into_iter();

    // Validate that the next token is an "="
    let next = token_iter.next().expect("expected '='");
    match next {
        TokenTree::Punct(punct) => {
            assert_eq!(punct.as_char(), '=', "expected '='");
        },
        _ => panic!("expected '='"),
    }

    // Pull a string literal and parse groups from this directly
    let groups = match token_iter.next().expect("expected string literal") {
        TokenTree::Literal(lit) => parse_linking_groups_from_str(&lit),
        _ => panic!("expected string literal"),
    };

    // Format into a slice literal expression
    let literals: Vec<LitStr> = groups.iter().map(|s| parse_quote!(#s)).collect();
    parse_quote! { [#(#literals.to_string()),*] }
}

/// Parse link groups from a string literal
fn parse_linking_groups_from_str(lit: &Literal) -> Vec<String> {
    // A string literal will come with an extra pair of quotes surrounding it so
    // remove those and trim whitespace for parsing
    let s = lit.to_string();
    let trimmed = s.trim_matches('"').replace(' ', "");

    trimmed.split(',').map(|s| s.to_string()).collect()
}
