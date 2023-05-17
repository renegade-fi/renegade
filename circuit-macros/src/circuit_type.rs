//! Macro implementation of the `circuit_type` macro that defines associated types and conversions
//! between them for an application level base type

mod singleprover_circuit;

use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{
    parse::Parser,
    parse_quote,
    punctuated::Punctuated,
    token::{Brace, Colon, Comma},
    Attribute, Expr, Field, FieldValue, Fields, FieldsNamed, Generics, ItemImpl, ItemStruct,
    Member, Result, Token, Type, TypePath,
};

use self::singleprover_circuit::build_circuit_types;

/// The trait name for the base type that all other types are derived from
const BASE_TYPE_TRAIT_NAME: &str = "BaseType";

/// The name of the method that converts a serialized scalar iterator to a base type
const FROM_SCALARS_METHOD_NAME: &str = "from_scalars";
/// The name of the method that converts a base type to a serialized vector of scalars
const TO_SCALARS_METHOD_NAME: &str = "to_scalars";
/// The identifier of the `Scalar` type
const SCALAR_TYPE_IDENT: &str = "Scalar";

/// The flag indicating the expansion should include a single prover circuit type definition
/// for the base type
const ARG_CIRCUIT_TYPE: &str = "singleprover_circuit";

/// The arguments to the `circuit_trace` macro
#[derive(Default)]
pub(crate) struct MacroArgs {
    /// Whether or not to allocate a circuit type for the struct
    pub build_circuit_types: bool,
}

pub(crate) fn parse_macro_args(args: TokenStream) -> Result<MacroArgs> {
    let mut macro_args = MacroArgs::default();
    let parsed_args =
        Punctuated::<Ident, Comma>::parse_terminated.parse2(TokenStream2::from(args))?;

    for arg in parsed_args.iter() {
        match arg.to_string().as_str() {
            ARG_CIRCUIT_TYPE => macro_args.build_circuit_types = true,
            unknown => panic!("received unexpected argument {unknown}"),
        }
    }

    Ok(macro_args)
}

// -------------------
// | Core Macro Impl |
// -------------------

// Implementation of the type derivation macro
pub(crate) fn circuit_type_impl(target_struct: ItemStruct, macro_args: MacroArgs) -> TokenStream {
    // Copy the existing struct into the result
    let mut out_tokens = TokenStream2::default();
    out_tokens.extend(target_struct.to_token_stream());

    // Build the implementation of the `BaseType` trait
    out_tokens.extend(build_base_type_impl(&target_struct));

    // Parse info out of the base struct
    if macro_args.build_circuit_types {
        let circuit_type_tokens = build_circuit_types(&target_struct);
        out_tokens.extend(circuit_type_tokens);
    }

    out_tokens.into()
}

// ---------------------------
// | BaseType Implementation |
// ---------------------------

fn build_base_type_impl(base_type: &ItemStruct) -> TokenStream2 {
    let trait_ident = Ident::new(BASE_TYPE_TRAIT_NAME, Span::call_site());
    let base_type_ident = base_type.ident.clone();

    let from_scalars_impl = build_deserialize_method(
        Ident::new(FROM_SCALARS_METHOD_NAME, Span::call_site()),
        Ident::new(SCALAR_TYPE_IDENT, Span::call_site()),
        trait_ident.clone(),
        base_type,
    );

    let to_scalars_impl = build_serialize_method(
        Ident::new(TO_SCALARS_METHOD_NAME, Span::call_site()),
        Ident::new(SCALAR_TYPE_IDENT, Span::call_site()),
        base_type,
    );

    let impl_block: ItemImpl = parse_quote! {
        impl #trait_ident for #base_type_ident {
            #from_scalars_impl
            #to_scalars_impl
        }
    };
    impl_block.to_token_stream()
}

// -----------
// | Helpers |
// -----------

/// Implements a serialization function that looks like
///     fn #method_name(self) -> Vec<#type> {
///         vec![self.field1, self.field2, ...]
///     }
fn build_serialize_method(
    method_name: Ident,
    target_type: Ident,
    self_struct: &ItemStruct,
) -> TokenStream2 {
    let mut serialize_expr = Punctuated::<Expr, Comma>::new();
    for field in self_struct.fields.iter().cloned() {
        let field_ident = field.ident;
        serialize_expr.push(parse_quote!(self.#field_ident));
    }

    let body: Expr = parse_quote!(vec![#serialize_expr]);
    parse_quote! {
        fn #method_name(self) -> Vec<#target_type> {
            #body
        }
    }
}

/// Implements a deserialization function for a trait that looks like the following
///     fn #method_name<I: Iterator<Item = #from_type>>(i: &mut I) -> Self {
///         Self { field1: i.next().unwrap(), field2: , ... }
///     }
fn build_deserialize_method(
    method_name: Ident,
    from_type: Ident,
    trait_ident: Ident,
    self_struct: &ItemStruct,
) -> TokenStream2 {
    let mut fields_expr: Punctuated<FieldValue, Comma> = Punctuated::new();
    for field in self_struct.fields.iter().cloned() {
        let ident = field.ident.expect("only named fields supported");
        let field_type = field.ty;

        // The parse field expr recursively calls `#method_name` on the field type
        let parse_field_expr: Expr = parse_quote! {
            <#field_type as #trait_ident>::#method_name(i)
        };

        fields_expr.push(FieldValue {
            attrs: Vec::new(),
            member: Member::Named(ident),
            colon_token: Some(Colon::default()),
            expr: parse_field_expr,
        });
    }

    parse_quote! {
        fn #method_name<I: Iterator<Item = #from_type>>(i: &mut I) -> Self {
            Self {
                #fields_expr
            }
        }
    }
}

/// Build a replica of the given struct with the given modifications, using an
/// implemented trait's associated type as the new type for each field
fn build_modified_struct_from_associated_types(
    base_type: &ItemStruct,
    new_name: Ident,
    attributes: Vec<Attribute>,
    type_derivation_trait_ident: Ident,
    associated_type_ident: Ident,
) -> ItemStruct {
    // Build the fields fo the var struct
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

            Field {
                vis: f.vis.clone(),
                attrs: Vec::new(),
                ident: name,
                colon_token: f.colon_token,
                ty: Type::Path(type_path),
            }
        })
        .collect_vec();

    let mut named = Punctuated::<Field, Token![,]>::new();
    for field in new_fields.into_iter() {
        named.push(field);
    }

    let named_fields = FieldsNamed {
        brace_token: Brace::default(),
        named,
    };

    ItemStruct {
        attrs: attributes,
        vis: base_type.vis.clone(),
        struct_token: Token![struct](Span::call_site()),
        ident: new_name,
        generics: Generics::default(),
        fields: Fields::Named(named_fields),
        semi_token: None,
    }
}
