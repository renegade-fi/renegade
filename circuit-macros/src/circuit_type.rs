//! Macro implementation of the `circuit_type` macro that defines associated types and conversions
//! between them for an application level base type

mod linkable_types;
mod mpc_types;
mod multiprover_circuit_types;
mod secret_share_types;
mod singleprover_circuit_types;

use itertools::Itertools;
use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{
    parse::Parser,
    parse_quote,
    punctuated::Punctuated,
    token::{Brace, Colon, Comma},
    Attribute, Expr, Field, FieldValue, Fields, FieldsNamed, Generics, ItemFn, ItemImpl,
    ItemStruct, Member, Path, Result, Stmt, Token, Type, TypePath,
};

use self::{
    linkable_types::build_linkable_types, mpc_types::build_mpc_types,
    multiprover_circuit_types::build_multiprover_circuit_types,
    secret_share_types::build_secret_share_types, singleprover_circuit_types::build_circuit_types,
};

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
/// The flag indicating the expansion should include types for an MPC circuit
const ARG_MPC_TYPE: &str = "mpc";
/// The flag indicating the expansion should include types for a multiprover circuit
const ARG_MULTIPROVER_TYPE: &str = "multiprover_circuit";
/// The flag indicating the expansion should include a proof-linkable type
const ARG_LINKABLE_TYPE: &str = "linkable";
/// The flag indicating the expansion should include multiprover linkable types
const ARG_MULTIPROVER_LINKABLE_TYPES: &str = "multiprover_linkable";
/// The flag indicating the expansion should include secret share types
const ARG_SHARE_TYPE: &str = "secret_share";

/// The arguments to the `circuit_trace` macro
#[derive(Default)]
pub(crate) struct MacroArgs {
    /// Whether or not to allocate a circuit type for the struct
    pub build_circuit_types: bool,
    /// Whether or not to allocate linkable commitment types for the struct
    pub build_linkable_types: bool,
    /// Whether or not to allocate MPC circuit types for the struct
    pub build_mpc_types: bool,
    /// Whether or not to allocate multiprover circuit types for the struct
    pub build_mulitprover_types: bool,
    /// Whether or not to allocate multiprover linkable circuit types for the struct
    pub build_multiprover_linkable_types: bool,
    /// Whether or not to allocate secret share types for the struct
    pub build_secret_share_types: bool,
}

impl MacroArgs {
    /// Validate the argument combinations
    pub fn validate(&self) {
        // A multiprover type must also be a base circuit type
        if self.build_mulitprover_types {
            assert!(
                self.build_circuit_types,
                "multiprover circuit type requires singleprover circuit type"
            );
        }

        // A linkable type also requires a circuit base type to be defined
        if self.build_linkable_types {
            assert!(
                self.build_circuit_types,
                "linkable types require a circuit base type to implement"
            )
        }

        // A multiprover linkable type must also be linkable and a circuit base type
        if self.build_multiprover_linkable_types {
            assert!(
                self.build_circuit_types && self.build_linkable_types,
                "multiprover linkable types require both circuit base type and base linkable types"
            )
        }

        // A secret share type requires the base type be a single-prover circuit type
        if self.build_secret_share_types {
            assert!(
                self.build_circuit_types,
                "secret share types require single-prover circuit types"
            )
        }
    }
}

/// Parse macro args from the invocation details
pub(crate) fn parse_macro_args(args: TokenStream) -> Result<MacroArgs> {
    let mut macro_args = MacroArgs::default();
    let parsed_args =
        Punctuated::<Ident, Comma>::parse_terminated.parse2(TokenStream2::from(args))?;

    for arg in parsed_args.iter() {
        match arg.to_string().as_str() {
            ARG_CIRCUIT_TYPE => macro_args.build_circuit_types = true,
            ARG_LINKABLE_TYPE => macro_args.build_linkable_types = true,
            ARG_MPC_TYPE => macro_args.build_mpc_types = true,
            ARG_MULTIPROVER_TYPE => macro_args.build_mulitprover_types = true,
            ARG_MULTIPROVER_LINKABLE_TYPES => macro_args.build_multiprover_linkable_types = true,
            ARG_SHARE_TYPE => macro_args.build_secret_share_types = true,
            unknown => panic!("received unexpected argument {unknown}"),
        }
    }

    macro_args.validate();
    Ok(macro_args)
}

// -------------------
// | Core Macro Impl |
// -------------------

/// Implementation of the type derivation macro
pub(crate) fn circuit_type_impl(target_struct: ItemStruct, macro_args: MacroArgs) -> TokenStream {
    // Copy the existing struct into the result
    let mut out_tokens = TokenStream2::default();
    out_tokens.extend(target_struct.to_token_stream());

    // Build the implementation of the `BaseType` trait
    out_tokens.extend(build_base_type_impl(&target_struct));

    // Build singleprover circuit types
    if macro_args.build_circuit_types {
        let circuit_type_tokens = build_circuit_types(&target_struct);
        out_tokens.extend(circuit_type_tokens);
    }

    // Build MPC types
    if macro_args.build_mpc_types {
        let mpc_type_tokens = build_mpc_types(&target_struct);
        out_tokens.extend(mpc_type_tokens);
    }

    // Build Multiprover circuit types
    if macro_args.build_mulitprover_types {
        let multiprover_type_tokens = build_multiprover_circuit_types(&target_struct);
        out_tokens.extend(multiprover_type_tokens)
    }

    // Build the commitment-linkable type
    if macro_args.build_linkable_types {
        let linkable_type_tokens =
            build_linkable_types(&target_struct, macro_args.build_multiprover_linkable_types);
        out_tokens.extend(linkable_type_tokens);
    }

    // Build secret share types
    if macro_args.build_secret_share_types {
        let secret_share_type_tokens = build_secret_share_types(&target_struct);
        out_tokens.extend(secret_share_type_tokens);
    }

    out_tokens.into()
}

// ---------------------------
// | BaseType Implementation |
// ---------------------------

/// Build the `impl BaseType` block
fn build_base_type_impl(base_type: &ItemStruct) -> TokenStream2 {
    let trait_ident = new_ident(BASE_TYPE_TRAIT_NAME);
    let base_type_ident = base_type.ident.clone();
    let scalar_type_path = path_from_ident(new_ident(SCALAR_TYPE_IDENT));

    let from_scalars_impl = build_deserialize_method(
        Ident::new(FROM_SCALARS_METHOD_NAME, Span::call_site()),
        scalar_type_path.clone(),
        path_from_ident(trait_ident.clone()),
        base_type,
    );

    let to_scalars_impl = build_serialize_method(
        Ident::new(TO_SCALARS_METHOD_NAME, Span::call_site()),
        scalar_type_path,
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

/// A helper that specifies the default call site span for an Identifier
fn new_ident(name: &str) -> Ident {
    Ident::new(name, Span::call_site())
}

/// A helper that creates an identifier with the given prefix
fn ident_with_prefix(original: &str, prefix: &str) -> Ident {
    new_ident(&format!("{prefix}{original}"))
}

/// A helper to strip a prefix from an identifier and return a new identifier
fn ident_strip_prefix(original: &str, prefix: &str) -> Ident {
    let stripped = original.strip_prefix(prefix).unwrap_or(original);
    new_ident(stripped)
}

/// A helper that creates an identifier with the given suffix
fn ident_with_suffix(original: &str, suffix: &str) -> Ident {
    new_ident(&format!("{original}{suffix}"))
}

/// A helper to strip a suffix from an identifier and return a new identifier
fn ident_strip_suffix(original: &str, suffix: &str) -> Ident {
    let stripped = original.strip_suffix(suffix).unwrap_or(original);
    new_ident(stripped)
}

/// Convert a string to a `Path` syntax tree object representing a type path
fn str_to_path(s: &str) -> Path {
    path_from_ident(new_ident(s))
}

/// Convert an `Ident` directly into a `Path`
fn path_from_ident(identifier: Ident) -> Path {
    parse_quote!(#identifier)
}

/// Implements a serialization function that looks like
///     fn #method_name(self) -> Vec<#target_type> {
///         vec![self.field1, self.field2, ...]
///     }
fn build_serialize_method(
    method_name: Ident,
    target_type: Path,
    self_struct: &ItemStruct,
) -> TokenStream2 {
    let mut field_exprs: Vec<Stmt> = Vec::with_capacity(self_struct.fields.len());
    for field in self_struct.fields.iter().cloned() {
        let field_ident = field.ident;
        field_exprs.push(parse_quote! {
            res.extend(self.#field_ident.#method_name());
        });
    }

    let fn_impl: ItemFn = parse_quote! {
        fn #method_name(self) -> Vec<#target_type> {
            let mut res = Vec::new();
            #(#field_exprs)*

            res
        }
    };
    fn_impl.to_token_stream()
}

/// Implements a deserialization function for a trait that looks like the following
///     fn #method_name<I: Iterator<Item = #from_type>>(i: &mut I) -> Self {
///         Self { field1: i.next().unwrap(), field2: , ... }
///     }
fn build_deserialize_method(
    method_name: Ident,
    from_type: Path,
    trait_ident: Path,
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
    generics: Generics,
    type_derivation_trait_ident: Path,
    associated_type_ident: Path,
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
        generics,
        fields: Fields::Named(named_fields),
        semi_token: None,
    }
}
