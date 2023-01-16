//! Groups proc-macro macro definitions used in the circuits crate

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{
    parse_quote,
    punctuated::Punctuated,
    token::{Comma, Paren},
    Attribute, Expr, ExprCall, FnArg, ItemFn, Pat, Signature,
};

/// The feature flag that enables tracing via these macros
#[allow(dead_code)]
const TRACER_FEATURE_FLAG: &str = "bench";
/// The suffix appended to the trace target implementation to give it a different signature
/// from its trampoline
const TRACE_TARGET_SUFFIX: &str = "impl";

/// A macro that wraps the target function in a kretprobe inspired trampoline function
/// and traces statistics through the target's execution
///
/// This macro expands to two implementations of the trampoline which are conditionally
/// compiled between. When the `bench` feature flag is active, the full-fledged tracing
/// implementation is compiled into the trampoline. This implementation collects circuit
/// statistics at the gadget scope.
///
/// When the `bench` feature flag is not active, the trampoline implementation is a simple
/// passthrough -- calling the target function directly. Concretely, `rustc` will expand this
/// macro to the passthrough and then fold the trampoline into the caller during optimization.
/// An example of such a conditionally compiled wrapper is: https://godbolt.org/z/jj4fz75Yr
/// Notice that when the `bench` feature is disabled, the intermediate call is removed
#[proc_macro_attribute]
pub fn circuit_trace(_: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemFn = syn::parse(item).unwrap();
    circuit_trace_impl(ast)
}

/// Implementation of the circuit tracer, parses the token stream and defines the two
/// trampoline function implementation
fn circuit_trace_impl(target_fn: ItemFn) -> TokenStream {
    let mut out_tokens = TokenStream2::default();

    // Build the trampoline implementations
    let (inactive_impl, active_impl) = build_trampoline_impls(&target_fn);
    out_tokens.extend(inactive_impl.to_token_stream());
    out_tokens.extend(active_impl.to_token_stream());

    // Modify the target function to have a different signature from the trampoline
    out_tokens.extend(modify_target_fn(&target_fn).to_token_stream());

    out_tokens.into()
}

/// Build both trampoline implementations (active and inactive) and return their parsed
/// syntax-tree types
fn build_trampoline_impls(target_fn: &ItemFn) -> (ItemFn, ItemFn) {
    (
        build_inactive_trampoline(target_fn),
        build_active_trampoline(target_fn),
    )
}

/// Build the trampoline implementation that actively traces the target, gated behind the
/// "bench" feature flag
fn build_active_trampoline(target_fn: &ItemFn) -> ItemFn {
    // In the active trampoline, we keep the signature and visibility of the target the same
    // The changes are to add an attribute #[cfg(feature = "bench")] and change the body to:
    //  1. Add a prelude that sets up trace metrics and scope
    //  2. Call the target method
    //  3. Add an epilog to close trace metrics and scope
    let mut out_fn = target_fn.clone();

    // Add the conditional compilation attr
    let attr: Attribute = parse_quote! {
        #[cfg(feature = #TRACER_FEATURE_FLAG)]
    };
    out_fn.attrs.push(attr);

    // Modify the body to pass-through to the trace target
    let call_expr = build_target_invocation(&out_fn.sig);
    out_fn.block = parse_quote!({println!("active trampoline"); #call_expr});

    out_fn
}

/// Build the trampoline implementation that does not trace and simply passes through to
/// the target function. This implementation is active when the `bench` feature flag is disabled
fn build_inactive_trampoline(target_fn: &ItemFn) -> ItemFn {
    // In the inactive trampoline, we keep the signature and visibility of the target the same
    // The changes are to add an attribute #[cfg(not(feature = "bench"))] and change the body to call
    // the target
    let mut out_fn = target_fn.clone();

    // Add the conditional compilation attr
    let attr: Attribute = parse_quote! {
        #[cfg(not(feature = #TRACER_FEATURE_FLAG))]
    };
    out_fn.attrs.push(attr);

    // Modify the body to pass-through to the trace target
    let call_expr = build_target_invocation(&out_fn.sig);
    out_fn.block = parse_quote!({println!("inactive trampoline"); #call_expr});

    out_fn
}

/// Build the argument list for the target function from the trampoline function's signature
fn build_target_invocation(trampoline_sig: &Signature) -> ExprCall {
    let mut args = Vec::new();
    let mut parsed_receiver = None;

    for input_arg in trampoline_sig.inputs.clone().into_iter() {
        match input_arg {
            FnArg::Typed(type_pattern) => {
                match *type_pattern.pat {
                    Pat::Ident(pattern) => args.push(pattern.ident),
                    _ => {}
                };
            }
            FnArg::Receiver(receiver) => parsed_receiver = Some(receiver),
        }
    }

    // Build the expression resolving to the function; using Self:: prelude if the
    let target_fn_name = get_modified_target_name(trampoline_sig);
    let function = if parsed_receiver.is_some() {
        // If a receiver was found (i.e. this is a call with &self) expand the macro to
        // a MethodCallExpr
        Expr::Path(parse_quote!(Self::#target_fn_name))
    } else {
        Expr::Path(parse_quote!(#target_fn_name))
    };

    // Build the argument expression passed to the function call
    let mut punctuated_args: Punctuated<Expr, Comma> = Punctuated::new();
    if let Some(receiver) = parsed_receiver {
        punctuated_args.push(parse_quote!(#receiver))
    }
    for arg in args.into_iter() {
        punctuated_args.push(parse_quote!(#arg))
    }

    ExprCall {
        attrs: Vec::new(),
        func: Box::new(function),
        paren_token: Paren::default(),
        args: punctuated_args,
    }
}

/// Build the modified target function
///
/// The tracing target needs to be renamed so that calls to `fn_name` will route through the
fn modify_target_fn(target_fn: &ItemFn) -> ItemFn {
    let mut modified_target = target_fn.clone();
    modified_target.sig.ident = get_modified_target_name(&target_fn.sig);

    modified_target
}

/// Get the name of the modified target fn given the unmodified signature
fn get_modified_target_name(sig: &Signature) -> Ident {
    let modified_name = format!("{}_{}", sig.ident.to_string(), TRACE_TARGET_SUFFIX);
    Ident::new(&modified_name, Span::call_site())
}
