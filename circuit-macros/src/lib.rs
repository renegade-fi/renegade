//! Defines macros used in the `circuits` crate; macros must be defined in a
//! separate crate
#![deny(clippy::missing_docs_in_private_items)]

use proc_macro::TokenStream;
use syn::{ItemFn, ItemStruct};

mod circuit_trace;
mod circuit_type;

// -----------
// | Tracing |
// -----------

/// A macro that wraps the target function in a kretprobe inspired trampoline
/// function and traces statistics through the target's execution
///
/// This macro expands to two implementations of the trampoline which are
/// conditionally compiled between. When the `bench` feature flag is active, the
/// full-fledged tracing implementation is compiled into the trampoline. This
/// implementation collects circuit statistics at the gadget scope.
///
/// When the `bench` feature flag is not active, the trampoline implementation
/// is a simple passthrough -- calling the target function directly. Concretely,
/// `rustc` will expand this macro to the passthrough and then fold the
/// trampoline into the caller during optimization. An example of such a conditionally compiled wrapper is: https://godbolt.org/z/jj4fz75Yr
/// Notice that when the `bench` feature is disabled, the intermediate call is
/// removed
///
/// The tracer supports the following metrics:
///     - Number of constraints generated
///     - Number of multipliers allocated
///     - Constraint generation latency
/// To enable a metric on a target add it to the arguments in the macro, for
/// example, to enable all metrics one might write the following
///     #[circuit_trace(n_constraints, n_multipliers, latency)]
///     fn target() { }
#[proc_macro_attribute]
pub fn circuit_trace(args: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemFn = syn::parse(item).unwrap();
    let macro_args = circuit_trace::parse_macro_args(args).unwrap();

    circuit_trace::circuit_trace_impl(ast, macro_args)
}

// ---------
// | Types |
// ---------

/// A macro that defines associated circuit types, and conversions between them
/// for a base type satisfying the appropriate structure
/// Check [`circuit_type::MacroArgs`] for details on how this macro is
/// configured
#[proc_macro_attribute]
pub fn circuit_type(args: TokenStream, item: TokenStream) -> TokenStream {
    let ast: ItemStruct = syn::parse(item).unwrap();
    let macro_args = circuit_type::parse_macro_args(args).unwrap();

    circuit_type::circuit_type_impl(ast, macro_args)
}
