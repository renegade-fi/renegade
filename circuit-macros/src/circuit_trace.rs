//! Groups proc-macro macro definitions used in the circuits crate

#![deny(missing_docs)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(unsafe_code)]

use proc_macro::TokenStream;
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::{quote, ToTokens};
use syn::{
    parse::Parser,
    parse_quote,
    punctuated::Punctuated,
    token::{Comma, Paren},
    Attribute, Expr, ExprCall, FnArg, ItemFn, Pat, Result, Signature, Visibility,
};

/// Argument given to enable tracing constraint generation latency
const ARG_CONSTRAINT_LATENCY: &str = "latency";
/// Argument given to enable tracing the number of constraints
const ARG_N_CONSTRAINTS: &str = "n_constraints";
/// Argument given to enable tracing the number of multipliers
const ARG_N_MULTIPLIERS: &str = "n_multipliers";
/// Argument passed to signal that the target is not an associated function
const ARG_NON_ASSOCIATED: &str = "non_associated";
/// The feature flag that enables tracing via these macros
#[allow(dead_code)]
const TRACER_FEATURE_FLAG: &str = "bench";
/// The suffix appended to the trace target implementation to give it a
/// different signature from its trampoline
const TRACE_TARGET_SUFFIX: &str = "impl";

/// Stores the macro arguments as to which metrics are enabled for a given
/// tracing target
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct MacroArgs {
    /// The number of constraints metric
    pub n_constraints: bool,
    /// The number of multiplier metric
    pub n_multipliers: bool,
    /// The constraint generation latency metric
    pub latency: bool,
    /// Flag indicating that the target is a not an associated function of some
    /// gadget type
    pub non_associated: bool,
}

impl MacroArgs {
    /// Returns true if all metrics are disabled for a given target
    pub fn all_disabled(&self) -> bool {
        !(self.n_constraints || self.n_multipliers || self.latency)
    }
}

/// Parse the arguments into a set of enabled features
pub(crate) fn parse_macro_args(args: TokenStream) -> Result<MacroArgs> {
    let mut macro_args = MacroArgs::default();
    let parsed_args =
        Punctuated::<Ident, Comma>::parse_terminated.parse2(TokenStream2::from(args))?;

    for arg in parsed_args.iter() {
        match arg.to_string().as_str() {
            ARG_CONSTRAINT_LATENCY => macro_args.latency = true,
            ARG_N_CONSTRAINTS => macro_args.n_constraints = true,
            ARG_N_MULTIPLIERS => macro_args.n_multipliers = true,
            ARG_NON_ASSOCIATED => macro_args.non_associated = true,
            _ => continue,
        }
    }

    Ok(macro_args)
}

/// Implementation of the circuit tracer, parses the token stream and defines
/// the two trampoline function implementation
pub(crate) fn circuit_trace_impl(target_fn: ItemFn, macro_args: MacroArgs) -> TokenStream {
    let mut out_tokens = TokenStream2::default();

    // Build the trampoline implementations
    let (inactive_impl, active_impl) = build_trampoline_impls(&target_fn, macro_args);
    out_tokens.extend(inactive_impl.to_token_stream());
    out_tokens.extend(active_impl.to_token_stream());

    // Modify the target function to have a different signature from the trampoline
    out_tokens.extend(modify_target_fn(&target_fn).to_token_stream());

    out_tokens.into()
}

/// Build both trampoline implementations (active and inactive) and return their
/// parsed syntax-tree types
fn build_trampoline_impls(target_fn: &ItemFn, macro_args: MacroArgs) -> (ItemFn, ItemFn) {
    (
        build_inactive_trampoline(target_fn, macro_args),
        build_active_trampoline(target_fn, macro_args),
    )
}

/// Build the trampoline implementation that actively traces the target, gated
/// behind the "bench" feature flag
fn build_active_trampoline(target_fn: &ItemFn, macro_args: MacroArgs) -> ItemFn {
    // In the active trampoline, we keep the signature and visibility of the target
    // the same The changes are to add an attribute #[cfg(feature = "bench")]
    // and change the body to:
    //  1. Add a prelude that sets up trace metrics and scope
    //  2. Call the target method
    //  3. Add an epilog to close trace metrics and scope
    let mut out_fn = target_fn.clone();

    // Add the conditional compilation attr
    let attr: Attribute = parse_quote! {
        #[cfg(feature = #TRACER_FEATURE_FLAG)]
    };
    out_fn.attrs.push(attr);

    // Build the prelude and epilogue of the tracer
    let tracer_prelude = build_tracer_prelude(&target_fn.sig.ident, macro_args);
    let tracer_epilogue = build_tracer_epilogue(macro_args);
    let call_expr = build_target_invocation(&out_fn.sig, macro_args);

    out_fn.block = parse_quote! {
        {
            #tracer_prelude;
            let ret = #call_expr;
            #tracer_epilogue;
            ret
        }
    };

    out_fn
}

/// Builds the prelude to the tracer, registers metrics and takes measurements
/// that must happen before circuit execution (e.g. current timestamp)
///
/// TODO: When trace metrics involving the constraint system are enabled (e.g.
/// n_constraints) the macro assumes the existence of a local binding `cs:
/// ConstraintSystem` that can be used to query the constraint system metrics.
/// In the future, we should remove this brittle assumption or allow rebinding
/// the name as a macro argument
fn build_tracer_prelude(target_fn_name: &Ident, macro_args: MacroArgs) -> TokenStream2 {
    // Scope into the target fn
    let fn_name_string = target_fn_name.to_string();

    let mut tokens = TokenStream2::default();

    // Scope into the target function
    tokens.extend(quote! {
        {
            CURR_SCOPE.lock().unwrap().scope_in(#fn_name_string.to_string());
        } // CURR_SCOPE lock released
    });

    // Setup enabled metrics, we intentionally obfuscate the names of the trace
    // variables to ensure they don't alias with any (well named) local bindings
    if macro_args.n_constraints {
        tokens.extend(quote! {
            let __n_constraint_pre = cs.num_constraints() as u64;
        });
    }

    if macro_args.n_multipliers {
        tokens.extend(quote! {
            let __n_multipliers_pre = cs.num_multipliers() as u64;
        });
    }

    if macro_args.latency {
        tokens.extend(quote! {
            let __time_pre = std::time::Instant::now();
        })
    }

    tokens
}

/// Builds the epilogue after the tracer, records metrics into global
/// `MetricsCapture` for analysis and closes the current scope
fn build_tracer_epilogue(macro_args: MacroArgs) -> TokenStream2 {
    // Record dummy metrics and scope out of the method
    let mut tokens = TokenStream2::default();

    // Record timing first before performing any other operations, including locking
    // the metrics
    if macro_args.latency {
        tokens.extend(quote! {
            let __latency = __time_pre.elapsed().as_millis();
        });
    }

    tokens.extend(quote! {
        let mut __locked_scope = CURR_SCOPE.lock().unwrap();
    });

    // Now, if any metrics are to be collected, lock the global metrics store
    if !macro_args.all_disabled() {
        tokens.extend(quote! {
            let mut __locked_metrics = SCOPED_METRICS.lock().unwrap();
        });
    }

    // Record any enabled metrics
    if macro_args.n_constraints {
        tokens.extend(quote! {
            let __new_constraints = cs.num_constraints() as u64;
            __locked_metrics.record_metric(
                __locked_scope.clone(),
                #ARG_N_CONSTRAINTS.to_string(),
                __new_constraints - __n_constraint_pre
            );
        })
    }

    if macro_args.n_multipliers {
        tokens.extend(quote! {
            let __new_multipliers = cs.num_multipliers() as u64;
            __locked_metrics.record_metric(
                __locked_scope.clone(),
                #ARG_N_MULTIPLIERS.to_string(),
                __new_multipliers - __n_multipliers_pre
            );
        })
    }

    if macro_args.latency {
        tokens.extend(quote! {
            __locked_metrics.record_metric(
                __locked_scope.clone(),
                #ARG_CONSTRAINT_LATENCY.to_string(),
                __latency.try_into().unwrap()
            );
        })
    }

    // Close the current scope
    tokens.extend(quote! {
        __locked_scope.scope_out();
    });

    tokens
}

/// Build the trampoline implementation that does not trace and simply passes
/// through to the target function. This implementation is active when the
/// `bench` feature flag is disabled
fn build_inactive_trampoline(target_fn: &ItemFn, macro_args: MacroArgs) -> ItemFn {
    // In the inactive trampoline, we keep the signature and visibility of the
    // target the same The changes are to add an attribute #[cfg(not(feature =
    // "bench"))] and change the body to call the target
    let mut out_fn = target_fn.clone();

    // Add the conditional compilation attr
    let attr: Attribute = parse_quote! {
        #[cfg(not(feature = #TRACER_FEATURE_FLAG))]
    };
    out_fn.attrs.push(attr);

    // Modify the body to pass-through to the trace target
    let call_expr = build_target_invocation(&out_fn.sig, macro_args);
    out_fn.block = parse_quote!({ #call_expr });

    out_fn
}

/// Build the argument list for the target function from the trampoline
/// function's signature
fn build_target_invocation(trampoline_sig: &Signature, macro_args: MacroArgs) -> ExprCall {
    let mut args = Vec::new();
    let mut parsed_receiver = None;

    for input_arg in trampoline_sig.inputs.clone().into_iter() {
        match input_arg {
            FnArg::Typed(type_pattern) => {
                if let Pat::Ident(pattern) = *type_pattern.pat {
                    args.push(pattern.ident)
                };
            },
            FnArg::Receiver(receiver) => parsed_receiver = Some(receiver),
        }
    }

    // Build the expression resolving to the function; using Self:: prelude if the
    let target_fn_name = get_modified_target_name(trampoline_sig);
    let function = if macro_args.non_associated {
        // The default is that gadgets specify circuitry in associated functions, if the
        // non-associated flag is explicitly set, call the function outside of
        // the current object's scope
        Expr::Path(parse_quote!(#target_fn_name))
    } else {
        Expr::Path(parse_quote!(Self::#target_fn_name))
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
/// The tracing target needs to be renamed so that calls to `fn_name` will route
/// through the trampoline implementation. As well, we mask the visibility to
/// private and allow the trampoline to inherit the visibility of the underlying
/// implementation
fn modify_target_fn(target_fn: &ItemFn) -> ItemFn {
    let mut modified_target = target_fn.clone();
    modified_target.sig.ident = get_modified_target_name(&target_fn.sig);
    modified_target.vis = Visibility::Inherited; // private

    modified_target
}

/// Get the name of the modified target fn given the unmodified signature
fn get_modified_target_name(sig: &Signature) -> Ident {
    let modified_name = format!("{}_{}", sig.ident, TRACE_TARGET_SUFFIX);
    Ident::new(&modified_name, Span::call_site())
}
