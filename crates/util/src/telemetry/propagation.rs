//! Helpers for propagating tracing information across processes
use std::collections::HashMap;

use http::{
    HeaderMap,
    header::{HeaderName, HeaderValue},
};
use opentelemetry::{
    Context, global,
    propagation::{Extractor, Injector},
};
use std::str::FromStr;
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Represents the context of a trace
pub type TraceContext = HashMap<String, String>;

/// Helper struct for injecting tracing context into a TraceContext
pub struct TraceContextInjector<'a>(&'a mut TraceContext);
/// Helper struct for extracting tracing context from a TraceContext
pub struct TraceContextExtractor<'a>(&'a TraceContext);

impl Injector for TraceContextInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

impl Extractor for TraceContextExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

/// Create a new TraceContext containing string-keyed trace context
pub fn trace_context() -> TraceContext {
    let mut trace_context = TraceContext::new();
    global::get_text_map_propagator(|prop| {
        prop.inject_context(
            &tracing::Span::current().context(),
            &mut TraceContextInjector(&mut trace_context),
        )
    });

    trace_context
}

/// Extract trace context from a TraceContext
fn extract_trace_context(headers: &TraceContext) -> Context {
    let extractor = TraceContextExtractor(headers);
    global::get_text_map_propagator(|prop| prop.extract(&extractor))
}

/// Set the parent span from a TraceContext context
pub fn set_parent_span_from_context(headers: &TraceContext) {
    let context = if headers.is_empty() {
        tracing::Span::current().context().clone()
    } else {
        extract_trace_context(headers)
    };

    set_parent_span(context);
}

/// Set the parent span from an `opentelemetry::Context`
pub fn set_parent_span(context: Context) {
    tracing::Span::current().set_parent(context);
}

/// Add propagation headers derived from the current span context into a
/// mutable `http::HeaderMap` using the globally configured propagator.
pub fn add_trace_context_to_headers(headers: &mut HeaderMap) {
    for (key, value) in trace_context() {
        let maybe_name = HeaderName::from_str(&key);
        let maybe_val = HeaderValue::from_str(&value);
        if let (Ok(name), Ok(val)) = (maybe_name, maybe_val) {
            headers.insert(name, val);
        }
    }
}

/// Extract a parent span from an `http::HeaderMap` (e.g., from an HTTP
/// request), using the globally configured propagator, and set it as the
/// current span's parent.
pub fn set_parent_span_from_headers(headers: &HeaderMap) {
    // Copy incoming header values into a string-typed TraceContext for extraction
    let mut trace_ctx = TraceContext::new();
    for (k, v) in headers.iter() {
        if let Ok(val) = v.to_str() {
            trace_ctx.insert(k.as_str().to_owned(), val.to_owned());
        }
    }

    set_parent_span_from_context(&trace_ctx);
}
