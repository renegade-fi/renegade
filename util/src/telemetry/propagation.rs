//! Helpers for propagating tracing information across processes
use std::collections::HashMap;

use opentelemetry::{
    global,
    propagation::{Extractor, Injector},
    Context,
};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Represents the context of a trace
pub type TraceContextHeaders = HashMap<String, String>;

/// Helper struct for injecting tracing context into a TraceContextHeaders
pub struct TraceContextHeadersInjector<'a>(&'a mut TraceContextHeaders);
/// Helper struct for extracting tracing context from a TraceContextHeaders
pub struct TraceContextHeadersExtractor<'a>(&'a TraceContextHeaders);

impl<'a> Injector for TraceContextHeadersInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        self.0.insert(key.to_string(), value);
    }
}

impl<'a> Extractor for TraceContextHeadersExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(String::as_str).collect()
    }
}

/// Create a new TraceContextHeaders containing string-keyed trace context
pub fn trace_context_headers() -> TraceContextHeaders {
    let mut trace_context = TraceContextHeaders::new();
    global::get_text_map_propagator(|prop| {
        prop.inject_context(
            &tracing::Span::current().context(),
            &mut TraceContextHeadersInjector(&mut trace_context),
        )
    });

    trace_context
}

/// Extract trace context from a TraceContextHeaders
pub fn trace_context_from_headers(headers: &TraceContextHeaders) -> Context {
    let extractor = TraceContextHeadersExtractor(headers);
    global::get_text_map_propagator(|prop| prop.extract(&extractor))
}

/// Set the parent span from a TraceContextHeaders context
pub fn set_parent_span_from_headers(headers: &TraceContextHeaders) {
    let context = if headers.is_empty() {
        tracing::Span::current().context().clone()
    } else {
        trace_context_from_headers(headers)
    };

    tracing::Span::current().set_parent(context);
}
