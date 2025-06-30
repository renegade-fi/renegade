//! Helpers for propagating tracing information across processes
use std::collections::HashMap;

use opentelemetry::{
    Context, global,
    propagation::{Extractor, Injector},
};
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

    tracing::Span::current().set_parent(context);
}
