//! Helper methods for capturing telemetry information throughout the relayer

use tracing::Value;

/// Fills in field `field_name` with `field_value` on the current span.
///
/// Intended to be used when spans are constructed with empty fields whose
/// values are computed at some point in the span and must be injected at that
/// time.
pub fn backfill_trace_field<V: Value>(field_name: &str, field_value: V) {
    tracing::Span::current().record(field_name, field_value);
}
