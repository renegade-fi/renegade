//! Adapted from https://github.com/will-bank/datadog-tracing/blob/main/src/formatter.rs
//!
//! An event formatter to emit events in a way that Datadog can correlate them
//! with traces.
//!
//! Datadog's trace ID and span ID format is different from the OpenTelemetry
//! standard. Using this formatter, the trace ID is converted to the correct
//! format. It also adds the trace ID to the `dd.trace_id` field and the span ID
//! to the `dd.span_id` field, which is where Datadog looks for these by default
//! (although the path to the trace ID can be overridden in Datadog).

#![allow(missing_docs)]
#![allow(clippy::missing_docs_in_private_items)]

use std::io;

use chrono::Utc;
use opentelemetry::trace::{SpanId, TraceContextExt, TraceId};
use serde::ser::{SerializeMap, Serializer as _};
use serde::Serialize;
use tracing::{Event, Subscriber};
use tracing_opentelemetry::OtelData;

use tracing_serde::AsSerde;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields};
use tracing_subscriber::registry::{LookupSpan, SpanRef};

#[derive(Serialize)]
struct DatadogId(u64);

struct TraceInfo {
    trace_id: DatadogId,
    span_id: DatadogId,
}

impl From<TraceId> for DatadogId {
    fn from(value: TraceId) -> Self {
        let bytes = &value.to_bytes()[std::mem::size_of::<u64>()..std::mem::size_of::<u128>()];
        Self(u64::from_be_bytes(bytes.try_into().unwrap_or_default()))
    }
}

impl From<SpanId> for DatadogId {
    fn from(value: SpanId) -> Self {
        Self(u64::from_be_bytes(value.to_bytes()))
    }
}

fn lookup_trace_info<S>(span_ref: &SpanRef<S>) -> Option<TraceInfo>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    span_ref.extensions().get::<OtelData>().map(|o| {
        let trace_id = if o.parent_cx.has_active_span() {
            o.parent_cx.span().span_context().trace_id()
        } else {
            o.builder.trace_id.unwrap_or(TraceId::INVALID)
        };
        TraceInfo {
            trace_id: trace_id.into(),
            span_id: o.builder.span_id.unwrap_or(SpanId::INVALID).into(),
        }
    })
}

// mostly stolen from here: https://github.com/tokio-rs/tracing/issues/1531
pub struct DatadogFormatter;

impl<S, N> FormatEvent<S, N> for DatadogFormatter
where
    S: Subscriber + for<'lookup> LookupSpan<'lookup>,
    N: for<'writer> FormatFields<'writer> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> std::fmt::Result
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        let meta = event.metadata();

        let mut visit = || {
            let mut serializer = serde_json::Serializer::new(WriteAdaptor::new(&mut writer));
            let mut serializer = serializer.serialize_map(None)?;
            serializer.serialize_entry("timestamp", &Utc::now().to_rfc3339())?;
            serializer.serialize_entry("level", &meta.level().as_serde())?;
            serializer.serialize_entry("target", meta.target())?;

            if let Some(filename) = meta.file() {
                serializer.serialize_entry("filename", filename)?;
            }

            if let Some(line_number) = meta.line() {
                serializer.serialize_entry("line_number", &line_number)?;
            }

            // fields -> stolen from https://github.com/tokio-rs/tracing/blob/tracing-subscriber-0.3.17/tracing-subscriber/src/fmt/format/json.rs#L263-L268
            let mut visitor = tracing_serde::SerdeMapVisitor::new(serializer);
            event.record(&mut visitor);
            serializer = visitor.take_serializer()?;

            if let Some(ref span_ref) = ctx.lookup_current() {
                if let Some(trace_info) = lookup_trace_info(span_ref) {
                    serializer.serialize_entry("dd.span_id", &trace_info.span_id)?;
                    serializer.serialize_entry("dd.trace_id", &trace_info.trace_id)?;
                }
            }

            serializer.end()
        };

        visit().map_err(|_| std::fmt::Error)?;
        writeln!(writer)
    }
}

struct WriteAdaptor<'a> {
    fmt_write: &'a mut dyn std::fmt::Write,
}

impl<'a> WriteAdaptor<'a> {
    fn new(fmt_write: &'a mut dyn std::fmt::Write) -> Self {
        Self { fmt_write }
    }
}

impl<'a> io::Write for WriteAdaptor<'a> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let s =
            std::str::from_utf8(buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        self.fmt_write.write_str(s).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(s.as_bytes().len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::DatadogId;
    use opentelemetry::trace::{SpanId, TraceId};

    #[test]
    fn test_trace_id_converted_to_datadog_id() {
        let trace_id = TraceId::from_hex("2de7888d8f42abc9c7ba048b78f7a9fb").unwrap();
        let datadog_id: DatadogId = trace_id.into();

        assert_eq!(datadog_id.0, 14391820556292303355);
    }

    #[test]
    fn test_invalid_trace_id_converted_to_zero() {
        let trace_id = TraceId::INVALID;
        let datadog_id: DatadogId = trace_id.into();

        assert_eq!(datadog_id.0, 0);
    }

    #[test]
    fn test_span_id_converted_to_datadog_id() {
        let span_id = SpanId::from_hex("58406520a0066491").unwrap();
        let datadog_id: DatadogId = span_id.into();

        assert_eq!(datadog_id.0, 6359193864645272721);
    }
}
