//! Configuration for exporting traces to an OTLP collector

use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    Resource, runtime,
    trace::{self, BatchConfig, Sampler, Tracer},
};
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    resource::{DEPLOYMENT_ENVIRONMENT, SERVICE_NAME, SERVICE_VERSION},
};

use crate::err_str;

use super::{
    TelemetrySetupError,
    datadog::{UnifiedServiceTags, get_unified_service_tags},
};

/// Fraction of traces to keep at the root. The relayer's steady-state span
/// volume (raft + matching engine + settlement) overruns the BSP's export
/// pipeline at full rate; deterministic head sampling preserves whole traces
/// instead of random channel-full drops that fragment them.
const TRACE_SAMPLE_RATIO: f64 = 0.5;

/// BatchSpanProcessor max in-memory queue (spans). The opentelemetry-rust 0.21
/// default (2048) overflows in under a second under relayer load.
const BSP_MAX_QUEUE_SIZE: usize = 65_536;

/// BatchSpanProcessor max spans per export batch (default 512). Larger batches
/// amortize per-export overhead and raise sustained export throughput.
const BSP_MAX_EXPORT_BATCH_SIZE: usize = 4096;

/// BatchSpanProcessor scheduled flush interval (default 5s). Shorter so the
/// queue drains continuously instead of accumulating between flushes.
const BSP_SCHEDULED_DELAY: Duration = Duration::from_secs(1);

/// BatchSpanProcessor concurrent in-flight exports (default 1). Multiple
/// concurrent exports prevent a single slow batch from stalling drain.
const BSP_MAX_CONCURRENT_EXPORTS: usize = 4;

/// Constructs the resource tags for OTLP traces
fn otlp_resource() -> Result<Resource, TelemetrySetupError> {
    let UnifiedServiceTags { service, env, version } = get_unified_service_tags()?;

    Ok(Resource::from_schema_url(
        [
            KeyValue::new(SERVICE_NAME, service),
            KeyValue::new(SERVICE_VERSION, version),
            KeyValue::new(DEPLOYMENT_ENVIRONMENT, env),
        ],
        SCHEMA_URL,
    ))
}

/// Creates an OTLP tracing pipeline for sending spans to the collector
pub fn configure_otlp_tracer(
    datadog_enabled: bool,
    collector_endpoint: String,
) -> Result<Tracer, TelemetrySetupError> {
    let sampler = Sampler::ParentBased(Box::new(Sampler::TraceIdRatioBased(TRACE_SAMPLE_RATIO)));

    let trace_config = if datadog_enabled {
        trace::Config::default().with_resource(otlp_resource()?).with_sampler(sampler)
    } else {
        trace::Config::default().with_sampler(sampler)
    };

    let batch_config = BatchConfigBuilder::default()
        .with_max_queue_size(BSP_MAX_QUEUE_SIZE)
        .with_max_export_batch_size(BSP_MAX_EXPORT_BATCH_SIZE)
        .with_scheduled_delay(BSP_SCHEDULED_DELAY)
        .with_max_concurrent_exports(BSP_MAX_CONCURRENT_EXPORTS)
        .build();

    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(trace_config)
        .with_batch_config(batch_config)
        .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(collector_endpoint))
        .install_batch(runtime::Tokio)
        .map_err(err_str!(TelemetrySetupError::Tracer))
}
