//! Configuration for exporting traces to an OTLP collector

use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{
    runtime,
    trace::{self, BatchConfig, Tracer},
    Resource,
};
use opentelemetry_semantic_conventions::{
    resource::{DEPLOYMENT_ENVIRONMENT, SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};

use crate::err_str;

use super::{
    datadog::{get_unified_service_tags, UnifiedServiceTags},
    TelemetrySetupError,
};

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
    let trace_config = if datadog_enabled {
        trace::Config::default().with_resource(otlp_resource()?)
    } else {
        trace::Config::default()
    };

    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(trace_config)
        .with_batch_config(BatchConfig::default())
        .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(collector_endpoint))
        .install_batch(runtime::Tokio)
        .map_err(err_str!(TelemetrySetupError::Tracer))
}
