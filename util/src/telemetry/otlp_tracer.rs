//! Configuration for exporting traces to an OTLP collector

use std::env;

use opentelemetry::{trace::TraceError, KeyValue};
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

/// The [OTLP service name](https://opentelemetry.io/docs/specs/semconv/resource/#service)
/// for the relayer
const RELAYER_SERVICE_NAME: &str = "renegade_relayer";

/// Constructs the resource tags for OTLP traces
fn otlp_resource(deployment_env: Option<String>) -> Resource {
    let mut resource_kvs = vec![
        KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
        KeyValue::new(SERVICE_NAME, RELAYER_SERVICE_NAME),
    ];

    if let Some(env) = deployment_env {
        resource_kvs.push(KeyValue::new(DEPLOYMENT_ENVIRONMENT, env));
    }

    Resource::from_schema_url(resource_kvs, SCHEMA_URL)
}

/// Creates an OTLP tracing pipeline for sending spans to the collector
pub fn configure_otlp_tracer(
    deployment_env: Option<String>,
    collector_endpoint: String,
) -> Result<Tracer, TraceError> {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(trace::Config::default().with_resource(otlp_resource(deployment_env)))
        .with_batch_config(BatchConfig::default())
        .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(collector_endpoint))
        .install_batch(runtime::Tokio)
}
