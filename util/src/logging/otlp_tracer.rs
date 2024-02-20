//! Configuration for exporting traces to an OTLP collector

use std::env;

use opentelemetry::{trace::TraceError, KeyValue};
use opentelemetry_sdk::{
    runtime,
    trace::{self, BatchConfig, Tracer},
    Resource,
};
use opentelemetry_semantic_conventions::{
    resource::{DEPLOYMENT_ENVIRONMENT, SERVICE_NAME, SERVICE_VERSION},
    SCHEMA_URL,
};

/// Constructs the resource tags for OTLP traces
fn otlp_resource() -> Resource {
    let mut resource_kvs = vec![KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION"))];

    if let Ok(service_name) = env::var("DD_SERVICE") {
        resource_kvs.push(KeyValue::new(SERVICE_NAME, service_name));
    }

    if let Ok(env) = env::var("DD_ENV") {
        resource_kvs.push(KeyValue::new(DEPLOYMENT_ENVIRONMENT, env));
    }

    Resource::from_schema_url(resource_kvs, SCHEMA_URL)
}

/// Creates an OTLP tracing pipeline for sending spans to the collector
pub fn configure_otlp_tracer() -> Result<Tracer, TraceError> {
    opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_trace_config(trace::Config::default().with_resource(otlp_resource()))
        .with_batch_config(BatchConfig::default())
        .with_exporter(opentelemetry_otlp::new_exporter().tonic())
        .install_batch(runtime::Tokio)
}
