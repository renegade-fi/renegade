//! Defines helpers for logging

use std::{error::Error, fmt::Display};
pub use tracing_subscriber::{filter::LevelFilter, fmt::format::Format};
use tracing_subscriber::{
    fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};

use crate::err_str;

pub mod formatter;
pub mod metrics;
pub mod otlp_tracer;

/// The [OTLP service name](https://opentelemetry.io/docs/specs/semconv/resource/#service)
/// for the relayer
pub const RELAYER_SERVICE_NAME: &str = "renegade_relayer";

/// Possible errors that occur when setting up telemetry
/// for the relayer
#[derive(Debug)]
pub enum TelemetrySetupError {
    /// Error emitted when setting up the OTLP tracer
    Tracer(String),
    /// Error emitted when the OTLP deployment environemt
    /// is not provided
    DeploymentEnvUnset,
    /// Error emitted when the OTLP collector endpoint is not provided
    CollectorEndpointUnset,
    /// Error emitted when setting up the statsd metrics recorder
    Metrics(String),
}

impl Error for TelemetrySetupError {}
impl Display for TelemetrySetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Initialize a logger at the given log level
pub fn setup_system_logger(level: LevelFilter) {
    tracing_subscriber::fmt().event_format(Format::default().pretty()).with_max_level(level).init();
}

/// A builder for configuring telemetry for the relayer
#[derive(Default)]
pub struct TelemetryBuilder {
    /// The subscriber layers to add to the telemetry stack
    layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>>,
}

impl TelemetryBuilder {
    /// Add a subscriber layer to the telemetry builder
    fn with_layer<L: Layer<Registry> + Send + Sync>(mut self, layer: L) -> Self {
        self.layers.push(layer.boxed());
        self
    }

    /// Configure logging for the relayer
    pub fn with_logging(self, datadog_enabled: bool) -> Self {
        if datadog_enabled {
            opentelemetry::global::set_text_map_propagator(
                opentelemetry_datadog::DatadogPropagator::new(),
            );

            self.with_layer(fmt::layer().json().event_format(formatter::DatadogFormatter))
        } else {
            self.with_layer(fmt::layer().pretty())
        }
    }

    /// Configure OTLP tracing for the relayer
    pub fn with_tracing(
        self,
        deployment_env: Option<String>,
        collector_endpoint: String,
    ) -> Result<Self, TelemetrySetupError> {
        let otlp_tracer = otlp_tracer::configure_otlp_tracer(deployment_env, collector_endpoint)
            .map_err(err_str!(TelemetrySetupError::Tracer))?;
        let otlp_trace_layer = tracing_opentelemetry::layer().with_tracer(otlp_tracer);

        Ok(self.with_layer(otlp_trace_layer))
    }

    /// Configure StatsD metrics for the relayer
    pub fn with_metrics(
        self,
        statsd_host: &str,
        statsd_port: u16,
    ) -> Result<Self, TelemetrySetupError> {
        metrics::configure_metrics_statsd_recorder(statsd_host, statsd_port)
            .map_err(err_str!(TelemetrySetupError::Metrics))?;

        Ok(self.with_layer(metrics_tracing_context::MetricsLayer::new()))
    }

    /// Initialize the global subscriber with the configured telemetry layers
    pub fn build(self) {
        let layers = self.layers.with_filter(
            EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy(),
        );
        tracing_subscriber::registry().with(layers).init()
    }
}

/// Configures logging, tracing, and metrics for the relayer
/// based on the compilation features enabled
pub fn configure_telemetry(
    datadog_enabled: bool,
    otlp_enabled: bool,
    metrics_enabled: bool,
    deployment_env: Option<String>,
    collector_endpoint: String,
    statsd_host: &str,
    statsd_port: u16,
) -> Result<(), TelemetrySetupError> {
    let mut telemetry = TelemetryBuilder::default().with_logging(datadog_enabled);

    if otlp_enabled {
        telemetry = telemetry.with_tracing(deployment_env, collector_endpoint)?;
    }

    if metrics_enabled {
        telemetry = telemetry.with_metrics(statsd_host, statsd_port)?;
    }

    telemetry.build();

    Ok(())
}
