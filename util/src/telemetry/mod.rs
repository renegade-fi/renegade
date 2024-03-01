//! Defines helpers for logging

use std::{error::Error, fmt::Display};
pub use tracing_subscriber::{filter::LevelFilter, fmt::format::Format};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use crate::err_str;

#[cfg(feature = "datadog")]
pub mod formatter;

#[cfg(feature = "trace-otlp")]
pub mod otlp_tracer;

/// Possible errors that occur when setting up telemetry
/// for the relayer
#[derive(Debug)]
pub enum TelemetrySetupError {
    /// Error setting up the OTLP tracer
    Tracer(String),
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

/// Configures logging, tracing, and metrics for the relayer
/// based on the compilation features enabled
pub fn configure_telemetry() -> Result<(), TelemetrySetupError> {
    let mut layers = Vec::new();

    #[cfg(feature = "datadog")]
    {
        layers.push(fmt::layer().json().event_format(formatter::DatadogFormatter).boxed());

        opentelemetry::global::set_text_map_propagator(
            opentelemetry_datadog::DatadogPropagator::new(),
        );
    }
    #[cfg(not(feature = "datadog"))]
    layers.push(fmt::layer().pretty().boxed());

    #[cfg(feature = "trace-otlp")]
    {
        let otlp_tracer =
            otlp_tracer::configure_otlp_tracer().map_err(err_str!(TelemetrySetupError::Tracer))?;
        let otlp_trace_layer = tracing_opentelemetry::layer().with_tracer(otlp_tracer);
        layers.push(otlp_trace_layer.boxed());
    }

    tracing_subscriber::registry()
        .with(
            EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy(),
        )
        .with(layers)
        .init();

    Ok(())
}
