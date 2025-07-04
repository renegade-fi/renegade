//! Configures a metrics recorder to send metrics to a statsd server

use metrics_exporter_statsd::StatsdBuilder;
use metrics_tracing_context::TracingContextLayer;
use metrics_util::layers::Layer;

use crate::err_str;

use super::{
    TelemetrySetupError,
    datadog::{SERVICE_TAG, UnifiedServiceTags, get_unified_service_tags},
};

/// Default metrics prefix used for the relayer
pub const DEFAULT_RELAYER_METRICS_PREFIX: &str = "renegade_relayer";
/// Default buffer size for metrics in bytes
pub const DEFAULT_METRICS_BUFFER_SIZE: usize = 1024;
/// Default queue size for metrics in number of elements
pub const DEFAULT_METRICS_QUEUE_SIZE: usize = 1024 * 1024;

/// Configuration for metrics collection
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// The prefix to use for metrics emitted by the relayer
    pub metrics_prefix: String,
    /// The size (in bytes) of the buffer which metrics data must fill before
    /// being flushed out over UDP
    pub buffer_size: usize,
    /// The size (in # of elements) of the queue which the metrics exporter
    /// maintains.
    ///
    /// If the queue is full, metrics data will be dropped.
    ///
    /// We effectively want an unbounded queue, but the `StatsdBuilder` doesn't
    /// support this, so we set a sufficiently large value here.
    pub queue_size: usize,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            metrics_prefix: DEFAULT_RELAYER_METRICS_PREFIX.to_string(),
            buffer_size: DEFAULT_METRICS_BUFFER_SIZE,
            queue_size: DEFAULT_METRICS_QUEUE_SIZE,
        }
    }
}

/// Configures a statsd metrics recorder with custom configuration
pub fn configure_metrics_statsd_recorder_with_config(
    datadog_enabled: bool,
    statsd_host: &str,
    statsd_port: u16,
    config: &MetricsConfig,
) -> Result<(), TelemetrySetupError> {
    let mut builder = StatsdBuilder::from(statsd_host, statsd_port)
        .with_buffer_size(config.buffer_size)
        .with_queue_size(config.queue_size);

    if datadog_enabled {
        let UnifiedServiceTags { service, env, version } = get_unified_service_tags()?;
        builder = builder
            .with_default_tag(SERVICE_TAG, service)
            .with_default_tag("env", env)
            .with_default_tag("version", version);
    };

    let recorder = TracingContextLayer::all().layer(
        builder
            .build(Some(&config.metrics_prefix))
            .map_err(err_str!(TelemetrySetupError::Metrics))?,
    );

    metrics::set_global_recorder(recorder).unwrap();

    Ok(())
}

/// Configures a statsd metrics recorder with default configuration
pub fn configure_metrics_statsd_recorder(
    datadog_enabled: bool,
    statsd_host: &str,
    statsd_port: u16,
) -> Result<(), TelemetrySetupError> {
    configure_metrics_statsd_recorder_with_config(
        datadog_enabled,
        statsd_host,
        statsd_port,
        &MetricsConfig::default(),
    )
}
