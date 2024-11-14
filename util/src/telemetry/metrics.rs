//! Configures a metrics recorder to send metrics to a statsd server

use metrics_exporter_statsd::StatsdBuilder;
use metrics_tracing_context::TracingContextLayer;
use metrics_util::layers::Layer;

use crate::err_str;

use super::{
    datadog::{get_unified_service_tags, UnifiedServiceTags, SERVICE_TAG},
    TelemetrySetupError,
};

/// The prefix to used for metrics emitted by the relayer
pub const RELAYER_METRICS_PREFIX: &str = "renegade_relayer";

/// The size (in bytes) of the buffer which metrics data must fill before being
/// flushed out over UDP
pub const METRICS_BUFFER_SIZE: usize = 1024;
/// The size (in # of elements) of the queue which the metrics exporter
/// maintains.
///
/// If the queue is full, metrics data will be dropped.
///
/// We effectively want an unbounded queue, but the `StatsdBuilder` doesn't
/// support this, so we set a suffiiently large value here.
pub const METRICS_QUEUE_SIZE: usize = 1024 * 1024;

/// Configures a statsd metrics recorder
pub fn configure_metrics_statsd_recorder(
    datadog_enabled: bool,
    statsd_host: &str,
    statsd_port: u16,
) -> Result<(), TelemetrySetupError> {
    let mut builder = StatsdBuilder::from(statsd_host, statsd_port)
        .with_buffer_size(METRICS_BUFFER_SIZE)
        .with_queue_size(METRICS_QUEUE_SIZE);

    if datadog_enabled {
        let UnifiedServiceTags { service, env, version } = get_unified_service_tags()?;
        builder = builder
            .with_default_tag(SERVICE_TAG, service)
            .with_default_tag("env", env)
            .with_default_tag("version", version);
    };

    let recorder = TracingContextLayer::all().layer(
        builder
            .build(Some(RELAYER_METRICS_PREFIX))
            .map_err(err_str!(TelemetrySetupError::Metrics))?,
    );

    metrics::set_global_recorder(recorder).unwrap();

    Ok(())
}
