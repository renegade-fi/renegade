//! Configures a metrics recorder to send metrics to a statsd server

use metrics_exporter_statsd::{StatsdBuilder, StatsdError};
use metrics_tracing_context::TracingContextLayer;
use metrics_util::layers::Layer;

use super::RELAYER_SERVICE_NAME;

/// Configures a statsd metrics recorder
pub fn configure_metrics_statsd_recorder(
    statsd_host: &str,
    statsd_port: u16,
) -> Result<(), StatsdError> {
    let recorder = TracingContextLayer::all().layer(
        StatsdBuilder::from(statsd_host, statsd_port)
            .with_buffer_size(0)
            .build(Some(RELAYER_SERVICE_NAME))?,
    );

    metrics::set_global_recorder(recorder).unwrap();

    Ok(())
}
