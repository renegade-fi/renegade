//! Types and helpers for configuring DataDog telemetry

use std::env;

use super::TelemetrySetupError;

/// The current relayer version
const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod formatter;

/// The name of the environment variable used to set the
/// service name for DataDog unified service tagging
pub const DD_SERVICE_ENV_VAR: &str = "DD_SERVICE";
/// The name of the environment variable used to set the
/// environment for DataDog unified service tagging
pub const DD_ENV_ENV_VAR: &str = "DD_ENV";
/// The name of the tag used to identify the service in DataDog
pub const SERVICE_TAG: &str = "service";
/// The name of the tag used to identify the environment in DataDog
pub const ENV_TAG: &str = "env";
/// The name of the tag used to identify the version in DataDog
pub const VERSION_TAG: &str = "version";

/// A struct representing the unified service tags
/// expected by DataDog.
///
/// https://docs.datadoghq.com/getting_started/tagging/unified_service_tagging
pub struct UnifiedServiceTags {
    /// The service name
    pub service: String,
    /// The environment
    pub env: String,
    /// The version
    pub version: String,
}

/// Get the unified service tags for the relayer
pub fn get_unified_service_tags() -> Result<UnifiedServiceTags, TelemetrySetupError> {
    let service = env::var(DD_SERVICE_ENV_VAR).map_err(|_| TelemetrySetupError::EnvVarMissing)?;
    let env = env::var(DD_ENV_ENV_VAR).map_err(|_| TelemetrySetupError::EnvVarMissing)?;
    let version = VERSION.to_string();

    Ok(UnifiedServiceTags { service, env, version })
}
