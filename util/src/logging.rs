//! Defines helpers for logging

use chrono::Local;
use env_logger::Builder;
use std::io::Write;
use tracing::log::LevelFilter;

/// Initialize a logger at the given log level
pub fn setup_system_logger(level: LevelFilter) {
    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] {} - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.module_path().unwrap(),
                record.args()
            )
        })
        .filter(None, level)
        .init();
}
