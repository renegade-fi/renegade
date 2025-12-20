//! An atomic gauge for recording metrics. Exposes an
//! increment/decrement/set API that is not natively supported by StatsD.

use std::sync::atomic::Ordering;

use atomic_float::AtomicF64;

/// Stores the value of the gauge metric
pub struct Gauge {
    /// The name of the gauge metric
    name: String,
    /// The tags associated with the gauge metric
    tags: Vec<(String, String)>,
    /// The value of the gauge metric
    value: AtomicF64,
}

impl Gauge {
    /// Create a new gauge metric with an initial value
    pub fn new(name: String, tags: Vec<(String, String)>) -> Self {
        Self { name, tags, value: AtomicF64::default() }
    }

    /// Increment the gauge metric by a given value
    pub fn increment(&self, value: f64) {
        self.value.fetch_add(value, Ordering::Relaxed);
        self.record_gauge();
    }

    /// Decrement the gauge metric by a given value
    pub fn decrement(&self, value: f64) {
        self.value.fetch_sub(value, Ordering::Relaxed);
        self.record_gauge();
    }

    /// Set the gauge metric to a given value
    pub fn set(&self, value: f64) {
        self.value.store(value, Ordering::Relaxed);
        self.record_gauge();
    }

    /// Get the value of the gauge metric
    pub fn get(&self) -> f64 {
        self.value.load(Ordering::Relaxed)
    }

    // -----------
    // | Helpers |
    // -----------

    /// Record the gauge metric
    fn record_gauge(&self) {
        metrics::gauge!(self.name.clone(), self.tags.as_slice()).set(self.get());
    }
}
