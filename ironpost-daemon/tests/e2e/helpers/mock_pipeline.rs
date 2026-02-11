//! Mock pipeline implementations for E2E lifecycle tests.
//!
//! Provides configurable mock pipelines that implement `DynPipeline`
//! for testing module registry start/stop ordering and fault isolation.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use ironpost_core::error::IronpostError;
use ironpost_core::pipeline::{BoxFuture, DynPipeline, HealthStatus};

/// A mock pipeline that tracks start/stop calls and supports configurable behavior.
///
/// Use this to verify:
/// - Start/stop ordering via `stop_order` counter
/// - Health status reporting
/// - Failure injection
pub struct MockPipeline {
    /// Whether this pipeline has been started.
    pub started: Arc<AtomicBool>,
    /// Whether this pipeline has been stopped.
    pub stopped: Arc<AtomicBool>,
    /// The health status to report.
    health: HealthStatus,
    /// If set, `start()` will return this error.
    start_error: Option<String>,
    /// If set, `stop()` will return this error.
    stop_error: Option<String>,
    /// If set, `stop()` will sleep for this duration before returning.
    stop_delay: Option<Duration>,
    /// Shared counter to record stop ordering across multiple pipelines.
    stop_order: Option<Arc<StopOrderTracker>>,
    /// Name of this pipeline (for order tracking).
    name: String,
}

/// Tracks the order in which pipelines are stopped.
pub struct StopOrderTracker {
    counter: AtomicUsize,
    /// Stores (name, order) pairs. Protected by tokio::sync::Mutex.
    log: tokio::sync::Mutex<Vec<(String, usize)>>,
}

impl StopOrderTracker {
    /// Create a new stop order tracker.
    #[allow(dead_code)]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            counter: AtomicUsize::new(0),
            log: tokio::sync::Mutex::new(Vec::new()),
        })
    }

    /// Record a stop event and return the order number.
    async fn record(&self, name: &str) -> usize {
        let order = self.counter.fetch_add(1, Ordering::SeqCst);
        let mut log = self.log.lock().await;
        log.push((name.to_owned(), order));
        order
    }

    /// Get the recorded stop order log.
    #[allow(dead_code)]
    pub async fn get_log(&self) -> Vec<(String, usize)> {
        self.log.lock().await.clone()
    }
}

#[allow(dead_code)]
impl MockPipeline {
    /// Create a healthy mock pipeline.
    pub fn healthy(name: &str) -> Self {
        Self {
            started: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(AtomicBool::new(false)),
            health: HealthStatus::Healthy,
            start_error: None,
            stop_error: None,
            stop_delay: None,
            stop_order: None,
            name: name.to_owned(),
        }
    }

    /// Create a mock pipeline that fails on `start()`.
    pub fn failing_start(name: &str, error_msg: &str) -> Self {
        Self {
            started: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(AtomicBool::new(false)),
            health: HealthStatus::Unhealthy(error_msg.to_owned()),
            start_error: Some(error_msg.to_owned()),
            stop_error: None,
            stop_delay: None,
            stop_order: None,
            name: name.to_owned(),
        }
    }

    /// Create a mock pipeline that fails on `stop()`.
    pub fn failing_stop(name: &str, error_msg: &str) -> Self {
        Self {
            started: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(AtomicBool::new(false)),
            health: HealthStatus::Healthy,
            start_error: None,
            stop_error: Some(error_msg.to_owned()),
            stop_delay: None,
            stop_order: None,
            name: name.to_owned(),
        }
    }

    /// Create a mock pipeline with a specified health status.
    pub fn with_health(name: &str, health: HealthStatus) -> Self {
        Self {
            started: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(AtomicBool::new(false)),
            health,
            start_error: None,
            stop_error: None,
            stop_delay: None,
            stop_order: None,
            name: name.to_owned(),
        }
    }

    /// Set a delay for the `stop()` method.
    pub fn with_stop_delay(mut self, delay: Duration) -> Self {
        self.stop_delay = Some(delay);
        self
    }

    /// Attach a stop order tracker for verifying shutdown ordering.
    pub fn with_stop_order(mut self, tracker: Arc<StopOrderTracker>) -> Self {
        self.stop_order = Some(tracker);
        self
    }

    /// Check if this pipeline was started.
    pub fn was_started(&self) -> bool {
        self.started.load(Ordering::SeqCst)
    }

    /// Check if this pipeline was stopped.
    pub fn was_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }
}

impl DynPipeline for MockPipeline {
    fn start(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
        let started = self.started.clone();
        let error = self.start_error.clone();

        Box::pin(async move {
            if let Some(msg) = error {
                return Err(ironpost_core::error::PipelineError::InitFailed(msg).into());
            }
            started.store(true, Ordering::SeqCst);
            Ok(())
        })
    }

    fn stop(&mut self) -> BoxFuture<'_, Result<(), IronpostError>> {
        let stopped = self.stopped.clone();
        let error = self.stop_error.clone();
        let delay = self.stop_delay;
        let tracker = self.stop_order.clone();
        let name = self.name.clone();

        Box::pin(async move {
            if let Some(delay) = delay {
                tokio::time::sleep(delay).await;
            }

            if let Some(tracker) = tracker {
                tracker.record(&name).await;
            }

            if let Some(msg) = error {
                return Err(ironpost_core::error::PipelineError::ChannelSend(msg).into());
            }

            stopped.store(true, Ordering::SeqCst);
            Ok(())
        })
    }

    fn health_check(&self) -> BoxFuture<'_, HealthStatus> {
        let health = self.health.clone();
        Box::pin(async move { health })
    }
}
