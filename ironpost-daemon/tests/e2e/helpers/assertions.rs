//! Channel assertion helpers for E2E tests.
//!
//! Provides timeout-based assertions for receiving events from `tokio::mpsc` channels.

use std::fmt::Debug;
use std::time::Duration;

use tokio::sync::mpsc;

/// Default timeout for channel receive assertions.
#[allow(dead_code)]
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Short timeout for asserting that no event is received.
#[allow(dead_code)]
pub const SHORT_TIMEOUT: Duration = Duration::from_millis(200);

/// Assert that a value is received from an `mpsc::Receiver` within the given timeout.
///
/// Returns the received value on success.
///
/// # Panics
///
/// Panics if the timeout expires or the channel is closed before a value is received.
#[allow(dead_code)]
pub async fn assert_received_within<T: Debug>(rx: &mut mpsc::Receiver<T>, timeout: Duration) -> T {
    match tokio::time::timeout(timeout, rx.recv()).await {
        Ok(Some(value)) => value,
        Ok(None) => panic!("channel closed before receiving a value"),
        Err(_) => panic!("timed out after {:?} waiting for value on channel", timeout),
    }
}

/// Assert that no value is received from an `mpsc::Receiver` within the given timeout.
///
/// # Panics
///
/// Panics if a value is received before the timeout expires.
#[allow(dead_code)]
pub async fn assert_not_received_within<T: Debug>(rx: &mut mpsc::Receiver<T>, timeout: Duration) {
    match tokio::time::timeout(timeout, rx.recv()).await {
        Ok(Some(value)) => panic!("expected no value but received: {:?}", value),
        Ok(None) => {} // Channel closed, that's fine
        Err(_) => {}   // Timeout -- expected
    }
}

/// Collect all values received from an `mpsc::Receiver` until timeout.
///
/// Returns the collected values. Does not panic if no values are received.
#[allow(dead_code)]
pub async fn collect_within<T: Debug>(rx: &mut mpsc::Receiver<T>, timeout: Duration) -> Vec<T> {
    let mut values = Vec::new();
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(value)) => values.push(value),
            Ok(None) => break, // Channel closed
            Err(_) => break,   // Timeout
        }
    }

    values
}
