//! E2E integration tests for ironpost-daemon.
//!
//! These tests validate cross-module event flows, lifecycle management,
//! configuration handling, and fault isolation using mock pipelines.
//!
//! # Test Structure
//!
//! - `helpers/` -- Shared test utilities (config builder, event factories, assertions)
//! - `scenarios/` -- Test files organized by scenario (S1-S6)
//!
//! # Running
//!
//! ```bash
//! cargo test -p ironpost-daemon --test e2e
//! ```

mod helpers;
mod scenarios;
