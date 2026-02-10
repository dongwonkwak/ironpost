//! Ironpost daemon library.
//!
//! This library exposes internal modules for integration testing.
//! In production, `ironpost-daemon` is used as a binary (main.rs).

pub mod health;
pub mod modules;
pub mod orchestrator;
