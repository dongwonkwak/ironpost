#![doc = include_str!("../README.md")]
//!
//! # Module Structure
//!
//! - [`error`]: Domain error types (`ContainerGuardError`)
//! - [`config`]: Guard configuration (`ContainerGuardConfig`, builder)
//! - [`event`]: Container lifecycle events (`ContainerEvent`, `ContainerEventKind`)
//! - [`docker`]: Docker API abstraction (`DockerClient` trait, `BollardDockerClient`)
//! - [`policy`]: Security policies (`SecurityPolicy`, `PolicyEngine`, `TargetFilter`)
//! - [`isolation`]: Isolation actions (`IsolationAction`, `IsolationExecutor`)
//! - [`monitor`]: Container monitoring (`DockerMonitor`)
//! - [`guard`]: Main orchestrator (`ContainerGuard`, `ContainerGuardBuilder`)
//!
//! # Architecture
//!
//! ```text
//! AlertEvent --mpsc--> ContainerGuard
//!                          |
//!                     PolicyEngine.evaluate()
//!                          |
//!                     IsolationExecutor.execute()
//!                          |
//!                     ActionEvent --mpsc--> downstream
//! ```

pub mod config;
pub mod docker;
pub mod error;
pub mod event;
pub mod guard;
pub mod isolation;
pub mod monitor;
pub mod policy;

// --- Public API Re-exports ---

// Guard (main orchestrator)
pub use guard::{ContainerGuard, ContainerGuardBuilder};

// Configuration
pub use config::{ContainerGuardConfig, ContainerGuardConfigBuilder};

// Error
pub use error::ContainerGuardError;

// Events
pub use event::{ContainerEvent, ContainerEventKind};

// Docker API
pub use docker::{BollardDockerClient, DockerClient};

// Policy
pub use policy::{
    PolicyEngine, PolicyMatch, SecurityPolicy, TargetFilter, load_policies_from_dir,
    load_policy_from_file,
};

// Isolation
pub use isolation::{IsolationAction, IsolationExecutor};

// Monitor
pub use monitor::DockerMonitor;
