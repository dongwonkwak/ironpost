#![doc = include_str!("../README.md")]
//!
//! # Module Structure
//!
//! - [`error`]: Domain error types (`SbomScannerError`)
//! - [`config`]: Scanner configuration (`SbomScannerConfig`, builder)
//! - [`event`]: Scan result events (`ScanEvent`)
//! - [`types`]: Domain types (`Package`, `PackageGraph`, `Ecosystem`, `SbomFormat`, `SbomDocument`)
//! - [`parser`]: Lockfile parsers (`LockfileParser` trait, `CargoLockParser`, `NpmLockParser`)
//! - [`sbom`]: SBOM document generation (`SbomGenerator`, CycloneDX, SPDX)
//! - [`vuln`]: Vulnerability matching (`VulnDb`, `VulnMatcher`, `ScanResult`, `ScanFinding`)
//! - [`scanner`]: Main orchestrator (`SbomScanner`, `SbomScannerBuilder`, `Pipeline` impl)
//!
//! # Architecture
//!
//! ```text
//! scan_dirs --> LockfileDetector --> LockfileParser --> PackageGraph
//!                                                          |
//!                                    +---------------------+---------------------+
//!                                    |                                           |
//!                              SbomGenerator                                VulnMatcher
//!                                    |                                           |
//!                              SbomDocument                               Vec<ScanFinding>
//!                                                                               |
//!                                                                         AlertEvent
//!                                                                               |
//!                                                                      mpsc --> downstream
//! ```

pub mod config;
pub mod error;
pub mod event;
pub mod parser;
pub mod sbom;
pub mod scanner;
pub mod types;
pub mod vuln;

// --- Public API Re-exports ---

// Scanner (main orchestrator)
pub use scanner::{SbomScanner, SbomScannerBuilder};

// Configuration
pub use config::{SbomScannerConfig, SbomScannerConfigBuilder};

// Error
pub use error::SbomScannerError;

// Events
pub use event::ScanEvent;

// Types
pub use types::{Ecosystem, Package, PackageGraph, SbomDocument, SbomFormat};

// Parser
pub use parser::cargo::CargoLockParser;
pub use parser::npm::NpmLockParser;
pub use parser::{LockfileDetector, LockfileParser};

// SBOM Generator
pub use sbom::SbomGenerator;

// Vulnerability
pub use vuln::db::{VersionRange, VulnDb, VulnDbEntry};
pub use vuln::{ScanFinding, ScanResult, SeverityCounts, VulnMatcher};
