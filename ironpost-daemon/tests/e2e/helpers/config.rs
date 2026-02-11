//! Test configuration builder for E2E tests.
//!
//! Provides [`TestConfigBuilder`] for creating `IronpostConfig` instances
//! with fine-grained control over which modules are enabled and with what settings.

use std::io::Write;
use std::path::PathBuf;

use ironpost_core::config::IronpostConfig;

/// Builder for constructing test-friendly `IronpostConfig` instances.
///
/// By default, all modules are **disabled** and settings use safe test defaults
/// (e.g., empty PID file path, temp data directory).
///
/// # Example
///
/// ```ignore
/// let config = TestConfigBuilder::new()
///     .log_pipeline(true)
///     .container(true)
///     .build();
/// ```
#[allow(dead_code)]
pub struct TestConfigBuilder {
    config: IronpostConfig,
}

#[allow(dead_code)]
impl TestConfigBuilder {
    /// Create a new builder with all modules disabled and test-safe defaults.
    pub fn new() -> Self {
        let mut config = IronpostConfig::default();

        // Override defaults for test safety
        config.general.pid_file = String::new(); // No PID file in tests
        config.general.data_dir = std::env::temp_dir()
            .join("ironpost-test")
            .to_string_lossy()
            .into_owned();

        // Disable all modules by default
        config.ebpf.enabled = false;
        config.log_pipeline.enabled = false;
        config.container.enabled = false;
        config.sbom.enabled = false;

        Self { config }
    }

    /// Enable or disable the eBPF engine module.
    pub fn ebpf(mut self, enabled: bool) -> Self {
        self.config.ebpf.enabled = enabled;
        if enabled {
            // Provide valid defaults for enabled eBPF
            self.config.ebpf.interface = "eth0".to_owned();
            self.config.ebpf.xdp_mode = "skb".to_owned();
        }
        self
    }

    /// Enable or disable the log pipeline module.
    pub fn log_pipeline(mut self, enabled: bool) -> Self {
        self.config.log_pipeline.enabled = enabled;
        self
    }

    /// Enable or disable the container guard module.
    pub fn container(mut self, enabled: bool) -> Self {
        self.config.container.enabled = enabled;
        self
    }

    /// Enable or disable the SBOM scanner module.
    pub fn sbom(mut self, enabled: bool) -> Self {
        self.config.sbom.enabled = enabled;
        if enabled {
            // Provide valid defaults for enabled SBOM
            self.config.sbom.output_format = "cyclonedx".to_owned();
            self.config.sbom.min_severity = "medium".to_owned();
        }
        self
    }

    /// Set the log level.
    pub fn log_level(mut self, level: &str) -> Self {
        self.config.general.log_level = level.to_owned();
        self
    }

    /// Set the log format.
    pub fn log_format(mut self, format: &str) -> Self {
        self.config.general.log_format = format.to_owned();
        self
    }

    /// Set the PID file path.
    pub fn pid_file(mut self, path: &str) -> Self {
        self.config.general.pid_file = path.to_owned();
        self
    }

    /// Set the batch size for the log pipeline.
    pub fn batch_size(mut self, size: usize) -> Self {
        self.config.log_pipeline.batch_size = size;
        self
    }

    /// Set the SBOM output format.
    pub fn sbom_output_format(mut self, format: &str) -> Self {
        self.config.sbom.output_format = format.to_owned();
        self
    }

    /// Set the eBPF XDP mode.
    pub fn xdp_mode(mut self, mode: &str) -> Self {
        self.config.ebpf.xdp_mode = mode.to_owned();
        self
    }

    /// Set the eBPF interface.
    pub fn ebpf_interface(mut self, interface: &str) -> Self {
        self.config.ebpf.interface = interface.to_owned();
        self
    }

    /// Set the SBOM min severity.
    pub fn sbom_min_severity(mut self, severity: &str) -> Self {
        self.config.sbom.min_severity = severity.to_owned();
        self
    }

    /// Get mutable access to the underlying config for advanced customization.
    pub fn config_mut(&mut self) -> &mut IronpostConfig {
        &mut self.config
    }

    /// Build and return the `IronpostConfig`.
    ///
    /// Note: This does NOT call `validate()`. Call `build_validated()` if you
    /// need a validated config.
    pub fn build(self) -> IronpostConfig {
        self.config
    }

    /// Build, validate, and return the `IronpostConfig`.
    ///
    /// # Panics
    ///
    /// Panics if the configuration fails validation.
    pub fn build_validated(self) -> IronpostConfig {
        let config = self.config;
        config
            .validate()
            .expect("TestConfigBuilder produced invalid config");
        config
    }
}

impl Default for TestConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Write an `IronpostConfig` to a temporary TOML file and return its path.
///
/// Uses `tempfile::NamedTempFile` which is automatically cleaned up on drop.
/// The caller must keep the returned `NamedTempFile` alive for the duration of the test.
///
/// # Panics
///
/// Panics if serialization or file writing fails.
#[allow(dead_code)]
pub fn write_config_to_tempfile(config: &IronpostConfig) -> (tempfile::NamedTempFile, PathBuf) {
    let toml_str = toml::to_string_pretty(config).expect("failed to serialize config to TOML");
    let mut file = tempfile::NamedTempFile::new().expect("failed to create temp file");
    file.write_all(toml_str.as_bytes())
        .expect("failed to write config to temp file");
    file.flush().expect("failed to flush temp file");
    let path = file.path().to_path_buf();
    (file, path)
}
