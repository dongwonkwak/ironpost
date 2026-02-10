//! Output formatting abstraction for text vs JSON rendering
//!
//! All subcommand output flows through [`OutputWriter`] which handles format switching.
//! This keeps format-specific logic out of command handlers entirely.

use std::io::Write;

use serde::Serialize;

use crate::cli::OutputFormat;
use crate::error::CliError;

/// Abstraction for writing CLI output in different formats.
///
/// Subcommand handlers call `writer.render(&payload)` where `payload`
/// implements both `Serialize` (for JSON) and `Render` (for text).
pub struct OutputWriter {
    format: OutputFormat,
}

impl OutputWriter {
    pub fn new(format: OutputFormat) -> Self {
        Self { format }
    }

    /// Render a payload to stdout.
    ///
    /// For `Text` format, delegates to `Render::render_text()`.
    /// For `Json` format, serialises via `serde_json`.
    pub fn render<T: Render + Serialize>(&self, payload: &T) -> Result<(), CliError> {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        match self.format {
            OutputFormat::Text => {
                payload.render_text(&mut handle)?;
            }
            OutputFormat::Json => {
                serde_json::to_writer_pretty(&mut handle, payload)?;
                writeln!(handle)?;
            }
        }
        Ok(())
    }
}

/// Trait for human-readable text rendering.
///
/// Implemented by every CLI output payload alongside `serde::Serialize`.
pub trait Render {
    fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()>;
}
