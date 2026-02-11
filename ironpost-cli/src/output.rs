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
    /// Create a new output writer with the specified format.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ironpost_cli::output::{OutputWriter};
    /// use ironpost_cli::cli::OutputFormat;
    ///
    /// let writer = OutputWriter::new(OutputFormat::Text);
    /// ```
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct TestPayload {
        field1: String,
        field2: u32,
    }

    impl Render for TestPayload {
        fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
            writeln!(w, "Field1: {}", self.field1)?;
            writeln!(w, "Field2: {}", self.field2)?;
            Ok(())
        }
    }

    #[test]
    fn test_output_writer_text_format() {
        let _writer = OutputWriter::new(OutputFormat::Text);
        let payload = TestPayload {
            field1: "test value".to_owned(),
            field2: 42,
        };

        let mut buffer = Vec::new();
        payload
            .render_text(&mut buffer)
            .expect("text rendering should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(
            output.contains("Field1: test value"),
            "should render field1"
        );
        assert!(output.contains("Field2: 42"), "should render field2");
    }

    #[test]
    fn test_output_writer_json_format_structure() {
        let payload = TestPayload {
            field1: "test".to_owned(),
            field2: 100,
        };

        let json = serde_json::to_string(&payload).expect("json serialization should succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("should parse back to JSON");

        assert_eq!(
            parsed["field1"].as_str(),
            Some("test"),
            "field1 should be in JSON"
        );
        assert_eq!(
            parsed["field2"].as_u64(),
            Some(100),
            "field2 should be in JSON"
        );
    }

    #[test]
    fn test_output_writer_json_pretty_formatting() {
        let payload = TestPayload {
            field1: "value".to_owned(),
            field2: 1,
        };

        let json = serde_json::to_string_pretty(&payload).expect("pretty JSON should succeed");
        assert!(json.contains('\n'), "pretty JSON should contain newlines");
        assert!(
            json.contains("  "),
            "pretty JSON should contain indentation"
        );
    }

    #[test]
    fn test_render_text_empty_payload() {
        #[derive(Serialize)]
        struct EmptyPayload;

        impl Render for EmptyPayload {
            fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
                writeln!(w, "Empty")?;
                Ok(())
            }
        }

        let payload = EmptyPayload;
        let mut buffer = Vec::new();
        payload
            .render_text(&mut buffer)
            .expect("rendering empty payload should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert_eq!(output.trim(), "Empty");
    }

    #[test]
    fn test_render_text_with_special_characters() {
        #[derive(Serialize)]
        struct SpecialPayload {
            text: String,
        }

        impl Render for SpecialPayload {
            fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
                writeln!(w, "{}", self.text)?;
                Ok(())
            }
        }

        let payload = SpecialPayload {
            text: "Line 1\nLine 2\tTabbed\r\nWindows line".to_owned(),
        };

        let mut buffer = Vec::new();
        payload
            .render_text(&mut buffer)
            .expect("rendering special chars should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("Line 1"));
        assert!(output.contains("Line 2"));
    }

    #[test]
    fn test_render_text_unicode_content() {
        #[derive(Serialize)]
        struct UnicodePayload {
            text: String,
        }

        impl Render for UnicodePayload {
            fn render_text(&self, w: &mut dyn Write) -> std::io::Result<()> {
                writeln!(w, "{}", self.text)?;
                Ok(())
            }
        }

        let payload = UnicodePayload {
            text: "Unicode: 日本語 한글 العربية 🦀".to_owned(),
        };

        let mut buffer = Vec::new();
        payload
            .render_text(&mut buffer)
            .expect("rendering unicode should succeed");

        let output = String::from_utf8(buffer).expect("valid UTF-8");
        assert!(output.contains("Unicode:"));
        assert!(output.contains("日本語"));
        assert!(output.contains("🦀"));
    }

    #[test]
    fn test_json_serialization_with_nested_struct() {
        #[derive(Serialize)]
        struct Nested {
            inner: String,
        }

        #[derive(Serialize)]
        struct Parent {
            outer: String,
            nested: Nested,
        }

        let payload = Parent {
            outer: "outer".to_owned(),
            nested: Nested {
                inner: "inner".to_owned(),
            },
        };

        let json = serde_json::to_string(&payload).expect("nested serialization should succeed");
        assert!(json.contains("outer"));
        assert!(json.contains("inner"));
        assert!(json.contains("nested"));
    }

    #[test]
    fn test_json_serialization_with_vec() {
        #[derive(Serialize)]
        struct ListPayload {
            items: Vec<String>,
        }

        let payload = ListPayload {
            items: vec!["item1".to_owned(), "item2".to_owned(), "item3".to_owned()],
        };

        let json = serde_json::to_string(&payload).expect("vec serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        let items = parsed["items"].as_array().expect("items should be array");
        assert_eq!(items.len(), 3, "should have 3 items");
    }

    #[test]
    fn test_json_serialization_with_option_some() {
        #[derive(Serialize)]
        struct OptionalPayload {
            value: Option<String>,
        }

        let payload = OptionalPayload {
            value: Some("present".to_owned()),
        };

        let json = serde_json::to_string(&payload).expect("option serialization should succeed");
        assert!(json.contains("present"));
    }

    #[test]
    fn test_json_serialization_with_option_none() {
        #[derive(Serialize)]
        struct OptionalPayload {
            value: Option<String>,
        }

        let payload = OptionalPayload { value: None };

        let json = serde_json::to_string(&payload).expect("option serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse JSON");

        assert!(parsed["value"].is_null(), "None should be null in JSON");
    }
}
