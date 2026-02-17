#![no_main]

use ironpost_core::pipeline::LogParser;
use ironpost_log_pipeline::parser::JsonLogParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parser = JsonLogParser::default();
    let _ = parser.parse(data);
});
