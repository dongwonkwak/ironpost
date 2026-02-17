#![no_main]

use ironpost_core::pipeline::LogParser;
use ironpost_log_pipeline::parser::SyslogParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let parser = SyslogParser::new();

    // 크래시나 패닉 없이 Ok 또는 Err을 반환해야 한다
    let _ = parser.parse(data);
});
