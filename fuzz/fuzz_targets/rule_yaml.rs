#![no_main]

use ironpost_log_pipeline::rule::RuleLoader;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // YAML 파서는 &str을 받으므로 UTF-8 변환 필요
    if let Ok(yaml_str) = std::str::from_utf8(data) {
        let _ = RuleLoader::parse_yaml(yaml_str, "fuzz-input.yml");
    }
});
