#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_sbom_scanner::parser::LockfileParser;
use ironpost_sbom_scanner::parser::npm::NpmLockParser;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        let parser = NpmLockParser;
        let _ = parser.parse(content, "fuzz/package-lock.json");
    }
});
