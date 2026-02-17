#![no_main]

use ironpost_sbom_scanner::parser::npm::NpmLockParser;
use ironpost_sbom_scanner::parser::LockfileParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        let parser = NpmLockParser;
        let _ = parser.parse(content, "fuzz/package-lock.json");
    }
});
