#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_sbom_scanner::parser::LockfileParser;
use ironpost_sbom_scanner::parser::cargo::CargoLockParser;

fuzz_target!(|data: &[u8]| {
    if let Ok(content) = std::str::from_utf8(data) {
        let parser = CargoLockParser;
        let _ = parser.parse(content, "fuzz/Cargo.lock");
    }
});
