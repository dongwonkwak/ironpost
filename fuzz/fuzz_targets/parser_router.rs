#![no_main]

use libfuzzer_sys::fuzz_target;
use ironpost_log_pipeline::parser::ParserRouter;

fuzz_target!(|data: &[u8]| {
    let router = ParserRouter::with_defaults();
    let _ = router.parse(data);
});
