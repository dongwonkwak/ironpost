#![no_main]

use ironpost_log_pipeline::parser::ParserRouter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let router = ParserRouter::with_defaults();
    let _ = router.parse(data);
});
