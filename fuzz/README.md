# Fuzzing Infrastructure

This directory contains fuzzing targets for Ironpost, using [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) to discover security vulnerabilities and edge cases.

## Overview

Ironpost uses libFuzzer to fuzz critical components:

- **syslog_parser**: RFC 5424/3164 syslog parsing with UTF-8 handling
- **json_parser**: JSON log parsing with arbitrary input handling
- **parser_router**: Log format detection and routing
- **rule_yaml**: YAML rule parsing and validation
- **rule_matcher**: Log pattern matching and rule evaluation
- **cargo_lock**: Cargo.lock dependency parsing
- **npm_lock**: NPM package-lock.json parsing
- **sbom_roundtrip**: SBOM serialization/deserialization

## Quick Start

### Prerequisites

Ensure you have the nightly Rust toolchain installed:

```bash
rustup toolchain add nightly
rustup component add rust-src --toolchain nightly
```

### Running Fuzzing Locally

To fuzz a specific target for 30 seconds:

```bash
cd fuzz
cargo +nightly fuzz run -s none <target> -- -max_total_time=30
```

Available targets:
- `fuzz_syslog_parser`
- `fuzz_json_parser`
- `fuzz_parser_router`
- `fuzz_rule_yaml`
- `fuzz_rule_matcher`
- `fuzz_cargo_lock`
- `fuzz_npm_lock`
- `fuzz_sbom_roundtrip`

Example:

```bash
# Fuzz syslog parser for 30 seconds
cargo +nightly fuzz run -s none fuzz_syslog_parser -- -max_total_time=30

# Fuzz with a specific corpus
cargo +nightly fuzz run -s none fuzz_json_parser -- corpus/fuzz_json_parser -max_total_time=60
```

### Running All Targets

Use the provided helper script to run all fuzzing targets sequentially:

```bash
bash run_fuzz_all.sh
```

This runs all 8 targets sequentially for 30 seconds each by default.
To change duration:
```bash
bash run_fuzz_all.sh 60
```

## Understanding Crashes

When a crash is found, libFuzzer creates a minimized crash file in `artifacts/<target>/crash-*`.

### Crash Handling Procedure

1. **Locate the crash file**:
   ```bash
   ls -la fuzz/artifacts/fuzz_syslog_parser/
   ```

2. **Minimize the crash** (optional, libFuzzer usually does this):
   ```bash
   cargo +nightly fuzz tmin -s none fuzz_syslog_parser fuzz/artifacts/fuzz_syslog_parser/crash-<hash>
   ```

3. **Inspect the crash file**:
   ```bash
   xxd fuzz/artifacts/fuzz_syslog_parser/crash-<hash> | head -20
   ```

4. **Add a regression test** to ensure the bug doesn't resurface:
   - Create a test case in the parser's test module with the crash input
   - Verify it now passes (doesn't panic)
   - Add it to `crates/<module>/src/<parser>.rs` under `#[cfg(test)]`

5. **Fix the underlying issue**:
   - Identify the root cause in the parser code
   - Implement a fix following Ironpost's code guidelines
   - Ensure error handling is robust (use `?` or `.map_err()` appropriately)

6. **Verify the fix**:
   ```bash
   cargo test -p <package>
   cargo +nightly fuzz run -s none <target> artifacts/<target>/crash-<hash>
   ```
   The target should complete without crashing.

7. **Clean up**:
   ```bash
   rm fuzz/artifacts/<target>/crash-*
   ```

### Example: UTF-8 Crash in Syslog Parser

**Issue**: Panic at `syslog.rs:389` when multibyte UTF-8 char appears at structured data boundary

**Crash input**: Syslog message with `\xff\xfe` (invalid UTF-8) in structured data

**Root cause**: Using `idx + 1` instead of `idx + ch.len_utf8()` when tracking position through Unicode characters

**Fix**: Updated boundary calculation to account for multibyte UTF-8 sequences

**Regression test** added in `crates/log-pipeline/src/parser/syslog.rs::tests`:
```rust
#[test]
fn parse_structured_data_with_invalid_utf8_in_sd() {
    let parser = SyslogParser::new();
    let mut raw = Vec::from(&b"<34>1 2024-01-15T12:00:00Z host app - - ["[..]);
    raw.extend_from_slice(&[0xff, 0xfe]);
    raw.extend_from_slice(b"] msg");
    let result = parser.parse(&raw);
    let _ = result;  // Should not panic
}
```

## Corpus Management

The fuzzing corpus (test inputs) is stored in `corpus/<target>/` directories.

### Preserving Corpus Across Runs

Useful inputs are automatically added to the corpus:
- Coverage-increasing inputs
- Edge cases discovered during fuzzing
- Regression test cases

To manually add an input:
```bash
cp my_input.txt corpus/fuzz_syslog_parser/
```

### Caching Corpus in CI

The GitHub Actions workflow caches corpus between runs to speed up fuzzing:

```yaml
- uses: actions/cache@v4
  with:
    path: fuzz/corpus/${{ matrix.target }}
    key: fuzz-corpus-${{ matrix.target }}-${{ github.run_id }}
```

This ensures that interesting inputs discovered in one run are available for future runs.

## Adding a New Fuzzing Target

To add a new fuzzing target:

1. **Create the target file**:
   ```bash
   cargo +nightly fuzz add fuzz_my_new_parser
   ```

2. **Implement the fuzz target** in `fuzz/fuzz_targets/fuzz_my_new_parser.rs`:
   ```rust
   #![no_main]
   use ironpost_core::pipeline::LogParser;
   use libfuzzer_sys::fuzz_target;
   use ironpost_log_pipeline::parser::JsonLogParser;

   fuzz_target!(|data: &[u8]| {
       let parser = JsonLogParser::default();
       let _ = parser.parse(data);
   });
   ```

3. **Test it locally**:
   ```bash
   cargo +nightly fuzz run fuzz_my_new_parser -- -max_total_time=10
   ```

4. **Update the workflow** in `.github/workflows/fuzz.yml`:
   - Add target to the `matrix.target` list

5. **Document it** in this README

## Known Issues and Limitations

### ASAN Compatibility

The fuzzing targets use `-s none` flag to disable Address Sanitizer due to LLVM version mismatches in some environments. This is specified in both local runs and CI workflows.

### Performance

- Fuzzing is resource-intensive and CPU-bound
- Each target runs for 5 minutes in CI (300 seconds)
- Local fuzzing should be run for shorter durations (30-60 seconds) for development
- Consider lowering `-max_total_time` (e.g. 10-30s) for faster iteration

### Platform Support

Fuzzing targets build on Linux, macOS, and Windows but are optimized for Linux (CI environment).

## Troubleshooting

### Compilation Issues

If you encounter `error[E0433]: cannot find crate 'fuzz_target'`:
- Ensure you're using `cargo +nightly`
- Update rust-src: `rustup component add rust-src --toolchain nightly`

### LLVM Errors

If LLVM compilation fails:
- Use `-s none` flag to disable Address Sanitizer
- Ensure nightly toolchain is up to date: `rustup update nightly`

### Out of Memory

If fuzzing consumes too much memory:
- Reduce `-max_total_time` or use `-max_len` to limit input size
- Run on a machine with more available memory
- Consider running targets sequentially instead of parallel

## CI Integration

The `.github/workflows/fuzz.yml` workflow:

- Runs on a schedule (daily at 2 AM UTC)
- Can be triggered manually with `workflow_dispatch`
- Runs all 8 targets in parallel with 5-minute timeout each
- Uploads crash artifacts for analysis
- Fails the job if crashes are found
- Caches corpus for faster subsequent runs

To view fuzzing results:
1. Go to GitHub Actions → Fuzzing workflow
2. Check recent runs for crash artifacts
3. Download artifacts to investigate crashes locally

## References

- [cargo-fuzz documentation](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer/)
- [Rust Fuzzing Book](https://rust-fuzz.github.io/book/)
- Ironpost [CLAUDE.md](../CLAUDE.md) for code guidelines
