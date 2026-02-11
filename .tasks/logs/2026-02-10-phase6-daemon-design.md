# Phase 6: ironpost-daemon Architecture Design

- **Task**: T6-1 (design portion)
- **Agent**: architect
- **Date**: 2026-02-10
- **Duration**: ~60 min

## What was done

1. **Read all crate public APIs** to understand channel patterns and builder APIs:
   - `ironpost-core`: Pipeline/DynPipeline traits, Event types, IronpostConfig, error hierarchy
   - `ironpost-ebpf-engine`: EbpfEngine + Builder, PacketEvent output channel
   - `ironpost-log-pipeline`: LogPipeline + Builder, PacketEvent input / AlertEvent output
   - `ironpost-sbom-scanner`: SbomScanner + Builder, AlertEvent output
   - `ironpost-container-guard`: ContainerGuard + Builder, AlertEvent input / ActionEvent output

2. **Analyzed existing daemon code** (`ironpost-daemon/src/main.rs`):
   - Current skeleton only wires log-pipeline + container-guard
   - Missing: eBPF engine, SBOM scanner, config loading, graceful shutdown, health check, CLI

3. **Designed complete daemon architecture**:
   - Channel topology (packet, alert, action channels)
   - Alert channel merging (log-pipeline + sbom-scanner -> single alert_rx)
   - Module registry with ordered start/stop
   - Error isolation strategy
   - Health check aggregation

4. **Created deliverables**:
   - `.knowledge/daemon-design.md` -- comprehensive design document (300+ lines)
   - `ironpost.toml.example` -- complete configuration file with comments
   - `ironpost-daemon/Cargo.toml` -- updated with clap, serde, serde_json dependencies
   - `ironpost-daemon/src/main.rs` -- entry point with CLI parsing and config loading
   - `ironpost-daemon/src/cli.rs` -- clap derive CLI definitions
   - `ironpost-daemon/src/orchestrator.rs` -- module assembly and lifecycle management
   - `ironpost-daemon/src/health.rs` -- aggregated health check types and functions
   - `ironpost-daemon/src/logging.rs` -- tracing-subscriber initialization
   - `ironpost-daemon/src/modules/mod.rs` -- ModuleHandle, ModuleRegistry
   - `ironpost-daemon/src/modules/ebpf.rs` -- eBPF engine init (Linux only)
   - `ironpost-daemon/src/modules/log_pipeline.rs` -- log pipeline init
   - `ironpost-daemon/src/modules/container_guard.rs` -- container guard init
   - `ironpost-daemon/src/modules/sbom_scanner.rs` -- SBOM scanner init

## Files created/modified

- `.knowledge/daemon-design.md` (NEW)
- `ironpost.toml.example` (NEW)
- `ironpost-daemon/Cargo.toml` (MODIFIED)
- `ironpost-daemon/src/main.rs` (REWRITTEN)
- `ironpost-daemon/src/cli.rs` (NEW)
- `ironpost-daemon/src/orchestrator.rs` (NEW)
- `ironpost-daemon/src/health.rs` (NEW)
- `ironpost-daemon/src/logging.rs` (NEW)
- `ironpost-daemon/src/modules/mod.rs` (NEW)
- `ironpost-daemon/src/modules/ebpf.rs` (NEW)
- `ironpost-daemon/src/modules/log_pipeline.rs` (NEW)
- `ironpost-daemon/src/modules/container_guard.rs` (NEW)
- `ironpost-daemon/src/modules/sbom_scanner.rs` (NEW)

## Key Design Decisions

1. **Single alert channel**: Both log-pipeline and sbom-scanner share one alert_tx.
   Container-guard consumes from the shared alert_rx. This is simpler than having
   separate channels and a multiplexer.

2. **ModuleRegistry**: Tracks modules in registration order (producers first).
   start_all() iterates forward, stop_all() iterates backward. This ensures
   producers stop before consumers for clean event draining.

3. **DynPipeline**: All modules are boxed as `Box<dyn DynPipeline>` for uniform
   lifecycle management. The blanket impl in core automatically converts any
   `Pipeline` implementor into `DynPipeline`.

4. **Error isolation via Result, not panic**: With `panic = "abort"` in Cargo.toml,
   panics terminate the process. The daemon relies on `Result` propagation and
   health check degradation rather than panic catching.

5. **Conditional eBPF**: The eBPF module is behind `#[cfg(target_os = "linux")]`
   at the module level, so the daemon compiles cleanly on macOS.

## Next steps

- T6-1 implementation: Fill in `todo!()` bodies in all daemon modules
- T6-3: ironpost.toml integration tests
