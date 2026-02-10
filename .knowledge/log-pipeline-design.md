# Log Pipeline Design Document

## 1. Overview

`ironpost-log-pipeline` is the log analysis module of the Ironpost security monitoring platform.
It collects logs from multiple sources (syslog RFC 5424, JSON, file tailing, eBPF events via
`tokio::mpsc`), parses them into a unified `LogEntry` format, runs YAML-based detection rules
(simplified Sigma style), and generates `AlertEvent` instances for downstream modules.

### Goals

- Parse Syslog RFC 5424 and structured JSON logs
- Receive `PacketEvent` from ebpf-engine via `tokio::mpsc` (assembled in `ironpost-daemon`)
- YAML-based rule engine with field matching, regex, and threshold conditions
- Buffered pipeline with configurable batch size and flush intervals
- Log rotation support for file-based collection
- Clean separation via core traits (`Pipeline`, `LogParser`, `Detector`)
- Zero direct dependency on peer crates (only `ironpost-core`)

## 2. Architecture

```
                    ironpost-daemon (assembly layer)
                    ================================
                    |  PacketEvent mpsc::Receiver   |
                    |            |                   |
                    v            v                   |
            +------ log-pipeline crate ------+       |
            |                                |       |
            |  +-----------+  +-----------+  |       |
            |  | Collector |  | Collector |  |       |
            |  | (Syslog)  |  | (File)    |  |       |
            |  +-----+-----+  +-----+-----+  |       |
            |        |              |         |       |
            |        v              v         |       |
            |  +-------------------------+   |       |
            |  |    RawLog Buffer        |   |       |
            |  | (bounded VecDeque)      |   |       |
            |  +-----------+-------------+   |       |
            |              |                 |       |
            |              v                 |       |
            |  +-------------------------+   |       |
            |  |      Parser Router      |   |       |
            |  |  Syslog | JSON | Auto   |   |       |
            |  +-----------+-------------+   |       |
            |              |                 |       |
            |              v                 |       |
            |  +-------------------------+   |       |
            |  |     Rule Engine         |   |       |
            |  | YAML rules + matching   |   |       |
            |  +-----------+-------------+   |       |
            |              |                 |       |
            |         AlertEvent             |       |
            |              |                 |       |
            |              v                 |       |
            |  +-------------------------+   |       |
            |  |   Alert Dispatcher      |   |       |
            |  | mpsc::Sender<AlertEvent>|   |       |
            |  +-------------------------+   |       |
            +--------------------------------+       |
                                                     |
                          AlertEvent -----> container-guard (via daemon)
```

## 3. Module Breakdown

### 3.1 `error.rs` -- Domain Error Types

- `LogPipelineError` enum with `thiserror`
- Variants: `Parse`, `RuleLoad`, `RuleMatch`, `Collector`, `Buffer`, `Config`, `Channel`
- `From<LogPipelineError> for IronpostError` via `PipelineError` wrapping

### 3.2 `config.rs` -- Pipeline Configuration

- `PipelineConfig` struct that maps from `ironpost_core::config::LogPipelineConfig`
- Rule directory path, buffer limits, parser selection
- Builder pattern for complex construction

### 3.3 `parser/` -- Log Parsers

- `mod.rs`: `ParserRouter` that auto-detects format or uses configured parser
- `syslog.rs`: RFC 5424 syslog parser implementing `LogParser` trait
  - Structured data extraction (SD-ID, SD-PARAM)
  - Priority (facility + severity) decoding
  - Timestamp parsing (RFC 3339 subset)
- `json.rs`: Structured JSON log parser implementing `LogParser` trait
  - Configurable field mapping (timestamp_field, message_field, etc.)
  - Nested field extraction with dot notation

### 3.4 `collector/` -- Log Collection

- `mod.rs`: `CollectorSet` managing multiple collectors
- `file.rs`: File tail collector with rotation detection (inode tracking)
- `syslog_udp.rs`: UDP syslog receiver (RFC 5424 over UDP/514)
- `syslog_tcp.rs`: TCP syslog receiver (RFC 5424 over TCP/601)
- `event_receiver.rs`: `PacketEvent` receiver from eBPF engine via `mpsc::Receiver`
  - Converts `PacketEvent` to raw log bytes for parser consumption

### 3.5 `rule/` -- Rule Engine

- `mod.rs`: `RuleEngine` coordinator
- `loader.rs`: YAML rule file loading and validation
- `matcher.rs`: Rule matching logic against `LogEntry`
- `types.rs`: Rule data structures (condition, action, metadata)

### 3.6 `buffer.rs` -- Log Buffering

- Bounded in-memory buffer (`VecDeque` with max capacity)
- Batch flush on size threshold or time interval
- Backpressure: when buffer is full, oldest entries are dropped with warning log

### 3.7 `alert.rs` -- Alert Generation

- Creates `AlertEvent` from rule match results
- Deduplication within configurable time window
- Rate limiting per rule

### 3.8 `pipeline.rs` -- Pipeline Orchestration

- `LogPipeline` struct implementing `Pipeline` trait
- Lifecycle: `start()` -> spawns collector tasks, parser workers, rule engine loop
- `stop()` -> graceful drain of buffer, cancel workers
- `health_check()` -> reports buffer utilization, parser errors, rule count

### 3.9 `lib.rs` -- Public API

- Re-exports: `LogPipeline`, `LogPipelineBuilder`, `LogPipelineError`, `PipelineConfig`
- Re-exports: `SyslogParser`, `JsonLogParser`
- Re-exports: `RuleEngine`, `DetectionRule`

## 4. Data Flow

```
1. Collection Phase
   File watcher / Syslog UDP / TCP / PacketEvent receiver
            |
            v
   Raw bytes + source metadata
            |
2. Buffering Phase
            |
            v
   RawLogBuffer (bounded VecDeque)
   - Batch when: count >= batch_size OR elapsed >= flush_interval
            |
3. Parsing Phase
            |
            v
   ParserRouter selects parser (auto-detect or configured)
   -> SyslogParser / JsonLogParser
   -> Result<LogEntry, ParseError>
   - Parse failures: logged + counted, entry skipped
            |
4. Rule Matching Phase
            |
            v
   RuleEngine.evaluate(entry) -> Vec<RuleMatch>
   - Each rule: field conditions (exact/regex/contains)
   - Threshold rules: N matches within T seconds
            |
5. Alert Generation Phase
            |
            v
   AlertGenerator.generate(rule_match, entry) -> AlertEvent
   - Deduplication check
   - Rate limit check
   - Severity mapping from rule definition
            |
6. Dispatch Phase
            |
            v
   mpsc::Sender<AlertEvent> -> downstream (container-guard, storage)
```

## 5. Rule Engine Design

### 5.1 YAML Rule Schema (Simplified Sigma)

```yaml
id: ssh_brute_force
title: SSH Brute Force Attempt
description: Detects multiple failed SSH login attempts from same source
severity: high
status: enabled

# Match conditions (AND logic within a detection block)
detection:
  # Field matching conditions
  condition:
    process: sshd
    message|contains: "Failed password"

  # Optional: threshold for correlation
  threshold:
    field: source_ip       # group by this field
    count: 5               # minimum matches
    timeframe: 300         # within N seconds

# What to include in the alert
alert:
  title: "SSH Brute Force from {source_ip}"
  description: "Detected {count} failed SSH login attempts"

# Optional: tags for categorization
tags:
  - authentication
  - brute_force
  - ssh
```

### 5.2 Condition Modifiers

| Modifier | Example | Description |
|----------|---------|-------------|
| (none) | `process: sshd` | Exact match |
| `|contains` | `message|contains: "Failed"` | Substring match |
| `|startswith` | `hostname|startswith: "web-"` | Prefix match |
| `|endswith` | `source|endswith: ".log"` | Suffix match |
| `|regex` | `message|regex: "Failed.*root"` | Regex match |
| `|gt` | `severity|gt: medium` | Greater than (for ordered fields) |

### 5.3 Matching Algorithm

1. Load rules from YAML directory on startup
2. For each `LogEntry`:
   a. Evaluate each enabled rule's conditions against entry fields
   b. All conditions in a detection block must match (AND logic)
   c. If threshold is defined, maintain per-group counters in a time window
   d. On match: create `RuleMatch` with matched rule + entry reference
3. Rules are evaluated in priority order (Critical > High > Medium > Low > Info)
4. Short-circuit: stop evaluating lower-priority rules after first Critical match (configurable)

### 5.4 Rule Hot-Reload

- Watch rule directory with `tokio::watch` for config changes
- Reload rules without pipeline restart
- Validate new rules before replacing active ruleset

## 6. Buffer and Rotation Strategy

### 6.1 In-Memory Buffer

- `RawLogBuffer`: bounded `VecDeque<RawLog>` with configurable max capacity
- Default: 10,000 entries
- When full: drop oldest entry + increment drop counter + `tracing::warn!`
- Flush trigger: `batch_size` reached OR `flush_interval` elapsed (whichever first)

### 6.2 File Rotation Detection

- Track file by `(dev, inode)` on Unix systems
- Periodic stat check (every 1 second)
- When inode changes: finish reading old file, open new file at offset 0
- Handle truncation: if file size < last read position, reset to beginning

## 7. Error Handling

### 7.1 Error Categories

| Category | Behavior | Example |
|----------|----------|---------|
| Parse failure | Log + skip entry | Malformed syslog line |
| Rule load failure | Log + continue with existing rules | Invalid YAML syntax |
| Collector I/O error | Log + retry with backoff | File permission denied |
| Channel send failure | Log + drop event | Downstream receiver closed |
| Buffer overflow | Drop oldest + warn | Burst of log entries |
| Config error | Fail startup | Invalid syslog bind address |

### 7.2 Recovery Strategy

- Collectors: exponential backoff retry (1s, 2s, 4s, ... max 60s)
- Parser: skip unparseable entries, maintain error counter
- Rule engine: continue with last valid ruleset
- Buffer: drop oldest policy (configurable to drop newest as alternative)

## 8. Integration Points

### 8.1 With Core Crate

- Implements `Pipeline` trait for lifecycle management
- Implements `LogParser` trait for syslog/JSON parsers
- Uses `LogEvent`, `AlertEvent`, `EventMetadata` types
- Uses `LogEntry`, `Alert`, `Severity` domain types
- Error conversion: `LogPipelineError` -> `PipelineError` -> `IronpostError`
- Configuration: reads `LogPipelineConfig` section from `IronpostConfig`

### 8.2 With eBPF Engine (via daemon)

- Receives `PacketEvent` through `tokio::mpsc::Receiver<PacketEvent>`
- Channel is wired in `ironpost-daemon` -- no direct crate dependency
- PacketEvent is converted to enriched log entry for rule matching

### 8.3 With Container Guard (via daemon)

- Sends `AlertEvent` through `tokio::mpsc::Sender<AlertEvent>`
- Channel is wired in `ironpost-daemon`

## 9. Configuration Schema

```toml
[log_pipeline]
enabled = true
sources = ["syslog", "file"]
syslog_bind = "0.0.0.0:514"
watch_paths = ["/var/log/syslog", "/var/log/auth.log"]
batch_size = 100
flush_interval_secs = 5

# Rule engine settings (extended from core config)
rule_dir = "/etc/ironpost/rules"
rule_reload_secs = 30

# Buffer settings
buffer_capacity = 10000
drop_policy = "oldest"   # "oldest" or "newest"

# Alert settings
alert_dedup_window_secs = 60
alert_rate_limit_per_rule = 10  # max alerts per rule per minute
```

## 10. Performance Considerations

### 10.1 Hot Path Optimization

- Parser: `nom` combinators for zero-copy parsing where possible
- Buffer: `VecDeque` with pre-allocated capacity
- Rule matching: pre-compile regex patterns at rule load time
- Field access: consider converting `LogEntry.fields` to `HashMap` for O(1) lookup
  (addresses Phase 1 review W7)

### 10.2 Concurrency Model

- Each collector runs in its own tokio task
- Parser workers: configurable count (default: number of CPU cores)
  - CPU-bound parsing via `tokio::task::spawn_blocking`
- Rule engine: single-threaded to avoid lock contention on counters
- Alert dispatch: async send through mpsc channel

### 10.3 Memory Budget

- Buffer: max `buffer_capacity * avg_entry_size` (estimated ~1KB/entry = ~10MB default)
- Rule engine threshold counters: bounded by `MAX_TRACKED_GROUPS` per rule
- Regex patterns: compiled once, shared via `Arc`

### 10.4 Backpressure

- Bounded mpsc channels at every stage
- Buffer overflow: drop + warn (not block)
- Parser slow: entries accumulate in buffer up to capacity
- Rule engine slow: parsed entries wait in channel
