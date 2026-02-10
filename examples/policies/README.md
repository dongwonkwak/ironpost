# Ironpost Container Guard - Example Policies

This directory contains example security policies for the Ironpost container guard module.

## Policy Structure

Each policy is defined in a TOML file with the following structure:

```toml
id = "unique-policy-id"
name = "Human-Readable Policy Name"
description = "Detailed description of what this policy does"
enabled = true  # or false
severity_threshold = "Critical"  # Info, Low, Medium, High, Critical
priority = 1  # Lower number = higher priority

[target_filter]
container_names = ["pattern-*"]  # Glob patterns
image_patterns = ["nginx:*"]     # Glob patterns
labels = []                       # Label selectors (future)

[action]
# One of:
NetworkDisconnect = { networks = ["bridge", "host"] }
# Pause = []
# Stop = []
```

## Available Policies

### 1. critical-network-isolate.toml
- **Severity Threshold**: Critical
- **Action**: Disconnect from networks
- **Target**: Containers with names matching `compromised-*` or `suspicious-*`
- **Use Case**: Immediate network isolation for critical security incidents

### 2. high-web-pause.toml
- **Severity Threshold**: High
- **Action**: Pause container
- **Target**: Web servers (nginx, apache)
- **Use Case**: Freeze suspicious web containers for investigation

### 3. medium-database-stop.toml
- **Severity Threshold**: Medium
- **Action**: Stop container
- **Target**: Database containers
- **Use Case**: Complete shutdown of potentially compromised databases
- **Note**: Disabled by default due to service impact

## Policy Evaluation

Policies are evaluated in priority order (lowest number first):
1. First matching policy wins (short-circuit evaluation)
2. Policy must be `enabled = true`
3. Alert severity must meet or exceed `severity_threshold`
4. Container must match `target_filter` patterns

## Target Filter Matching

- **container_names**: Glob patterns matched against container name
  - `*` matches any characters
  - `?` matches single character
  - Examples: `"web-*"`, `"nginx-?"`, `"*-prod"`

- **image_patterns**: Glob patterns matched against image name
  - Examples: `"nginx:*"`, `"postgres:1?.?"`, `"*/redis:*"`

- **Empty filters**: Empty array matches all containers

- **Multiple patterns**: OR logic within a field, AND logic between fields
  - `container_names = ["web-*", "api-*"]` → matches web-1 OR api-1
  - Both container_names AND image_patterns must match if both are set

## Loading Policies

### From Directory (Recommended)
```rust
use ironpost_container_guard::load_policies_from_dir;
use std::path::Path;

let policies = load_policies_from_dir(Path::new("/etc/ironpost/policies"))?;
for policy in policies {
    policy_engine.add_policy(policy)?;
}
```

### From Single File
```rust
use ironpost_container_guard::load_policy_from_file;
use std::path::Path;

let policy = load_policy_from_file(Path::new("my-policy.toml"))?;
policy_engine.add_policy(policy)?;
```

## Best Practices

1. **Start Conservative**: Begin with `enabled = false` for aggressive policies
2. **Test Thoroughly**: Verify policies in development before production
3. **Priority Ordering**: Lower priority (higher number) for less critical policies
4. **Severity Matching**: Use appropriate thresholds (Critical > High > Medium > Low)
5. **Target Specificity**: Narrow filters reduce false positives
6. **Document Actions**: Clear descriptions help incident response

## Action Types

### NetworkDisconnect
- **Effect**: Disconnects container from specified networks
- **Impact**: Container loses network connectivity but continues running
- **Recovery**: Manually reconnect networks or restart container
- **Use Case**: Isolate suspicious network activity

### Pause
- **Effect**: Pauses container processes (SIGSTOP to all processes)
- **Impact**: Container state frozen, no CPU usage
- **Recovery**: Unpause container or restart
- **Use Case**: Preserve state for forensic analysis

### Stop
- **Effect**: Gracefully stops container (SIGTERM + SIGKILL after timeout)
- **Impact**: Container completely stopped, must be restarted
- **Recovery**: Restart container manually
- **Use Case**: Complete isolation when other methods insufficient

## Configuration

Set the policy directory in `ironpost.toml`:

```toml
[container]
enabled = true
policy_path = "/etc/ironpost/policies"
auto_isolate = true
```

Or via environment variable:
```bash
export IRONPOST_CONTAINER_POLICY_PATH="/etc/ironpost/policies"
```

## Troubleshooting

### Policy Not Loading
- Check file has `.toml` extension
- Verify TOML syntax is valid
- Check logs for parsing errors
- Ensure policy passes validation (non-empty id, name)

### Policy Not Matching
- Verify policy is `enabled = true`
- Check alert severity meets threshold
- Verify glob patterns match container name/image
- Check policy priority order (lower first)

### Action Fails
- Verify Docker socket permissions
- Check container exists and is running
- Review container-guard logs for error details
- Ensure network names are correct for NetworkDisconnect

## Further Reading

- [Container Guard Design](../../.knowledge/container-guard-design.md)
- [Phase 4 Implementation Plan](../../.tasks/plans/phase-4-container.md)
- [Ironpost Core Documentation](../../crates/core/README.md)
