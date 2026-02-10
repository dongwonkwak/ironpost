# ironpost-container-guard

Ironpost container guard -- Docker container monitoring, policy-based isolation, and network control.

## Overview

This crate provides security monitoring and automatic isolation for Docker containers.
It receives `AlertEvent` messages from other Ironpost modules (ebpf-engine, log-pipeline)
via `tokio::mpsc` channels and evaluates security policies to determine whether to
isolate the target container.

## Features

- Docker container lifecycle event watching (create, start, stop, delete)
- Security policy-based container isolation (network disconnect, pause, stop)
- Automatic response to security alerts from ebpf-engine and log-pipeline
- Docker API integration via the `bollard` crate
- Configurable retry and timeout for isolation actions
- Container inventory caching with TTL

## Architecture

```text
AlertEvent --mpsc--> ContainerGuard
                         |
                    PolicyEngine.evaluate()
                         |
                    IsolationExecutor.execute()
                         |
                    ActionEvent --mpsc--> downstream
```
