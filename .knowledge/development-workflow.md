# Development Workflow - Cross-Platform Strategy

## Overview

Ironpost는 macOS에서 개발하고 Linux에서 검증하는 하이브리드 접근을 권장합니다.

## 1. Daily Development (macOS)

### Environment Setup
```bash
# 현재 macOS 환경 그대로 사용
rustup default stable
cargo install cargo-watch
```

### Development Loop
```bash
# 빠른 체크 (macOS에서)
cargo check --workspace
cargo test --workspace --lib
cargo clippy --workspace -- -D warnings

# Auto-reload 개발
cargo watch -x check -x test
```

### What Works on macOS
- ✅ Core library (완전 테스트)
- ✅ Log Pipeline (완전 테스트)
- ✅ Container Guard (Docker Desktop 필요)
- ✅ SBOM Scanner (완전 테스트)
- ⚠️ eBPF Engine (컴파일만, 실행 불가)

## 2. Linux Testing (VM/Container)

### Option A: Docker Dev Container (추천)

**Dockerfile.dev**
```dockerfile
FROM rust:1.83-bookworm

# eBPF 개발 도구 설치
RUN apt-get update && apt-get install -y \
    linux-headers-generic \
    clang \
    llvm \
    libelf-dev \
    bpftool \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
```

**사용법:**
```bash
# Linux 컨테이너 시작 (privileged 필요)
docker run -it --rm \
  --privileged \
  --network host \
  -v $(pwd):/workspace \
  -v /sys/kernel/debug:/sys/kernel/debug:ro \
  rust:1.83-bookworm bash

# 컨테이너 내에서 eBPF 테스트
cd /workspace
cargo test --package ironpost-ebpf-engine
cargo run --package ironpost-daemon
```

### Option B: Multipass VM

```bash
# Ubuntu VM 생성 (macOS에서)
multipass launch --name ironpost-dev --cpus 4 --memory 8G --disk 50G

# VM 접속
multipass shell ironpost-dev

# 코드 동기화 (자동)
multipass mount $(pwd) ironpost-dev:/home/ubuntu/ironpost
```

### Option C: Cloud Development (필요시)

```bash
# EC2/GCE/Azure VM으로 SSH 개발
# VS Code Remote-SSH로 원격 개발 가능
```

## 3. Testing Strategy

### Unit Tests (macOS)
```bash
# 모든 라이브러리 유닛 테스트 (eBPF 제외)
cargo test --workspace --lib
```

### Integration Tests (Linux 필요)
```bash
# eBPF 통합 테스트는 Linux VM에서만
cargo test --package ironpost-ebpf-engine --test '*'
```

### E2E Tests (Linux 필수)
```bash
# 전체 시스템 통합 테스트
cd tests/e2e
docker compose up --abort-on-container-exit
```

## 4. CI/CD Pipeline

GitHub Actions에서 자동으로 두 플랫폼 테스트:

```yaml
# .github/workflows/ci.yml
jobs:
  test-macos:
    runs-on: macos-latest
    steps:
      - run: cargo test --workspace  # eBPF 포함 (조건부 컴파일로 Linux 전용 코드 자동 제외)

  test-linux:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test --workspace  # eBPF 포함
```

## 5. Development Phases

### Phase 6 (현재): Integration & Polish
- **주 환경**: macOS (orchestrator, daemon, CLI)
- **Linux 검증**: 주 1-2회 VM/컨테이너 테스트
- **작업**: daemon 통합, CLI 구현, 문서 완성, 리뷰 수정 반영

### 향후 계획 (Phase 6 이후)
Phase 6 완료 후 다음 단계는 필요에 따라 계획됩니다:
- E2E 통합 테스트 (Docker Compose 환경)
- 성능 튜닝 및 벤치마크
- 프로덕션 배포 준비

## 6. Recommended Setup (현재)

```bash
# macOS에서 일상 개발
export IRONPOST_DEV_ENV=macos
cargo watch -x 'test --workspace --lib'

# 필요시 Linux 검증 (일주일에 1-2회)
multipass shell ironpost-dev
cd ironpost
cargo test --workspace
cargo run --package ironpost-daemon -- --config ironpost.toml.example
```

## 7. Quick Reference

| Task | Environment | Frequency |
|------|-------------|-----------|
| 코드 작성/리팩토링 | macOS | 매일 |
| 단위 테스트 | macOS | 매 커밋 |
| Container Guard 테스트 | macOS | 관련 변경 시 |
| eBPF 동작 확인 | Linux VM | 주 1-2회 |
| 전체 통합 테스트 | Linux VM | Phase 6 완료 후 |
| 성능 측정 | Linux VM/Bare Metal | 필요시 |

## 8. Troubleshooting

### "eBPF 테스트가 skip됨"
- 정상입니다. macOS에서는 `#[cfg(target_os = "linux")]`로 자동 스킵
- Linux VM에서만 실제 실행

### "Docker daemon 연결 실패"
- macOS: Docker Desktop 실행 확인
- Linux: `sudo systemctl start docker`

### "BPF program load failed"
- Linux 커널 5.7+ 확인: `uname -r`
- CAP_BPF 권한 또는 root 필요
- `sudo ./target/debug/ironpost-daemon`

## Conclusion

**현재 Phase 6에서는 macOS 주 개발 환경을 유지하고, eBPF 관련 작업만 Linux VM으로 검증하는 것이 가장 효율적입니다.**
