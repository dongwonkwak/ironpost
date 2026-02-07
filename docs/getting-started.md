# 빌드 및 실행 가이드

## 사전 요구사항

- Rust 1.80 이상 (stable)
- Nightly 툴체인 (eBPF 빌드용): `rustup install nightly`
- Linux 커널 5.8 이상 (eBPF 지원)
- `llvm-tools` 또는 `lld`: `rustup component add llvm-tools-preview`

## 빌드

### 메인 프로젝트 빌드

```bash
cargo build
```

또는 릴리스 모드:

```bash
cargo build --release
```

### eBPF 커널 프로그램 빌드

eBPF는 특별한 타겟과 nightly 툴체인이 필요하므로 xtask를 사용합니다:

```bash
cargo run -p xtask -- build-ebpf
```

릴리스 모드:

```bash
cargo run -p xtask -- build-ebpf --release
```

> **참고**: eBPF 크레이트는 기본 빌드 대상이 아닙니다. 필요할 때만 위 명령어로 별도 빌드하세요.

## 실행

(placeholder)

## 설정

(placeholder)
