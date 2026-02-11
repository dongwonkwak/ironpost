# Ironpost build automation
# Install just: cargo install just
# Usage: just <recipe>

# Default recipe (show available commands)
default:
    @just --list

# Development build (fast, excludes eBPF)
build:
    cargo run -p xtask -- build

# Production build (includes eBPF on Linux, optimized)
build-all:
    cargo run -p xtask -- build --all --release

# Build eBPF only (Linux only)
build-ebpf:
    cargo run -p xtask -- build-ebpf --release

# Run all pre-commit checks
check:
    cargo fmt --all --check
    cargo clippy --workspace -- -D warnings
    cargo test --workspace
    cargo doc --workspace --no-deps

# Format code
fmt:
    cargo fmt --all

# Run clippy lints
clippy:
    cargo clippy --workspace -- -D warnings

# Run tests
test:
    cargo test --workspace

# Run tests with output
test-verbose:
    cargo test --workspace -- --nocapture

# Generate documentation
doc:
    cargo doc --workspace --no-deps --open

# Clean build artifacts
clean:
    cargo clean

# Install development prerequisites
setup:
    rustup toolchain install stable
    rustup toolchain install nightly --component rust-src
    cargo install bpf-linker || echo "Warning: bpf-linker install failed (Linux only)"
    cargo install cargo-watch || echo "Warning: cargo-watch install failed"
    just install-hooks

# Watch mode for development
watch:
    cargo watch -x "run -p xtask -- build"

# Start daemon (requires config file)
run:
    cargo run -p ironpost-daemon -- --config ironpost.toml

# Run CLI
cli *ARGS:
    cargo run -p ironpost-cli -- {{ARGS}}

# Install git hooks
install-hooks:
    @echo "📦 Installing git hooks..."
    @cp hooks/pre-commit .git/hooks/pre-commit
    @cp hooks/pre-push .git/hooks/pre-push
    @chmod +x .git/hooks/pre-commit
    @chmod +x .git/hooks/pre-push
    @echo "✅ Git hooks installed successfully!"
    @echo "   Pre-commit: fmt, clippy (빠른 검사)"
    @echo "   Pre-push: test, doc (무거운 검사)"
    @echo "   Bypass: --no-verify 플래그 사용"
