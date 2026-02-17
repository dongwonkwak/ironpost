#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# fuzz 디렉토리가 아니면 이동
if [ ! -f "Cargo.toml" ] || ! grep -q "cargo-fuzz" Cargo.toml 2>/dev/null; then
    if [ -d "fuzz" ]; then
        cd fuzz
    else
        echo "ERROR: fuzz 디렉토리를 찾을 수 없습니다."
        exit 1
    fi
fi

DURATION="${1:-30}"
echo "=== Fuzzing all targets (${DURATION}s each) ==="
echo ""

TARGETS=(
    fuzz_syslog_parser
    fuzz_json_parser
    fuzz_parser_router
    fuzz_rule_yaml
    fuzz_rule_matcher
    fuzz_cargo_lock
    fuzz_npm_lock
    fuzz_sbom_roundtrip
)

PASSED=0
FAILED=0
CRASH_LIST=""

for target in "${TARGETS[@]}"; do
    echo "--- Running: $target (${DURATION}s) ---"
    if cargo +nightly fuzz run "$target" -- -max_total_time="$DURATION" 2>&1 | tail -5; then
        echo "✅ $target: OK"
        PASSED=$((PASSED + 1))
    else
        echo "❌ $target: CRASH FOUND"
        FAILED=$((FAILED + 1))
        CRASH_LIST="${CRASH_LIST}\n  - $target"
    fi
    echo ""
done

echo "=== Results ==="
echo "Passed: $PASSED / ${#TARGETS[@]}"
echo "Failed: $FAILED / ${#TARGETS[@]}"

if [ $FAILED -gt 0 ]; then
    echo -e "\nCrash targets:$CRASH_LIST"
    echo ""
    echo "크래시 재현: cargo +nightly fuzz run <target> fuzz/artifacts/<target>/<crash_file>"
    exit 1
fi

echo "No crashes found! 🎉"
