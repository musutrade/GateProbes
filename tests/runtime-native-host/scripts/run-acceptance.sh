#!/usr/bin/env bash
# Build current native checkout, apply the test-only Core seam, run one exact test.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GP_ROOT="$(cd "$ROOT/../.." && pwd)"
NATIVE="$GP_ROOT/plugins/docker-runtime/native"
CORE="$ROOT/core-pin"
HOST_REL="tools/harness-gate/src/process/runtime_host_v2.rs"
TEST_NAME="$(python3 - "$ROOT/core.lock.json" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["test_name"])
PY
)"

if [ -n "$(git -C "$GP_ROOT" status --porcelain -- "$NATIVE")" ]; then
    echo "native source tree is not clean; refusing stale/mixed acceptance" >&2
    exit 1
fi

export CARGO_TARGET_DIR="$ROOT/target/native"
cargo build --locked --release --manifest-path "$NATIVE/Cargo.toml"
BINARY="$CARGO_TARGET_DIR/release/gateprobes-docker-runtime"
test -x "$BINARY"
SHA256="$(sha256sum "$BINARY" | cut -d' ' -f1)"
VERSION="$(python3 - "$NATIVE/Cargo.toml" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as handle:
    print(tomllib.load(handle)["package"]["version"])
PY
)"

restore() {
    if [ -e "$CORE/.git" ]; then
        git -C "$CORE" checkout -- "$HOST_REL" 2>/dev/null || true
    fi
}
trap restore EXIT
"$ROOT/scripts/prepare-core.sh"

export GATEPROBES_NATIVE_ADAPTER="$BINARY"
export GATEPROBES_NATIVE_ADAPTER_SHA256="$SHA256"
export GATEPROBES_NATIVE_ADAPTER_VERSION="$VERSION"
export CARGO_TARGET_DIR="$ROOT/target/core"
LOG="$ROOT/target/native-host.log"
set +e
timeout 300 cargo test --locked --manifest-path "$CORE/tools/harness-gate/Cargo.toml" \
    --bin harness-gate "$TEST_NAME" -- --ignored --exact 2>&1 | tee "$LOG"
STATUS=${PIPESTATUS[0]}
set -e
test "$STATUS" -eq 0
grep -Eq '^running 1 test$' "$LOG"
test "$(grep -Fc "test $TEST_NAME ... ok" "$LOG" || true)" -eq 1
grep -Eq '^test result: ok\. 1 passed; 0 failed; 0 ignored;' "$LOG"
echo "native entry + actual Core host acceptance passed: 1 executed, 1 passed, 0 ignored"
