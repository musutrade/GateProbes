#!/usr/bin/env bash
# Run the current-checkout acceptance matrix. No push/PR/CI/daemon action.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(git -C "$ROOT" rev-parse --show-toplevel)"
SOURCE_DIR="$REPO_ROOT/plugins/docker-runtime"

if [ ! -f "$SOURCE_DIR/fixture_wire.py" ]; then
    echo "runtime entry not found at $SOURCE_DIR" >&2
    exit 1
fi
if [ -n "$(git -C "$REPO_ROOT" status --porcelain -- "$SOURCE_DIR")" ]; then
    echo "runtime source is not a clean checkout; refusing stale/dirty acceptance" >&2
    exit 1
fi

HEAD="$(git -C "$REPO_ROOT" rev-parse HEAD)"
echo "candidate checkout: $HEAD"
"$ROOT/scripts/prepare-core.sh"

export GATEPROBES_V2_RUNTIME_SOURCE_DIR="$SOURCE_DIR"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target}"
mkdir -p "$CARGO_TARGET_DIR"
LOG="$CARGO_TARGET_DIR/runtime-v2-wire-rust.log"

set +e
cargo test \
    --locked \
    --manifest-path "$ROOT/Cargo.toml" \
    --test acceptance \
    -- \
    --test-threads=1 2>&1 | tee "$LOG"
STATUS=${PIPESTATUS[0]}
set -e

if [ "$STATUS" -ne 0 ]; then
    echo "Rust acceptance failed with status $STATUS" >&2
    exit "$STATUS"
fi
grep -Eq '^running 21 tests$' "$LOG" || {
    echo "expected exactly 21 Rust acceptance tests" >&2
    exit 1
}
grep -Eq '^test result: ok\. 21 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' "$LOG" || {
    echo "Rust acceptance did not report 21 passed, 0 failed, 0 ignored" >&2
    exit 1
}
if grep -Eq '^test result: .* [1-9][0-9]* ignored' "$LOG"; then
    echo "ignored tests are not allowed in acceptance" >&2
    exit 1
fi
echo "Rust acceptance: 21 passed, 0 failed, 0 ignored"
