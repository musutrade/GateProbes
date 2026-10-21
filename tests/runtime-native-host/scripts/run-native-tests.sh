#!/usr/bin/env bash
# Run the current native adapter tests with an exact count and zero skips.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GP_ROOT="$(cd "$ROOT/../.." && pwd)"
NATIVE="$GP_ROOT/plugins/docker-runtime/native"
EXPECTED_TESTS=33

if [ -n "$(git -C "$GP_ROOT" status --porcelain -- "$NATIVE")" ]; then
    echo "native source tree is not clean; refusing stale/mixed test run" >&2
    exit 1
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/target/native-tests}"
mkdir -p "$CARGO_TARGET_DIR"
LOG="$CARGO_TARGET_DIR/native-tests.log"

set +e
cargo +1.99.1 test --locked --target x86_64-unknown-linux-musl --manifest-path "$NATIVE/Cargo.toml" -- --test-threads=1 2>&1 | tee "$LOG"
STATUS=${PIPESTATUS[0]}
set -e
if [ "$STATUS" -ne 0 ]; then
    echo "native tests failed with status $STATUS" >&2
    exit "$STATUS"
fi

python3 - "$LOG" "$EXPECTED_TESTS" <<'PY'
import re
import sys

path, expected_text = sys.argv[1], sys.argv[2]
expected = int(expected_text)
text = open(path, encoding="utf-8").read()
results = re.findall(
    r"^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;",
    text,
    flags=re.MULTILINE,
)
if not results:
    raise SystemExit("native test output contains no test result")
passed = sum(int(row[1]) for row in results)
failed = sum(int(row[2]) for row in results)
ignored = sum(int(row[3]) for row in results)
if any(row[0] != "ok" for row in results):
    raise SystemExit("native test result is not ok")
if passed != expected:
    raise SystemExit(f"expected {expected} native tests, observed {passed}")
if failed:
    raise SystemExit(f"native tests failed: {failed}")
if ignored:
    raise SystemExit(f"native skipped/ignored tests are not allowed: {ignored}")
print(f"native tests: {passed} passed, 0 failed, 0 ignored (exact {expected})")
PY
