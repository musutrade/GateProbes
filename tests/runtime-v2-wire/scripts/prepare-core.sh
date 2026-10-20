#!/usr/bin/env bash
# Checkout and verify the exact Core parser used by the acceptance harness.
# The checkout is fixed at tests/runtime-v2-wire/core-pin so the committed
# Cargo path cannot drift from the verified source.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/core.lock.json"
CORE="$ROOT/core-pin"

if [ -n "${PROXY_ENV:-}" ] && [ -f "$PROXY_ENV" ]; then
    # shellcheck disable=SC1090
    . "$PROXY_ENV"
fi

read_lock() {
    python3 - "$LOCK" "$1" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as handle:
    print(json.load(handle)[sys.argv[2]])
PY
}

PIN="$(read_lock commit)"
REPO="$(read_lock repository)"
PARSER_SHA="$(read_lock v2_parser_sha256)"
SOURCE_REPO="${GATEHOUSE_REPO:-$REPO}"

if [ -e "$CORE" ] && [ ! -e "$CORE/.git" ]; then
    echo "$CORE exists but is not a Git checkout" >&2
    exit 1
fi
if [ ! -e "$CORE/.git" ]; then
    mkdir -p "$(dirname "$CORE")"
    git clone --no-checkout "$SOURCE_REPO" "$CORE"
fi
if ! git -C "$CORE" cat-file -e "${PIN}^{commit}" 2>/dev/null; then
    git -C "$CORE" fetch --no-tags origin "$PIN"
fi
git -C "$CORE" checkout --detach "$PIN" >/dev/null

ACTUAL_PIN="$(git -C "$CORE" rev-parse HEAD)"
if [ "$ACTUAL_PIN" != "$PIN" ]; then
    echo "Core pin mismatch: expected $PIN, got $ACTUAL_PIN" >&2
    exit 1
fi

python3 - "$CORE" "$LOCK" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys

core = pathlib.Path(sys.argv[1])
lock = json.load(open(sys.argv[2], encoding='utf-8'))
status = subprocess.check_output(
    ['git', '-C', str(core), 'status', '--porcelain', '--untracked-files=no'],
    text=True,
).strip()
if status:
    raise SystemExit('pinned Core checkout has tracked modifications:\n' + status)
expected = lock['crate_files']
tracked = set(subprocess.check_output(
    ['git', '-C', str(core), 'ls-files', lock['crate_path']],
    text=True,
).splitlines())
if tracked != set(expected):
    missing = sorted(set(expected) - tracked)
    extra = sorted(tracked - set(expected))
    raise SystemExit(f'Core crate file set mismatch: missing={missing} extra={extra}')
for relative, digest in sorted(expected.items()):
    actual = hashlib.sha256((core / relative).read_bytes()).hexdigest()
    if actual != digest:
        raise SystemExit(f'Core file digest mismatch for {relative}: {actual} != {digest}')
print(f'verified {len(expected)} tracked crate files; v2 parser {lock["v2_parser_sha256"]}')
PY

echo "Core pinned: $ACTUAL_PIN ($CORE)"
echo "v2 parser: $PARSER_SHA"
