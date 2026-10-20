#!/usr/bin/env bash
# Test-only Core checkout and allowlisted seam patch. No production edits.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CORE="$ROOT/core-pin"
LOCK="$ROOT/core.lock.json"
PATCH="$ROOT/native_acceptance.patch"

if [ -n "${PROXY_ENV:-}" ] && [ -f "$PROXY_ENV" ]; then
    # shellcheck disable=SC1090
    . "$PROXY_ENV"
fi

read_lock() {
    python3 - "$LOCK" "$1" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)[sys.argv[2]])
PY
}
PIN="$(read_lock commit)"
REPO="$(read_lock repository)"
HOST_REL="$(read_lock runtime_host_file)"
ORIGINAL_SHA="$(read_lock runtime_host_sha256)"
PATCHED_SHA="$(read_lock patched_runtime_host_sha256)"
CORE_LOCK_REL="$(read_lock core_lock_file)"
CORE_LOCK_SHA="$(read_lock core_lock_sha256)"
PATCH_SHA="$(read_lock patch_sha256)"
EXPECTED_ADDED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["patch_stats"]["additions"])' "$LOCK")"
EXPECTED_DELETED="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["patch_stats"]["deletions"])' "$LOCK")"
SOURCE_REPO="${GATEHOUSE_REPO:-$REPO}"

if [ -e "$CORE" ] && [ ! -e "$CORE/.git" ]; then
    echo "core-pin exists but is not a Git checkout" >&2
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
test "$(git -C "$CORE" rev-parse HEAD)" = "$PIN"

# Restore the fixed checkout to its committed original before any verification.
git -C "$CORE" checkout -- "$HOST_REL"
if [ -n "$(git -C "$CORE" status --porcelain --untracked-files=all)" ]; then
    echo "core-pin is not clean before patch" >&2
    git -C "$CORE" status --porcelain --untracked-files=all >&2
    exit 1
fi
test "$(sha256sum "$CORE/$HOST_REL" | cut -d' ' -f1)" = "$ORIGINAL_SHA"
test "$(sha256sum "$CORE/$CORE_LOCK_REL" | cut -d' ' -f1)" = "$CORE_LOCK_SHA"
test "$(sha256sum "$PATCH" | cut -d' ' -f1)" = "$PATCH_SHA"

git -C "$CORE" apply --check "$PATCH"
git -C "$CORE" apply "$PATCH"
test "$(sha256sum "$CORE/$HOST_REL" | cut -d' ' -f1)" = "$PATCHED_SHA"
NAME_STATUS="$(git -C "$CORE" diff --name-only)"
test "$NAME_STATUS" = "$HOST_REL"
read -r ADDED DELETED _ < <(git -C "$CORE" diff --numstat -- "$HOST_REL")
test "$ADDED" = "$EXPECTED_ADDED" && test "$DELETED" = "$EXPECTED_DELETED"
echo "Core pinned and test-only seam applied: $PIN"
