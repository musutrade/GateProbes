#!/usr/bin/env bash
# Offline contract tests for the immutable installer boundary.

set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/harness-gate-rust-collector-installer-test.XXXXXXXX")"
finish_fixture() {
    local status=$?
    if [[ -n "${HARNESS_GATE_INSTALL_TEST_EVIDENCE:-}" ]]; then
        if ! mkdir -p "$HARNESS_GATE_INSTALL_TEST_EVIDENCE" || \
            ! /bin/cp -R "$TEMP_ROOT/." "$HARNESS_GATE_INSTALL_TEST_EVIDENCE/"; then
            printf 'fixture evidence retained at %s (copy failed)\n' "$TEMP_ROOT" >&2
            ((status != 0)) || status=1
            exit "$status"
        fi
    elif ((status != 0)); then
        printf 'failed fixture retained at %s\n' "$TEMP_ROOT" >&2
        exit "$status"
    fi
    rm -rf -- "$TEMP_ROOT"
    exit "$status"
}
trap finish_fixture EXIT
FIXTURE="$TEMP_ROOT/fixture"
FAKE_BIN="$TEMP_ROOT/fake-bin"
mkdir -p "$FIXTURE" "$FAKE_BIN"
INSTALL_CASE=0
INSTALL_TMP_BASE="$TEMP_ROOT/tmp space ' quote"
mkdir -p "$INSTALL_TMP_BASE"
printf 'neighbor must survive\n' >"$INSTALL_TMP_BASE/neighbor-sentinel"
export HARNESS_GATE_TEST_DOWNLOAD_LOG="$TEMP_ROOT/download.log"

binary_name="harness-gate-rust-collector-linux-amd64"
printf 'verified fixture binary\n' >"$FIXTURE/$binary_name"
windows_binary_name="harness-gate-rust-collector-windows-amd64.exe"
printf 'verified windows fixture binary\n' >"$FIXTURE/$windows_binary_name"

hash_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    else
        shasum -a 256 "$path" | awk '{print $1}'
    fi
}

: >"$FIXTURE/SHA256SUMS"
printf '%s  %s\n' "$(hash_file "$FIXTURE/$binary_name")" "$binary_name" >>"$FIXTURE/SHA256SUMS"
printf '%s  %s\n' "$(hash_file "$FIXTURE/$windows_binary_name")" "$windows_binary_name" >>"$FIXTURE/SHA256SUMS"
printf 'signed-subject=SHA256SUMS\n' >"$FIXTURE/SHA256SUMS.sig"
printf 'identity=https://github.com/musutrade/GateProbes/.github/workflows/native-collector-release.yml@refs/tags/rust-collector-v0.1.0-rc.8\n' >"$FIXTURE/SHA256SUMS.crt"
printf 'signed-subject=%s\n' "$binary_name" >"$FIXTURE/$binary_name.sig"
printf 'identity=https://github.com/musutrade/GateProbes/.github/workflows/native-collector-release.yml@refs/tags/rust-collector-v0.1.0-rc.8\n' >"$FIXTURE/$binary_name.crt"
printf 'signed-subject=%s\n' "$windows_binary_name" >"$FIXTURE/$windows_binary_name.sig"
printf 'identity=https://github.com/musutrade/GateProbes/.github/workflows/native-collector-release.yml@refs/tags/rust-collector-v0.1.0-rc.8\n' >"$FIXTURE/$windows_binary_name.crt"

for platform in macos-amd64 macos-arm64; do
    asset="harness-gate-rust-collector-$platform"
    printf 'native %s fixture\n' "$platform" >"$FIXTURE/$asset"
    printf '%s  %s\n' "$(hash_file "$FIXTURE/$asset")" "$asset" >>"$FIXTURE/SHA256SUMS"
    printf 'signed-subject=%s\n' "$asset" >"$FIXTURE/$asset.sig"
    cp "$FIXTURE/$binary_name.crt" "$FIXTURE/$asset.crt"
done

# Offline signed-fixture doubles use a fixture manifest pin. The production
# script has no environment override or bypass for its historical RC8 digest.
INSTALLER="$TEMP_ROOT/install-native.sh"
sed "s/d8f2302dc56108b6db8d971bed18c7d3bf0265506768663de8fb91d27011444b/$(hash_file "$FIXTURE/SHA256SUMS")/g" \
    "$ROOT/tools/install/install-native.sh" >"$INSTALLER"

cat >"$FAKE_BIN/curl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
expected=(--fail --show-error --location --proto '=https' --tlsv1.2 --max-redirs 10 --retry 3 --retry-all-errors --output)
[[ "$#" -eq 14 ]] || { printf 'unexpected curl argv: %s\n' "$*" >&2; exit 2; }
for argument in "${expected[@]}"; do
    [[ "${1:-}" == "$argument" ]] || { printf 'unexpected curl option: %s\n' "${1:-}" >&2; exit 2; }
    shift
done
output="$1"
url="$2"
[[ "$url" != *'?'* && "$url" != *'#'* ]] || exit 22
prefix="https://github.com/musutrade/GateProbes/releases/download/"
[[ "$url" == "$prefix"* && "${HARNESS_GATE_TEST_DOWNLOAD_FAIL:-0}" != 1 ]] || exit 22
relative="${url#"$prefix"}"
filename="${url##*/}"
case "$relative" in
    rust-collector-v0.1.0-rc.8/*) source_file="$HARNESS_GATE_TEST_FIXTURE/$filename" ;;
    rust-collector-v0.1.0-rc.4/*) source_file="$HARNESS_GATE_TEST_FIXTURE/older/$filename" ;;
    *) exit 22 ;;
esac
printf '%s\n' "$url" >>"$HARNESS_GATE_TEST_DOWNLOAD_LOG"
[[ -f "$source_file" ]] || exit 22
/bin/cp "$source_file" "$output"
EOF
chmod 755 "$FAKE_BIN/curl"

cat >"$FAKE_BIN/cosign" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
original_args="$*"
[[ "${1:-}" == verify-blob ]] || exit 2
shift
signature=""
certificate=""
issuer=""
identity=""
subject=""
while (($# > 0)); do
    case "$1" in
        --signature) signature="${2:-}"; shift 2 ;;
        --certificate) certificate="${2:-}"; shift 2 ;;
        --certificate-oidc-issuer) issuer="${2:-}"; shift 2 ;;
        --certificate-identity) identity="${2:-}"; shift 2 ;;
        --*) exit 2 ;;
        *) [[ -z "$subject" ]] || exit 2; subject="$1"; shift ;;
    esac
done
expected_identity="https://github.com/musutrade/GateProbes/.github/workflows/native-collector-release.yml@refs/tags/${HARNESS_GATE_TEST_TAG:-rust-collector-v0.1.0-rc.8}"
[[ "$issuer" == 'https://token.actions.githubusercontent.com' ]] || exit 1
[[ "$identity" == "$expected_identity" ]] || exit 1
[[ -n "$signature" && -n "$certificate" && -n "$subject" ]] || exit 1
[[ "$(basename "$signature")" == "$(basename "$subject").sig" ]] || exit 1
[[ "$(basename "$certificate")" == "$(basename "$subject").crt" ]] || exit 1
grep -Fxq "identity=$expected_identity" "$certificate" || exit 1
grep -Fxq "signed-subject=$(basename "$subject")" "$signature" || exit 1
printf '%s\n' "$original_args" >>"$HARNESS_GATE_TEST_COSIGN_LOG"
if [[ "${HARNESS_GATE_TEST_COSIGN_FAIL:-0}" == 1 ]]; then exit 1; fi
exit 0
EOF
chmod 755 "$FAKE_BIN/cosign"

cat >"$FAKE_BIN/uname" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-}" in
    -s)
        case "${HARNESS_GATE_TEST_PLATFORM:-linux}" in
            windows) printf 'MINGW64_NT\n' ;;
            macos-*) printf 'Darwin\n' ;;
            *) printf 'Linux\n' ;;
        esac ;;
    -m)
        case "${HARNESS_GATE_TEST_PLATFORM:-linux}" in
            *-arm64) printf 'arm64\n' ;;
            *) printf 'x86_64\n' ;;
        esac ;;
    *) exit 2 ;;
esac
EOF
chmod 755 "$FAKE_BIN/uname"

cat >"$FAKE_BIN/cp" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${HARNESS_GATE_TEST_BLOCK_CP:-0}" == 1 && "${2:-}" == */.harness-gate-rust-collector.* && -n "${HARNESS_GATE_TEST_CP_STARTED:-}" ]]; then
    : >"$HARNESS_GATE_TEST_CP_STARTED"
    while [[ ! -e "${HARNESS_GATE_TEST_CP_RELEASE:-}" ]]; do
        sleep 0.05
    done
fi
if [[ "${HARNESS_GATE_TEST_ACTIVATION_FAIL:-0}" == 1 && "${2:-}" == */.harness-gate-rust-collector.* ]]; then exit 24; fi
exec /bin/cp "$@"
EOF
chmod 755 "$FAKE_BIN/cp"

cat >"$FAKE_BIN/chmod" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${HARNESS_GATE_TEST_CHMOD_FAIL:-0}" == 1 && "${2:-}" == */.harness-gate-rust-collector.* ]]; then exit 25; fi
exec /bin/chmod "$@"
EOF
cat >"$FAKE_BIN/mv" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${HARNESS_GATE_TEST_RENAME_FAIL:-0}" == 1 && "${3:-}" == */.harness-gate-rust-collector.* ]]; then exit 26; fi
exec /bin/mv "$@"
EOF
chmod 755 "$FAKE_BIN/chmod" "$FAKE_BIN/mv"

run_installer() {
    local destination="$1"
    shift
    INSTALL_CASE=$((INSTALL_CASE + 1))
    local case_tmp="$INSTALL_TMP_BASE/case-$INSTALL_CASE" status
    mkdir -p "$case_tmp"
    find "$case_tmp" -name 'gateprobes-install.*' >"$TEMP_ROOT/tmp-$INSTALL_CASE.before"
    if env \
        TMPDIR="$case_tmp" \
        PATH="$FAKE_BIN:$PATH" \
        HARNESS_GATE_TEST_FIXTURE="$FIXTURE" \
        HARNESS_GATE_TEST_COSIGN_LOG="$TEMP_ROOT/cosign.log" \
        HARNESS_GATE_TEST_PLATFORM="${HARNESS_GATE_TEST_PLATFORM:-linux}" \
        HARNESS_GATE_TEST_BLOCK_CP="${HARNESS_GATE_TEST_BLOCK_CP:-0}" \
        HARNESS_GATE_TEST_CP_STARTED="${HARNESS_GATE_TEST_CP_STARTED:-}" \
        HARNESS_GATE_TEST_CP_RELEASE="${HARNESS_GATE_TEST_CP_RELEASE:-}" \
        bash "$INSTALLER" --version 0.1.0-rc.8 --install-dir "$destination" "$@"; then
        status=0
    else
        status=$?
    fi
    find "$case_tmp" -name 'gateprobes-install.*' >"$TEMP_ROOT/tmp-$INSTALL_CASE.after"
    [[ ! -s "$TEMP_ROOT/tmp-$INSTALL_CASE.after" ]] || {
        printf 'installer left temporary roots in %s\n' "$case_tmp" >&2
        exit 1
    }
    grep -Fxq 'neighbor must survive' "$INSTALL_TMP_BASE/neighbor-sentinel" || exit 1
    printf 'case=%s status=%s temporary-roots=0 args=%s\n' "$INSTALL_CASE" "$status" "$*" >>"$TEMP_ROOT/lifecycle.log"
    return "$status"
}

mode_of() {
    if stat -c '%a' "$1" >/dev/null 2>&1; then
        stat -c '%a' "$1"
    else
        stat -f '%Lp' "$1"
    fi
}

assert_file_content() {
    local path="$1"
    [[ -f "$path" ]] || { printf 'missing expected file: %s\n' "$path" >&2; exit 1; }
    cmp -s "$FIXTURE/$binary_name" "$path" || {
        printf 'file content mismatch: %s\n' "$path" >&2
        exit 1
    }
}

install_dir="$TEMP_ROOT/install"
run_installer "$install_dir"
assert_file_content "$install_dir/harness-gate-rust-collector"
[[ "$(mode_of "$install_dir/harness-gate-rust-collector")" == 755 ]] || exit 1
[[ "$(wc -l <"$TEMP_ROOT/cosign.log")" -eq 2 ]] || exit 1
[[ -z "$(find "$install_dir" -maxdepth 1 -name '.harness-gate-rust-collector.*' -print -quit)" ]] || exit 1

first_inode="$(stat -c '%i' "$install_dir/harness-gate-rust-collector" 2>/dev/null || stat -f '%i' "$install_dir/harness-gate-rust-collector")"
printf 'old binary\n' >"$install_dir/harness-gate-rust-collector"
run_installer "$install_dir" >/dev/null
assert_file_content "$install_dir/harness-gate-rust-collector"
second_inode="$(stat -c '%i' "$install_dir/harness-gate-rust-collector" 2>/dev/null || stat -f '%i' "$install_dir/harness-gate-rust-collector")"
[[ "$first_inode" != "$second_inode" ]] || exit 1

tampered_dir="$TEMP_ROOT/tampered"
mkdir -m 700 "$tampered_dir"
printf 'old binary\n' >"$tampered_dir/harness-gate-rust-collector"
cp "$FIXTURE/$binary_name" "$FIXTURE/original-binary"
printf 'tampered fixture binary\n' >"$FIXTURE/$binary_name"
set +e
run_installer "$tampered_dir" >/dev/null 2>&1
tampered_status=$?
set -e
((tampered_status == 1)) || exit 1
grep -Fxq 'old binary' "$tampered_dir/harness-gate-rust-collector" || exit 1
mv "$FIXTURE/original-binary" "$FIXTURE/$binary_name"

signature_dir="$TEMP_ROOT/signature-failure"
mkdir -m 700 "$signature_dir"
printf 'old binary\n' >"$signature_dir/harness-gate-rust-collector"
set +e
HARNESS_GATE_TEST_COSIGN_FAIL=1 run_installer "$signature_dir" >/dev/null 2>&1
signature_status=$?
set -e
((signature_status == 1)) || exit 1
grep -Fxq 'old binary' "$signature_dir/harness-gate-rust-collector" || exit 1

symlink_dir="$TEMP_ROOT/symlink"
mkdir -m 700 "$symlink_dir"
outside="$TEMP_ROOT/outside"
printf 'outside\n' >"$outside"
ln -s "$outside" "$symlink_dir/harness-gate-rust-collector"
set +e
run_installer "$symlink_dir" >/dev/null 2>&1
symlink_status=$?
set -e
((symlink_status != 0)) || exit 1
grep -Fxq 'outside' "$outside" || exit 1

parent_symlink="$TEMP_ROOT/parent-link"
ln -s "$TEMP_ROOT" "$parent_symlink"
set +e
run_installer "$parent_symlink/parent-install" >/dev/null 2>&1
parent_status=$?
set -e
((parent_status != 0)) || exit 1

wrong_identity_dir="$TEMP_ROOT/wrong-identity"
mkdir -m 700 "$wrong_identity_dir"
printf 'old binary\n' >"$wrong_identity_dir/harness-gate-rust-collector"
printf 'identity=https://example.invalid/wrong\n' >"$FIXTURE/$binary_name.crt"
set +e
run_installer "$wrong_identity_dir" >/dev/null 2>&1
wrong_identity_status=$?
set -e
((wrong_identity_status != 0)) || exit 1
grep -Fxq 'old binary' "$wrong_identity_dir/harness-gate-rust-collector" || exit 1
printf 'identity=https://github.com/musutrade/GateProbes/.github/workflows/native-collector-release.yml@refs/tags/rust-collector-v0.1.0-rc.8\n' >"$FIXTURE/$binary_name.crt"

windows_dir="$TEMP_ROOT/windows-install"
HARNESS_GATE_TEST_PLATFORM=windows run_installer "$windows_dir" >/dev/null
[[ -f "$windows_dir/harness-gate-rust-collector.exe" ]] || exit 1
[[ ! -e "$windows_dir/harness-gate-rust-collector" ]] || exit 1
cmp -s "$FIXTURE/$windows_binary_name" "$windows_dir/harness-gate-rust-collector.exe" || exit 1

# Launch through a foreground Python driver: asynchronous shell jobs inherit an
# ignored SIGINT and cannot exercise the installer's INT trap reliably.
for signal_name in HUP INT TERM; do
    signal_dir="$TEMP_ROOT/signal-$signal_name-install"
    signal_tmp="$INSTALL_TMP_BASE/signal-$signal_name"
    mkdir -m 700 "$signal_dir" "$signal_tmp"
    printf 'old binary\n' >"$signal_dir/harness-gate-rust-collector"
    env PATH="$FAKE_BIN:$PATH" \
        HARNESS_GATE_TEST_FIXTURE="$FIXTURE" \
        HARNESS_GATE_TEST_COSIGN_LOG="$TEMP_ROOT/cosign.log" \
        HARNESS_GATE_TEST_PLATFORM=linux \
        TMPDIR="$signal_tmp" \
        python3 - "$INSTALLER" "$signal_dir" "$signal_tmp" "$signal_name" <<'PY'
import os, pathlib, signal, subprocess, sys, time
script, destination, directory, name = sys.argv[1:]
root = pathlib.Path(directory)
ready, release = root / 'ready', root / 'release'
environment = {**os.environ, 'HARNESS_GATE_TEST_BLOCK_CP': '1',
               'HARNESS_GATE_TEST_CP_STARTED': str(ready), 'HARNESS_GATE_TEST_CP_RELEASE': str(release)}
before = list(root.glob('gateprobes-install.*'))
with (root / 'command.log').open('wb') as log:
    child = subprocess.Popen(['bash', script, '--version', '0.1.0-rc.8', '--install-dir', destination],
                             env=environment, stdout=log, stderr=subprocess.STDOUT)
    try:
        deadline = time.monotonic() + 10
        while not ready.exists():
            assert child.poll() is None, 'installer exited before activation barrier'
            assert time.monotonic() < deadline, 'activation readiness timed out'
            time.sleep(0.01)
        active = list(root.glob('gateprobes-install.*'))
        assert len(active) == 1, 'signal fixture must own a temporary installation root'
        number = getattr(signal, 'SIG' + name)
        child.send_signal(number)
        release.touch()
        status = child.wait(timeout=10)
        after = list(root.glob('gateprobes-install.*'))
        (root / 'lifecycle.txt').write_text(f'before={before}\nactive={active}\nafter={after}\nstatus={status}\n')
        assert status == 128 + number, (name, status)
        assert not before and not after, 'signal cleanup leaked installation root'
    finally:
        release.touch()
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
PY
    grep -Fxq 'old binary' "$signal_dir/harness-gate-rust-collector" || exit 1
    grep -Fxq 'neighbor must survive' "$INSTALL_TMP_BASE/neighbor-sentinel" || exit 1
    [[ -z "$(find "$signal_dir" -maxdepth 1 -name '.harness-gate-rust-collector.*' -print -quit)" ]] || exit 1
done

for failure in DOWNLOAD ACTIVATION CHMOD RENAME; do
    failure_dir="$TEMP_ROOT/lifecycle-$failure"
    mkdir -m 700 "$failure_dir"
    printf 'old binary\n' >"$failure_dir/harness-gate-rust-collector"
    options=()
    case "$failure" in
        DOWNLOAD) expected_status=22 ;;
        ACTIVATION|CHMOD|RENAME) expected_status=1 ;;
    esac
    export "HARNESS_GATE_TEST_${failure}_FAIL=1"
    if run_installer "$failure_dir" "${options[@]}"; then
        printf 'expected %s failure\n' "$failure" >&2
        exit 1
    else
        failure_status=$?
    fi
    ((failure_status == expected_status)) || exit 1
    unset "HARNESS_GATE_TEST_${failure}_FAIL"
    grep -Fxq 'old binary' "$failure_dir/harness-gate-rust-collector" || exit 1
    [[ -z "$(find "$failure_dir" -maxdepth 1 -name '.harness-gate-rust-collector.*' -print -quit)" ]] || exit 1
done

missing_dir="$TEMP_ROOT/missing-asset"
mkdir -m 700 "$missing_dir"
printf 'old binary\n' >"$missing_dir/harness-gate-rust-collector"
mv "$FIXTURE/$binary_name.sig" "$FIXTURE/$binary_name.sig.missing"
set +e
run_installer "$missing_dir" >/dev/null 2>&1
missing_status=$?
set -e
((missing_status != 0)) || exit 1
grep -Fxq 'old binary' "$missing_dir/harness-gate-rust-collector" || exit 1
mv "$FIXTURE/$binary_name.sig.missing" "$FIXTURE/$binary_name.sig"

unsafe_dir="$TEMP_ROOT/unsafe-permissions"
mkdir -m 0777 "$unsafe_dir"
chmod 0777 "$unsafe_dir"
printf 'old binary\n' >"$unsafe_dir/harness-gate-rust-collector"
set +e
run_installer "$unsafe_dir" >/dev/null 2>&1
unsafe_status=$?
set -e
((unsafe_status != 0)) || exit 1
grep -Fxq 'old binary' "$unsafe_dir/harness-gate-rust-collector" || exit 1

for invalid_version in latest 1.2 01.2.3 1.2.3-01 v1.2.3 '../escape'; do
    set +e
    env PATH="$FAKE_BIN:$PATH" bash "$INSTALLER" \
        --version "$invalid_version" --install-dir "$TEMP_ROOT/version" \
        >/dev/null 2>&1
    invalid_status=$?
    set -e
    ((invalid_status != 0)) || exit 1
done

for platform in macos-amd64 macos-arm64; do
    HARNESS_GATE_TEST_PLATFORM="$platform" run_installer "$TEMP_ROOT/$platform" >/dev/null
    cmp "$FIXTURE/harness-gate-rust-collector-$platform" "$TEMP_ROOT/$platform/harness-gate-rust-collector"
done
# Missing verifier is a diagnostic before any download or target creation.
: >"$TEMP_ROOT/download.log"
mv "$FAKE_BIN/cosign" "$FAKE_BIN/cosign.saved"
if run_installer "$TEMP_ROOT/missing-cosign" >"$TEMP_ROOT/missing-cosign.log" 2>&1; then exit 1; fi
grep -q 'cosign is required' "$TEMP_ROOT/missing-cosign.log"
[[ ! -s "$TEMP_ROOT/download.log" && ! -e "$TEMP_ROOT/missing-cosign" ]]
mv "$FAKE_BIN/cosign.saved" "$FAKE_BIN/cosign"
# Both manifest and executable signatures are mandatory.
mv "$FIXTURE/SHA256SUMS.sig" "$FIXTURE/SHA256SUMS.sig.saved"
if run_installer "$install_dir" >/dev/null 2>&1; then exit 1; fi
assert_file_content "$install_dir/harness-gate-rust-collector"
mv "$FIXTURE/SHA256SUMS.sig.saved" "$FIXTURE/SHA256SUMS.sig"
cp "$FIXTURE/SHA256SUMS" "$FIXTURE/SHA256SUMS.saved"
cat "$FIXTURE/SHA256SUMS.saved" >>"$FIXTURE/SHA256SUMS"
if run_installer "$install_dir" >/dev/null 2>&1; then exit 1; fi
assert_file_content "$install_dir/harness-gate-rust-collector"
mv "$FIXTURE/SHA256SUMS.saved" "$FIXTURE/SHA256SUMS"
# Upgrade and explicit rollback use signed atomic replacement.
mkdir "$FIXTURE/older"
printf 'older release fixture\n' >"$FIXTURE/older/$binary_name"
printf '%s  %s\n' "$(hash_file "$FIXTURE/older/$binary_name")" "$binary_name" >"$FIXTURE/older/SHA256SUMS"
for asset in SHA256SUMS "$binary_name"; do
    cp "$FIXTURE/$asset.sig" "$FIXTURE/older/$asset.sig"
    sed 's/rust-collector-v0.1.0-rc.8/rust-collector-v0.1.0-rc.4/g' "$FIXTURE/$asset.crt" >"$FIXTURE/older/$asset.crt"
done
HARNESS_GATE_TEST_TAG=rust-collector-v0.1.0-rc.4 run_installer "$install_dir" --version 0.1.0-rc.4 >/dev/null
cmp "$FIXTURE/older/$binary_name" "$install_dir/harness-gate-rust-collector"
run_installer "$install_dir" >/dev/null
assert_file_content "$install_dir/harness-gate-rust-collector"
for identity in \
    https://github.com/musutrade/Harness-Gate/.github/workflows/native-collector-release.yml@refs/tags/rust-collector-v0.1.0-rc.8 \
    https://github.com/musutrade/GateProbes/.github/workflows/native-collector-release.yml@refs/tags/rust-collector-v0.1.0-rc.4 \
    https://github.com/musutrade/GateProbes/.github/workflows/release.yml@refs/tags/rust-collector-v0.1.0-rc.8; do
    printf 'identity=%s\n' "$identity" >"$FIXTURE/$binary_name.crt"
    if run_installer "$install_dir" >/dev/null 2>&1; then exit 1; fi
    assert_file_content "$install_dir/harness-gate-rust-collector"
done
printf 'identity=https://github.com/musutrade/GateProbes/.github/workflows/native-collector-release.yml@refs/tags/rust-collector-v0.1.0-rc.8\n' >"$FIXTURE/$binary_name.crt"
REPO=evil/repo SIGNER_REPO=evil/repo RELEASE_WORKFLOW=evil.yml \
    RELEASE_BASE_URL=https://example.invalid HARNESS_GATE_VERSION=latest RC8_MANIFEST_SHA256=evil \
    run_installer "$TEMP_ROOT/pollution" >/dev/null
assert_file_content "$TEMP_ROOT/pollution/harness-gate-rust-collector"
if run_installer "$TEMP_ROOT/no-version" --version '' >/dev/null 2>&1; then exit 1; fi
if run_installer "$TEMP_ROOT/offline" --offline old.tar.gz >"$TEMP_ROOT/offline.log" 2>&1; then exit 1; fi
grep -q 'historical installer' "$TEMP_ROOT/offline.log"
python3 - "$ROOT" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
receipt = json.loads((root / 'docs/quality/issue-17/rc8-public-verification.json').read_text())
digest = next(a['sha256'] for a in receipt['assets'] if a['name'] == 'SHA256SUMS')
assert digest in (root / 'tools/install/install-native.sh').read_text()
PY
printf 'plugin installer integrity tests: pass\n'
