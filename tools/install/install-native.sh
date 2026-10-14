#!/usr/bin/env bash
# GateProbes owns native plugin install/upgrade/rollback from an exact release tag.

set -Eeuo pipefail
umask 022

REPO="musutrade/GateProbes"
BINARY_NAME="harness-gate-rust-collector"
RELEASE_BASE_URL="https://github.com/${REPO}/releases/download"
VERSION=""
INSTALL_DIR="${INSTALL_DIR:-${HOME}/.local/bin}"
OS=""
ARCH=""
PLATFORM=""
INSTALL_NAME="$BINARY_NAME"
ATOMIC_TEMPORARY=""
INSTALL_TEMPORARY_ROOT=""
RELEASE_WORKFLOW="native-collector-release.yml"
STAGED_BINARY=""

usage() {
    cat <<'EOF'
Usage: install-native.sh --version X.Y.Z [--install-dir DIR]

An explicit native Rust collector version is required (for example 0.1.0-rc.8).
Install, upgrade and rollback use the same verified atomic replacement.
Only musutrade/GateProbes native-collector-release.yml signatures for that
exact rust-collector-vX.Y.Z tag are trusted. No repository/signer fallback.
Requires Bash, curl or wget, SHA256 tooling and cosign on PATH.
Missing dependencies are diagnosed; no system toolchain is installed.
Historical bundled-runtime archives require their historical installer.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

cleanup_atomic_temporary() {
    if [[ -n "${ATOMIC_TEMPORARY:-}" ]]; then
        rm -f -- "$ATOMIC_TEMPORARY" 2>/dev/null || true
        ATOMIC_TEMPORARY=""
    fi
}

cleanup_installation() {
    local status=$?
    trap - EXIT
    cleanup_atomic_temporary
    if [[ -n "$INSTALL_TEMPORARY_ROOT" ]]; then
        rm -rf -- "$INSTALL_TEMPORARY_ROOT" 2>/dev/null || true
        INSTALL_TEMPORARY_ROOT=""
    fi
    exit "$status"
}

abort_on_signal() {
    local status="$1"
    cleanup_atomic_temporary
    exit "$status"
}

validate_version() {
    local version="${1:-$VERSION}"
    [[ "$version" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] \
        || die "plugin version must be exact SemVer without a v prefix (for example 0.1.0-rc.8)"
    if [[ "$version" == *-* ]]; then
        local prerelease="${version#*-}"
        prerelease="${prerelease%%+*}"
        local identifier
        IFS='.' read -r -a identifiers <<<"$prerelease"
        for identifier in "${identifiers[@]}"; do
            [[ ! "$identifier" =~ ^0[0-9]+$ ]] \
                || die "numeric prerelease identifiers must not contain leading zeroes"
        done
    fi
}

detect_platform() {
    local os
    local arch
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    arch="$(uname -m)"

    case "$os" in
        linux*) OS="linux" ;;
        darwin*) OS="macos" ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *) die "unsupported operating system: $os" ;;
    esac

    case "$arch" in
        x86_64|amd64) ARCH="amd64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *) die "unsupported architecture: $arch" ;;
    esac

    PLATFORM="${OS}-${ARCH}"
    INSTALL_NAME="$BINARY_NAME"
    if [[ "$OS" == windows ]]; then
        INSTALL_NAME="${BINARY_NAME}.exe"
    fi
}

download() {
    local url="$1"
    local output="$2"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --show-error --location --proto '=https' --tlsv1.2 \
            --max-redirs 10 --retry 3 --retry-all-errors --output "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        # TLSv1_2 rejects SSLv3/TLS 1.0/1.1 the same way curl's --tlsv1.2 does.
        wget --https-only --secure-protocol=TLSv1_2 --max-redirect=10 \
            --tries=3 --output-document="$output" "$url"
    else
        die "curl or wget is required"
    fi
    [[ ! -L "$output" && -f "$output" && -s "$output" ]] \
        || die "downloaded file is missing, symlinked, or empty: $url"
}

verify_checksum() {
    local dist="$1"
    local filename="$2"
    local manifest="$dist/SHA256SUMS"
    local selected="$dist/checksum.selected"
    local matches

    matches="$(LC_ALL=C awk -v expected="$filename" '$2 == expected { print; count++ } END { if (count != 1) exit 1 }' "$manifest")" \
        || die "SHA256SUMS does not contain exactly one entry for $filename"
    printf '%s\n' "$matches" >"$selected"
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$dist" && sha256sum --check --status "$(basename "$selected")") \
            || die "SHA256 checksum verification failed for $filename"
    elif command -v shasum >/dev/null 2>&1; then
        (cd "$dist" && shasum -a 256 --check --status "$(basename "$selected")") \
            || die "SHA256 checksum verification failed for $filename"
    else
        die "sha256sum or shasum is required"
    fi
}

verify_signature() {
    local dist="$1"
    local filename="$2"
    local identity_repo="$3"
    command -v cosign >/dev/null 2>&1 \
        || die "cosign is required for Sigstore verification (see https://docs.sigstore.dev/cosign/system_config/installation/)"

    # The release workflow's OIDC identity is bound to this exact selected tag.
    # The expected signer is a script-owned constant passed by the caller; it is never read from the
    # calling environment, so an exported lookalike variable cannot change it.
    cosign verify-blob \
        --signature "$dist/${filename}.sig" \
        --certificate "$dist/${filename}.crt" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        --certificate-identity "https://github.com/${identity_repo}/.github/workflows/${RELEASE_WORKFLOW}@refs/tags/${VERSION}" \
        "$dist/$filename" \
        || die "Sigstore verification failed for $filename"
}

validate_install_dir() {
    [[ "$INSTALL_DIR" = /* ]] || die "install directory must be an absolute path: $INSTALL_DIR"
    [[ "$INSTALL_DIR" != / ]] || die "install directory must not be the filesystem root"
    [[ "$INSTALL_DIR" != *$'\n'* && "$INSTALL_DIR" != *$'\r'* ]] \
        || die "install directory contains a line break"
    local component
    local current="/"
    local relative="${INSTALL_DIR#/}"
    IFS='/' read -r -a components <<<"$relative"
    for component in "${components[@]}"; do
        [[ -n "$component" && "$component" != "." && "$component" != ".." ]] \
            || die "install directory must not contain empty, dot, or traversal components"
        current="${current%/}/$component"
        [[ ! -L "$current" ]] || die "install directory contains a symlink component: $current"
    done
    if [[ -e "$INSTALL_DIR" && ! -d "$INSTALL_DIR" ]]; then
        die "install directory is not a directory: $INSTALL_DIR"
    fi
    if [[ ! -e "$INSTALL_DIR" ]]; then
        mkdir -p "$INSTALL_DIR"
        chmod 0755 "$INSTALL_DIR"
    fi
    [[ ! -L "$INSTALL_DIR" ]] || die "install directory must not be a symlink: $INSTALL_DIR"
    [[ -d "$INSTALL_DIR" && -w "$INSTALL_DIR" ]] || die "install directory is not writable: $INSTALL_DIR"

    # Do not install into a directory writable by group or other users.
    local mode
    if mode="$(stat -c '%a' "$INSTALL_DIR" 2>/dev/null)"; then
        :
    else
        mode="$(stat -f '%Lp' "$INSTALL_DIR" 2>/dev/null)" \
            || die "cannot inspect install directory permissions: $INSTALL_DIR"
    fi
    [[ "$mode" =~ ^[0-7]+$ ]] || die "cannot inspect install directory permissions: $INSTALL_DIR"
    local mode_number=$((8#$mode))
    (( (mode_number & 8#022) == 0 )) || die "install directory is group/other writable: $INSTALL_DIR"

    local target="$INSTALL_DIR/$INSTALL_NAME"
    [[ ! -L "$target" ]] || die "refusing to replace symlink target: $target"
    if [[ -e "$target" && ! -f "$target" ]]; then
        die "existing install target is not a regular file: $target"
    fi
}

atomic_install() {
    local source="$1"
    [[ ! -L "$source" && -f "$source" ]] || die "installation source is not a regular file: $source"
    validate_install_dir
    local target="$INSTALL_DIR/$INSTALL_NAME"
    ATOMIC_TEMPORARY="$(mktemp "$INSTALL_DIR/.${INSTALL_NAME}.XXXXXX")" \
        || die "cannot allocate an atomic install file in $INSTALL_DIR"
    if ! cp "$source" "$ATOMIC_TEMPORARY"; then
        cleanup_atomic_temporary
        die "cannot stage binary in $INSTALL_DIR"
    fi
    if ! chmod 0755 "$ATOMIC_TEMPORARY"; then
        cleanup_atomic_temporary
        die "cannot set executable mode in $INSTALL_DIR"
    fi
    if ! mv -f -- "$ATOMIC_TEMPORARY" "$target"; then
        cleanup_atomic_temporary
        die "cannot atomically install $target"
    fi
    ATOMIC_TEMPORARY=""
    printf 'installed %s %s (SHA256 %s)\n' "$BINARY_NAME" "$VERSION" "$(file_sha256 "$target")"
}

file_sha256() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$path" | awk '{print $1}'
    else
        shasum -a 256 "$path" | awk '{print $1}'
    fi
}

prepare_binary() {
    local temporary_root="$1"
    case "$PLATFORM" in
        linux-amd64|macos-amd64|macos-arm64|windows-amd64) ;;
        *) die "no release asset is published for $PLATFORM" ;;
    esac
    mkdir -p "$temporary_root"
    local extension=""
    [[ "$OS" == windows ]] && extension=".exe"
    local filename="${BINARY_NAME}-${PLATFORM}${extension}"
    local base_url="${RELEASE_BASE_URL}/${VERSION}"

    printf 'downloading and verifying %s from exact tag %s\n' "$filename" "$VERSION"
    download "${base_url}/${filename}" "$temporary_root/$filename"
    download "${base_url}/SHA256SUMS" "$temporary_root/SHA256SUMS"
    download "${base_url}/SHA256SUMS.sig" "$temporary_root/SHA256SUMS.sig"
    download "${base_url}/SHA256SUMS.crt" "$temporary_root/SHA256SUMS.crt"
    download "${base_url}/${filename}.sig" "$temporary_root/${filename}.sig"
    download "${base_url}/${filename}.crt" "$temporary_root/${filename}.crt"
    verify_signature "$temporary_root" "SHA256SUMS" "$SIGNER_REPO"
    # RC8 predates immutable release assets. Preserve the independently verified
    # original manifest rather than accepting a later same-tag replacement.
    if [[ "$VERSION" == rust-collector-v0.1.0-rc.8 ]]; then
        [[ "$(file_sha256 "$temporary_root/SHA256SUMS")" == d8f2302dc56108b6db8d971bed18c7d3bf0265506768663de8fb91d27011444b ]] \
            || die "legacy RC8 manifest differs from the reviewed public release"
    fi
    verify_checksum "$temporary_root" "$filename"
    verify_signature "$temporary_root" "$filename" "$SIGNER_REPO"
    STAGED_BINARY="$temporary_root/$filename"
}

main() {
    local SIGNER_REPO="$REPO"
    while (($# > 0)); do
        case "$1" in
            --version|--install-dir)
                (($# >= 2)) && [[ -n "$2" ]] || die "$1 requires a value"
                case "$1" in
                    --version) VERSION="$2" ;;
                    --install-dir) INSTALL_DIR="$2" ;;
                esac
                shift 2 ;;
            --offline) die "legacy bundled-runtime offline archives require their historical installer" ;;
            -h|--help) usage; return 0 ;;
            *) usage >&2; die "unknown argument: $1" ;;
        esac
    done
    [[ -n "$VERSION" ]] || die "--version is required; choose an exact plugin version"
    validate_version "v$VERSION"
    VERSION="rust-collector-v$VERSION"
    detect_platform
    command -v cosign >/dev/null 2>&1 || die "cosign is required; install a trusted verifier explicitly"
    command -v sha256sum >/dev/null 2>&1 || command -v shasum >/dev/null 2>&1 || die "sha256sum or shasum is required"
    INSTALL_TEMPORARY_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/gateprobes-install.XXXXXXXX")" \
        || die "cannot create temporary installation directory"
    trap cleanup_installation EXIT
    trap 'abort_on_signal 129' HUP
    trap 'abort_on_signal 130' INT
    trap 'abort_on_signal 143' TERM
    prepare_binary "$INSTALL_TEMPORARY_ROOT/native"
    atomic_install "$STAGED_BINARY"
}

main "$@"
