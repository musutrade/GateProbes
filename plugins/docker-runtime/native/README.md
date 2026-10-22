# Native Docker runtime and readiness source

This 0.2.0 source candidate contains separate v2 runtime and v3 readiness
executables. Neither has a Core production dependency or launches Python. The
launching host supplies executable identity, trusted expected inputs and process
supervision; this does not establish installed artifact or loader/library trust.

On Linux, the entry accepts no arguments, reads config/expected from sealed
host-owned fd3/fd4 and actual request from bounded stdin, and refuses extra live
fds. It strictly validates requests, original config-byte SHA-256 and every pin.
It checks canonical protected socket paths, socket owner and client euid without
claiming daemon authentication. Capabilities returns Inspect only without connect.
Remove requests are rejected. No other platform is supported by the entry.

Inspect uses GET /version, versioned /info, full-ID /containers inspection, then
/version and /info again under one five-second budget. Only exact Present facts
with matching before/after identities are emitted; errors and every non-200,
including 404, are Unavailable. Absent is never emitted. JSON duplicate keys and
malformed identities/labels are refused. Labels remain facts for Core comparison.
Responses are fully encoded and size-checked before stdout is written; protocol
errors have static diagnostics. Caller-owned Core cancellation and supervision
are still required; the native entry has no graceful signal/cancel protocol.

Transport uses nonblocking Unix sockets, 16 KiB/64-field headers and Content-Length
bodies up to 1 MiB. Chunked/compressed/redirect behavior is refused. Filesystem
checks are not hard-time-bounded; delayed trailing bytes after a complete body are
not waited for. Local socket identity is rechecked before/after I/O. These checks
do not prove rootless mode, user namespaces, daemon restarts or adversarial OS
isolation. No real Docker compatibility has been established.

Packaged acceptance must use downloaded released Core v0.7.1 through its protected
`adapter runtime-probe-v2` CLI. Core v0.6.0 does not contain that host.
No tag, release, service integration or lease migration is claimed by this source.
The package build pins Rust 1.99.1; reproducibility requires independent clean
build comparison and is not implied by the version declaration.

## Musl build identity

The packaging candidate uses the Rust 1.99.1 musl target with its absolute
`rust-lld` and self-contained CRT. `build-inputs.json` pins compiler, linker,
compiler libraries, target libraries/CRT and Rust notices. A GCC string in the
shipped CRT is not evidence of invoking the host GCC. The resulting ELF must
be PIE with RELRO and a non-executable stack, without INTERP or NEEDED entries.
Static linking embeds musl: security fixes require rebuilding and shipping a
new artifact. This does not establish kernel portability or daemon compatibility.
The preceding repair was byte-identical on Ubuntu 22.04, Ubuntu 24.04 and the
local Ubuntu 26.04 host (GateProbes CI run 39535862193). This 0.1.1 version
changes the artifact identity and must independently pass the same comparison
before publication. Ubuntu 22.04 checks build identity only: released Core 0.7.1
emits a GLIBC_2.39 loader warning there. Strict released-Core acceptance runs
on Ubuntu 24.04 and still requires empty stderr.
The published 0.1.0 artifact is immutable; this candidate must not replace it.

## Unreleased v3 readiness candidate

Native crate 0.2.0 additionally builds `gateprobes-docker-readiness`, a dedicated
`gate-runtime/v3` entry with `gate-runtime-engine-config/v3`. The existing
`gateprobes-docker-runtime` entry continues to use v2. There is no protocol
fallback or capability-based readiness. The new entry observes identity before
and after an exact percent-encoded image lookup, never pulls, and requires an
exact RepoDigests entry for digest references. A valid image-route404 reports
image_present=false; unavailable cannot establish absence of a container.

This is a local source candidate. Existing runtime0.1.1 package/import/release
metadata remains tied to immutable v2 artifacts. No 0.2.0 archive, signature,
provenance, importer or real-daemon acceptance is claimed by these sources.

### Staged product-selected builder

The source crate is now 0.2.0 and contains a dedicated readiness binary. The
package builder has an explicit `docker-readiness` profile selecting that binary,
v3 manifest, product-local README/acceptance entry and SBOM identity. Its planned
Core target is 0.9.0; this is not downloaded-release compatibility evidence.
Current-source builds of the historical docker-runtime 0.1.1 identity fail the
Cargo identity gate. Build historical artifacts only from their frozen source.

Product registration, the acceptance entry, release dispatch and reviewed Core
pins still need delivery wiring. This builder preparation does not produce a
published readiness archive or change the immutable v2 releases.
