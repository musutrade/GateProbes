# Podman lifecycle development checkpoint

This is an unpublished Linux-only library, not an installed plugin or mutation
entrypoint. It implements only native v6.1.4 info and exact full-ID image/container
inspect GET. No POST/DELETE, environment endpoint, proxy, CLI fallback, redirects
or retries exist. Docker product and artifacts remain separate.

The caller supplies ProtectedContext, one absolute deadline (maximum 30 seconds)
and cancellation callback. HTTP uses nonblocking connect/read/write and <=50ms
poll intervals, 16KiB headers, <=64 unique headers and <=1MiB body. Content-Length
and bounded chunked framing are supported; ambiguous framing, trailers and
compression fail. Already-buffered extra bytes are rejected; delayed trailing
bytes are outside this inherited HTTP subset. Filesystem metadata checks and the
caller's cancellation callback are not preempted by the I/O deadline.

Connection uses `/proc/self/fd/<held O_PATH fd>`; the context keeps this descriptor
alive, and path replacement is checked before sending and after reading. Linux
SO_PEERCRED must report a positive pid and uid matching the selected socket owner.
This verifies a local peer credential, not general authentication, process
lifetime, daemon restart continuity or hostile same-UID isolation. No startup or
socket activation assumptions are proven beyond the fake Unix listener tests.

The protocol dependency must temporarily be patched to the exact accompanying
Core source: published protocol0.3 lacks lifecycle_v2. No absolute patch is stored
in the manifest; this crate cannot be released or built standalone from published
protocol0.3. Use the frozen handoff's exact source/patch command for local review.
A future versioned protocol release, adapter entrypoint/install descriptor,
durable context+image+plan reservation, mutation/lease integration and real Podman
validation are required. HTTP code derives from the existing Docker lifecycle
transport but is private to this read-only product; Docker files are unchanged.

`capture_plan` fixes its exchange to this library's held-socket GET transport;
it accepts no caller GET callback or raw image response. It validates the exact
profile/config digest before connecting and shares one deadline across
info/image/info, then checks context/cancellation/deadline before returning a
PlanRecord. The caller may separately create-new the evidence file. The API
returns no installation, dispatch or lease capability: installation/executable
hashes are assertions, peer UID is not executable authentication, and saved
records can be replayed or changed by the same UID. This composition does not
make the public pure protocol decoder or its callback API trusted.

Fake tests cover the exact three routes with record persistence/reopen,
profile/config/deadline/cancel preflight zero-connection refusals, and final-info
failure withholding evidence. Real Podman, kernel fault/power-loss, installed
entrypoint, versioned protocol and mutation remain outside this checkpoint.

Operator name, labels and fixed port are preflight-validated before any socket
connection. Empty operator labels are allowed because image labels may supply
the final nonempty map; merged plan validation remains mandatory after capture.

Image IDs and the maximum 30-second deadline are checked at capture entry, before
connecting. Final-boundary tests call the same production finalizer with already
validated evidence to deterministically reject cancellation, expiry and changed
context; they are post-GET withholding tests, not zero-connection claims. Empty
operator labels are also exercised through all three GETs and PlanRecord using
inherited image labels.

Native entry checkpoint 117 adds an unpublished binary. It consumes actual fd3
and fd4, accepts no arguments, reads at most 64KiB stdin with nonblocking poll,
validates protected inputs, captures via fixed GET transport, and emits bounded
canonical capture response. SIGTERM/SIGINT set cancellation; stdin/stdout polling
and engine I/O share a deadline measured from process entry. Before request decode
only the 30-second upper bound is known; afterwards the request timeout is charged
from that same entry instant. Filesystem checks and CPU parsing are not preempted;
a future host must enforce its own deadline and kill/reap. No installation or
executable files are reopened by the child; parent provenance remains unproven.

Success requires exit0 plus the complete validated response. Nonzero exit may
leave a partial stdout write if cancellation/timeout occurs during output; the
host must reject all such output. Diagnostics contain no raw data (stderr empty).
No environment endpoint, fallback, mutation, or output-path argument exists.
Real-child fake-socket tests cover env_clear/cwd `/`, fd inheritance, positive
three-GET response and persistence, and unsealed/missing fd4 or malformed request
zero-connect refusals. Core runner acceptance is tracked separately; installed artifact/publication
and real Podman remain gates.

Native signal checkpoint 122 tests SIGTERM and SIGINT during stdin, the first
engine GET, and a full 4096-byte stdout pipe. Signals wait for observable fd
nonblocking state, a received request, or pipe occupancy; no fixed sleep selects
the phase. Each child exits 1 with empty stderr. Output-phase failures retain
only incomplete stdout, which cannot decode as a response. A separate case leaves
the pipe full without reading and verifies the request deadline terminates the
child, below the response size cap. These are fake-socket direct-child tests;
full stderr, descendant cleanup, real Podman and authority are not established.
