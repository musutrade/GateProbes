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
