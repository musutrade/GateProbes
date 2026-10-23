# Proposed Podman read-only installation boundary

Design only; no installed entrypoint, spawn, mutation or authority is implemented.
This is independent of Docker lifecycle-v1 and must reject its descriptors.

The next implementation should verify held host, installation, configuration and
executable bytes before exposing a private `VerifiedPodmanInstallation` value.
The host descriptor has exactly schema, installation_path,
installation_sha256, config_path, config_sha256. The installation descriptor has
exactly schema, product, version, protocol, executable_path, executable_sha256,
config_schema. Proposed schema IDs are `gate-runtime/podman-host-v1`,
`gate-runtime/podman-installation-v1`, `gate-runtime/podman-context-v1`.
The product tuple stays podman-lifecycle/0.1.0/gate-runtime/lifecycle-v2/podman.

Open question: current ExpectedContext has no schema wrapper. Prefer a separate
versioned wrapper embedding context, with a deliberate new loader rather than
silently interpreting existing config bytes as that wrapper. Existing evidence
keeps its exact old config bytes and cannot be adopted into a new installation.
Review must resolve how the new loader feeds the existing ProtectedContext
without reopening a caller-controlled configuration path or changing snapshot
hash meaning.

All descriptors: strict fields and explicit canonical serialization, no defaults,
current-euid owner, one link, 0400/0600, no symlink, bounded size and protected
ancestors. Executable: held regular ELF, current-euid/root ownership policy must
be explicit, no group/world writes, no setid, expected digest, exact path identity
checks before/after hashing. Record and revalidate held descriptor metadata and
same bytes; never authorize using only a pathname or caller hash. Linux launch
must eventually use the held executable FD, with fd3/fd4 protected input binding,
empty environment and fixed cwd. The first slice verifies files only: it does
not spawn anything or pretend the absent native entrypoint is available.

Derive profile and snapshot hashes from verified bytes. Existing PlanRecord
asserted_* fields remain assertions for compatibility. Do not rename them as
verified or change installation_verified() for records loaded from disk. A new
live verified snapshot may compare against them, but returns a separate scoped
match result and must revalidate on use. Saved evidence never recreates a live
verified installation handle. No lease, operator or mutation token is minted.

Before implementation, review: exact wrapper/schema policy and byte hash meaning;
executable ownership/mode/format policy; reuse versus isolation of filesystem
helpers; record-match API lifetime; substitution and duplicate/unknown matrix.
No published-protocol claim: versioned protocol release and native entrypoint
remain later coordinated changes. Verification does not authenticate daemon
startup identity or prevent hostile same-UID/root replacement after checks.
