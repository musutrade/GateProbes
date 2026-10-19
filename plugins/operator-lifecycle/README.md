# Explicit operator lifecycle

This external tool manages exact thin Git hooks and operator-owned canary records. It never decides quality, pushes commits, changes branch rules or schedules agents. Core is not a library dependency. The hooks filesystem implementation is retained from GateHouse 578a16befdc0017e1cf8d3021fc964d86cf23ad4, including lock ownership, byte identity, no-clobber creation and rollback of only files created by the operation.

Use `gateprobes-operator --project-root /project hooks --core /protected/harness-gate --core-sha256 <reviewed-sha256> install` (or status/uninstall). The protected Core binary is inspected read-only with `config print --resolved`; workloads are never run during installation. Existing managed hook bytes remain unchanged and still invoke harness-gate hook/verify on PATH when Git later runs them. Protect PATH/Core separately. Custom hooksPath, symlink and modified/foreign hooks remain rejected. No live repository hook installation is performed by release acceptance.

`canary --state /operator/state.json --slice team-a` and `rollback --state /operator/state.json` maintain the existing version1 external record shape only. Core never reads these markers; they are not a deployment, enforcement or rollback engine. State directories must be operator-protected and have a single writer. Existing markers and installed hooks are not changed automatically during migration. Historical Core commands remain until this replacement has been independently accepted.

Support is initially Linux x86_64. A bounded read-only child inspection is not hostile-process isolation. Private files and tokens must not be accessible to workload code. No production host state is modified during testing.
