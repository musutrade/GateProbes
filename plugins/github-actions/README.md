# Optional GitHub result actions

This distribution owns findings-feedback and report-artifact, migrated byte-for-byte from GateHouse main before extraction. They do not evaluate quality or participate in Core completion. findings-feedback emits advisory annotations (neutral is not gate success); report-artifact optionally uploads only pinned display files. Existing default-off publish/upload and trust checks are preserved.

For GitHub Actions, use `musutrade/GateProbes/plugins/github-actions/actions/findings-feedback@<reviewed-full-commit>` or the corresponding `report-artifact` path. Pin an exact reviewed release source commit, not a moving branch. Alternatively verify the immutable release archive digest/provenance, extract locally and use the selected action directory. Action inputs remain documented in each action.yml. Platform credentials stay in the consumer environment.

The archive includes the action implementations, action.yml files and their fake-API/local-file regression tests. Run `node --test actions/findings-feedback/feedback.test.cjs actions/report-artifact/prepare.test.cjs` after extraction. These tests perform no live API writes or artifact uploads. Distribution acceptance is Linux x86_64 with Node24; no new platform claim. Repository release provenance is not approval of incoming report pins.
