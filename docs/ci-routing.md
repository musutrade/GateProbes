# CI routing notes

The repository keeps one workflow that always starts, classifies the change and
ends in the fixed `Required Quality Aggregate` check. This note records the
routing contract and the measured timings observed so far.

## Contract

- Selection comes from [`tools/ci/classify.py`](../tools/ci/classify.py) and is
  derived from [`plugins/registry.json`](../plugins/registry.json): each plugin
  declares its directory, language, platforms, install/test/contract/package
  entries and the shared protocols it depends on.
- Lightweight declaration, link and forbidden-artifact checks always run.
- Plugin checks run only for the affected plugins in the matrix. The plugin job
  unconditionally requires an implemented executor for the selected language and
  fails explicitly for a language whose executor has not landed yet.
- A registered shared protocol change affects only the plugins that declare it;
  other shared paths stay conservative and select every plugin. Unknown paths,
  an empty diff or a classification failure also select the conservative full
  set, and the aggregate fails closed on missing or invalid selections.
- The aggregate rejects a failed classification, a selected task that did not
  succeed, a missing or invalid selection, and a missing lightweight run.

## Measured runs

Timings are wall-clock job durations from GitHub Actions on the public
repository; they are observations, not guarantees.

| Run | Scope | Classify | Lightweight | Plugins | Aggregate | Whole run |
| --- | --- | --- | --- | --- | --- | --- |
| PR #1 | 23 files, plugin and shared | 5s | 6s | 11s | 3s | 25s |
| PR #2 | 9 files, plugin, shared, unknown | 3s | 6s | 12s | 4s | 26s |
| PR #3 | executor guard, plugin and shared | 5s | 4s | 15s | 4s | — |

A pure-documentation change selects only the lightweight and aggregate jobs;
the plugin job is skipped by classification, and the aggregate accepts the
skip because the plugin tier was not selected.
