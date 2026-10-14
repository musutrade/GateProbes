# Cargo runner declarations and migration

GateHouse Issue #27 moves Cargo invocation rules into
[`runners/cargo-test.toml`](../runners/cargo-test.toml). It is a runner v2 definition
for the candidate Core implementing that issue. The current released/pinned Core
contract is unchanged; this document does not claim release compatibility.
Reference presets contain no runner blocks and do not need migration.

Core treats `kind` as identity. Copy the definition's fields into a flow runner
block and supply `threads`, `isolation`, and the existing optional result/argument
fields. A thread count of 1 is still explicitly inserted for Cargo. With no
thread count, omit `threads_args` and `threads_args_after`.

```sh
python3 tools/runners/migrate.py /path/to/flow.toml --output /path/to/flow.runner-v2.toml
/path/to/candidate-core --project-root /path/to/project --config /path/to/flow.runner-v2.toml config check
python3 -m unittest discover -s tools/runners -p 'test_*.py' -v
python3 tools/runners/accept.py --core /absolute/path/to/candidate-core
```

Migration supports inline and table runner declarations, writes a new file, and
refuses overwrite or repeated migration. TOML comments and formatting are
normalized; parsed values outside the runner and existing runner fields remain
identical, except runner version. Keep the original file and binary for rollback;
restore both together. Generic v1 receives only a version update. Invalid Cargo
programs and mixed contracts are rejected; validate all resulting flows with the
candidate Core before replacement.

The Core first inserts runner `args` at `args_position`, then inserts expanded
thread arguments immediately after the first `--`, appending `--` if missing.
This matches legacy Cargo ordering. User flags, including conflicting thread
flags, remain in place so Cargo/libtest keeps its own rejection semantics.
Core still enforces the 1..256 thread budget, declared injection, service env
collisions and multiple-worker isolation. Policy, requiredness, parser/counting,
shards, retries, baselines and final decisions remain Core responsibilities.

`accept.py` uses a temporary dependency-free Rust crate, real Cargo and a
forwarding shim to compare actual argv with Core reports. It tests absent and
existing separators, argument positions, conflicting flags, invalid programs,
invalid budgets, legacy versions, shared isolation and missing thread injection.
It changes an external definition and uses an unknown ID with the same Core
binary. POSIX, Python 3.11+ and Cargo are needed; no released-Core pin is changed.
CI runs migration self-tests. Candidate-Core acceptance is run explicitly until
a released Core fixed pair supporting runner v2 is available.
