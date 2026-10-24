//! Explicit lifecycle for exact, thin repository hooks. No gate execution here.
mod filesystem;
mod paths;
mod preserve;

use anyhow::{anyhow, ensure, Context, Result};
use filesystem::State;
use preserve::{LockRelease, Removal};
#[cfg(not(test))]
use std::io::Write as _;
use std::path::Path;

#[derive(Debug, Clone, Copy, clap::Subcommand)]
pub(crate) enum HookAction {
    /// Install both thin hooks without overwriting existing files.
    Install,
    /// Inspect both hooks without changing files (0 only when both are current).
    Status,
    /// Remove only exact managed hooks; absent hooks are harmless.
    Uninstall,
}

const HOOKS: [(&str, &str); 2] = [
    (
        "pre-commit",
        "#!/bin/sh\n# harness-gate managed hook v1\nexec harness-gate hook\n",
    ),
    (
        "pre-push",
        "#!/bin/sh\n# harness-gate managed hook v1\nexec harness-gate verify --all\n",
    ),
];

enum Completed {
    Status(bool),
    Changed(&'static str),
}

#[cfg(test)]
thread_local! {
    static OUTPUT: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) };
}

fn say(message: &str) {
    #[cfg(test)]
    OUTPUT.with(|output| output.borrow_mut().push(message.to_string()));
    #[cfg(not(test))]
    {
        let _ = writeln!(std::io::stdout(), "{message}");
    }
}

fn warn(message: &str) {
    #[cfg(test)]
    OUTPUT.with(|output| output.borrow_mut().push(message.to_string()));
    #[cfg(not(test))]
    {
        let _ = writeln!(std::io::stderr(), "{message}");
    }
}

fn readiness(root: &Path, core: &Path) -> Result<()> {
    let output = crate::capture(
        core,
        &[
            "--project-root",
            root.to_str().context("UTF-8 project path")?,
            "config",
            "print",
            "--resolved",
        ],
        root,
    )?;
    ensure!(
        output.status.success(),
        "Core configuration inspection failed"
    );
    let config: toml::Value = toml::from_str(std::str::from_utf8(&output.stdout)?)?;
    let profile = config["project"]["hook_profile"]
        .as_str()
        .context("missing hook profile")?;
    ensure!(
        config["steps"]
            .as_array()
            .context("missing configured steps")?
            .iter()
            .any(|step| step["profiles"]
                .as_array()
                .is_some_and(|profiles| profiles.iter().any(|p| p.as_str() == Some(profile)))),
        "configured hook profile has no participating steps"
    );
    Ok(())
}

/// A failed or incomplete scan is an error, not a warning: the command must not
/// claim success while retained objects may be invisible.
fn report_backups(directory: &Path) -> Result<()> {
    let rows = preserve::discover(directory)
        .context("preservation scan failed or was incomplete; no hooks were changed")?;
    for line in preserve::discovery_notices(&rows) {
        warn(&line);
    }
    Ok(())
}

pub(crate) fn run(root: &Path, core: &Path, action: HookAction) -> Result<bool> {
    let directory = paths::resolve(root)?;
    report_backups(&directory)?;
    if matches!(action, HookAction::Status)
        && directory
            .join(".harness-gate-hooks.lock")
            .symlink_metadata()
            .is_ok()
    {
        say("Hooks lifecycle: busy (lock exists)");
        return Ok(false);
    }
    let mut lock = if matches!(action, HookAction::Status) {
        None
    } else {
        Some(filesystem::Lock::acquire(&directory)?)
    };
    let outcome = (|| -> Result<Completed> {
        let states = HOOKS
            .iter()
            .map(|(name, content)| filesystem::inspect(&directory.join(name), content.as_bytes()))
            .collect::<Result<Vec<_>>>()?;
        if matches!(action, HookAction::Status) {
            return status(root, core, &states).map(Completed::Status);
        }
        ensure!(
            states.iter().all(|state| matches!(
                state,
                State::Absent | State::Current | State::NotExecutable
            )),
            "existing hooks are modified, foreign or unsafe; no files changed"
        );
        if matches!(action, HookAction::Uninstall) {
            uninstall(&directory, &states)
                .context("uninstall incomplete; inspect hooks status before retrying")?;
            return Ok(Completed::Changed(
                "Managed hooks removed (already absent is unchanged).",
            ));
        }
        readiness(root, core)?;
        ensure!(
            !states.contains(&State::NotExecutable),
            "managed hook is not executable; restore its permissions explicitly"
        );
        install(&directory, &states)?;
        Ok(Completed::Changed(
            "Managed pre-commit and pre-push hooks installed. No checks were executed.",
        ))
    })();
    match merge_outcome(outcome, lock.take().map(filesystem::Lock::finish))? {
        Completed::Status(value) => Ok(value),
        Completed::Changed(message) => {
            // Printed only after the lock was released successfully.
            say(message);
            Ok(true)
        }
    }
}

/// Explicit release runs on success and error paths. Both the command error and
/// the release error are kept; a lost lock is never reported as success.
fn merge_outcome<T>(outcome: Result<T>, release: Option<Result<LockRelease>>) -> Result<T> {
    let Some(release) = release else {
        return outcome;
    };
    match (outcome, release) {
        (Ok(value), Ok(LockRelease::Released { backup })) => {
            if let Some(notice) = preserve::lock_release_notice(&LockRelease::Released { backup }) {
                warn(&notice);
            }
            Ok(value)
        }
        (Ok(value), Ok(LockRelease::AlreadyAbsent)) => Ok(value),
        (Ok(_), Ok(LockRelease::LeftForeign { path })) => Err(anyhow!(
            "lock ownership was lost; a foreign object was left in place at {path:?}"
        )),
        (Ok(_), Ok(LockRelease::LostOwnership {
            backup,
            reason,
            restored,
        })) => Err(anyhow!(
            "lock ownership was lost ({reason}); exact object kept at {backup:?} (restored={restored})"
        )),
        (Ok(_), Err(error)) => Err(error
            .context("hooks command completed but lock release failed; the lock may still exist")),
        (Err(error), Ok(LockRelease::Released { backup })) => {
            if let Some(notice) = preserve::lock_release_notice(&LockRelease::Released { backup }) {
                warn(&notice);
            }
            Err(error)
        }
        (Err(error), Ok(LockRelease::AlreadyAbsent)) => Err(error),
        (Err(error), Ok(LockRelease::LeftForeign { path })) => Err(error.context(format!(
            "additionally the lifecycle lock was replaced by a foreign object at {path:?}"
        ))),
        (Err(error), Ok(LockRelease::LostOwnership {
            backup,
            reason,
            restored,
        })) => Err(error.context(format!(
            "additionally lock ownership was lost ({reason}); exact object kept at {backup:?} (restored={restored})"
        ))),
        (Err(error), Err(release)) => {
            Err(error.context(format!("additionally lock release failed: {release:#}")))
        }
    }
}

fn status(root: &Path, core: &Path, states: &[State]) -> Result<bool> {
    for ((name, _), state) in HOOKS.iter().zip(states) {
        say(&format!("{name}: {state:?}"));
    }
    match readiness(root, core) {
        Ok(()) => say("Configuration: hook profile participates"),
        Err(error) => say(&format!(
            "Configuration: {}",
            error.to_string().escape_debug()
        )),
    }
    Ok(states.iter().all(|state| *state == State::Current))
}

fn preserved_error(name: &str, removal: &Removal) -> anyhow::Error {
    match removal {
        Removal::Preserved {
            backup,
            reason,
            restored,
        } => anyhow!(
            "{name}: ownership was lost ({reason}); exact object kept at {backup:?} (restored={restored})"
        ),
        other => anyhow!("{name}: unexpected removal outcome {other:?}"),
    }
}

/// Every completed move is reported as soon as it happens and is named in the
/// error of a later failure, so a partial uninstall is always recoverable.
fn completed_backups(completed: &[Removal]) -> String {
    let paths = completed
        .iter()
        .filter_map(|removal| match removal {
            Removal::Removed { backup: Some(path) } | Removal::Preserved { backup: path, .. } => {
                Some(format!("{path:?}"))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if paths.is_empty() {
        "no hook object was moved before this failure".to_string()
    } else {
        format!("already retained backups: {}", paths.join(", "))
    }
}

fn uninstall(directory: &Path, states: &[State]) -> Result<Vec<Removal>> {
    let identities = HOOKS
        .iter()
        .zip(states)
        .map(|((name, _), state)| {
            if *state == State::Absent {
                Ok(None)
            } else {
                std::fs::symlink_metadata(directory.join(name)).map(Some)
            }
        })
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut completed = Vec::new();
    for ((name, content), identity) in HOOKS.iter().zip(identities) {
        let Some(identity) = identity else {
            continue;
        };
        match filesystem::remove_owned(&directory.join(name), content.as_bytes(), &identity) {
            Ok(removal) => {
                if let Some(notice) = preserve::removal_notice(&removal) {
                    warn(&notice);
                }
                if matches!(removal, Removal::Preserved { .. }) {
                    return Err(
                        preserved_error(name, &removal).context(completed_backups(&completed))
                    );
                }
                completed.push(removal);
            }
            Err(error) => return Err(error.context(completed_backups(&completed))),
        }
    }
    Ok(completed)
}

fn install(directory: &Path, states: &[State]) -> Result<()> {
    let mut created = Vec::new();
    for ((name, content), state) in HOOKS.iter().zip(states) {
        if *state == State::Current {
            continue;
        }
        match filesystem::publish(&directory.join(name), content.as_bytes()) {
            Ok(identity) => created.push((*name, content.as_bytes(), identity)),
            Err(error) => {
                let mut rollback = None;
                for (name, content, identity) in created {
                    match filesystem::remove_owned(&directory.join(name), content, &identity) {
                        Ok(removal) => {
                            if let Some(notice) = preserve::removal_notice(&removal) {
                                warn(&notice);
                            }
                            if matches!(removal, Removal::Preserved { .. }) {
                                rollback = Some(preserved_error(name, &removal));
                                break;
                            }
                        }
                        Err(cleanup) => {
                            rollback = Some(anyhow!("rollback retained changed hook: {cleanup:#}"));
                            break;
                        }
                    }
                }
                return Err(match rollback {
                    Some(extra) => error.context(format!(
                        "installation stopped: {extra:#}; rollback preserved or retained a hook; inspect hooks status"
                    )),
                    None => error.context(
                        "installation stopped; hooks created by this operation were rolled back",
                    ),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    fn write_hooks(directory: &Path) {
        for (name, content) in HOOKS {
            let path = directory.join(name);
            std::fs::write(&path, content).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
    }

    fn states(directory: &Path) -> Vec<State> {
        HOOKS
            .iter()
            .map(|(name, content)| {
                filesystem::inspect(&directory.join(name), content.as_bytes()).unwrap()
            })
            .collect()
    }

    fn backup_objects(directory: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(directory)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(preserve::BACKUP_PREFIX)
            })
            .map(|entry| entry.path().join("object"))
            .collect()
    }

    fn git_repo() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let status = std::process::Command::new("git")
            .args(["init", "-q"])
            .arg(root.path())
            .status()
            .unwrap();
        assert!(status.success());
        root
    }

    fn fake_core(directory: &Path) -> PathBuf {
        let path = directory.join("fake-core");
        std::fs::write(
            &path,
            "#!/bin/sh\ncat <<'EOF'\n[project]\nhook_profile = \"hook\"\n\n[[steps]]\nprofiles = [\"hook\"]\nEOF\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    fn take_output() -> Vec<String> {
        OUTPUT.with(|output| std::mem::take(&mut *output.borrow_mut()))
    }

    fn output_contains(needle: &str) -> bool {
        OUTPUT.with(|output| output.borrow().iter().any(|line| line.contains(needle)))
    }

    // Issue #92 production regression: uninstall keeps a foreign replacement.
    #[test]
    fn uninstall_preserves_foreign_replacement() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path();
        write_hooks(directory);
        let states = states(directory);
        preserve::test_arm_swap(b"foreign editor content");
        let result = uninstall(directory, &states);
        preserve::test_disarm_swap();
        let error = result.expect_err("lost ownership must be reported");
        let message = format!("{error:#}");
        assert!(message.contains("ownership was lost"), "{message}");
        assert_eq!(
            std::fs::read(directory.join("pre-commit")).unwrap(),
            b"foreign editor content"
        );
        assert_eq!(
            std::fs::read(directory.join("pre-push")).unwrap(),
            HOOKS[1].1.as_bytes()
        );
        let objects = backup_objects(directory);
        assert_eq!(objects.len(), 1);
        assert_eq!(
            std::fs::read(&objects[0]).unwrap(),
            b"foreign editor content"
        );
        assert!(message.contains(&format!("{:?}", objects[0].parent().unwrap())));
    }

    // Issue #92 production regression: install rollback keeps a foreign
    // replacement instead of deleting it.
    #[test]
    fn rollback_preserves_foreign_replacement() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path();
        std::fs::write(
            directory.join("pre-push"),
            "foreign arriving before install",
        )
        .unwrap();
        let states = states(directory);
        preserve::test_arm_swap(b"foreign editor content");
        let result = install(directory, &states);
        preserve::test_disarm_swap();
        let error = result.expect_err("install should fail on the foreign pre-push");
        assert!(format!("{error:#}").contains("preserved"));
        assert_eq!(
            std::fs::read(directory.join("pre-commit")).unwrap(),
            b"foreign editor content"
        );
        let objects = backup_objects(directory);
        assert_eq!(objects.len(), 1);
        assert_eq!(
            std::fs::read(&objects[0]).unwrap(),
            b"foreign editor content"
        );
    }

    #[test]
    fn late_second_target_conflict_rolls_back_only_created_hook() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("pre-push"),
            "foreign arriving after preflight",
        )
        .unwrap();
        assert!(install(root.path(), &[State::Absent, State::Absent]).is_err());
        assert!(!root.path().join("pre-commit").exists());
        assert_eq!(
            std::fs::read(root.path().join("pre-push")).unwrap(),
            b"foreign arriving after preflight"
        );
        let objects = backup_objects(root.path());
        assert_eq!(
            objects.len(),
            1,
            "rolled back hook is retained, not deleted"
        );
        assert_eq!(std::fs::read(&objects[0]).unwrap(), HOOKS[0].1.as_bytes());
    }

    #[test]
    fn merge_outcome_never_reports_success_for_a_lost_lock() {
        let lost = || {
            Ok(LockRelease::LostOwnership {
                backup: PathBuf::from("/tmp/backup"),
                reason: "foreign",
                restored: true,
            })
        };
        let error = merge_outcome(Ok(true), Some(lost())).unwrap_err();
        assert!(error.to_string().contains("/tmp/backup"));

        let foreign = || {
            Ok(LockRelease::LeftForeign {
                path: PathBuf::from("/tmp/lock"),
            })
        };
        assert!(merge_outcome(Ok(true), Some(foreign())).is_err());
        assert!(merge_outcome(Ok(true), None).unwrap());
    }

    #[test]
    fn merge_outcome_keeps_primary_and_release_errors() {
        let outcome: Result<bool> = Err(anyhow!("primary failure"));
        let release = Err(anyhow!("release failure"));
        let message = format!("{:#}", merge_outcome(outcome, Some(release)).unwrap_err());
        assert!(message.contains("primary failure"));
        assert!(message.contains("release failure"));

        let message = format!(
            "{:#}",
            merge_outcome::<bool>(
                Err(anyhow!("primary failure")),
                Some(Ok(LockRelease::AlreadyAbsent))
            )
            .unwrap_err()
        );
        assert!(message.contains("primary failure"));
    }

    // Command-level: an incomplete scan is a non-zero failure for status, not a
    // warning followed by exit 0.
    #[test]
    fn status_fails_when_preservation_scan_is_incomplete() {
        let root = git_repo();
        let core = fake_core(root.path());
        let hooks = root.path().join(".git/hooks");
        write_hooks(&hooks);
        for index in 0..1025 {
            std::fs::write(hooks.join(format!("extra-{index}")), b"").unwrap();
        }
        let result = run(root.path(), &core, HookAction::Status);
        assert!(result.is_err(), "incomplete scan must not succeed");
        let message = format!("{:#}", result.unwrap_err());
        assert!(message.contains("preservation scan failed"), "{message}");
    }

    // Command-level: a mutating command makes no changes when the scan fails.
    #[test]
    fn install_makes_no_changes_when_preservation_scan_is_incomplete() {
        let root = git_repo();
        let core = fake_core(root.path());
        let hooks = root.path().join(".git/hooks");
        for index in 0..1025 {
            std::fs::write(hooks.join(format!("extra-{index}")), b"").unwrap();
        }
        assert!(run(root.path(), &core, HookAction::Install).is_err());
        assert!(!hooks.join("pre-commit").exists());
        assert!(!hooks.join(".harness-gate-hooks.lock").exists());
        assert!(backup_objects(&hooks).is_empty());
    }

    // Command-level: the success line is printed only after a successful lock
    // release. A lost lock must fail without a preceding success message.
    #[test]
    fn install_reports_success_only_after_lock_release() {
        let root = git_repo();
        let core = fake_core(root.path());
        let hooks = root.path().join(".git/hooks");
        preserve::test_arm_swap(b"foreign lock content");
        let result = run(root.path(), &core, HookAction::Install);
        preserve::test_disarm_swap();
        let error = result.expect_err("lost lock must fail the command");
        assert!(format!("{error:#}").contains("lock ownership was lost"));
        assert!(
            !output_contains("installed. No checks were executed"),
            "success was printed before the lock release failed"
        );
        assert!(hooks.join("pre-commit").exists());
        assert_eq!(
            std::fs::read(hooks.join(".harness-gate-hooks.lock")).unwrap(),
            b"foreign lock content"
        );
    }

    // Command-level: a partial uninstall reports the first retained backup both
    // immediately and in the error, so nothing becomes unreachable.
    #[test]
    fn uninstall_reports_completed_backups_when_a_later_hook_fails() {
        let root = git_repo();
        let core = fake_core(root.path());
        let hooks = root.path().join(".git/hooks");
        write_hooks(&hooks);
        preserve::test_arm_swap_for("pre-push", b"foreign editor content");
        let result = run(root.path(), &core, HookAction::Uninstall);
        preserve::test_disarm_swap();
        let error = result.expect_err("lost ownership must fail uninstall");
        let message = format!("{error:#}");
        assert!(message.contains("already retained backups"), "{message}");
        assert!(!hooks.join("pre-commit").exists());
        assert_eq!(
            std::fs::read(hooks.join("pre-push")).unwrap(),
            b"foreign editor content"
        );
        let objects = backup_objects(&hooks);
        // pre-commit backup, pre-push backup and the released lock backup.
        assert_eq!(objects.len(), 3, "removed hook, preserved hook and lock");
        assert!(objects
            .iter()
            .any(|path| std::fs::read(path).unwrap() == HOOKS[0].1.as_bytes()));
        assert!(objects
            .iter()
            .any(|path| std::fs::read(path).unwrap() == b"foreign editor content"));
        assert!(message.contains(&format!(
            "{:?}",
            objects
                .iter()
                .find(|path| std::fs::read(path).unwrap() == HOOKS[0].1.as_bytes())
                .unwrap()
                .parent()
                .unwrap()
        )));
        assert!(
            output_contains("retained hook object at"),
            "completed backup was not reported immediately"
        );
        assert!(
            !output_contains("Managed hooks removed"),
            "success must not be reported for a partial uninstall"
        );
        take_output();
    }
}
