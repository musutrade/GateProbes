//! Explicit lifecycle for exact, thin repository hooks. No gate execution here.
mod filesystem;
mod paths;

use anyhow::{ensure, Context, Result};
use filesystem::State;
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

pub(crate) fn run(root: &Path, core: &Path, action: HookAction) -> Result<bool> {
    let directory = paths::resolve(root)?;
    if matches!(action, HookAction::Status)
        && directory
            .join(".harness-gate-hooks.lock")
            .symlink_metadata()
            .is_ok()
    {
        println!("Hooks lifecycle: busy (lock exists)");
        return Ok(false);
    }
    let _lock = if matches!(action, HookAction::Status) {
        None
    } else {
        Some(filesystem::Lock::acquire(&directory)?)
    };
    let states = HOOKS
        .iter()
        .map(|(name, content)| filesystem::inspect(&directory.join(name), content.as_bytes()))
        .collect::<Result<Vec<_>>>()?;
    if matches!(action, HookAction::Status) {
        return status(root, core, &states);
    }
    ensure!(
        states
            .iter()
            .all(|state| matches!(state, State::Absent | State::Current | State::NotExecutable)),
        "existing hooks are modified, foreign or unsafe; no files changed"
    );
    if matches!(action, HookAction::Uninstall) {
        uninstall(&directory, &states)
            .context("uninstall incomplete; inspect hooks status before retrying")?;
        println!("Managed hooks removed (already absent is unchanged).");
        return Ok(true);
    }
    readiness(root, core)?;
    ensure!(
        !states.contains(&State::NotExecutable),
        "managed hook is not executable; restore its permissions explicitly"
    );
    install(&directory, &states)?;
    println!("Managed pre-commit and pre-push hooks installed. No checks were executed.");
    Ok(true)
}

fn status(root: &Path, core: &Path, states: &[State]) -> Result<bool> {
    for ((name, _), state) in HOOKS.iter().zip(states) {
        println!("{name}: {state:?}");
    }
    match readiness(root, core) {
        Ok(()) => println!("Configuration: hook profile participates"),
        Err(error) => println!("Configuration: {}", error.to_string().escape_debug()),
    }
    Ok(states.iter().all(|state| *state == State::Current))
}

fn uninstall(directory: &Path, states: &[State]) -> Result<()> {
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
    for ((name, content), identity) in HOOKS.iter().zip(identities) {
        if let Some(identity) = identity {
            filesystem::remove_owned(&directory.join(name), content.as_bytes(), &identity)?;
        }
    }
    Ok(())
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
                for (name, content, identity) in created {
                    if let Err(cleanup) =
                        filesystem::remove_owned(&directory.join(name), content, &identity)
                    {
                        return Err(error.context(format!(
                            "rollback retained changed hook: {cleanup}; inspect hooks status"
                        )));
                    }
                }
                return Err(error.context(
                    "installation stopped; hooks created by this operation were rolled back",
                ));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Reproduction of issue #92 for the uninstall path: the identity snapshot is
    // taken, then the file is replaced before the final removal.
    #[test]
    fn reproduction_uninstall_deletes_foreign_replacement() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path();
        for (name, content) in HOOKS {
            let path = directory.join(name);
            std::fs::write(&path, content).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
        }
        let states = HOOKS
            .iter()
            .map(|(name, content)| filesystem::inspect(&directory.join(name), content.as_bytes()))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        filesystem::test_arm_remove_swap(b"foreign editor content");
        let result = uninstall(directory, &states);
        filesystem::test_disarm_remove_swap();
        assert!(result.is_ok(), "uninstall removed without detecting the swap");
        assert!(!directory.join("pre-commit").exists(), "foreign pre-commit was deleted");
    }

    // Reproduction of issue #92 for the install rollback path.
    #[test]
    fn reproduction_rollback_deletes_foreign_replacement() {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path();
        std::fs::write(directory.join("pre-push"), "foreign arriving before install").unwrap();
        let states = HOOKS
            .iter()
            .map(|(name, content)| filesystem::inspect(&directory.join(name), content.as_bytes()))
            .collect::<Result<Vec<_>>>()
            .unwrap();
        filesystem::test_arm_remove_swap(b"foreign editor content");
        let result = install(directory, &states);
        filesystem::test_disarm_remove_swap();
        assert!(result.is_err(), "install should fail on the foreign pre-push");
        assert!(!directory.join("pre-commit").exists(), "foreign rollback target was deleted");
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
    }
}
