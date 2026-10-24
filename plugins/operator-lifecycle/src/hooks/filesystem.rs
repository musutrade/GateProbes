use anyhow::{ensure, Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

pub(super) const MARKER: &str = "# harness-gate managed hook v1";

// Deterministic interleaving hooks for tests only. Release builds contain no
// injection point and no extra state.
#[cfg(test)]
thread_local! {
    pub(super) static BEFORE_REMOVE: std::cell::RefCell<Option<fn(&Path)>> = const { std::cell::RefCell::new(None) };
    pub(super) static BEFORE_LOCK_REMOVE: std::cell::RefCell<Option<fn(&Path)>> = const { std::cell::RefCell::new(None) };
    pub(super) static REPLACEMENT_BYTES: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(super) fn test_arm_remove_swap(bytes: &[u8]) {
    REPLACEMENT_BYTES.with(|slot| *slot.borrow_mut() = bytes.to_vec());
    BEFORE_REMOVE.with(|slot| *slot.borrow_mut() = Some(test_replace_file));
}

#[cfg(test)]
pub(super) fn test_disarm_remove_swap() {
    BEFORE_REMOVE.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
pub(super) fn test_replace_file(path: &Path) {
    // Runs between the final identity check and the removal syscall.
    let bytes = REPLACEMENT_BYTES.with(|slot| slot.borrow().clone());
    let _ = fs::remove_file(path);
    let _ = fs::write(path, bytes);
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum State {
    Absent,
    Current,
    NotExecutable,
    Modified,
    Foreign,
    Unsafe,
}

pub(super) fn inspect(path: &Path, expected: &[u8]) -> Result<State> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(State::Absent),
        Err(error) => return Err(error.into()),
    };
    if !meta.is_file() || meta.file_type().is_symlink() {
        return Ok(State::Unsafe);
    }
    let mut bytes = Vec::new();
    let file = fs::File::open(path)?;
    ensure!(
        same_identity(&meta, &file.metadata()?),
        "hook changed during inspection"
    );
    file.take(16384).read_to_end(&mut bytes)?;
    if bytes != expected {
        return Ok(if String::from_utf8_lossy(&bytes).contains(MARKER) {
            State::Modified
        } else {
            State::Foreign
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o111 == 0 {
            return Ok(State::NotExecutable);
        }
    }
    Ok(State::Current)
}

pub(super) fn publish(path: &Path, content: &[u8]) -> Result<fs::Metadata> {
    let mut file = tempfile::NamedTempFile::new_in(path.parent().context("hook parent")?)?;
    file.write_all(content)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o755))?;
    }
    file.as_file().sync_all()?;
    let identity = file.as_file().metadata()?;
    file.persist_noclobber(path)
        .map_err(|error| error.error)
        .context("publish hook without overwriting existing files")?;
    Ok(identity)
}

pub(super) fn remove_owned(path: &Path, content: &[u8], identity: &fs::Metadata) -> Result<()> {
    let state = inspect(path, content)?;
    if state == State::Absent {
        return Ok(());
    }
    ensure!(
        matches!(state, State::Current | State::NotExecutable),
        "hook changed; refusing to remove {}",
        path.display()
    );
    ensure!(
        same_identity(identity, &fs::symlink_metadata(path)?),
        "hook object changed; refusing deletion"
    );
    #[cfg(test)]
    BEFORE_REMOVE.with(|slot| {
        if let Some(hook) = *slot.borrow() {
            hook(path);
        }
    });
    fs::remove_file(path).context("remove owned hook")
}

pub(super) struct Lock {
    path: std::path::PathBuf,
    identity: fs::Metadata,
}
impl Lock {
    pub(super) fn acquire(directory: &Path) -> Result<Self> {
        let path = directory.join(".harness-gate-hooks.lock");
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .context(
                "hooks lifecycle busy or stale lock exists; inspect before removing lock manually",
            )?;
        Ok(Self {
            path,
            identity: file.metadata()?,
        })
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        if let Ok(meta) = fs::symlink_metadata(&self.path) {
            if same_identity(&self.identity, &meta)
                && meta.len() == 0
                && !meta.file_type().is_symlink()
            {
                #[cfg(test)]
                BEFORE_LOCK_REMOVE.with(|slot| {
                    if let Some(hook) = *slot.borrow() {
                        hook(&self.path);
                    }
                });
                let _ = fs::remove_file(&self.path);
            }
        }
    }
}

pub(super) fn same_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        left.dev() == right.dev() && left.ino() == right.ino()
    }
    #[cfg(not(unix))]
    {
        matches!((left.created(), right.created(), left.modified(), right.modified()),
            (Ok(a), Ok(b), Ok(c), Ok(d)) if a == b && c == d && left.len() == right.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn no_clobber_and_owned_removal_preserve_conflicts() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("hook");
        publish(&path, b"managed").unwrap();
        let identity = fs::symlink_metadata(&path).unwrap();
        assert!(publish(&path, b"replacement").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"managed");
        fs::write(&path, b"external edit").unwrap();
        assert!(remove_owned(&path, b"managed", &identity).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"external edit");
        fs::remove_file(&path).unwrap();
        assert!(remove_owned(&path, b"managed", &identity).is_ok());
    }
    fn install_swap(path: &Path) {
        BEFORE_REMOVE.with(|slot| *slot.borrow_mut() = Some(test_replace_file));
        let _ = path;
    }

    fn clear_swap() {
        BEFORE_REMOVE.with(|slot| *slot.borrow_mut() = None);
        BEFORE_LOCK_REMOVE.with(|slot| *slot.borrow_mut() = None);
    }

    // Reproduction of issue #92: the foreign file is deleted because the final
    // check and remove_file are not atomic. This test documents current
    // behaviour and must be replaced by a preservation assertion with the fix.
    #[test]
    fn reproduction_remove_owned_deletes_foreign_replacement() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("pre-commit");
        publish(&path, b"managed").unwrap();
        let identity = fs::symlink_metadata(&path).unwrap();
        REPLACEMENT_BYTES.with(|slot| *slot.borrow_mut() = b"external editor content".to_vec());
        install_swap(&path);
        let result = remove_owned(&path, b"managed", &identity);
        clear_swap();
        assert!(result.is_ok(), "current implementation removes without detecting the swap");
        assert!(!path.exists(), "foreign replacement was deleted");
    }

    // Reproduction of the same window in Lock::drop.
    #[test]
    fn reproduction_lock_drop_deletes_foreign_replacement() {
        let root = tempfile::tempdir().unwrap();
        let lock = Lock::acquire(root.path()).unwrap();
        let path = lock.path.clone();
        REPLACEMENT_BYTES.with(|slot| *slot.borrow_mut() = b"foreign lock content".to_vec());
        BEFORE_LOCK_REMOVE.with(|slot| *slot.borrow_mut() = Some(test_replace_file));
        drop(lock);
        BEFORE_LOCK_REMOVE.with(|slot| *slot.borrow_mut() = None);
        assert!(!path.exists(), "foreign lock replacement was deleted");
    }

    #[test]
    fn lifecycle_lock_is_exclusive_and_never_steals_existing_lock() {
        let root = tempfile::tempdir().unwrap();
        let first = Lock::acquire(root.path()).unwrap();
        assert!(Lock::acquire(root.path()).is_err());
        drop(first);
        assert!(Lock::acquire(root.path()).is_ok());
        fs::write(root.path().join(".harness-gate-hooks.lock"), "foreign").unwrap();
        assert!(Lock::acquire(root.path()).is_err());
        assert_eq!(
            fs::read(root.path().join(".harness-gate-hooks.lock")).unwrap(),
            b"foreign"
        );
    }
}

// Test-only prototype of the proposed preservation algorithm. It is not wired
// into production; it exists to make the design reviewable and executable.
#[cfg(test)]
pub(super) mod preserve_prototype {
    use super::*;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_STAGING: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Outcome {
        Removed,
        RestoredForeign { path: PathBuf },
        RetainedConflict { recovery: PathBuf },
    }

    fn staging_dir(parent: &Path) -> Result<PathBuf> {
        for _ in 0..16 {
            let name = format!(
                ".harness-gate-preserve-{:016x}",
                NEXT_STAGING.fetch_add(1, Ordering::Relaxed)
            );
            let dir = parent.join(name);
            match fs::create_dir(&dir) {
                Ok(()) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
                    }
                    let meta = fs::symlink_metadata(&dir)?;
                    ensure!(
                        meta.is_dir() && !meta.file_type().is_symlink(),
                        "unsafe preservation staging directory"
                    );
                    return Ok(dir);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("cannot create private preservation staging directory")
    }

    fn contents(path: &Path) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(16384).read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    fn restore_no_clobber(staged: &Path, path: &Path) -> Result<bool> {
        let meta = fs::symlink_metadata(staged)?;
        if meta.is_dir() {
            // No portable no-clobber directory rename in std; retain and report.
            return Ok(false);
        }
        match fs::hard_link(staged, path) {
            Ok(()) => {
                fs::remove_file(staged)?;
                Ok(true)
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    /// Isolate, verify after the move, delete only a verified original, and
    /// restore anything else without clobbering. Directories are retained.
    pub(super) fn remove_owned_preserving(
        path: &Path,
        content: &[u8],
        identity: &fs::Metadata,
    ) -> Result<Outcome> {
        let parent = path.parent().context("hook parent")?;
        let staging = staging_dir(parent)?;
        let staged = staging.join("object");
        fs::rename(path, &staged).context("isolate hook before removal")?;
        let meta = fs::symlink_metadata(&staged)?;
        let ours = meta.is_file()
            && !meta.file_type().is_symlink()
            && same_identity(identity, &meta)
            && contents(&staged)? == content;
        if ours {
            fs::remove_file(&staged).context("remove verified owned hook")?;
            let _ = fs::remove_dir(&staging);
            return Ok(Outcome::Removed);
        }
        if restore_no_clobber(&staged, path)? {
            let _ = fs::remove_dir(&staging);
            return Ok(Outcome::RestoredForeign {
                path: path.to_path_buf(),
            });
        }
        Ok(Outcome::RetainedConflict { recovery: staged })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn owned(root: &Path, bytes: &[u8]) -> (PathBuf, fs::Metadata) {
            let path = root.join("pre-commit");
            fs::write(&path, bytes).unwrap();
            let identity = fs::symlink_metadata(&path).unwrap();
            (path, identity)
        }

        #[test]
        fn verified_original_is_removed_without_staging_leftovers() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            let outcome = remove_owned_preserving(&path, b"managed", &identity).unwrap();
            assert_eq!(outcome, Outcome::Removed);
            assert!(!path.exists());
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        }

        #[test]
        fn foreign_replacement_is_restored_without_clobber() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"foreign editor content").unwrap();
            let outcome = remove_owned_preserving(&path, b"managed", &identity).unwrap();
            assert_eq!(
                outcome,
                Outcome::RestoredForeign { path: path.clone() }
            );
            assert_eq!(fs::read(&path).unwrap(), b"foreign editor content");
            assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
        }

        #[test]
        fn conflict_keeps_recoverable_copy_and_reports_path() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"foreign").unwrap();
            // Simulate a second arrival after isolation but before restore.
            let parent = path.parent().unwrap();
            let staging = staging_dir(parent).unwrap();
            let staged = staging.join("object");
            fs::rename(&path, &staged).unwrap();
            fs::write(&path, b"new arrival").unwrap();
            assert!(!restore_no_clobber(&staged, &path).unwrap());
            let outcome = remove_owned_preserving(&path, b"managed", &identity);
            // The current path is now the new arrival, so this call restores it
            // again or reports a conflict; either way nothing is deleted.
            assert!(matches!(
                outcome.unwrap(),
                Outcome::RestoredForeign { .. } | Outcome::RetainedConflict { .. }
            ));
            assert!(path.exists());
            assert_eq!(fs::read(&path).unwrap(), b"new arrival");
        }

        #[test]
        fn symlink_and_directory_are_never_deleted() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            fs::remove_file(&path).unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink("foreign-target", &path).unwrap();
            let outcome = remove_owned_preserving(&path, b"managed", &identity).unwrap();
            assert!(matches!(
                outcome,
                Outcome::RestoredForeign { .. } | Outcome::RetainedConflict { .. }
            ));
            assert!(fs::symlink_metadata(&path).unwrap().file_type().is_symlink());

            let dir_path = root.path().join("pre-push");
            fs::create_dir(&dir_path).unwrap();
            let dir_identity = fs::symlink_metadata(&dir_path).unwrap();
            let outcome = remove_owned_preserving(&dir_path, b"managed", &dir_identity).unwrap();
            match outcome {
                Outcome::RetainedConflict { recovery } => {
                    assert!(recovery.is_dir(), "directory kept in the reported recovery path");
                }
                other => panic!("directory must be retained, got {other:?}"),
            }
        }

        #[test]
        fn crash_between_rename_and_decision_preserves_the_file() {
            let root = tempfile::tempdir().unwrap();
            let (path, _identity) = owned(root.path(), b"managed");
            let staging = staging_dir(root.path()).unwrap();
            let staged = staging.join("object");
            fs::rename(&path, &staged).unwrap();
            // Simulated crash: no decision or cleanup ran.
            assert!(!path.exists());
            assert_eq!(fs::read(&staged).unwrap(), b"managed");
        }
    }
}
