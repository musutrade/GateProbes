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

// Test-only prototype v2: retain the moved inode as a recoverable backup.
// Nothing here is wired into production; it exists to review the retention and
// reporting semantics before a production implementation.
#[cfg(test)]
pub(super) mod preserve_prototype {
    use super::*;
    use std::fs::DirBuilder;
    use std::path::{Path, PathBuf};

    pub(super) const BACKUP_PREFIX: &str = ".harness-gate-preserve-";

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Outcome {
        /// Path freed; the moved inode is retained as a backup.
        RemovedOwned { backup: PathBuf },
        /// Foreign or modified object restored no-clobber; the backup link stays.
        Restored {
            path: PathBuf,
            backup: PathBuf,
            reason: &'static str,
        },
        /// Restore was impossible without clobbering; the object stays in backup.
        RetainedConflict { backup: PathBuf, reason: &'static str },
    }

    #[derive(Debug, Clone)]
    pub(super) struct Backup {
        pub(super) dir: PathBuf,
        pub(super) object: PathBuf,
    }

    #[derive(Debug)]
    pub(super) struct BackupReport {
        pub(super) dir: PathBuf,
        pub(super) object: PathBuf,
        pub(super) kind: &'static str,
        pub(super) size: u64,
        pub(super) escaped: String,
    }

    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum LockRelease {
        AlreadyAbsent,
        Released { backup: PathBuf },
        LeftForeign { path: PathBuf },
    }

    fn unique_name() -> String {
        let mut bytes = [0u8; 16];
        let random = fs::File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut bytes))
            .is_ok();
        if !random {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|value| value.as_nanos())
                .unwrap_or(0);
            bytes[..8].copy_from_slice(&nanos.to_le_bytes());
            bytes[8..12].copy_from_slice(&std::process::id().to_le_bytes());
        }
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn backup_directory(parent: &Path) -> Result<Backup> {
        for _ in 0..16 {
            let dir = parent.join(format!("{BACKUP_PREFIX}{}", unique_name()));
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&dir) {
                Ok(()) => {
                    let meta = fs::symlink_metadata(&dir)?;
                    ensure!(
                        meta.is_dir() && !meta.file_type().is_symlink(),
                        "unsafe preservation backup directory"
                    );
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        ensure!(
                            meta.permissions().mode() & 0o077 == 0,
                            "preservation backup directory is not private"
                        );
                    }
                    return Ok(Backup {
                        object: dir.join("object"),
                        dir,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        anyhow::bail!("cannot create private preservation backup directory")
    }

    fn read_bytes(path: &Path) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        fs::File::open(path)?.take(16384).read_to_end(&mut bytes)?;
        Ok(bytes)
    }

    /// Atomically move the object into a private backup directory. The inode is
    /// never unlinked; pre-opened writers keep the same inode alive in the
    /// backup. The target name is checked free first; a same-user race remains
    /// and is explicitly out of scope.
    pub(super) fn isolate(path: &Path) -> Result<Backup> {
        let parent = path.parent().context("hook parent")?;
        let backup = backup_directory(parent)?;
        match fs::symlink_metadata(&backup.object) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            _ => anyhow::bail!("preservation backup target unexpectedly exists"),
        }
        fs::rename(path, &backup.object).context("isolate object into backup")?;
        Ok(backup)
    }

    /// Decide after the move. Only an exact owned object may free the path, and
    /// even then its inode stays in the backup. Everything else is restored
    /// no-clobber or retained with its exact backup path.
    pub(super) fn classify(
        backup: &Backup,
        path: &Path,
        content: &[u8],
        identity: &fs::Metadata,
    ) -> Result<Outcome> {
        let meta = fs::symlink_metadata(&backup.object)?;
        let ours = meta.is_file()
            && !meta.file_type().is_symlink()
            && same_identity(identity, &meta)
            && read_bytes(&backup.object)? == content;
        if ours {
            return Ok(Outcome::RemovedOwned {
                backup: backup.dir.clone(),
            });
        }
        if meta.is_dir() {
            return Ok(Outcome::RetainedConflict {
                backup: backup.dir.clone(),
                reason: "directory",
            });
        }
        let reason = if meta.file_type().is_symlink() {
            "symlink"
        } else if same_identity(identity, &meta) {
            "modified"
        } else {
            "foreign"
        };
        match fs::hard_link(&backup.object, path) {
            Ok(()) => Ok(Outcome::Restored {
                path: path.to_path_buf(),
                backup: backup.dir.clone(),
                reason,
            }),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                Ok(Outcome::RetainedConflict {
                    backup: backup.dir.clone(),
                    reason: "restore target occupied",
                })
            }
            Err(error) => Err(error.into()),
        }
    }

    /// Read-only discovery of crash residue. Never mutates anything.
    pub(super) fn discover(directory: &Path) -> Result<Vec<BackupReport>> {
        let mut rows = Vec::new();
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(BACKUP_PREFIX) {
                continue;
            }
            let meta = fs::symlink_metadata(entry.path())?;
            if !meta.is_dir() || meta.file_type().is_symlink() {
                continue;
            }
            let object = entry.path().join("object");
            let Ok(object_meta) = fs::symlink_metadata(&object) else {
                continue;
            };
            let kind = if object_meta.file_type().is_symlink() {
                "symlink"
            } else if object_meta.is_dir() {
                "directory"
            } else {
                "file"
            };
            rows.push(BackupReport {
                escaped: format!("{:?}", object),
                dir: entry.path(),
                object,
                kind,
                size: object_meta.len(),
            });
        }
        rows.sort_by(|left, right| left.dir.cmp(&right.dir));
        Ok(rows)
    }

    /// Lock release is separate from hook removal: verify identity, then move
    /// the lock into a backup. A foreign lock is never moved or deleted.
    pub(super) fn release_lock(path: &Path, identity: &fs::Metadata) -> Result<LockRelease> {
        let meta = match fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(LockRelease::AlreadyAbsent)
            }
            Err(error) => return Err(error.into()),
        };
        if !same_identity(identity, &meta) {
            return Ok(LockRelease::LeftForeign {
                path: path.to_path_buf(),
            });
        }
        let backup = isolate(path)?;
        Ok(LockRelease::Released { backup: backup.dir })
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Write as _;

        fn owned(root: &Path, bytes: &[u8]) -> (PathBuf, fs::Metadata) {
            let path = root.join("pre-commit");
            fs::write(&path, bytes).unwrap();
            let identity = fs::symlink_metadata(&path).unwrap();
            (path, identity)
        }

        fn same_inode(left: &Path, right: &Path) -> bool {
            same_identity(
                &fs::symlink_metadata(left).unwrap(),
                &fs::symlink_metadata(right).unwrap(),
            )
        }

        #[test]
        fn preopened_fd_write_after_isolation_is_preserved() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            let mut handle = fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap();
            let backup = isolate(&path).unwrap();
            handle.write_all(b"user edit after isolation").unwrap();
            handle.sync_all().unwrap();
            let outcome = classify(&backup, &path, b"managed", &identity).unwrap();
            assert!(matches!(outcome, Outcome::Restored { reason: "modified", .. }));
            assert_eq!(fs::read(&backup.object).unwrap(), b"user edit after isolation");
            assert_eq!(fs::read(&path).unwrap(), b"user edit after isolation");
            assert!(same_inode(&backup.object, &path));
        }

        #[test]
        fn preopened_fd_with_existing_hardlink_keeps_edits_visible() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            let extra = root.path().join("editor-link");
            fs::hard_link(&path, &extra).unwrap();
            let mut handle = fs::OpenOptions::new().write(true).open(&path).unwrap();
            let backup = isolate(&path).unwrap();
            handle.write_all(b"edit through hard link").unwrap();
            let _ = classify(&backup, &path, b"managed", &identity).unwrap();
            assert_eq!(fs::read(&extra).unwrap(), b"edit through hard link");
            assert_eq!(fs::read(&backup.object).unwrap(), b"edit through hard link");
        }

        // Why v1 was rejected: a pre-opened writer keeps the inode alive, so an
        // unlink after verification still loses the user's later write.
        #[test]
        fn v1_style_unlink_after_verification_loses_preopened_edit() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            let mut handle = fs::OpenOptions::new().write(true).open(&path).unwrap();
            let backup = isolate(&path).unwrap();
            assert!(same_identity(&identity, &fs::symlink_metadata(&backup.object).unwrap()));
            handle.write_all(b"user edit").unwrap();
            fs::remove_file(&backup.object).unwrap(); // v1 behaviour
            assert!(!backup.object.exists());
            drop(handle);
            assert_eq!(fs::read_dir(&backup.dir).unwrap().count(), 0, "the edit is gone");
        }

        #[test]
        fn owned_object_frees_path_but_keeps_backup() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            let backup = isolate(&path).unwrap();
            let outcome = classify(&backup, &path, b"managed", &identity).unwrap();
            assert_eq!(outcome, Outcome::RemovedOwned { backup: backup.dir.clone() });
            assert!(!path.exists());
            assert_eq!(fs::read(&backup.object).unwrap(), b"managed");
        }

        #[test]
        fn foreign_object_is_restored_with_backup_link() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            // Keep the original inode alive so the filesystem cannot reuse its
            // number for the replacement; dev+ino alone is not a strong identity.
            let keep = root.path().join("kept-inode");
            fs::hard_link(&path, &keep).unwrap();
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"foreign content").unwrap();
            let backup = isolate(&path).unwrap();
            let outcome = classify(&backup, &path, b"managed", &identity).unwrap();
            assert!(matches!(outcome, Outcome::Restored { reason: "foreign", .. }));
            assert_eq!(fs::read(&path).unwrap(), b"foreign content");
            assert_eq!(fs::read(&backup.object).unwrap(), b"foreign content");
            assert!(same_inode(&path, &backup.object));
        }

        #[test]
        fn restore_conflict_retains_backup_and_reports_path() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            fs::remove_file(&path).unwrap();
            fs::write(&path, b"foreign").unwrap();
            let backup = isolate(&path).unwrap();
            fs::write(&path, b"new arrival").unwrap();
            let outcome = classify(&backup, &path, b"managed", &identity).unwrap();
            match outcome {
                Outcome::RetainedConflict { backup: dir, reason } => {
                    assert_eq!(reason, "restore target occupied");
                    assert_eq!(fs::read(dir.join("object")).unwrap(), b"foreign");
                }
                other => panic!("expected retained conflict, got {other:?}"),
            }
            assert_eq!(fs::read(&path).unwrap(), b"new arrival");
        }

        #[test]
        fn symlink_and_directory_are_never_deleted() {
            let root = tempfile::tempdir().unwrap();
            let (path, identity) = owned(root.path(), b"managed");
            fs::remove_file(&path).unwrap();
            #[cfg(unix)]
            std::os::unix::fs::symlink("foreign-target", &path).unwrap();
            let backup = isolate(&path).unwrap();
            let outcome = classify(&backup, &path, b"managed", &identity).unwrap();
            assert!(matches!(outcome, Outcome::Restored { reason: "symlink", .. }));
            assert!(fs::symlink_metadata(&path).unwrap().file_type().is_symlink());

            let directory = root.path().join("pre-push");
            fs::create_dir(&directory).unwrap();
            let dir_identity = fs::symlink_metadata(&directory).unwrap();
            let backup = isolate(&directory).unwrap();
            let outcome = classify(&backup, &directory, b"managed", &dir_identity).unwrap();
            assert!(matches!(outcome, Outcome::RetainedConflict { reason: "directory", .. }));
            assert!(backup.object.is_dir());
        }

        #[test]
        fn crash_residue_is_discovered_read_only_with_exact_path() {
            let root = tempfile::tempdir().unwrap();
            let (path, _identity) = owned(root.path(), b"managed");
            let backup = isolate(&path).unwrap();
            // Simulated crash: no classify, no cleanup.
            let rows = discover(root.path()).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].object, backup.object);
            assert!(rows[0].escaped.contains("object"));
            assert!(rows[0].size > 0);
            assert_eq!(fs::read(&backup.object).unwrap(), b"managed");
        }

        #[test]
        fn lock_release_retains_backup_and_leaves_new_holder_alone() {
            let root = tempfile::tempdir().unwrap();
            let lock = Lock::acquire(root.path()).unwrap();
            let old_identity = lock.identity.clone();
            let path = lock.path.clone();
            let released = release_lock(&path, &old_identity).unwrap();
            let LockRelease::Released { backup } = released else {
                panic!("expected released lock");
            };
            assert!(!path.exists());
            assert!(backup.join("object").exists());
            let new_lock = Lock::acquire(root.path()).unwrap();
            // An old instance's fallback must not touch the new holder.
            let stale = release_lock(&path, &old_identity).unwrap();
            assert!(matches!(stale, LockRelease::LeftForeign { .. }));
            assert!(path.exists());
            drop(new_lock);
        }
    }
}
