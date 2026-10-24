use anyhow::{ensure, Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use super::preserve::{self, LockRelease, Removal};

pub(super) const MARKER: &str = "# harness-gate managed hook v1";

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

pub(super) fn remove_owned(
    path: &Path,
    content: &[u8],
    identity: &fs::Metadata,
) -> Result<Removal> {
    let state = inspect(path, content)?;
    if state == State::Absent {
        return Ok(Removal::AlreadyAbsent);
    }
    ensure!(
        matches!(state, State::Current | State::NotExecutable),
        "hook changed; refusing to remove {path:?}"
    );
    let meta = fs::symlink_metadata(path).with_context(|| format!("inspect hook {path:?}"))?;
    ensure!(
        same_identity(identity, &meta),
        "hook object changed; refusing deletion of {path:?}"
    );
    preserve::retire(path, content, identity)
}

pub(super) struct Lock {
    path: PathBuf,
    identity: fs::Metadata,
    // Holding the creation-time handle keeps the inode alive, so an isolated
    // object can be verified against it without inode reuse.
    #[cfg(unix)]
    file: fs::File,
    finished: bool,
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
        let identity = file
            .metadata()
            .with_context(|| format!("inspect lifecycle lock {path:?}"))?;
        Ok(Self {
            path,
            identity,
            #[cfg(unix)]
            file,
            finished: false,
        })
    }

    /// Explicit release after every hook action and preservation report. The
    /// caller must inspect the returned outcome and never report plain success
    /// for `LeftForeign` or `LostOwnership`.
    pub(super) fn finish(mut self) -> Result<LockRelease> {
        self.finished = true;
        #[cfg(unix)]
        {
            preserve::release_lock(&self.path, &self.identity, &self.file)
        }
        #[cfg(not(unix))]
        {
            preserve::release_lock(&self.path, &self.identity)
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        // Fallback for unwinding paths that never reached `finish`. It only
        // preserves; it never deletes and never re-moves a finished lock.
        if self.finished {
            return;
        }
        #[cfg(unix)]
        let outcome = preserve::release_lock(&self.path, &self.identity, &self.file);
        #[cfg(not(unix))]
        let outcome = preserve::release_lock(&self.path, &self.identity);
        if let Ok(LockRelease::LostOwnership {
            backup,
            reason,
            restored,
        }) = outcome
        {
            eprintln!(
                "warning: lifecycle lock ownership was lost ({reason}); exact object kept at {backup:?} (restored={restored})"
            );
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
        let removal = remove_owned(&path, b"managed", &identity).unwrap();
        assert_eq!(removal, Removal::AlreadyAbsent);
        publish(&path, b"managed").unwrap();
        let identity = fs::symlink_metadata(&path).unwrap();
        let removal = remove_owned(&path, b"managed", &identity).unwrap();
        let Removal::Removed {
            backup: Some(backup),
        } = removal
        else {
            panic!("expected retained backup, got {removal:?}");
        };
        assert!(!path.exists());
        assert_eq!(fs::read(backup.join("object")).unwrap(), b"managed");
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

    #[test]
    fn finish_retains_lock_backup_and_is_not_repeated_by_drop() {
        let root = tempfile::tempdir().unwrap();
        let lock = Lock::acquire(root.path()).unwrap();
        let path = lock.path.clone();
        let release = lock.finish().unwrap();
        let LockRelease::Released {
            backup: Some(backup),
        } = release
        else {
            panic!("expected retained lock backup, got {release:?}");
        };
        assert!(!path.exists());
        assert_eq!(fs::read(backup.join("object")).unwrap(), b"");
        let backups = fs::read_dir(root.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(preserve::BACKUP_PREFIX)
            })
            .count();
        assert_eq!(backups, 1, "Drop must not move an already-finished lock");
    }
}
