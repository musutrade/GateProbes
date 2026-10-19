use anyhow::{ensure, Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::Path;

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
