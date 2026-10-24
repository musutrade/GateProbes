//! Preservation instead of deletion for hook and lock objects (issue #92).
//!
//! On Unix every mutating path moves the object into a private backup directory
//! and never unlinks it. An object that is not the exact managed one is restored
//! no-clobber through a hard link, or retained in the backup when restore would
//! clobber. Holding the creation-time file handle keeps the inode alive, so a
//! writer that opened the object before isolation keeps its data.
//!
//! The 16 KiB constant is an inspection read cap, not a bound on how large a
//! retained object can grow through an already-open descriptor.
//!
//! Non-Unix keeps the previous support range: an identity check followed by
//! removal, with no new platform API and no cross-platform issue #92 claim.

use anyhow::{ensure, Context, Result};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::filesystem::same_identity;

pub(crate) const BACKUP_PREFIX: &str = ".harness-gate-preserve-";
const INSPECT_CAP: u64 = 16 * 1024;
const MAX_SCAN_ENTRIES: usize = 1024;

#[cfg(test)]
thread_local! {
    static BEFORE_ISOLATE: std::cell::RefCell<Option<fn(&Path)>> = const { std::cell::RefCell::new(None) };
    static REPLACEMENT_BYTES: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
pub(crate) fn test_arm_swap(bytes: &[u8]) {
    REPLACEMENT_BYTES.with(|slot| *slot.borrow_mut() = bytes.to_vec());
    BEFORE_ISOLATE.with(|slot| *slot.borrow_mut() = Some(test_replace_file));
}

#[cfg(test)]
pub(crate) fn test_disarm_swap() {
    BEFORE_ISOLATE.with(|slot| *slot.borrow_mut() = None);
}

#[cfg(test)]
fn test_replace_file(path: &Path) {
    let bytes = REPLACEMENT_BYTES.with(|slot| slot.borrow().clone());
    let _ = fs::remove_file(path);
    let _ = fs::write(path, bytes);
}

/// Result of retiring a hook object. `backup` is `None` only on platforms that
/// keep the previous non-preserving behaviour.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Removal {
    AlreadyAbsent,
    Removed {
        backup: Option<PathBuf>,
    },
    Preserved {
        backup: PathBuf,
        reason: &'static str,
        restored: bool,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum LockRelease {
    AlreadyAbsent,
    Released {
        backup: Option<PathBuf>,
    },
    LeftForeign {
        path: PathBuf,
    },
    LostOwnership {
        backup: PathBuf,
        reason: &'static str,
        restored: bool,
    },
}

#[derive(Debug)]
pub(crate) struct BackupReport {
    pub(crate) escaped: String,
    pub(crate) kind: &'static str,
    /// Logical object size as reported by metadata; not disk usage and not a
    /// recursive directory size.
    pub(crate) size: u64,
}

#[derive(Debug)]
struct Backup {
    dir: PathBuf,
    object: PathBuf,
}

#[cfg(unix)]
fn backup_directory(parent: &Path) -> Result<Backup> {
    // `tempfile` creates the directory with an atomic 0700 mode (mkdtemp) and a
    // random name; keeping it prevents its Drop from deleting the backup.
    let mut builder = tempfile::Builder::new();
    builder.prefix(BACKUP_PREFIX);
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(fs::Permissions::from_mode(0o700));
    }
    let dir = builder
        .tempdir_in(parent)
        .with_context(|| format!("create private preservation directory in {parent:?}"))?
        .keep();
    let meta = fs::symlink_metadata(&dir)
        .with_context(|| format!("inspect preservation directory {dir:?}"))?;
    ensure!(
        meta.is_dir() && !meta.file_type().is_symlink(),
        "preservation directory {dir:?} is not a real directory"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            meta.permissions().mode() & 0o077 == 0,
            "preservation directory {dir:?} is not private"
        );
    }
    Ok(Backup {
        object: dir.join("object"),
        dir,
    })
}

#[cfg(unix)]
fn isolate(path: &Path) -> Result<Backup> {
    let parent = path.parent().context("hook parent")?;
    let backup = backup_directory(parent)?;
    match fs::symlink_metadata(&backup.object) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => anyhow::bail!(
            "preservation target {:?} unexpectedly exists; {path:?} was not moved",
            backup.object
        ),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect preservation target {:?}", backup.object))
        }
    }
    #[cfg(test)]
    BEFORE_ISOLATE.with(|slot| {
        if let Some(hook) = *slot.borrow() {
            hook(path);
        }
    });
    fs::rename(path, &backup.object).with_context(|| {
        format!(
            "isolate {path:?} into preservation object {:?}",
            backup.object
        )
    })?;
    Ok(backup)
}

/// Returns `None` when the isolated object is exactly the held one, otherwise a
/// reason. Only an exact match may free the source path, and even then the inode
/// stays in the backup.
#[cfg(unix)]
fn staged_mismatch(
    backup: &Backup,
    held: &fs::Metadata,
    expected: Option<&[u8]>,
) -> Result<Option<&'static str>> {
    let meta = fs::symlink_metadata(&backup.object)
        .with_context(|| format!("inspect preserved object {:?}", backup.object))?;
    if meta.file_type().is_symlink() {
        return Ok(Some("symlink"));
    }
    if !meta.is_file() {
        return Ok(Some(if meta.is_dir() {
            "directory"
        } else {
            "special"
        }));
    }
    if !same_identity(held, &meta) {
        return Ok(Some("foreign"));
    }
    match expected {
        Some(content) => {
            if meta.len() != content.len() as u64 {
                return Ok(Some("modified"));
            }
            let mut bytes = Vec::new();
            fs::File::open(&backup.object)
                .with_context(|| format!("read preserved object {:?}", backup.object))?
                .take(INSPECT_CAP)
                .read_to_end(&mut bytes)
                .with_context(|| format!("read preserved object {:?}", backup.object))?;
            if bytes != content {
                return Ok(Some("modified"));
            }
        }
        None => {
            if meta.len() != 0 {
                return Ok(Some("modified"));
            }
        }
    }
    Ok(None)
}

#[cfg(unix)]
fn restore_no_clobber(backup: &Backup, path: &Path) -> Result<bool> {
    match fs::hard_link(&backup.object, path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => Err(error).with_context(|| {
            format!(
                "restore {path:?} from preservation object {:?}",
                backup.object
            )
        }),
    }
}

#[cfg(unix)]
fn classify(
    backup: Backup,
    path: &Path,
    held: &fs::Metadata,
    expected: Option<&[u8]>,
) -> Result<Removal> {
    match staged_mismatch(&backup, held, expected)? {
        None => Ok(Removal::Removed {
            backup: Some(backup.dir),
        }),
        Some(reason) => {
            // std has no no-clobber directory restore; keep it for manual recovery.
            let restored = if reason == "directory" {
                false
            } else {
                restore_no_clobber(&backup, path)?
            };
            Ok(Removal::Preserved {
                backup: backup.dir,
                reason,
                restored,
            })
        }
    }
}

#[cfg(unix)]
pub(crate) fn retire(path: &Path, content: &[u8], held: &fs::Metadata) -> Result<Removal> {
    let backup = isolate(path)?;
    classify(backup, path, held, Some(content))
}

#[cfg(not(unix))]
pub(crate) fn retire(path: &Path, _content: &[u8], held: &fs::Metadata) -> Result<Removal> {
    let meta = fs::symlink_metadata(path).with_context(|| format!("inspect {path:?}"))?;
    ensure!(
        same_identity(held, &meta) && !meta.file_type().is_symlink(),
        "hook object changed; refusing deletion of {path:?}"
    );
    fs::remove_file(path).with_context(|| format!("remove owned hook {path:?}"))?;
    Ok(Removal::Removed { backup: None })
}

#[cfg(unix)]
pub(crate) fn release_lock(
    path: &Path,
    held: &fs::Metadata,
    handle: &fs::File,
) -> Result<LockRelease> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LockRelease::AlreadyAbsent)
        }
        Err(error) => return Err(error).with_context(|| format!("inspect lock {path:?}")),
    };
    if meta.file_type().is_symlink() || !same_identity(held, &meta) {
        return Ok(LockRelease::LeftForeign {
            path: path.to_path_buf(),
        });
    }
    let backup = isolate(path)?;
    let handle_meta = handle
        .metadata()
        .with_context(|| format!("inspect held lifecycle lock {path:?}"))?;
    match staged_mismatch(&backup, &handle_meta, None)? {
        None => Ok(LockRelease::Released {
            backup: Some(backup.dir),
        }),
        Some(reason) => {
            // std has no no-clobber directory restore; keep it for manual recovery.
            let restored = if reason == "directory" {
                false
            } else {
                restore_no_clobber(&backup, path)?
            };
            Ok(LockRelease::LostOwnership {
                backup: backup.dir,
                reason,
                restored,
            })
        }
    }
}

#[cfg(not(unix))]
pub(crate) fn release_lock(path: &Path, held: &fs::Metadata) -> Result<LockRelease> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(LockRelease::AlreadyAbsent)
        }
        Err(error) => return Err(error).with_context(|| format!("inspect lock {path:?}")),
    };
    if meta.file_type().is_symlink() || !same_identity(held, &meta) || meta.len() != 0 {
        return Ok(LockRelease::LeftForeign {
            path: path.to_path_buf(),
        });
    }
    fs::remove_file(path).with_context(|| format!("remove owned lock {path:?}"))?;
    Ok(LockRelease::Released { backup: None })
}

/// Read-only discovery of retained objects and crash residue. Never mutates
/// anything, never follows symlinks, and fails explicitly when the scan would be
/// incomplete instead of returning a truncated result.
#[cfg(unix)]
pub(crate) fn discover(directory: &Path) -> Result<Vec<BackupReport>> {
    let mut rows = Vec::new();
    let mut seen = 0usize;
    for entry in fs::read_dir(directory).with_context(|| format!("scan {directory:?}"))? {
        seen += 1;
        ensure!(
            seen <= MAX_SCAN_ENTRIES,
            "preservation scan exceeded {MAX_SCAN_ENTRIES} directory entries in {directory:?}; refusing to report an incomplete result"
        );
        let entry = entry.with_context(|| format!("read entry {seen} in {directory:?}"))?;
        let name = entry.file_name();
        if !name.to_string_lossy().starts_with(BACKUP_PREFIX) {
            continue;
        }
        let path = entry.path();
        let meta = fs::symlink_metadata(&path)
            .with_context(|| format!("inspect preservation residue {path:?}"))?;
        if meta.file_type().is_symlink() {
            rows.push(BackupReport {
                escaped: format!("{path:?}"),
                kind: "symlink",
                size: meta.len(),
            });
            continue;
        }
        if !meta.is_dir() {
            rows.push(BackupReport {
                escaped: format!("{path:?}"),
                kind: "unexpected",
                size: meta.len(),
            });
            continue;
        }
        let object = path.join("object");
        match fs::symlink_metadata(&object) {
            Ok(object_meta) => {
                let kind = if object_meta.file_type().is_symlink() {
                    "symlink"
                } else if object_meta.is_dir() {
                    "directory"
                } else {
                    "file"
                };
                rows.push(BackupReport {
                    escaped: format!("{object:?}"),
                    kind,
                    size: object_meta.len(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => rows.push(BackupReport {
                escaped: format!("{object:?}"),
                kind: "empty",
                size: 0,
            }),
            Err(error) => {
                return Err(error).with_context(|| format!("inspect preserved object {object:?}"))
            }
        }
    }
    rows.sort_by(|left, right| left.escaped.cmp(&right.escaped));
    Ok(rows)
}

#[cfg(not(unix))]
pub(crate) fn discover(_directory: &Path) -> Result<Vec<BackupReport>> {
    Ok(Vec::new())
}

pub(crate) fn removal_notice(removal: &Removal) -> Option<String> {
    match removal {
        Removal::Removed {
            backup: Some(backup),
        } => Some(format!(
            "warning: retained hook object at {backup:?}; nothing is deleted automatically"
        )),
        Removal::Preserved {
            backup,
            reason,
            restored,
        } => Some(format!(
            "warning: hook object was {reason}; exact object kept at {backup:?} (restored={restored})"
        )),
        _ => None,
    }
}

pub(crate) fn lock_release_notice(release: &LockRelease) -> Option<String> {
    match release {
        LockRelease::Released {
            backup: Some(backup),
        } => Some(format!(
            "warning: retained lifecycle lock at {backup:?}; nothing is deleted automatically"
        )),
        _ => None,
    }
}

pub(crate) fn discovery_notices(rows: &[BackupReport]) -> Vec<String> {
    if rows.is_empty() {
        return Vec::new();
    }
    let mut lines = vec![format!(
        "warning: {} retained hook object(s); review and remove manually:",
        rows.len()
    )];
    lines.extend(rows.iter().map(|row| {
        format!(
            "  {} ({}, {} bytes logical)",
            row.escaped, row.kind, row.size
        )
    }));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::path::PathBuf;

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
        let mut handle = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let backup = isolate(&path).unwrap();
        handle.write_all(b"user edit after isolation").unwrap();
        handle.sync_all().unwrap();
        let removal = classify(backup, &path, &identity, Some(b"managed")).unwrap();
        let Removal::Preserved {
            backup,
            reason,
            restored,
        } = removal
        else {
            panic!("expected preservation, got {removal:?}");
        };
        assert_eq!(reason, "modified");
        assert!(restored);
        assert_eq!(
            fs::read(backup.join("object")).unwrap(),
            b"user edit after isolation"
        );
        assert_eq!(fs::read(&path).unwrap(), b"user edit after isolation");
        assert!(same_inode(&backup.join("object"), &path));
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
        let _ = classify(backup, &path, &identity, Some(b"managed")).unwrap();
        assert_eq!(fs::read(&extra).unwrap(), b"edit through hard link");
        assert_eq!(fs::read(&path).unwrap(), b"edit through hard link");
    }

    // Regression fixture for the rejected v1 policy: an unlink after
    // verification loses a write made through a pre-opened descriptor. It
    // documents why production never unlinks the isolated object; it does not
    // exercise a production code path.
    #[test]
    fn regression_fixture_v1_unlink_loses_preopened_edit() {
        let root = tempfile::tempdir().unwrap();
        let (path, identity) = owned(root.path(), b"managed");
        let mut handle = fs::OpenOptions::new().write(true).open(&path).unwrap();
        let backup = isolate(&path).unwrap();
        assert!(same_identity(
            &identity,
            &fs::symlink_metadata(&backup.object).unwrap()
        ));
        handle.write_all(b"user edit").unwrap();
        fs::remove_file(&backup.object).unwrap(); // v1 behaviour
        drop(handle);
        assert_eq!(
            fs::read_dir(&backup.dir).unwrap().count(),
            0,
            "v1 loses the edit; production must retain the object"
        );
    }

    #[test]
    fn owned_object_frees_path_but_keeps_backup() {
        let root = tempfile::tempdir().unwrap();
        let (path, identity) = owned(root.path(), b"managed");
        let removal = retire(&path, b"managed", &identity).unwrap();
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
    fn foreign_object_is_restored_with_backup_link() {
        let root = tempfile::tempdir().unwrap();
        let (path, identity) = owned(root.path(), b"managed");
        let keep = root.path().join("kept-inode");
        fs::hard_link(&path, &keep).unwrap();
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"foreign content").unwrap();
        let removal = retire(&path, b"managed", &identity).unwrap();
        let Removal::Preserved {
            backup,
            reason,
            restored,
        } = removal
        else {
            panic!("expected preservation, got {removal:?}");
        };
        assert_eq!(reason, "foreign");
        assert!(restored);
        assert_eq!(fs::read(&path).unwrap(), b"foreign content");
        assert_eq!(fs::read(backup.join("object")).unwrap(), b"foreign content");
        assert!(same_inode(&path, &backup.join("object")));
    }

    #[test]
    fn restore_conflict_retains_backup_and_reports_path() {
        let root = tempfile::tempdir().unwrap();
        let (path, identity) = owned(root.path(), b"managed");
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"foreign").unwrap();
        let backup = isolate(&path).unwrap();
        fs::write(&path, b"new arrival").unwrap();
        let removal = classify(backup, &path, &identity, Some(b"managed")).unwrap();
        let Removal::Preserved {
            backup, restored, ..
        } = removal
        else {
            panic!("expected retained conflict, got {removal:?}");
        };
        assert!(!restored);
        assert_eq!(fs::read(backup.join("object")).unwrap(), b"foreign");
        assert_eq!(fs::read(&path).unwrap(), b"new arrival");
        let notice = removal_notice(&Removal::Preserved {
            backup,
            reason: "foreign",
            restored: false,
        })
        .unwrap();
        assert!(notice.contains("object"));
    }

    #[test]
    fn symlink_and_directory_are_never_deleted() {
        let root = tempfile::tempdir().unwrap();
        let (path, identity) = owned(root.path(), b"managed");
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("foreign-target", &path).unwrap();
        let removal = retire(&path, b"managed", &identity).unwrap();
        assert!(matches!(
            removal,
            Removal::Preserved {
                reason: "symlink",
                restored: true,
                ..
            }
        ));
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());

        let directory = root.path().join("pre-push");
        fs::create_dir(&directory).unwrap();
        let dir_identity = fs::symlink_metadata(&directory).unwrap();
        let removal = retire(&directory, b"managed", &dir_identity).unwrap();
        let Removal::Preserved {
            backup,
            reason,
            restored,
        } = removal
        else {
            panic!("expected retained directory");
        };
        assert_eq!(reason, "directory");
        assert!(!restored);
        assert!(backup.join("object").is_dir());
    }

    #[test]
    fn crash_residue_is_discovered_read_only_with_exact_path() {
        let root = tempfile::tempdir().unwrap();
        let (path, _identity) = owned(root.path(), b"managed");
        let backup = isolate(&path).unwrap();
        let rows = discover(root.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].escaped, format!("{:?}", backup.object));
        assert_eq!(rows[0].kind, "file");
        assert_eq!(rows[0].size, 7);
        assert_eq!(fs::read(&backup.object).unwrap(), b"managed");
        assert!(fs::read_dir(root.path()).unwrap().count() >= 1);
    }

    #[test]
    fn discovery_is_bounded_and_reports_unexpected_residue() {
        let root = tempfile::tempdir().unwrap();
        let residue = root.path().join(format!("{BACKUP_PREFIX}odd"));
        fs::create_dir(&residue).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", residue.join("object")).unwrap();
        let rows = discover(root.path()).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "symlink");
        assert!(rows[0].escaped.contains("object"));

        for index in 0..MAX_SCAN_ENTRIES {
            fs::write(root.path().join(format!("entry-{index}")), b"").unwrap();
        }
        let error = discover(root.path()).unwrap_err();
        assert!(error.to_string().contains("incomplete"));
    }

    #[test]
    fn discovery_surfaces_permission_errors() {
        let root = tempfile::tempdir().unwrap();
        let locked = root.path().join("locked");
        fs::create_dir(&locked).unwrap();
        let residue = locked.join(format!("{BACKUP_PREFIX}one"));
        fs::create_dir(&residue).unwrap();
        fs::write(residue.join("object"), b"managed").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read_dir(&locked).is_ok() {
            // A privileged user can still read the directory; nothing to assert.
            fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }
        let error = discover(&locked).unwrap_err();
        assert!(error.to_string().contains("locked"));
        fs::set_permissions(&locked, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn lock_release_preserves_replacement_between_precheck_and_rename() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".harness-gate-hooks.lock");
        let handle = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let identity = handle.metadata().unwrap();
        test_arm_swap(b"foreign lock content");
        let release = release_lock(&path, &identity, &handle);
        test_disarm_swap();
        let release = release.unwrap();
        let LockRelease::LostOwnership {
            backup,
            reason,
            restored,
        } = release
        else {
            panic!("expected lost ownership, got {release:?}");
        };
        assert_eq!(reason, "foreign");
        assert!(restored);
        assert_eq!(fs::read(&path).unwrap(), b"foreign lock content");
        assert_eq!(
            fs::read(backup.join("object")).unwrap(),
            b"foreign lock content"
        );
        assert!(same_inode(&path, &backup.join("object")));
    }

    #[test]
    fn stale_release_leaves_new_holder_alone() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join(".harness-gate-hooks.lock");
        let old = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let old_identity = old.metadata().unwrap();
        let release = release_lock(&path, &old_identity, &old).unwrap();
        assert!(matches!(release, LockRelease::Released { backup: Some(_) }));
        let new = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        let stale = release_lock(&path, &old_identity, &old).unwrap();
        assert!(matches!(stale, LockRelease::LeftForeign { .. }));
        assert!(path.exists());
        drop(new);
    }

    #[test]
    fn notices_use_escaped_paths_and_report_every_residue() {
        let rows = vec![
            BackupReport {
                escaped: "/tmp/a b/object".to_string(),
                kind: "file",
                size: 3,
            },
            BackupReport {
                escaped: "/tmp/x/object".to_string(),
                kind: "directory",
                size: 0,
            },
        ];
        let lines = discovery_notices(&rows);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("2 retained"));
        assert!(lines[1].contains("/tmp/a b/object"));
        assert!(lines[2].contains("directory"));
    }
}
