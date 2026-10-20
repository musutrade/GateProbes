//! Local filesystem/socket observations, not daemon or namespace authentication.
use crate::input::{Config, Result};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

#[derive(Debug, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl Identity {
    fn of(m: &std::fs::Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            mode: m.mode(),
            uid: m.uid(),
            gid: m.gid(),
            nlink: m.nlink(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}

pub struct SocketIdentity {
    path: PathBuf,
    uid: u32,
    principal: u32,
    identity: Identity,
}

fn observe(path: &Path, uid: u32, principal: u32) -> Result<Identity> {
    let rejected = "runtime local identity rejected";
    if principal != unsafe { libc::geteuid() }
        || !path.is_absolute()
        || std::fs::canonicalize(path).map_err(|_| rejected)? != path
    {
        return Err(rejected);
    }
    for parent in path.ancestors().skip(1) {
        let metadata = std::fs::symlink_metadata(parent).map_err(|_| rejected)?;
        if !metadata.is_dir()
            || ![0, principal].contains(&metadata.uid())
            || metadata.mode() & 0o022 != 0
        {
            return Err(rejected);
        }
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| rejected)?;
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(rejected);
    }
    Ok(Identity::of(&metadata))
}

impl SocketIdentity {
    pub fn verify(config: &Config) -> Result<Self> {
        let path = PathBuf::from(&config.socket_path);
        let identity = observe(&path, config.socket_uid, config.principal_uid)?;
        Ok(Self {
            path,
            uid: config.socket_uid,
            principal: config.principal_uid,
            identity,
        })
    }
    pub fn revalidate(&self) -> Result<()> {
        if observe(&self.path, self.uid, self.principal)? != self.identity {
            return Err("runtime local identity changed");
        }
        Ok(())
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}
