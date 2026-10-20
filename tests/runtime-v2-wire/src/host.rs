//! Host-side spawn pinning: env_clear, no additional arguments, stdin actual,
//! fd3 config and fd4 expected request as sealed memfds.

use std::collections::BTreeSet;
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Stdio};

#[derive(Default)]
pub struct SpawnSpec {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub stdin: Vec<u8>,
    pub fd3: Option<OwnedFd>,
    pub fd4: Option<OwnedFd>,
    pub extras: Vec<(RawFd, OwnedFd)>,
}

pub struct HostOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl HostOutput {
    pub fn succeeded(&self) -> bool {
        self.status.success()
    }

    pub fn stdout_empty(&self) -> bool {
        self.stdout.is_empty()
    }

    pub fn stdout_within_limit(&self) -> bool {
        self.stdout.len() <= crate::MAX_MESSAGE_BYTES
    }
}

pub fn run(spec: SpawnSpec) -> io::Result<HostOutput> {
    let mut command = Command::new(&spec.executable);
    command.env_clear();
    command.args(&spec.args);
    command.current_dir(&spec.cwd);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    const MAX_TARGET_FD: RawFd = 512;
    let mut requested = Vec::new();
    if let Some(fd) = &spec.fd3 {
        requested.push((fd.as_raw_fd(), 3));
    }
    if let Some(fd) = &spec.fd4 {
        requested.push((fd.as_raw_fd(), 4));
    }
    for (target, fd) in &spec.extras {
        requested.push((fd.as_raw_fd(), *target));
    }

    let mut reserved = BTreeSet::new();
    for (source, target) in &requested {
        if *source < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("source descriptor out of range: {source}"),
            ));
        }
        let flags = unsafe { libc::fcntl(*source, libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::FD_CLOEXEC == 0
            && unsafe { libc::fcntl(*source, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if *target < 3 || *target > MAX_TARGET_FD {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("target descriptor out of range: {target}"),
            ));
        }
        if !reserved.insert(*target) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("duplicate target descriptor: {target}"),
            ));
        }
    }

    // Stage every source before any dup2. Without this, a source that equals a
    // later target (or a swap) is clobbered by sequential child remapping.
    let stage_min = reserved
        .iter()
        .next_back()
        .map_or(64, |target| (*target + 1).max(64));
    let mut staged = Vec::new();
    let mut remap = Vec::new();
    for (source, target) in requested {
        let copy = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, stage_min) };
        if copy < 0 {
            return Err(io::Error::last_os_error());
        }
        let copy = unsafe { OwnedFd::from_raw_fd(copy) };
        remap.push((copy.as_raw_fd(), target));
        staged.push(copy);
    }
    let reserved_for_child: Vec<RawFd> = reserved.into_iter().collect();

    unsafe {
        command.pre_exec(move || {
            for (source, target) in &remap {
                if libc::dup2(*source, *target) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for fd in 3..2048 {
                if !reserved_for_child.contains(&fd) {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }

    let mut child = command.spawn()?;
    drop(staged);
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&spec.stdin)?;
    }
    let output = child.wait_with_output()?;
    Ok(HostOutput {
        status: output.status,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}
