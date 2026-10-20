//! Host-side spawn pinning: env_clear, no additional arguments, stdin actual,
//! fd3 config and fd4 expected request as sealed memfds.

use std::ffi::OsString;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
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

    let mut duplicates = Vec::new();
    if let Some(fd) = &spec.fd3 {
        duplicates.push((fd.as_raw_fd(), 3));
    }
    if let Some(fd) = &spec.fd4 {
        duplicates.push((fd.as_raw_fd(), 4));
    }
    for (target, fd) in &spec.extras {
        duplicates.push((fd.as_raw_fd(), *target));
    }
    let mut reserved: Vec<RawFd> = duplicates.iter().map(|(_, target)| *target).collect();
    reserved.sort_unstable();
    reserved.dedup();
    let duplicates_for_child = duplicates.clone();

    unsafe {
        command.pre_exec(move || {
            for (source, target) in &duplicates_for_child {
                if libc::dup2(*source, *target) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            for fd in 3..1024 {
                if !reserved.contains(&fd) {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }

    let mut child = command.spawn()?;
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
