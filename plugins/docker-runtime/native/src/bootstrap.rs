//! Linux fixture bootstrap: sealed host-owned fd3/fd4, no path reopen or fallback.
//! This does not independently authenticate the launching host or installed code.
use crate::input::{self, Config, Request, Result, LIMIT};
use std::io::Read;

fn reject<T>() -> Result<T> {
    Err("runtime bootstrap rejected")
}

#[cfg(target_os = "linux")]
fn sealed(fd: libc::c_int) -> Result<Vec<u8>> {
    let mut before: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut before) } != 0 {
        return reject();
    }
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    let required = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_mode & 0o7777 != 0o600
        || before.st_uid != unsafe { libc::geteuid() }
        || before.st_nlink != 0
        || before.st_size < 0
        || before.st_size > LIMIT as i64
        || seals < 0
        || seals & required != required
    {
        return reject();
    }
    let mut bytes = vec![0; before.st_size as usize];
    let mut offset = 0;
    while offset < bytes.len() {
        let count = unsafe {
            libc::pread(
                fd,
                bytes[offset..].as_mut_ptr().cast(),
                bytes.len() - offset,
                offset as libc::off_t,
            )
        };
        if count <= 0 {
            return reject();
        }
        offset += count as usize;
    }
    let mut after: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut after) } != 0
        || before.st_dev != after.st_dev
        || before.st_ino != after.st_ino
        || before.st_size != after.st_size
        || before.st_mode != after.st_mode
        || before.st_uid != after.st_uid
        || before.st_nlink != after.st_nlink
    {
        return reject();
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
pub(crate) fn read_bytes() -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    if std::env::args_os().count() != 1 {
        return reject();
    }
    // Drop the directory iterator before checking descriptors, so its transient
    // descriptor does not cause a false rejection. No inherited fd is closed.
    let fds: Vec<i32> = std::fs::read_dir("/proc/self/fd")
        .map_err(|_| "runtime bootstrap rejected")?
        .map(|entry| {
            entry
                .ok()
                .and_then(|e| e.file_name().to_str().and_then(|s| s.parse().ok()))
        })
        .collect::<Option<Vec<_>>>()
        .ok_or("runtime bootstrap rejected")?;
    for fd in fds {
        if fd > 4 && unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1 {
            return reject();
        }
    }
    let config = sealed(3)?;
    let expected = sealed(4)?;
    let mut actual = Vec::new();
    std::io::stdin()
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut actual)
        .map_err(|_| "runtime bootstrap rejected")?;
    Ok((expected, actual, config))
}

#[cfg(target_os = "linux")]
pub fn read() -> Result<(Request, Config)> {
    let (expected, actual, config) = read_bytes()?;
    input::validate_inputs(&expected, &actual, &config)
}

#[cfg(not(target_os = "linux"))]
pub fn read() -> Result<(Request, Config)> {
    reject()
}
