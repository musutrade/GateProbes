//! Linux sealed-memfd construction and digest helpers for the host side.

use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::FileExt;
use std::path::Path;

pub const REQUIRED_SEALS: i32 =
    libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    let value = digest.finalize();
    let mut output = String::with_capacity(64);
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("writing to String");
    }
    output
}

fn create(name: &str, flags: libc::c_uint) -> io::Result<OwnedFd> {
    let name =
        CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL"))?;
    let fd = unsafe { libc::memfd_create(name.as_ptr(), flags | libc::MFD_CLOEXEC) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fchmod(fd, 0o600) } < 0 {
        let error = io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn write_all(fd: RawFd, mut bytes: &[u8]) -> io::Result<()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if written == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "memfd write"));
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

pub fn sealed(name: &str, bytes: &[u8]) -> io::Result<OwnedFd> {
    let fd = create(name, libc::MFD_ALLOW_SEALING)?;
    write_all(fd.as_raw_fd(), bytes)?;
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_SEALS) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn unsealed(name: &str, bytes: &[u8]) -> io::Result<OwnedFd> {
    let fd = create(name, libc::MFD_ALLOW_SEALING)?;
    write_all(fd.as_raw_fd(), bytes)?;
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

pub fn seals(fd: RawFd) -> io::Result<i32> {
    let value = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

pub fn regular_file(path: &Path, bytes: &[u8]) -> io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)?;
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } < 0 {
        return Err(io::Error::last_os_error());
    }
    file.write_all_at(bytes, 0)?;
    Ok(file)
}

pub fn read_sealed(fd: &OwnedFd) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut offset = 0u64;
    let mut buffer = [0u8; 4096];
    loop {
        let count = unsafe {
            libc::pread(
                fd.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                offset as libc::off_t,
            )
        };
        if count < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if count == 0 {
            return Ok(output);
        }
        output.extend_from_slice(&buffer[..count as usize]);
        offset += count as u64;
    }
}
