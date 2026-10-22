//! Installed lifecycle executable: protected fd3/fd4 and exact bounded stdin only.
#[cfg(target_os = "linux")]
fn main() {
    if entry().is_err() {
        std::process::exit(2);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    std::process::exit(2);
}

#[cfg(target_os = "linux")]
fn entry() -> Result<(), ()> {
    use std::{
        fs::File,
        io::{Read, Write},
        os::fd::FromRawFd,
        time::Duration,
    };
    let mut input = Vec::new();
    std::io::stdin()
        .take(65_537)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    if input.len() > 65_536 {
        return Err(());
    }
    // Core installs these exact descriptors; validation rejects missing, ordinary
    // or unsealed files before any socket operation. No public paths or env input.
    let duplicate = |source| {
        let fd = unsafe { libc::fcntl(source, libc::F_DUPFD_CLOEXEC, 5) };
        if fd < 0 {
            return Err(());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    };
    let config = duplicate(3)?;
    let expected = duplicate(4)?;
    let response = gateprobes_docker_lifecycle::adapter::execute(
        &config,
        &expected,
        &input,
        Duration::from_secs(30),
        || false,
    )
    .map_err(|_| ())?;
    let value = serde_json::to_value(response).map_err(|_| ())?;
    let bytes = serde_json::to_vec(&value).map_err(|_| ())?;
    if bytes.len() > 65_536 {
        return Err(());
    }
    std::io::stdout().write_all(&bytes).map_err(|_| ())
}
