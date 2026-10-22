#[cfg(target_os = "linux")]
mod entry {
    use gatehouse_runtime_protocol::lifecycle_v2::{
        capture_inputs,
        capture_wire::{encode_response, CaptureRequest},
        profile::SlotIdentity,
    };
    use std::{
        fs::File,
        os::fd::FromRawFd,
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };
    static CANCELLED: AtomicBool = AtomicBool::new(false);
    extern "C" fn cancel(_: i32) {
        CANCELLED.store(true, Ordering::SeqCst);
    }
    fn cancelled() -> bool {
        CANCELLED.load(Ordering::SeqCst)
    }
    fn budget(end: Instant) -> Result<(), ()> {
        if cancelled() || Instant::now() >= end {
            Err(())
        } else {
            Ok(())
        }
    }
    fn wait(fd: i32, events: i16, end: Instant) -> Result<(), ()> {
        loop {
            budget(end)?;
            let mut p = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut p, 1, 20) };
            if n > 0 {
                return Ok(());
            }
            if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(());
            }
        }
    }
    fn nonblock(fd: i32) -> Result<(), ()> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            Err(())
        } else {
            Ok(())
        }
    }
    fn input(end: Instant) -> Result<Vec<u8>, ()> {
        nonblock(0)?;
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            wait(0, libc::POLLIN, end)?;
            let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
            if n == 0 {
                return Ok(out);
            }
            if n < 0 {
                if matches!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) {
                    continue;
                }
                return Err(());
            }
            out.extend_from_slice(&buf[..n as usize]);
            if out.len() > 65536 {
                return Err(());
            }
        }
    }
    fn output(bytes: &[u8], end: Instant) -> Result<(), ()> {
        nonblock(1)?;
        let mut offset = 0;
        while offset < bytes.len() {
            wait(1, libc::POLLOUT, end)?;
            let n =
                unsafe { libc::write(1, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
            if n <= 0 {
                if n < 0
                    && matches!(
                        std::io::Error::last_os_error().kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    )
                {
                    continue;
                }
                return Err(());
            }
            offset += n as usize;
        }
        budget(end)
    }
    pub fn run() -> Result<(), ()> {
        let start = Instant::now();
        unsafe {
            libc::signal(libc::SIGTERM, cancel as *const () as usize);
            libc::signal(libc::SIGINT, cancel as *const () as usize);
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }
        if std::env::args_os().len() != 1 {
            return Err(());
        }
        // Validate actual inherited numbers before transferring ownership to File.
        for fd in [3, 4] {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                return Err(());
            }
        }
        let config = unsafe { File::from_raw_fd(3) };
        let expected = unsafe { File::from_raw_fd(4) };
        let bytes = input(start + Duration::from_secs(30))?;
        let request = CaptureRequest::decode(&bytes).map_err(|_| ())?;
        let end = start + Duration::from_millis(request.timeout_ms as u64);
        budget(end)?;
        let inputs = capture_inputs::parse(config, expected, &bytes).map_err(|_| ())?;
        budget(end)?;
        let r = inputs.request();
        let e = inputs.expected();
        let context = inputs.context().map_err(|_| ())?;
        let identity = SlotIdentity {
            profile: r.profile.clone(),
            installation_sha256: e.installation_sha256.clone(),
            config_sha256: e.config_sha256.clone(),
            executable_sha256: e.executable_sha256.clone(),
        };
        let record = gateprobes_podman_lifecycle::capture_plan(
            context,
            &r.image_id,
            &identity,
            r.inputs.clone(),
            end,
            &cancelled,
        )
        .map_err(|_| ())?;
        let response = encode_response(&record, r, e, context).map_err(|_| ())?;
        context.revalidate().map_err(|_| ())?;
        budget(end)?;
        output(&response, end)
    }
}
fn main() {
    #[cfg(target_os = "linux")]
    if entry::run().is_ok() {
        return;
    }
    // No raw configuration or daemon response in diagnostics.
    std::process::exit(1);
}
