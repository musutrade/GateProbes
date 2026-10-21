//! Bounded Linux Unix HTTP GET subset. No proxy/env/CLI, redirects, compression,
//! chunked framing or absence inference. Filesystem revalidation is not timed.
use crate::{
    input::{Config, Result},
    socket_identity::SocketIdentity,
};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, net::UnixStream},
    },
    time::{Duration, Instant},
};

const ERROR: &str = "runtime HTTP rejected";
const HEADER_LIMIT: usize = 16_384;
const BODY_LIMIT: usize = 1_048_576;
pub enum Route<'a> {
    Version,
    Info,
    Inspect(&'a str),
    Image(&'a str),
}
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}

fn budget(deadline: Instant, cancelled: &impl Fn() -> bool) -> Result<()> {
    if cancelled() || Instant::now() >= deadline {
        Err(ERROR)
    } else {
        Ok(())
    }
}
fn wait(fd: i32, events: i16, deadline: Instant, cancelled: &impl Fn() -> bool) -> Result<()> {
    loop {
        budget(deadline, cancelled)?;
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .clamp(1, 50) as i32;
        let mut poll = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut poll, 1, millis) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(ERROR);
        }
        if result > 0 {
            budget(deadline, cancelled)?;
            return Ok(());
        }
    }
}
fn connect(
    socket: &SocketIdentity,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<UnixStream> {
    let path = socket.path().as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.is_empty() || path.len() >= address.sun_path.len() || path.contains(&0) {
        return Err(ERROR);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(path) {
        *target = *byte as libc::c_char;
    }
    budget(deadline, cancelled)?;
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(ERROR);
    }
    // SAFETY: the freshly allocated descriptor is now exclusively owned.
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let result = unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    };
    if result != 0 {
        // EAGAIN (Unix listen backlog full) is refused, not mistaken for a
        // completed asynchronous connection. EINPROGRESS uses SO_ERROR.
        if io::Error::last_os_error().raw_os_error() != Some(libc::EINPROGRESS) {
            return Err(ERROR);
        }
        wait(fd, libc::POLLOUT, deadline, cancelled)?;
        if stream.take_error().map_err(|_| ERROR)?.is_some() {
            return Err(ERROR);
        }
    }
    budget(deadline, cancelled)?;
    Ok(stream)
}
fn receive(
    stream: &mut UnixStream,
    bytes: &mut [u8],
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<usize> {
    loop {
        budget(deadline, cancelled)?;
        match stream.read(bytes) {
            Ok(0) => return Err(ERROR),
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(stream.as_raw_fd(), libc::POLLIN, deadline, cancelled)?
            }
            Err(_) => return Err(ERROR),
        }
    }
}
fn send(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<()> {
    while !bytes.is_empty() {
        budget(deadline, cancelled)?;
        match stream.write(bytes) {
            Ok(0) => return Err(ERROR),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                wait(stream.as_raw_fd(), libc::POLLOUT, deadline, cancelled)?
            }
            Err(_) => return Err(ERROR),
        }
    }
    Ok(())
}
fn headers(raw: &[u8]) -> Result<(u16, usize)> {
    let raw = std::str::from_utf8(raw).map_err(|_| ERROR)?;
    let mut lines = raw.split("\r\n");
    let status_line = lines.next().ok_or(ERROR)?;
    let mut status = status_line.splitn(3, ' ');
    if !matches!(status.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
        return Err(ERROR);
    }
    let code = status.next().ok_or(ERROR)?;
    if code.len() != 3 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ERROR);
    }
    let code: u16 = code.parse().map_err(|_| ERROR)?;
    if !(200..=599).contains(&code)
        || !status
            .next()
            .unwrap_or("")
            .bytes()
            .all(|b| (32..=126).contains(&b))
    {
        return Err(ERROR);
    }
    let mut fields = BTreeMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ERROR)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || !value.bytes().all(|b| b == b'\t' || (32..=126).contains(&b))
        {
            return Err(ERROR);
        }
        if fields
            .insert(name.to_ascii_lowercase(), value.trim_matches([' ', '\t']))
            .is_some()
            || fields.len() > 64
        {
            return Err(ERROR);
        }
    }
    if fields.contains_key("transfer-encoding")
        || fields
            .get("content-encoding")
            .is_some_and(|s| *s != "identity")
    {
        return Err(ERROR);
    }
    let length = fields.get("content-length").ok_or(ERROR)?;
    if length.len() > 10 || length.is_empty() || !length.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ERROR);
    }
    let count: usize = length.parse().map_err(|_| ERROR)?;
    if count > BODY_LIMIT || count.to_string() != *length {
        return Err(ERROR);
    }
    Ok((code, count))
}

pub fn get(
    config: &Config,
    socket: &SocketIdentity,
    route: Route<'_>,
    deadline: Instant,
    cancelled: &impl Fn() -> bool,
) -> Result<Reply> {
    if deadline.saturating_duration_since(Instant::now()) > Duration::from_secs(30) {
        return Err(ERROR);
    }
    // Config must come from input validation; still reject request-line injection
    // here so this public transport boundary cannot emit arbitrary methods/paths.
    let parts: Vec<_> = config.api_version.split('.').collect();
    if parts.len() != 2
        || !parts
            .iter()
            .all(|p| p.parse::<u16>().is_ok_and(|n| n.to_string() == *p))
    {
        return Err(ERROR);
    }
    let path = match route {
        Route::Version => "/version".to_owned(),
        Route::Info => format!("/v{}/info", config.api_version),
        Route::Image(image) => {
            crate::input_v3::validate_image(image)?;
            let encoded: String = image
                .bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect();
            format!("/v{}/images/{encoded}/json", config.api_version)
        }
        Route::Inspect(id) => {
            if id.len() != 64
                || !id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(ERROR);
            }
            format!("/v{}/containers/{id}/json", config.api_version)
        }
    };
    if socket.path().as_os_str() != std::ffi::OsStr::new(&config.socket_path) {
        return Err(ERROR);
    }
    socket.revalidate()?;
    let mut stream = connect(socket, deadline, cancelled)?;
    send(&mut stream, format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n").as_bytes(), deadline, cancelled)?;
    let mut raw = Vec::new();
    while !raw.ends_with(b"\r\n\r\n") {
        if raw.len() >= HEADER_LIMIT {
            return Err(ERROR);
        }
        let mut byte = [0];
        receive(&mut stream, &mut byte, deadline, cancelled)?;
        raw.push(byte[0]);
    }
    let (status, length) = headers(&raw[..raw.len() - 4])?;
    let mut body = vec![0; length];
    let mut offset = 0;
    while offset < length {
        offset += receive(&mut stream, &mut body[offset..], deadline, cancelled)?;
    }
    // Refuse already available trailing bytes; do not wait for EOF on a
    // keep-alive peer. Delayed extra bytes are outside this framing subset.
    let mut extra = [0];
    match stream.read(&mut extra) {
        Ok(0) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
        _ => return Err(ERROR),
    }
    drop(stream);
    socket.revalidate()?;
    budget(deadline, cancelled)?;
    Ok(Reply { status, body })
}
