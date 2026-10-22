//! Bounded RFC 9112 section 7.1 subset: hex sizes, CRLF, no extensions/trailers.
use super::{Result, BODY_LIMIT, ERROR};
const MAX_CHUNKS: usize = 4096;
pub(super) fn decode(mut read: impl FnMut(&mut [u8]) -> Result<()>) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for index in 0..=MAX_CHUNKS {
        let mut size = 0usize;
        let mut digits = 0;
        loop {
            let mut b = [0];
            read(&mut b)?;
            if b[0] == b'\r' {
                read(&mut b)?;
                if b[0] != b'\n' || digits == 0 {
                    return Err(ERROR);
                }
                break;
            }
            if !b[0].is_ascii_hexdigit() || digits == 8 {
                return Err(ERROR);
            }
            size = size
                .checked_mul(16)
                .and_then(|n| n.checked_add((b[0] as char).to_digit(16)? as usize))
                .ok_or(ERROR)?;
            digits += 1;
        }
        if size == 0 {
            let mut end = [0; 2];
            read(&mut end)?;
            if end != *b"\r\n" {
                return Err(ERROR);
            }
            return Ok(body);
        }
        let total = body.len().checked_add(size).ok_or(ERROR)?;
        if index == MAX_CHUNKS || total > BODY_LIMIT {
            return Err(ERROR);
        }
        let start = body.len();
        body.resize(total, 0);
        read(&mut body[start..])?;
        let mut end = [0; 2];
        read(&mut end)?;
        if end != *b"\r\n" {
            return Err(ERROR);
        }
    }
    Err(ERROR)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};
    fn parse(bytes: &[u8]) -> Result<Vec<u8>> {
        let mut input = Cursor::new(bytes);
        decode(|b| input.read_exact(b).map_err(|_| ERROR))
    }
    #[test]
    fn chunked_bounds_and_exact_framing() {
        assert_eq!(parse(b"1\r\n{\r\n1\r\n}\r\n0\r\n\r\n").unwrap(), b"{}");
        assert_eq!(
            parse(b"A\r\n0123456789\r\n00\r\n\r\n").unwrap(),
            b"0123456789"
        );
        for bad in [
            b"".as_slice(),
            b"\r\n",
            b"1\nA",
            b"x\r\n",
            b"-1\r\n",
            b"1;x=y\r\na\r\n0\r\n\r\n",
            b"1\r\naX",
            b"2\r\na",
            b"0\r\nX: y\r\n\r\n",
            b"100001\r\n",
            b"ffffffffffffffff\r\n",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let mut too_many = b"1\r\nx\r\n".repeat(MAX_CHUNKS + 1);
        too_many.extend_from_slice(b"0\r\n\r\n");
        assert!(parse(&too_many).is_err());
        let mut aggregate = format!("{:x}\r\n", BODY_LIMIT).into_bytes();
        aggregate.extend(vec![b'x'; BODY_LIMIT]);
        aggregate.extend_from_slice(b"\r\n1\r\nx\r\n0\r\n\r\n");
        assert!(parse(&aggregate).is_err());
    }
    #[test]
    fn read_failure_never_restarts_decoding() {
        for fail_at in 0..9 {
            let mut input = Cursor::new(b"1\r\na\r\n0\r\n\r\n");
            let mut calls = 0;
            let result = decode(|b| {
                let call = calls;
                calls += 1;
                if call == fail_at {
                    return Err(ERROR);
                }
                input.read_exact(b).map_err(|_| ERROR)
            });
            assert!(result.is_err());
            assert_eq!(calls, fail_at + 1);
        }
    }
}
