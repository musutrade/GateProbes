use std::io::{Read, Write};
use std::net::TcpListener;

const CONTRACT: &str = include_str!("../openapi.json");

fn response(path: &str) -> (&str, String) {
    match path {
        "/openapi.json" => ("200 OK", CONTRACT.to_owned()),
        "/quote" => ("200 OK", r#"{"amount":42,"currency":"USD"}"#.to_owned()),
        _ => ("404 Not Found", r#"{"error":"not found"}"#.to_owned()),
    }
}

fn main() -> std::io::Result<()> {
    // Ephemeral loopback port; stdout communicates the address to the collector.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    println!("http://{}", listener.local_addr()?);
    std::io::stdout().flush()?;
    for stream in listener.incoming() {
        let mut stream = stream?;
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5)))?;
        let mut request = [0; 4096];
        let count = stream.read(&mut request)?;
        let request = String::from_utf8_lossy(&request[..count]);
        let path = request.split_whitespace().nth(1).unwrap_or("/");
        let (status, body) = response(path);
        write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serves_quote_contract_and_unknown_path() {
        assert_eq!(
            response("/quote"),
            ("200 OK", r#"{"amount":42,"currency":"USD"}"#.to_owned())
        );
        assert_eq!(response("/openapi.json").1, CONTRACT);
        assert_eq!(response("/missing").0, "404 Not Found");
    }
}
