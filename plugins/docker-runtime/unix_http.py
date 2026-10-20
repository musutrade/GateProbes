"""Bounded read-only Unix HTTP transport. Status codes are not runtime facts."""
from dataclasses import dataclass
import re
import socket
import time


class TransportError(ValueError):
    """No endpoint, body or server-controlled error is replayed."""


@dataclass(frozen=True)
class Reply:
    status: int
    body: bytes


def require(condition):
    if not condition:
        raise TransportError('runtime HTTP transport rejected')


class Reader:
    def __init__(self, connection, deadline, cancelled):
        self.connection = connection
        self.deadline = deadline
        self.cancelled = cancelled
        self.buffer = bytearray()

    def budget(self):
        require(not self.cancelled())
        remaining = self.deadline - time.monotonic()
        require(remaining > 0)
        self.connection.settimeout(min(remaining, 0.05))

    def receive(self, size):
        while True:
            self.budget()
            try:
                chunk = self.connection.recv(size)
            except socket.timeout:
                continue
            require(bool(chunk))
            return chunk

    def headers(self):
        while b'\r\n\r\n' not in self.buffer:
            require(len(self.buffer) < 16384)
            self.buffer.extend(self.receive(min(4096, 16384 - len(self.buffer))))
        head, body = bytes(self.buffer).split(b'\r\n\r\n', 1)
        self.buffer = bytearray(body)
        return head

    def body(self, length):
        require(len(self.buffer) <= length)
        while len(self.buffer) < length:
            self.buffer.extend(self.receive(min(65536, length - len(self.buffer))))
        self.budget()
        return bytes(self.buffer)


def parse_headers(raw, maximum):
    lines = raw.split(b'\r\n')
    require(bool(lines) and len(lines) <= 65)
    match = re.fullmatch(rb'HTTP/1\.[01] ([2-5][0-9][0-9])(?: [\x20-\x7e]*)?', lines[0])
    require(match is not None)
    headers = {}
    for line in lines[1:]:
        name, separator, value = line.partition(b':')
        require(bool(separator) and re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) is not None)
        name = name.lower()
        require(name not in headers)
        require(all(byte == 9 or 32 <= byte <= 126 for byte in value))
        headers[name] = value.strip(b' \t')
    # First supported framing is one exact Content-Length body. Chunked/EOF
    # framing and compression are explicitly refused, never guessed or decoded.
    require(b'transfer-encoding' not in headers)
    require(headers.get(b'content-encoding', b'identity') == b'identity')
    length = headers.get(b'content-length', b'')
    require(re.fullmatch(rb'0|[1-9][0-9]{0,9}', length) is not None)
    length = int(length)
    require(length <= maximum)
    return int(match[1]), length


def get(config, path, *, timeout=5.0, max_body=1048576, cancelled=lambda: False):
    """Only GET known identity/inspect routes. No redirect, proxy or fallback.

    Unsupported framing fails closed. This does not classify 404 as absence or
    validate daemon identity. Caller must validate the resulting facts separately.
    """
    try:
        require(type(timeout) in (int, float) and 0 < timeout <= 30)
        require(type(max_body) is int and 0 < max_body <= 1048576)
        require(type(path) is str)
        routes = ('/version', f'/v{config.api_version}/info')
        inspect = re.fullmatch(r'/v' + re.escape(config.api_version)
                               + r'/containers/[0-9a-f]{64}/json', path)
        require(path in routes or inspect is not None)
        config.revalidate()
        require(not cancelled())
        deadline = time.monotonic() + timeout
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            reader = Reader(connection, deadline, cancelled)
            reader.budget()
            connection.connect(config.socket_path)
            request = (f'GET {path} HTTP/1.1\r\nHost: localhost\r\n'
                       'Accept: application/json\r\nAccept-Encoding: identity\r\n'
                       'Connection: close\r\n\r\n').encode('ascii')
            offset = 0
            while offset < len(request):
                reader.budget()
                try:
                    sent = connection.send(request[offset:])
                except socket.timeout:
                    continue
                require(sent > 0)
                offset += sent
            status, length = parse_headers(reader.headers(), max_body)
            body = reader.body(length)
        config.revalidate()
        require(not cancelled() and time.monotonic() < deadline)
        return Reply(status, body)
    except (OSError, ValueError, TypeError, AttributeError, OverflowError):
        raise TransportError('runtime HTTP transport rejected') from None
