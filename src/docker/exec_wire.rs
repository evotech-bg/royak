//! Strict bounded HTTP framing for admission observations and Create receipts.
//! A partial body or timeout is UNKNOWN, never a completed Create response.
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};
const HEAD: usize = 16 * 1024;
pub(super) const JSON: usize = 1024 * 1024;
#[derive(Clone, Debug)]
pub(super) struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}
pub(super) trait TimedStream: Read + Write {
    fn read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
    fn write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()>;
}
impl TimedStream for UnixStream {
    fn read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_read_timeout(timeout)
    }
    fn write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        self.set_write_timeout(timeout)
    }
}

fn exact(reader: &mut impl Read, out: &mut [u8]) -> Result<(), String> {
    let mut pos = 0;
    while pos < out.len() {
        match reader.read(&mut out[pos..]) {
            Ok(0) => return Err("truncated Docker response".into()),
            Ok(n) => pos += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(format!("Docker response read: {e}")),
        }
    }
    Ok(())
}
fn line(reader: &mut impl Read, bound: usize) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    loop {
        if result.len() >= bound {
            return Err("Docker framing line exceeds bound".into());
        }
        let mut byte = [0];
        exact(reader, &mut byte)?;
        result.push(byte[0]);
        if result.ends_with(b"\r\n") {
            result.truncate(result.len() - 2);
            return Ok(result);
        }
        if byte[0] == b'\n' {
            return Err("invalid Docker HTTP line ending".into());
        }
    }
}
pub(super) fn parse(reader: &mut impl Read, bound: usize) -> Result<Response, String> {
    parse_mode(reader, bound, false, false)
}
fn parse_mode(
    reader: &mut impl Read,
    bound: usize,
    raw_start: bool,
    require_keepalive: bool,
) -> Result<Response, String> {
    let status_line = line(reader, HEAD)?;
    let status = std::str::from_utf8(&status_line).map_err(|_| "non-ASCII HTTP status")?;
    let parts = status.split(' ').collect::<Vec<_>>();
    if parts.len() < 3
        || !matches!(parts[0], "HTTP/1.1" | "HTTP/1.0")
        || parts[1].len() != 3
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
    {
        return Err("invalid HTTP status".into());
    }
    let status: u16 = parts[1].parse().map_err(|_| "invalid HTTP status")?;
    if !(200..=599).contains(&status) && !(raw_start && status == 101) {
        return Err("unsupported interim/upgrade response for JSON operation".into());
    }
    let mut content_length = None;
    let mut chunked = false;
    let mut used = status_line.len() + 2;
    let mut upgrade = false;
    let mut connection_upgrade = false;
    let mut connection_close = false;
    let mut connection_keepalive = false;
    loop {
        let raw = line(reader, HEAD.saturating_sub(used))?;
        used += raw.len() + 2;
        if raw.is_empty() {
            break;
        }
        let text = std::str::from_utf8(&raw).map_err(|_| "invalid HTTP header")?;
        let (key, value) = text.split_once(':').ok_or("invalid HTTP header")?;
        if key.is_empty() || key.bytes().any(|b| !b.is_ascii_alphanumeric() && b != b'-') {
            return Err("invalid HTTP header name".into());
        }
        let value = value.trim_matches([' ', '\t']);
        if value.bytes().any(|b| b < 32 && b != b'\t' || b == 127) {
            return Err("invalid HTTP header value".into());
        }
        if key.eq_ignore_ascii_case("content-length") {
            if content_length.is_some()
                || value.is_empty()
                || !value.bytes().all(|b| b.is_ascii_digit())
            {
                return Err("invalid/duplicate Content-Length".into());
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "Content-Length overflow")?,
            );
        }
        if key.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err("unsupported/duplicate Transfer-Encoding".into());
            }
            chunked = true;
        }
        if key.eq_ignore_ascii_case("upgrade") {
            if upgrade || !value.eq_ignore_ascii_case("tcp") {
                return Err("invalid raw Start Upgrade".into());
            }
            upgrade = true;
        }
        if key.eq_ignore_ascii_case("connection") {
            connection_upgrade |= value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("upgrade"));
            connection_close |= value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("close"));
            connection_keepalive |= value
                .split(',')
                .any(|v| v.trim().eq_ignore_ascii_case("keep-alive"));
        }
    }
    if chunked && content_length.is_some() {
        return Err("ambiguous HTTP framing".into());
    }
    if status == 101 && (!upgrade || !connection_upgrade || chunked || content_length.is_some()) {
        return Err("invalid raw Start101 framing".into());
    }
    if require_keepalive
        && (status != 200
            || connection_close
            || upgrade
            || connection_upgrade
            || (parts[0] != "HTTP/1.1" && !connection_keepalive))
    {
        return Err("same-connection preflight did not preserve HTTP keep-alive".into());
    }
    let mut body = Vec::new();
    if let Some(len) = content_length {
        if len > bound {
            return Err("Docker body exceeds bound".into());
        }
        body.resize(len, 0);
        exact(reader, &mut body)?;
    } else if chunked {
        let mut chunks = 0usize;
        loop {
            chunks += 1;
            if chunks > bound.saturating_add(1) {
                return Err("excessive chunk framing".into());
            }
            let size = line(reader, 128)?;
            if size.is_empty() || size.len() > 16 || !size.iter().all(|b| b.is_ascii_hexdigit()) {
                return Err("invalid chunk length".into());
            }
            let len = usize::from_str_radix(std::str::from_utf8(&size).unwrap(), 16)
                .map_err(|_| "chunk size overflow")?;
            if len == 0 {
                // Docker JSON has no required trailers. Reject unknown trailer
                // authority and require the final CRLF to be present.
                if !line(reader, 2)?.is_empty() {
                    return Err("unsupported chunk trailer".into());
                }
                break;
            }
            if len > bound.saturating_sub(body.len()) {
                return Err("Docker chunked body exceeds bound".into());
            }
            let start = body.len();
            body.resize(start + len, 0);
            exact(reader, &mut body[start..])?;
            let mut end = [0; 2];
            exact(reader, &mut end)?;
            if &end != b"\r\n" {
                return Err("invalid chunk terminator".into());
            }
        }
    } else if raw_start && matches!(status, 101 | 200) {
        reader
            .take(bound as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|e| format!("raw Docker Start stream incomplete: {e}"))?;
        if body.len() > bound {
            return Err("raw Docker Start output exceeds bound".into());
        }
    } else if status != 204 {
        return Err("Docker response needs explicit bounded framing".into());
    }
    Ok(Response { status, body })
}

/// Per-read deadline is reset only to the remaining original operation budget,
/// never to a new period. Header-drip peers cannot extend the Create deadline.
struct Deadline<'a, S: TimedStream> {
    stream: &'a mut S,
    deadline: Instant,
}
impl<S: TimedStream> Read for Deadline<'_, S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Docker operation deadline")
            })?;
        self.stream.read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}
pub(super) fn request<S: TimedStream>(
    stream: &mut S,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    bound: usize,
    deadline: Instant,
) -> Result<Response, String> {
    request_mode(stream, method, path, body, bound, deadline, false, false)
}
pub(super) fn request_raw_start<S: TimedStream>(
    stream: &mut S,
    path: &str,
    body: &[u8],
    bound: usize,
    deadline: Instant,
) -> Result<Response, String> {
    request_mode(
        stream,
        "POST",
        path,
        Some(body),
        bound,
        deadline,
        true,
        false,
    )
}
pub(super) fn keepalive_info<S: TimedStream>(
    stream: &mut S,
    deadline: Instant,
) -> Result<Response, String> {
    request_mode(stream, "GET", "/info", None, JSON, deadline, false, true)
}
/// Closed consumer preflight only: preserve the inspected connection for its
/// later full-CID effect. Original absolute budget and strict framing remain.
pub(super) fn keepalive_get<S:TimedStream>(stream:&mut S,path:&str,bound:usize,deadline:Instant)
    ->Result<Response,String>{
    request_mode(stream,"GET",path,None,bound,deadline,false,true)
}
/// Exact legacy full-CID removal only. Does not widen old exec request_head
/// method acceptance or expose a generic DELETE request constructor.
pub(super) fn delete_container<S:TimedStream>(stream:&mut S,id:&str,force:bool,deadline:Instant)
    ->Result<Response,String>{
    delete_container_mode(stream,id,force,deadline,false)
}
pub(super) fn keepalive_delete_container<S:TimedStream>(stream:&mut S,id:&str,deadline:Instant)
    ->Result<Response,String>{delete_container_mode(stream,id,false,deadline,true)}
fn delete_container_mode<S:TimedStream>(stream:&mut S,id:&str,force:bool,deadline:Instant,keepalive:bool)
    ->Result<Response,String>{
    if id.len()!=64||!id.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)){
        return Err("legacy removal needs an actually inspected full CID".into());
    }
    let suffix=if force{"?force=true"}else{""};
    let connection=if keepalive{"keep-alive"}else{"close"};
    let head=format!("DELETE /containers/{id}{suffix} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: {connection}\r\n\r\n");
    write_request_until(stream,head.as_bytes(),&[],deadline,Instant::now)
        .map_err(|_|"legacy full-CID delete write failed/UNKNOWN")?;
    parse_mode(&mut Deadline{stream,deadline},JSON,false,keepalive)
}
pub(super) fn keepalive_post<S:TimedStream>(stream:&mut S,path:&str,body:Option<&[u8]>,bound:usize,deadline:Instant)
    ->Result<Response,String>{request_mode(stream,"POST",path,body,bound,deadline,false,true)}
pub(super) fn request_head(
    method: &str,
    path: &str,
    len: usize,
    keepalive: bool,
) -> Result<Vec<u8>, String> {
    if !matches!(method, "GET" | "POST")
        || !path.starts_with('/')
        || path.bytes().any(|b| b < 33 || b > 126)
        || len > JSON
    {
        return Err("invalid or oversized Docker request".into());
    }
    let connection = if keepalive { "keep-alive" } else { "close" };
    Ok(format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nConnection: {connection}\r\nContent-Length: {len}\r\n\r\n").into_bytes())
}
/// One absolute operation deadline covers every partial write of BOTH header
/// and body. The clock is private and supplied as Instant::now in production;
/// a deterministic clock exists only in the source regression fixtures.
fn write_request_until<S: TimedStream>(
    stream: &mut S,
    header: &[u8],
    body: &[u8],
    deadline: Instant,
    mut now: impl FnMut() -> Instant,
) -> std::io::Result<()> {
    for mut pending in [header, body] {
        while !pending.is_empty() {
            let left = deadline
                .checked_duration_since(now())
                .filter(|duration| !duration.is_zero())
                .ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "Docker operation deadline")
                })?;
            stream.write_timeout(Some(left))?;
            match stream.write(pending) {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "Docker request write made no progress",
                    ));
                }
                Ok(written) if written <= pending.len() => {
                    pending = &pending[written..];
                }
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Docker transport reported an impossible write length",
                    ));
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {
                    // Retry only after recomputing the same absolute budget.
                }
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn request_mode<S: TimedStream>(
    stream: &mut S,
    method: &str,
    path: &str,
    body: Option<&[u8]>,
    bound: usize,
    deadline: Instant,
    raw_start: bool,
    keepalive: bool,
) -> Result<Response, String> {
    if !matches!(method, "GET" | "POST")
        || !path.starts_with('/')
        || path.bytes().any(|b| b < 33 || b > 126)
    {
        return Err("invalid Docker request target".into());
    }
    let body = body.unwrap_or(&[]);
    if body.len() > JSON {
        return Err("Docker request exceeds bound".into());
    }
    let header = request_head(method, path, body.len(), keepalive)?;
    write_request_until(stream, &header, body, deadline, Instant::now)
        .map_err(|e| format!("Docker request write: {e}"))?;
    parse_mode(
        &mut Deadline { stream, deadline },
        bound,
        raw_start,
        keepalive,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    #[test]
    fn bounded_complete_content_length_and_chunked() {
        for raw in [
            b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".as_slice(),
        ] {
            assert_eq!(parse(&mut Cursor::new(raw), 2).unwrap().body, b"{}");
        }
    }
    #[test]
    fn malformed_truncated_duplicate_oversized_and_drip_cannot_be_receipts() {
        for raw in [
            "HTTP/1.1 201 Created\r\nContent-Length: 3\r\n\r\n{}",
            "HTTP/1.1 201 Created\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "HTTP/1.1 201 Created\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n{}",
            "HTTP/1.1 201 Created\r\nContent-Length: 9\r\n\r\n{}",
            "HTTP/1.1 201 Created\r\n\r\n{}",
            "HTTP/1.1 201 Created\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n",
            "HTTP/1.1 100 Continue\r\nContent-Length: 2\r\n\r\n{}",
        ] {
            assert!(parse(&mut Cursor::new(raw), 2).is_err(), "{raw}");
        }
    }
    #[test]
    fn raw_start_mode_is_separate_from_json_receipts_and_remains_bounded() {
        for raw in [
            b"HTTP/1.1 101 Upgraded\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\nok".as_slice(),
            b"HTTP/1.1 200 OK\r\nContent-Type: application/vnd.docker.raw-stream\r\n\r\nok"
                .as_slice(),
        ] {
            assert!(parse(&mut Cursor::new(raw), 2).is_err());
            assert_eq!(
                parse_mode(&mut Cursor::new(raw), 2, true, false)
                    .unwrap()
                    .body,
                b"ok"
            );
            assert!(parse_mode(&mut Cursor::new(raw), 1, true, false).is_err());
        }
        assert!(parse_mode(
            &mut Cursor::new(b"HTTP/1.1 101 Upgraded\r\n\r\nok"),
            2,
            true,
            false
        )
        .is_err());
    }
    #[test]
    fn preflight_requires_explicit_persistent_http_and_refuses_close_or_upgrade() {
        for raw in [
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
            b"HTTP/1.1 200 OK\r\nUpgrade: tcp\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
        ] {
            assert!(parse_mode(&mut Cursor::new(raw), 2, false, true).is_err());
        }
        assert!(parse_mode(
            &mut Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"),
            2,
            false,
            true
        )
        .is_ok());
    }
}

#[cfg(test)]
mod absolute_write_regressions {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::rc::Rc;

    enum Step {
        Bytes(usize, u64),
        Interrupted(u64),
        Zero,
        BrokenPipe,
    }
    struct PartialStream {
        clock: Rc<Cell<Instant>>,
        steps: VecDeque<Step>,
        timeouts: RefCell<Vec<Duration>>,
        bytes: Vec<u8>,
        calls: usize,
    }
    impl Read for PartialStream {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            panic!("write regression must not read");
        }
    }
    impl Write for PartialStream {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.calls += 1;
            let step = self.steps.pop_front().expect("unexpected extra write");
            let elapsed = match &step {
                Step::Bytes(_, elapsed) | Step::Interrupted(elapsed) => *elapsed,
                _ => 0,
            };
            self.clock
                .set(self.clock.get() + Duration::from_millis(elapsed));
            match step {
                Step::Bytes(limit, _) => {
                    let count = limit.min(bytes.len());
                    self.bytes.extend_from_slice(&bytes[..count]);
                    Ok(count)
                }
                Step::Interrupted(_) => Err(std::io::ErrorKind::Interrupted.into()),
                Step::Zero => Ok(0),
                Step::BrokenPipe => Err(std::io::ErrorKind::BrokenPipe.into()),
            }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("write regression must not flush or reset a budget");
        }
    }
    impl TimedStream for PartialStream {
        fn read_timeout(&self, _: Option<Duration>) -> std::io::Result<()> {
            panic!("write regression must not set a read timeout");
        }
        fn write_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
            let timeout = timeout.expect("finite remaining timeout required");
            assert!(!timeout.is_zero());
            self.timeouts.borrow_mut().push(timeout);
            Ok(())
        }
    }
    fn fixture(steps: Vec<Step>) -> (PartialStream, Rc<Cell<Instant>>, Instant) {
        let base = Instant::now();
        let clock = Rc::new(Cell::new(base));
        (
            PartialStream {
                clock: clock.clone(),
                steps: steps.into(),
                timeouts: RefCell::new(Vec::new()),
                bytes: Vec::new(),
                calls: 0,
            },
            clock,
            base + Duration::from_millis(100),
        )
    }
    fn millis(stream: &PartialStream) -> Vec<u128> {
        stream
            .timeouts
            .borrow()
            .iter()
            .map(Duration::as_millis)
            .collect()
    }

    #[test]
    fn partial_progress_cannot_extend_shared_header_and_body_deadline() {
        let (mut stream, clock, deadline) = fixture(vec![
            Step::Bytes(2, 20),
            Step::Bytes(2, 30),
            Step::Bytes(1, 50),
        ]);
        let error = write_request_until(&mut stream, b"ABCD", b"xyz", deadline, || clock.get())
            .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(stream.bytes, b"ABCDx");
        assert_eq!(stream.calls, 3);
        assert_eq!(millis(&stream), vec![100, 80, 50]);
    }

    #[test]
    fn completing_header_at_deadline_does_not_grant_a_new_body_budget() {
        let (mut stream, clock, deadline) = fixture(vec![Step::Bytes(4, 100)]);
        let error =
            write_request_until(&mut stream, b"ABCD", b"x", deadline, || clock.get()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(stream.bytes, b"ABCD");
        assert_eq!(stream.calls, 1);
        assert_eq!(millis(&stream), vec![100]);
    }

    #[test]
    fn interrupted_writes_retry_only_with_remaining_absolute_budget() {
        let (mut stream, clock, deadline) = fixture(vec![
            Step::Interrupted(40),
            Step::Bytes(1, 10),
            Step::Interrupted(50),
        ]);
        let error =
            write_request_until(&mut stream, b"ABCD", b"x", deadline, || clock.get()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert_eq!(stream.bytes, b"A");
        assert_eq!(stream.calls, 3);
        assert_eq!(millis(&stream), vec![100, 60, 50]);
    }

    #[test]
    fn write_zero_is_an_error_without_retry_or_finished_receipt() {
        let (mut stream, clock, deadline) = fixture(vec![Step::Zero]);
        let error =
            write_request_until(&mut stream, b"ABCD", b"x", deadline, || clock.get()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WriteZero);
        assert!(stream.bytes.is_empty());
        assert_eq!(stream.calls, 1);
    }

    #[test]
    fn write_transport_error_is_preserved_after_the_first_attempt() {
        let (mut stream, clock, deadline) = fixture(vec![Step::BrokenPipe]);
        let error =
            write_request_until(&mut stream, b"ABCD", b"x", deadline, || clock.get()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(stream.bytes.is_empty());
        assert_eq!(stream.calls, 1);
    }

    #[test]
    fn successful_partial_writes_preserve_all_bytes_with_decreasing_timeouts() {
        let (mut stream, clock, deadline) = fixture(vec![
            Step::Bytes(2, 10),
            Step::Bytes(2, 10),
            Step::Bytes(1, 20),
            Step::Bytes(1, 5),
        ]);
        write_request_until(&mut stream, b"ABCD", b"xy", deadline, || clock.get()).unwrap();
        assert_eq!(stream.bytes, b"ABCDxy");
        assert_eq!(stream.calls, 4);
        assert_eq!(millis(&stream), vec![100, 90, 80, 60]);
    }
}
