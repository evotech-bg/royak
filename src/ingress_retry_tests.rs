use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn endpoint(port: u16) -> IngressBackend {
    ("127.0.0.1".into(), port, String::new(), 0)
}

async fn receive(stream: &mut TcpStream) -> Vec<u8> {
    let mut data = Vec::new();
    let mut byte = [0; 1];
    while !data.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        data.push(byte[0]);
        assert!(data.len() < 16384);
    }
    let header = std::str::from_utf8(&data).unwrap();
    let length: usize = header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(key, _)| key.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse().unwrap())
        .unwrap_or(0);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    data.extend(body);
    data
}

async fn listener() -> (TcpListener, IngressBackend) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = endpoint(listener.local_addr().unwrap().port());
    (listener, address)
}

async fn good(listener: TcpListener) -> Vec<u8> {
    let (mut stream, _) = listener.accept().await.unwrap();
    let request = receive(&mut stream).await;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await
        .unwrap();
    request
}

#[tokio::test]
async fn get_lost_response_uses_another_endpoint_and_quarantines_the_failed_one() {
    let (failed, first) = listener().await;
    let (healthy, second) = listener().await;
    let failure = tokio::spawn(async move {
        let (mut stream, _) = failed.accept().await.unwrap();
        let request = receive(&mut stream).await;
        drop(stream);
        (failed, request)
    });
    let success = tokio::spawn(good(healthy));
    let value = proxy_backends(
        &[first.clone(), second],
        "GET",
        "/read?key=one",
        &HeaderMap::new(),
        b"",
    )
    .await
    .unwrap();
    assert_eq!((value.0, value.1), (200, b"ok".to_vec()));
    let (failed, request) = failure.await.unwrap();
    assert!(request.starts_with(b"GET /read?key=one HTTP/1.1"));
    assert!(success
        .await
        .unwrap()
        .starts_with(b"GET /read?key=one HTTP/1.1"));
    let (healthy, next) = listener().await;
    let success = tokio::spawn(good(healthy));
    assert_eq!(
        proxy_backends(&[first, next], "GET", "/next", &HeaderMap::new(), b"")
            .await
            .unwrap()
            .0,
        200
    );
    success.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(60), failed.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn incomplete_get_response_is_replaced_by_a_complete_response() {
    let (failed, first) = listener().await;
    let (healthy, second) = listener().await;
    let failure = tokio::spawn(async move {
        let (mut stream, _) = failed.accept().await.unwrap();
        receive(&mut stream).await;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort")
            .await
            .unwrap();
    });
    let success = tokio::spawn(good(healthy));
    let value = proxy_backends(&[first, second], "GET", "/", &HeaderMap::new(), b"")
        .await
        .unwrap();
    assert_eq!((value.0, value.1), (200, b"ok".to_vec()));
    failure.await.unwrap();
    success.await.unwrap();
}

#[tokio::test]
async fn lost_write_response_never_transmits_to_another_endpoint() {
    for method in ["POST", "PUT", "PATCH", "DELETE"] {
        let (failed, first) = listener().await;
        let (other, second) = listener().await;
        let effect = tokio::spawn(async move {
            let (mut stream, _) = failed.accept().await.unwrap();
            receive(&mut stream).await
        });
        assert!(proxy_backends(
            &[first, second],
            method,
            "/write",
            &HeaderMap::new(),
            b"unique-effect"
        )
        .await
        .is_err());
        assert!(effect.await.unwrap().ends_with(b"unique-effect"));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(60), other.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn several_stale_endpoints_do_not_hide_a_live_fourth_endpoint() {
    let mut stale = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..3 {
        let (socket, address) = listener().await;
        stale.push(socket);
        addresses.push(address);
    }
    let (healthy, address) = listener().await;
    addresses.push(address);
    drop(stale);
    let success = tokio::spawn(good(healthy));
    assert_eq!(
        proxy_backends(&addresses, "GET", "/", &HeaderMap::new(), b"")
            .await
            .unwrap()
            .0,
        200
    );
    success.await.unwrap();
}

#[tokio::test]
async fn attempt_limit_does_not_probe_an_unbounded_backend_list() {
    let mut stale = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..8 {
        let (socket, address) = listener().await;
        stale.push(socket);
        addresses.push(address);
    }
    let (unattempted, address) = listener().await;
    addresses.push(address);
    drop(stale);
    assert!(
        proxy_backends(&addresses, "GET", "/", &HeaderMap::new(), b"")
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(60), unattempted.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn application_error_status_is_forwarded_without_replaying() {
    let (first, address) = listener().await;
    let (other, alternative) = listener().await;
    let response = tokio::spawn(async move {
        let (mut stream, _) = first.accept().await.unwrap();
        receive(&mut stream).await;
        stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 4\r\nConnection: close\r\n\r\nbusy").await.unwrap();
    });
    let value = proxy_backends(&[address, alternative], "GET", "/", &HeaderMap::new(), b"")
        .await
        .unwrap();
    assert_eq!((value.0, value.1), (503, b"busy".to_vec()));
    response.await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(60), other.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn total_deadline_bounds_a_connected_but_silent_endpoint() {
    let (silent, first) = listener().await;
    let (other, second) = listener().await;
    let stall = tokio::spawn(async move {
        let (mut stream, _) = silent.accept().await.unwrap();
        receive(&mut stream).await;
        std::future::pending::<()>().await;
    });
    let start = tokio::time::Instant::now();
    assert!(proxy_backends_until(
        &[first, second],
        "GET",
        "/",
        &HeaderMap::new(),
        b"",
        start + std::time::Duration::from_millis(80)
    )
    .await
    .is_err());
    assert!(start.elapsed() < std::time::Duration::from_millis(500));
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), other.accept())
            .await
            .is_err()
    );
    stall.abort();
    let _ = stall.await;
}
