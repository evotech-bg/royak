//! Node-to-node transport.
//!
//! Every inter-node call (census heartbeat/inventory, create/delete pod, pod
//! logs, Raft RPCs) goes through here:
//!
//! * the request is HMAC-signed with the cluster secret (`auth::node_headers`),
//! * the RESPONSE must carry a signature too, bound to the request's nonce and
//!   to the HTTP status, so a man in the middle can neither forge nor replay a
//!   peer's answer (census, vote, append-entries, logs),
//! * every request and response BODY is sealed (AES-256-GCM, key derived from
//!   the cluster secret) before it is signed, so pod logs, census and Raft
//!   traffic stay confidential whether or not the hop is TLS,
//! * when the cluster runs with `--tls`, the connection is TLS too. Peers use
//!   per-process self-signed certificates that are NOT verified: identity is
//!   proven by the signatures and confidentiality by the sealing, so a man in
//!   the middle who terminates TLS sees only sealed, signed bytes.

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

static TLS: AtomicBool = AtomicBool::new(false);

/// Peers are reached over TLS (set when this node serves its API with --tls;
/// all nodes of a cluster must agree).
pub fn set_tls(on: bool) {
    TLS.store(on, Ordering::SeqCst);
}

fn tls_on() -> bool {
    TLS.load(Ordering::SeqCst)
}

/// What the server signs for a response to a request with `req_nonce`.
fn response_signing(path: &str, req_nonce: &str, status: u16) -> (String, String) {
    (format!("RESPONSE {status}"), format!("{path}\n{req_nonce}"))
}

const SEAL_PURPOSE: &[u8] = b"royak-node-rpc-v1";

/// Seal a node-RPC body for the wire (empty stays empty).
fn seal_body(plain: &[u8]) -> Result<Vec<u8>, String> {
    if plain.is_empty() { return Ok(Vec::new()); }
    crate::auth::seal_for_cluster(SEAL_PURPOSE, plain).map(String::into_bytes)
}

/// Open a sealed node-RPC body (empty stays empty). Fails on anything that was
/// not sealed with this cluster's secret.
pub fn open_body(wire: &[u8]) -> Result<Vec<u8>, String> {
    if wire.is_empty() { return Ok(Vec::new()); }
    let s = std::str::from_utf8(wire).map_err(|_| "node RPC body is not sealed".to_string())?;
    crate::auth::unseal_for_cluster(SEAL_PURPOSE, s)
}

/// Server side: seal the response body and sign the sealed bytes, bound to the
/// request's nonce and the status. Returns (wire body, signature headers).
pub fn seal_and_sign_response(path: &str, req_nonce: &str, status: u16, body: &[u8]) -> (Vec<u8>, Vec<(&'static str, String)>) {
    let wire = seal_body(body).unwrap_or_default();
    let (m, p) = response_signing(path, req_nonce, status);
    let sig = crate::auth::node_headers(&m, &p, &wire).unwrap_or_default();
    (wire, sig)
}

// ─── TLS client config ───

#[derive(Debug)]
struct SignedPeerVerifier(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for SignedPeerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Identity is proven by the signed response, not by the certificate.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config() -> Arc<rustls::ClientConfig> {
    static C: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    C.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cfg = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring supports the default TLS versions")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SignedPeerVerifier(provider)))
            .with_no_client_auth();
        Arc::new(cfg)
    })
    .clone()
}

fn server_name() -> rustls::pki_types::ServerName<'static> {
    rustls::pki_types::ServerName::try_from("royak-node").expect("valid DNS name")
}

// ─── Request / response framing ───

fn build_request(method: &str, addr: &str, path: &str, body: &[u8]) -> Result<(Vec<u8>, String), String> {
    let sealed = seal_body(body)?;
    let body = sealed.as_slice();
    let sig = crate::auth::node_headers(method, path, body)?;
    let nonce = sig.iter().find(|(k, _)| *k == crate::auth::HDR_NONCE).map(|(_, v)| v.clone()).unwrap_or_default();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in &sig {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str("\r\n");
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    Ok((out, nonce))
}

/// True once `buf` holds a complete HTTP response (by Content-Length or the
/// chunked terminator).
fn response_complete(buf: &[u8]) -> bool {
    let Some(hpos) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { return false };
    let head = String::from_utf8_lossy(&buf[..hpos]).to_ascii_lowercase();
    let body = &buf[hpos + 4..];
    if let Some(len) = head.lines().find_map(|l| l.strip_prefix("content-length:").and_then(|v| v.trim().parse::<usize>().ok())) {
        return body.len() >= len;
    }
    head.contains("transfer-encoding: chunked") && body.ends_with(b"0\r\n\r\n")
}

fn dechunk(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") {
        let size = usize::from_str_radix(String::from_utf8_lossy(&rest[..pos]).trim(), 16).unwrap_or(0);
        if size == 0 { break; }
        let start = pos + 2;
        let end = (start + size).min(rest.len());
        out.extend_from_slice(&rest[start..end]);
        rest = &rest[(end + 2).min(rest.len())..];
    }
    out
}

/// Parse a full response, verify its signature, and return the body of a 2xx.
fn finish(raw: &[u8], path: &str, req_nonce: &str, addr: &str) -> Result<Vec<u8>, String> {
    let hpos = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| format!("{addr}: incomplete HTTP response"))?;
    let head = String::from_utf8_lossy(&raw[..hpos]).to_string();
    let status: u16 = head.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let headers: Vec<(String, String)> = head.lines().skip(1)
        .filter_map(|l| l.split_once(':').map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())))
        .collect();
    let chunked = headers.iter().any(|(k, v)| k == "transfer-encoding" && v.to_ascii_lowercase().contains("chunked"));
    let body = if chunked { dechunk(&raw[hpos + 4..]) } else { raw[hpos + 4..].to_vec() };
    let (m, p) = response_signing(path, req_nonce, status);
    let get = |k: &str| headers.iter().find(|(h, _)| h == k).map(|(_, v)| v.clone());
    crate::auth::verify_node(&m, &p, get, &body)
        .map_err(|e| format!("{addr}: unauthenticated response ({e}) — refusing it"))?;
    let body = open_body(&body).map_err(|e| format!("{addr}: response body: {e}"))?;
    if (200..300).contains(&status) {
        Ok(body)
    } else {
        Err(format!("{addr}: HTTP {status}: {}", String::from_utf8_lossy(&body[..body.len().min(300)])))
    }
}

fn read_framed<R: Read>(r: &mut R) -> Result<Vec<u8>, String> {
    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 16384];
    while !response_complete(&buf) {
        match r.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            // A TLS peer may close without close_notify; what we have decides.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(buf)
}

/// Blocking signed call to a peer's node endpoint. `addr` is `host:port`.
pub fn call(method: &str, addr: &str, path: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    use std::net::ToSocketAddrs;
    let (req, nonce) = build_request(method, addr, path, body)?;
    let sock = addr.to_socket_addrs().map_err(|e| format!("{addr}: {e}"))?.next().ok_or_else(|| format!("{addr}: no address"))?;
    let tcp = std::net::TcpStream::connect_timeout(&sock, Duration::from_secs(2)).map_err(|e| format!("connect {addr}: {e}"))?;
    tcp.set_read_timeout(Some(timeout)).ok();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();
    let raw = if tls_on() {
        let conn = rustls::ClientConnection::new(client_config(), server_name()).map_err(|e| format!("tls: {e}"))?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        s.write_all(&req).map_err(|e| format!("write {addr}: {e}"))?;
        read_framed(&mut s)?
    } else {
        let mut s = tcp;
        s.write_all(&req).map_err(|e| format!("write {addr}: {e}"))?;
        read_framed(&mut s)?
    };
    finish(&raw, path, &nonce, addr)
}

/// Async variant (Raft RPCs).
pub async fn call_async(method: &str, addr: &str, path: &str, body: &[u8], timeout: Duration) -> Result<Vec<u8>, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (req, nonce) = build_request(method, addr, path, body)?;
    let fut = async {
        let tcp = tokio::net::TcpStream::connect(addr).await.map_err(|e| format!("connect {addr}: {e}"))?;
        async fn read_all<S: tokio::io::AsyncRead + Unpin>(s: &mut S) -> Result<Vec<u8>, String> {
            let mut buf = Vec::with_capacity(4096);
            let mut chunk = [0u8; 16384];
            while !response_complete(&buf) {
                match s.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                    Err(e) => return Err(format!("read: {e}")),
                }
            }
            Ok(buf)
        }
        if tls_on() {
            let connector = tokio_rustls::TlsConnector::from(client_config());
            let mut s = connector.connect(server_name(), tcp).await.map_err(|e| format!("tls {addr}: {e}"))?;
            s.write_all(&req).await.map_err(|e| format!("write {addr}: {e}"))?;
            read_all(&mut s).await
        } else {
            let mut s = tcp;
            s.write_all(&req).await.map_err(|e| format!("write {addr}: {e}"))?;
            read_all(&mut s).await
        }
    };
    let raw = tokio::time::timeout(timeout, fut).await.map_err(|_| format!("rpc to {addr} timed out"))??;
    finish(&raw, path, &nonce, addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_secret() {
        std::env::set_var("ROYAK_CLUSTER_SECRET", "test-cluster-secret-0123456789abcdef");
    }

    fn response(status: u16, body: &[u8], hdrs: &[(&'static str, String)]) -> Vec<u8> {
        let mut h = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\n", body.len());
        for (k, v) in hdrs { h.push_str(&format!("{k}: {v}\r\n")); }
        h.push_str("\r\n");
        let mut out = h.into_bytes();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn signed_response_is_accepted_and_tampering_is_refused() {
        with_secret();
        let body = br#"[{"pod":"rk-web-1"}]"#;
        let (wire, sig) = seal_and_sign_response("/royak/v1/pods", "nonce-a", 200, body);
        assert!(response_complete(&response(200, &wire, &sig)));
        assert_eq!(finish(&response(200, &wire, &sig), "/royak/v1/pods", "nonce-a", "peer").unwrap(), body);

        // Unsigned → refused.
        assert!(finish(&response(200, &wire, &[]), "/royak/v1/pods", "nonce-b", "peer").is_err());
        // Forged body under a valid signature → refused.
        let (_, sig) = seal_and_sign_response("/royak/v1/pods", "nonce-c", 200, body);
        let (other, _) = seal_and_sign_response("/royak/v1/pods", "nonce-c", 200, b"[]");
        assert!(finish(&response(200, &other, &sig), "/royak/v1/pods", "nonce-c", "peer").is_err());
        // A response to a different request (other nonce) → refused.
        let (wire, sig) = seal_and_sign_response("/royak/v1/pods", "nonce-d", 200, body);
        assert!(finish(&response(200, &wire, &sig), "/royak/v1/pods", "nonce-e", "peer").is_err());
        // Status rewritten (e.g. 500 → 200) → refused.
        let (wire, sig) = seal_and_sign_response("/royak/v1/pods", "nonce-f", 500, body);
        assert!(finish(&response(200, &wire, &sig), "/royak/v1/pods", "nonce-f", "peer").is_err());
        // A correctly signed but unsealed (plaintext) body → refused.
        let (m, p) = response_signing("/royak/v1/pods", "nonce-g", 200);
        let sig = crate::auth::node_headers(&m, &p, body).unwrap();
        assert!(finish(&response(200, body, &sig), "/royak/v1/pods", "nonce-g", "peer").is_err());
    }

    #[test]
    fn bodies_are_sealed_on_the_wire_in_both_directions() {
        with_secret();
        let secret = br#"{"logs":"password=hunter2"}"#;
        let (req, _) = build_request("POST", "peer:1", "/royak/v1/heartbeat", secret).unwrap();
        assert!(!req.windows(7).any(|w| w == b"hunter2"), "request body must not travel in plaintext");
        let (wire, _) = seal_and_sign_response("/royak/v1/pod-logs/a/b", "n", 200, secret);
        assert!(!wire.windows(7).any(|w| w == b"hunter2"), "response body must not travel in plaintext");
        assert_eq!(open_body(&wire).unwrap(), secret);
        assert!(open_body(b"not sealed").is_err());
        assert_eq!(open_body(b"").unwrap(), b"");
    }
}
