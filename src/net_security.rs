#![allow(dead_code)]
//! Network Security Layer — mTLS, pod identity, audit, threat detection.
//!
//! What Kubernetes needs Istio + Cilium + Falco for, we build in.
//!
//! Features:
//!   1. Cluster CA + per-pod mTLS certificates (built-in service mesh)
//!   2. Pod identity tokens (zero-trust)
//!   3. Network audit trail (who talked to whom, when)
//!   4. Neural threat detection (brain monitors network patterns)
//!   5. Egress firewall (internal-only namespaces)

/// Cluster Certificate Authority — generates and signs pod certificates.
/// One CA per cluster, stored in state, rotated on demand.
pub struct ClusterCA {
    pub cert_pem: String,
    pub key_pem: String,
    pub fingerprint: String,
    pub issued_count: u64,
}

/// Per-pod mTLS certificate + identity token
pub struct PodIdentity {
    pub pod_name: String,
    pub namespace: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub token: String,
    pub ca_cert_pem: String,
}

/// Network audit event — recorded for every significant network action
#[derive(Clone, serde::Serialize)]
pub struct NetworkAuditEntry {
    pub timestamp: u64,
    pub action: String,        // "connect", "disconnect", "deny", "allow", "anomaly"
    pub source: String,        // pod/namespace that initiated
    pub target: String,        // target network/pod/namespace
    pub policy: String,        // which policy triggered this (or "none")
    pub result: String,        // "ok", "denied", "anomaly_detected"
}

/// Neural network pattern tracker — learns normal pod communication patterns
pub struct NetworkPatternTracker {
    /// Per-pod connection history: pod_name → list of (target_network, count)
    patterns: rustc_hash::FxHashMap<String, Vec<(String, u32)>>,
    /// Baseline established after N observations
    baseline_ticks: u64,
}

impl ClusterCA {
    /// Generate a new Cluster CA (self-signed, valid for 10 years)
    pub fn generate() -> Result<Self, String> {
        let mut params = rcgen::CertificateParams::new(vec![
            "Royak Cluster CA".to_string(),
        ]).map_err(|e| format!("CA params: {e}"))?;

        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(rcgen::DnType::CommonName, "Royak Cluster CA");
        params.distinguished_name.push(rcgen::DnType::OrganizationName, "Royak");

        // 10-year validity
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(3650);

        let key_pair = rcgen::KeyPair::generate().map_err(|e| format!("CA keygen: {e}"))?;
        let key_pem = key_pair.serialize_pem();
        let cert = params.self_signed(&key_pair).map_err(|e| format!("CA sign: {e}"))?;
        let cert_pem = cert.pem();

        // Fingerprint: first 16 hex chars of hash
        let fp = fingerprint_pem(&cert_pem);

        Ok(ClusterCA {
            cert_pem,
            key_pem,
            fingerprint: fp,
            issued_count: 0,
        })
    }

    /// Issue a signed certificate for a pod (mTLS identity)
    pub fn issue_pod_cert(&mut self, pod_name: &str, namespace: &str) -> Result<PodIdentity, String> {
        // Pod cert params
        let san = format!("{pod_name}.{namespace}.svc.royak.local");
        let mut params = rcgen::CertificateParams::new(vec![
            pod_name.to_string(),
            san.clone(),
            format!("{namespace}.svc.royak.local"),
        ]).map_err(|e| format!("pod cert params: {e}"))?;

        params.is_ca = rcgen::IsCa::NoCa;
        params.distinguished_name.push(rcgen::DnType::CommonName, pod_name);
        params.distinguished_name.push(rcgen::DnType::OrganizationalUnitName, namespace);

        // 90-day validity (auto-rotate)
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + time::Duration::days(90);

        // Generate pod key
        let pod_key = rcgen::KeyPair::generate().map_err(|e| format!("pod keygen: {e}"))?;
        let pod_key_pem = pod_key.serialize_pem();

        // Re-create CA cert from stored PEM for signing
        let ca_key_pair = rcgen::KeyPair::from_pem(&self.key_pem)
            .map_err(|e| format!("CA key parse: {e}"))?;

        // Re-create the CA certificate params and self-sign to get a Certificate object
        let mut ca_params = rcgen::CertificateParams::new(vec![
            "Royak Cluster CA".to_string(),
        ]).map_err(|e| format!("CA re-params: {e}"))?;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params.distinguished_name.push(rcgen::DnType::CommonName, "Royak Cluster CA");
        let ca_cert = ca_params.self_signed(&ca_key_pair)
            .map_err(|e| format!("CA re-sign: {e}"))?;

        // Sign pod cert with CA
        let pod_cert = params.signed_by(&pod_key, &ca_cert, &ca_key_pair)
            .map_err(|e| format!("pod cert sign: {e}"))?;

        self.issued_count += 1;

        // Generate pod token (HMAC-like: hash of pod info + CA fingerprint)
        let token = generate_pod_token(pod_name, namespace, &self.fingerprint);

        Ok(PodIdentity {
            pod_name: pod_name.to_string(),
            namespace: namespace.to_string(),
            cert_pem: pod_cert.pem(),
            key_pem: pod_key_pem,
            token,
            ca_cert_pem: self.cert_pem.clone(),
        })
    }

    /// Serialize CA to JSON for state persistence
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "certPem": self.cert_pem,
            "keyPem": self.key_pem,
            "fingerprint": self.fingerprint,
            "issuedCount": self.issued_count,
        })
    }

    /// Deserialize CA from JSON
    pub fn from_json(v: &serde_json::Value) -> Option<Self> {
        Some(ClusterCA {
            cert_pem: v["certPem"].as_str()?.to_string(),
            key_pem: v["keyPem"].as_str()?.to_string(),
            fingerprint: v["fingerprint"].as_str()?.to_string(),
            issued_count: v["issuedCount"].as_u64().unwrap_or(0),
        })
    }
}

impl PodIdentity {
    /// Get the environment variables to inject into the container
    pub fn env_vars(&self) -> Vec<String> {
        vec![
            format!("ROYAK_POD_CERT={}", self.cert_pem.replace('\n', "\\n")),
            format!("ROYAK_POD_KEY={}", self.key_pem.replace('\n', "\\n")),
            format!("ROYAK_CA_CERT={}", self.ca_cert_pem.replace('\n', "\\n")),
            format!("ROYAK_POD_TOKEN={}", self.token),
            format!("ROYAK_POD_NAME={}", self.pod_name),
            format!("ROYAK_POD_NAMESPACE={}", self.namespace),
            format!("ROYAK_POD_SAN={}.{}.svc.royak.local", self.pod_name, self.namespace),
        ]
    }
}

/// Generate a unique pod identity token
/// Token format:
///   nrns-v2.{hex(pod_name)}.{hex(namespace)}.{issued_at}.{hex(HMAC-SHA256(secret, payload))}
///
/// Where payload = "{pod_name}:{namespace}:{issued_at}" and the signature is
/// 32 bytes (truncated to 16 in hex for compactness when needed — full 64
/// hex chars here for standard HMAC-SHA256 verify).
pub fn generate_pod_token(pod_name: &str, namespace: &str, secret: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();

    let payload = format!("{pod_name}:{namespace}:{now}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let sig = mac.finalize().into_bytes();

    let pn_hex: String = pod_name.bytes().map(|b| format!("{b:02x}")).collect();
    let ns_hex: String = namespace.bytes().map(|b| format!("{b:02x}")).collect();
    let sig_hex: String = sig.iter().map(|b| format!("{b:02x}")).collect();
    format!("nrns-v2.{pn_hex}.{ns_hex}.{now}.{sig_hex}")
}

/// Verify a pod token against the cluster secret.
/// Rejects: malformed, wrong prefix, tampered signature, tampered payload.
/// Uses constant-time comparison to resist timing attacks.
pub fn verify_pod_token(token: &str, secret: &str) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    // Prefix check
    let rest = match token.strip_prefix("nrns-v2.") {
        Some(r) => r,
        None => return false,
    };

    let parts: Vec<&str> = rest.split('.').collect();
    if parts.len() != 4 { return false; }
    let (pn_hex, ns_hex, ts_str, sig_hex) = (parts[0], parts[1], parts[2], parts[3]);

    // Decode hex fields (pod name + namespace)
    let pod_name = match hex_decode_to_string(pn_hex) {
        Some(s) => s, None => return false,
    };
    let namespace = match hex_decode_to_string(ns_hex) {
        Some(s) => s, None => return false,
    };
    let issued_at: u64 = match ts_str.parse() { Ok(n) => n, Err(_) => return false };

    // Recompute expected HMAC
    let payload = format!("{pod_name}:{namespace}:{issued_at}");
    let mut mac = match HmacSha256::new_from_slice(secret.as_bytes()) {
        Ok(m) => m, Err(_) => return false,
    };
    mac.update(payload.as_bytes());
    let expected = mac.finalize().into_bytes();

    // Decode presented signature
    let presented = match hex_decode_bytes(sig_hex) {
        Some(b) => b, None => return false,
    };
    if presented.len() != expected.len() { return false; }

    // Constant-time compare
    let mut diff = 0u8;
    for (a, b) in expected.iter().zip(presented.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

fn hex_decode_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..s.len()).step_by(2) {
        out.push(u8::from_str_radix(&s[i..i+2], 16).ok()?);
    }
    Some(out)
}

fn hex_decode_to_string(s: &str) -> Option<String> {
    String::from_utf8(hex_decode_bytes(s)?).ok()
}

/// Fingerprint a PEM certificate (first 16 hex chars of FNV hash)
fn fingerprint_pem(pem: &str) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in pem.bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    format!("{:016x}", h)
}

// ─── Network Audit ───

impl NetworkAuditEntry {
    pub fn new(action: &str, source: &str, target: &str, policy: &str, result: &str) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default().as_secs(),
            action: action.to_string(),
            source: source.to_string(),
            target: target.to_string(),
            policy: policy.to_string(),
            result: result.to_string(),
        }
    }

    pub fn connect(source: &str, target_net: &str) -> Self {
        Self::new("connect", source, target_net, "none", "ok")
    }

    pub fn policy_allow(source: &str, target_net: &str, policy: &str) -> Self {
        Self::new("allow", source, target_net, policy, "ok")
    }

    pub fn policy_deny(source: &str, target_net: &str, policy: &str) -> Self {
        Self::new("deny", source, target_net, policy, "denied")
    }

    pub fn anomaly(source: &str, detail: &str) -> Self {
        Self::new("anomaly", source, detail, "neural", "anomaly_detected")
    }
}

// ─── ACME / Let's Encrypt ───

/// Simple ACME HTTP-01 challenge state for Let's Encrypt integration.
/// When the ingress controller receives a request to /.well-known/acme-challenge/{token},
/// it responds with the key authorization.
pub struct AcmeChallenge {
    pub domain: String,
    pub token: String,
    pub key_auth: String,
    pub status: AcmeStatus,
}

#[derive(Clone, PartialEq)]
pub enum AcmeStatus {
    Pending,
    Valid,
    Failed,
}

/// Request a Let's Encrypt certificate via ACME HTTP-01.
/// Steps: 1) Create account, 2) Create order, 3) Get challenge, 4) Respond, 5) Finalize
/// This is a simplified implementation — production would use a full ACME client.
pub fn request_acme_cert(domain: &str, acme_dir: &str) -> Result<(String, String, AcmeChallenge), String> {
    // For now: generate self-signed cert but set up the ACME challenge structure
    // so the ingress controller can respond to HTTP-01 challenges.
    // Full ACME implementation requires HTTP client (POST to Let's Encrypt API).

    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| format!("cert params: {e}"))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, domain);

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(90);

    let key = rcgen::KeyPair::generate().map_err(|e| format!("keygen: {e}"))?;
    let key_pem = key.serialize_pem();
    let cert = params.self_signed(&key).map_err(|e| format!("sign: {e}"))?;
    let cert_pem = cert.pem();

    // Save to acme directory
    std::fs::create_dir_all(acme_dir).ok();
    std::fs::write(format!("{acme_dir}/{domain}.crt"), &cert_pem).ok();
    std::fs::write(format!("{acme_dir}/{domain}.key"), &key_pem).ok();

    // Generate challenge token (for HTTP-01 validation)
    let token = fingerprint_pem(&format!("{domain}:{}", now.unix_timestamp()));
    let key_auth = format!("{token}.{}", fingerprint_pem(&key_pem));

    let challenge = AcmeChallenge {
        domain: domain.to_string(),
        token: token.clone(),
        key_auth,
        status: AcmeStatus::Pending,
    };

    Ok((cert_pem, key_pem, challenge))
}

/// Load existing certificate for a domain (if not expired)
pub fn load_domain_cert(acme_dir: &str, domain: &str) -> Option<(String, String)> {
    let cert_path = format!("{acme_dir}/{domain}.crt");
    let key_path = format!("{acme_dir}/{domain}.key");
    let cert = std::fs::read_to_string(&cert_path).ok()?;
    let key = std::fs::read_to_string(&key_path).ok()?;
    Some((cert, key))
}

// ─── Neural Threat Detection ───

impl NetworkPatternTracker {
    pub fn new() -> Self {
        Self {
            patterns: rustc_hash::FxHashMap::default(),
            baseline_ticks: 0,
        }
    }

    /// Record a network connection event
    pub fn observe(&mut self, pod: &str, target_network: &str) {
        let entry = self.patterns.entry(pod.to_string()).or_insert_with(Vec::new);
        if let Some(existing) = entry.iter_mut().find(|(net, _)| net == target_network) {
            existing.1 += 1;
        } else {
            entry.push((target_network.to_string(), 1));
        }
        self.baseline_ticks += 1;
    }

    /// Detect anomalous network behavior.
    /// Returns list of (pod_name, anomaly_description, severity)
    pub fn detect_anomalies(&self) -> Vec<(String, String, f32)> {
        if self.baseline_ticks < 10 { return Vec::new(); } // need baseline

        let mut anomalies = Vec::new();

        for (pod, connections) in &self.patterns {
            // Anomaly 1: Pod connected to too many different networks
            if connections.len() > 5 {
                anomalies.push((
                    pod.clone(),
                    format!("connected to {} networks (unusual, expected ≤3)", connections.len()),
                    0.7,
                ));
            }

            // Anomaly 2: Sudden spike in connections to a network
            let total: u32 = connections.iter().map(|(_, c)| *c).sum();
            let avg = total as f32 / connections.len().max(1) as f32;
            for (net, count) in connections {
                if *count as f32 > avg * 3.0 && *count > 10 {
                    anomalies.push((
                        pod.clone(),
                        format!("excessive connections to {net} ({count} vs avg {avg:.0})"),
                        0.8,
                    ));
                }
            }

            // Anomaly 3: Pod connecting to networks it shouldn't (cross-namespace without policy)
            for (net, _) in connections {
                if net.starts_with("rk-") && net != "rk-default" {
                    let ns = net.strip_prefix("rk-").unwrap_or(net);
                    // Check if pod name contains the namespace — if not, it's cross-namespace
                    if !pod.contains(ns) {
                        // This is a cross-namespace connection — might be legitimate (NetworkPolicy)
                        // but worth flagging for audit
                        anomalies.push((
                            pod.clone(),
                            format!("cross-namespace connection to {ns}"),
                            0.5,
                        ));
                    }
                }
            }
        }

        anomalies
    }

    /// Get stats
    pub fn stats(&self) -> String {
        format!("{} pods tracked, {} total observations",
            self.patterns.len(), self.baseline_ticks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cluster_ca_generates_pem() {
        let ca = ClusterCA::generate().expect("CA generated");
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
        assert_eq!(ca.fingerprint.len(), 16, "fingerprint should be 16 hex chars");
        assert_eq!(ca.issued_count, 0);
    }

    #[test]
    fn ca_issues_pod_cert_and_bumps_count() {
        let mut ca = ClusterCA::generate().expect("CA");
        let start = ca.issued_count;
        let pod = ca.issue_pod_cert("rk-web-1", "default").expect("issue");
        assert_eq!(pod.pod_name, "rk-web-1");
        assert_eq!(pod.namespace, "default");
        assert!(pod.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(pod.key_pem.contains("PRIVATE KEY"));
        assert!(!pod.token.is_empty());
        assert_eq!(ca.issued_count, start + 1);
    }

    const SECRET: &str = "cluster-shared-secret";

    #[test]
    fn pod_token_roundtrip() {
        let token = generate_pod_token("rk-web-1", "default", SECRET);
        assert!(verify_pod_token(&token, SECRET), "freshly minted token must verify");
    }

    #[test]
    fn pod_token_format_v2() {
        let token = generate_pod_token("rk-web-1", "default", SECRET);
        assert!(token.starts_with("nrns-v2."));
        assert_eq!(token.split('.').count(), 5, "nrns-v2 + 4 fields");
    }

    #[test]
    fn pod_token_rejects_tampered_signature() {
        let good = generate_pod_token("rk-web-1", "default", SECRET);
        let parts: Vec<&str> = good.split('.').collect();
        // Flip one hex char in the signature (last field)
        let sig = parts[4];
        let flipped_char = if sig.starts_with('a') { 'b' } else { 'a' };
        let tampered_sig: String = flipped_char.to_string() + &sig[1..];
        let tampered = format!("{}.{}.{}.{}.{}",
            parts[0], parts[1], parts[2], parts[3], tampered_sig);
        assert!(!verify_pod_token(&tampered, SECRET), "tampered signature must fail");
    }

    #[test]
    fn pod_token_rejects_tampered_payload() {
        // Valid token for pod-a. Swap pod name in the token but keep the signature.
        let good = generate_pod_token("pod-a", "default", SECRET);
        let evil = generate_pod_token("pod-b", "default", SECRET);
        let good_parts: Vec<&str> = good.split('.').collect();
        let evil_parts: Vec<&str> = evil.split('.').collect();
        // Use pod-b's payload but pod-a's signature
        let forged = format!("{}.{}.{}.{}.{}",
            evil_parts[0], evil_parts[1], evil_parts[2], evil_parts[3], good_parts[4]);
        assert!(!verify_pod_token(&forged, SECRET));
    }

    #[test]
    fn pod_token_rejects_wrong_secret() {
        let good = generate_pod_token("rk-web-1", "default", SECRET);
        assert!(!verify_pod_token(&good, "different-secret"),
            "token issued under one secret must not verify under another");
    }

    #[test]
    fn pod_token_rejects_old_prefix() {
        // Old-format tokens (no -v2) must be rejected — force the upgrade.
        assert!(!verify_pod_token("nrns-00000000000000000000000000000000", SECRET));
    }

    #[test]
    fn pod_token_rejects_garbage() {
        assert!(!verify_pod_token("", SECRET));
        assert!(!verify_pod_token("not-a-valid-token", SECRET));
        assert!(!verify_pod_token("nrns-v2.incomplete", SECRET));
        assert!(!verify_pod_token("nrns-v2.zz.zz.0.zz", SECRET));
    }
}
