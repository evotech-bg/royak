//! Encrypted transport for the cross-node mesh hop.
//!
//! The v0.3 mesh proxy forwards pod→service traffic between nodes in
//! plaintext. This module wraps the node→node hop in AES-256-GCM: every frame
//! is `[u32 len][12-byte nonce][ciphertext+tag]` with a fresh random nonce per
//! frame (no nonce reuse). The symmetric key is derived from the cluster
//! shared secret, so only nodes holding it can read cross-node traffic.
//!
//! This gives the same security property WireGuard would (cross-node traffic
//! authenticated + encrypted) using crypto we already ship and test, with no
//! new dependency and no kernel module — so it works on macOS's VM too.
//!
//! Handshake: an encrypting peer sends the 8-byte magic `RKMESHc1` first, so
//! the receiver can tell an encrypted peer connection from a plaintext
//! same-node pod connection.
//!
//! NOTE: the mesh data path (encrypted or not) only runs where container IPs
//! are host-routable, i.e. Linux — see COMPATIBILITY.md. The frame codec below
//! is unit-tested directly; the live cross-node run is exercised in CI.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use sha2::{Digest, Sha256};

pub const MESH_MAGIC: &[u8; 8] = b"RKMESHc1";
const MAX_FRAME: usize = 4 * 1024 * 1024;

/// Derive the 32-byte mesh key from the cluster shared secret.
pub fn mesh_key(cluster_secret: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"royak-mesh-v1");
    h.update(cluster_secret.as_bytes());
    let out = h.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out);
    key
}

fn cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("32-byte key")
}

/// Encode a plaintext chunk into one framed, encrypted message.
/// Layout: [u32 BE total-after-this-field][12B nonce][ciphertext||tag].
pub fn seal_frame(key: &[u8; 32], plaintext: &[u8], nonce12: [u8; 12]) -> Vec<u8> {
    let ct = cipher(key)
        .encrypt(Nonce::from_slice(&nonce12), plaintext)
        .expect("aes-gcm encrypt");
    let mut out = Vec::with_capacity(4 + 12 + ct.len());
    let payload_len = (12 + ct.len()) as u32;
    out.extend_from_slice(&payload_len.to_be_bytes());
    out.extend_from_slice(&nonce12);
    out.extend_from_slice(&ct);
    out
}

/// Try to decode exactly one frame from the front of `buf`. Returns
/// `Ok(Some((plaintext, consumed)))` when a whole frame is present,
/// `Ok(None)` when more bytes are needed, `Err` on a decrypt/format failure
/// (tampered or wrong key).
pub fn open_frame(key: &[u8; 32], buf: &[u8]) -> Result<Option<(Vec<u8>, usize)>, String> {
    if buf.len() < 4 {
        return Ok(None);
    }
    let payload_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if payload_len < 12 || payload_len > MAX_FRAME {
        return Err(format!("bad frame length {payload_len}"));
    }
    let total = 4 + payload_len;
    if buf.len() < total {
        return Ok(None);
    }
    let nonce = &buf[4..16];
    let ct = &buf[16..total];
    let pt = cipher(key)
        .decrypt(Nonce::from_slice(nonce), ct)
        .map_err(|_| "mesh frame decrypt failed (tampered or wrong cluster secret)".to_string())?;
    Ok(Some((pt, total)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(seed: u8) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[0] = seed;
        n[11] = seed.wrapping_add(7);
        n
    }

    #[test]
    fn roundtrip_single_frame() {
        let key = mesh_key("cluster-secret");
        let msg = b"GET / HTTP/1.1\r\nHost: web\r\n\r\n";
        let framed = seal_frame(&key, msg, nonce(1));
        let (pt, consumed) = open_frame(&key, &framed).unwrap().unwrap();
        assert_eq!(pt, msg);
        assert_eq!(consumed, framed.len());
    }

    #[test]
    fn partial_frame_needs_more() {
        let key = mesh_key("s");
        let framed = seal_frame(&key, b"hello world", nonce(2));
        // Only the first few bytes → not enough yet.
        assert!(open_frame(&key, &framed[..5]).unwrap().is_none());
        // Full frame → decodes.
        assert!(open_frame(&key, &framed).unwrap().is_some());
    }

    #[test]
    fn wrong_key_fails() {
        let framed = seal_frame(&mesh_key("right"), b"secret", nonce(3));
        assert!(open_frame(&mesh_key("wrong"), &framed).is_err());
    }

    #[test]
    fn tamper_fails() {
        let key = mesh_key("k");
        let mut framed = seal_frame(&key, b"data", nonce(4));
        let last = framed.len() - 1;
        framed[last] ^= 0xFF; // flip a ciphertext bit
        assert!(open_frame(&key, &framed).is_err());
    }

    #[test]
    fn two_frames_in_stream() {
        let key = mesh_key("k");
        let mut stream = seal_frame(&key, b"first", nonce(5));
        stream.extend_from_slice(&seal_frame(&key, b"second", nonce(6)));
        let (p1, c1) = open_frame(&key, &stream).unwrap().unwrap();
        assert_eq!(p1, b"first");
        let (p2, _) = open_frame(&key, &stream[c1..]).unwrap().unwrap();
        assert_eq!(p2, b"second");
    }
}
