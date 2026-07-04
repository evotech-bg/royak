#![allow(dead_code)]
//! NeuralState — cluster state stored as weight matrices.
//!
//! Instead of etcd (distributed KV) or JSON files, the cluster state
//! IS a neural network: keys are embedded as float vectors, values are
//! stored alongside. Lookup = hash (O(1)) or matmul (fuzzy).
//!
//! KV methods (delete, list_prefix, search, keys, iter) are a public
//! API surface reachable by tests and future callers.
//!
//! Binary persistence format (10-50x faster than JSON parse/serialize):
//!   [NRNS magic:4][version:4][count:4][dim:4]
//!   For each entry:
//!     [key_len:4][key_bytes][embedding:f32*dim][val_len:4][val_bytes]
//!
//! This is the foundation for neural orchestration:
//! the brain can directly query state via matmul.

use ndarray::{Array1, Array2};
use rustc_hash::FxHashMap;
use std::io::Write;

const MAGIC: [u8; 4] = *b"NRNS";
const STATE_VERSION: u32 = 1;
const DEFAULT_DIM: usize = 64;

struct StateEntry {
    key: String,
    embedding: Array1<f32>,
    value: Vec<u8>,
}

/// Neural key-value store — weights ARE the state.
pub struct NeuralState {
    dim: usize,
    entries: Vec<StateEntry>,
    index: FxHashMap<String, usize>,
    /// Cached key matrix for neural search (invalidated on mutation)
    key_matrix: Option<Array2<f32>>,
    /// Modification counter
    pub version: u64,
}

impl NeuralState {
    pub fn new() -> Self {
        Self {
            dim: DEFAULT_DIM,
            entries: Vec::new(),
            index: FxHashMap::default(),
            key_matrix: None,
            version: 0,
        }
    }

    /// Deterministic key embedding — hash-based, no training.
    /// Produces a unit-norm vector that represents the key string.
    fn embed_key(key: &str, dim: usize) -> Array1<f32> {
        let mut emb = Array1::<f32>::zeros(dim);

        // FNV-1a multi-seed hashing → spread across dimensions
        let mut h: u64 = 0xcbf29ce484222325;
        for (i, b) in key.bytes().enumerate() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);

            // Distribute into embedding dims using multiple projections
            let idx1 = (h as usize) % dim;
            let idx2 = (h.wrapping_shr(16) as usize) % dim;
            let idx3 = (h.wrapping_shr(32) as usize) % dim;
            let val = ((h & 0xFF) as f32 - 128.0) / 128.0;
            let pos = (i % 2 == 0) as u8 as f32 * 2.0 - 1.0;

            emb[idx1] += val * pos;
            emb[idx2] -= val * 0.5;
            emb[idx3] += val * 0.3 * pos;
        }

        // L2 normalize
        let norm = emb.dot(&emb).sqrt().max(1e-8);
        emb /= norm;
        emb
    }

    /// Set a key-value pair. Overwrites if key exists.
    pub fn set(&mut self, key: String, value: Vec<u8>) {
        self.key_matrix = None; // invalidate cache
        self.version += 1;

        if let Some(&idx) = self.index.get(&key) {
            // Update in-place
            self.entries[idx].value = value;
        } else {
            // New entry
            let embedding = Self::embed_key(&key, self.dim);
            let idx = self.entries.len();
            self.entries.push(StateEntry { key: key.clone(), embedding, value });
            self.index.insert(key, idx);
        }
    }

    /// Get value by exact key.
    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.index.get(key).map(|&idx| self.entries[idx].value.as_slice())
    }

    /// Delete a key. Returns true if it existed.
    pub fn delete(&mut self, key: &str) -> bool {
        if let Some(idx) = self.index.remove(key) {
            self.key_matrix = None;
            self.version += 1;

            // Swap-remove: move last entry into this slot
            let last = self.entries.len() - 1;
            if idx != last {
                let last_key = self.entries[last].key.clone();
                self.entries.swap(idx, last);
                self.index.insert(last_key, idx);
            }
            self.entries.pop();
            true
        } else {
            false
        }
    }

    /// List all keys with a given prefix.
    pub fn list_prefix(&self, prefix: &str) -> Vec<&str> {
        self.index.keys()
            .filter(|k| k.starts_with(prefix))
            .map(|k| k.as_str())
            .collect()
    }

    /// Neural fuzzy search: find keys most similar to query via matmul.
    /// Returns (key, similarity_score) pairs, sorted by similarity.
    pub fn search(&mut self, query: &str, top_k: usize) -> Vec<(&str, f32)> {
        if self.entries.is_empty() { return Vec::new(); }

        // Build key matrix if needed
        if self.key_matrix.is_none() {
            let n = self.entries.len();
            let mut mat = Array2::zeros((n, self.dim));
            for (i, entry) in self.entries.iter().enumerate() {
                mat.row_mut(i).assign(&entry.embedding);
            }
            self.key_matrix = Some(mat);
        }

        let q = Self::embed_key(query, self.dim);
        let km = self.key_matrix.as_ref().unwrap();

        // Similarity = q @ K.T (cosine, since both are unit-norm)
        let scores = km.dot(&q);

        // Top-k
        let mut scored: Vec<(usize, f32)> = scores.iter().enumerate()
            .map(|(i, &s)| (i, s))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);

        scored.iter()
            .map(|&(i, s)| (self.entries[i].key.as_str(), s))
            .collect()
    }

    /// Entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Save to binary file (atomic: write tmp, rename).
    pub fn save(&self, path: &str) -> Result<(), String> {
        let tmp = format!("{path}.tmp");
        let mut file = std::fs::File::create(&tmp).map_err(|e| format!("create {tmp}: {e}"))?;

        // Header
        file.write_all(&MAGIC).map_err(|e| e.to_string())?;
        file.write_all(&STATE_VERSION.to_le_bytes()).map_err(|e| e.to_string())?;
        file.write_all(&(self.entries.len() as u32).to_le_bytes()).map_err(|e| e.to_string())?;
        file.write_all(&(self.dim as u32).to_le_bytes()).map_err(|e| e.to_string())?;
        file.write_all(&self.version.to_le_bytes()).map_err(|e| e.to_string())?;

        // Entries
        for entry in &self.entries {
            let kb = entry.key.as_bytes();
            file.write_all(&(kb.len() as u32).to_le_bytes()).map_err(|e| e.to_string())?;
            file.write_all(kb).map_err(|e| e.to_string())?;

            // Key embedding
            for &v in entry.embedding.iter() {
                file.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())?;
            }

            // Value
            file.write_all(&(entry.value.len() as u32).to_le_bytes()).map_err(|e| e.to_string())?;
            file.write_all(&entry.value).map_err(|e| e.to_string())?;
        }

        // Atomic rename
        std::fs::rename(&tmp, path).map_err(|e| format!("rename: {e}"))?;
        Ok(())
    }

    /// Load from binary file.
    pub fn load(path: &str) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("read {path}: {e}"))?;
        if data.len() < 20 { return Err("file too small".to_string()); }

        let mut pos = 0;

        // Magic
        if &data[pos..pos+4] != MAGIC { return Err("bad magic".to_string()); }
        pos += 4;

        // Version
        let ver = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
        if ver != STATE_VERSION { return Err(format!("unsupported version: {ver}")); }
        pos += 4;

        // Count
        let count = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
        pos += 4;

        // Dim
        let dim = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
        pos += 4;

        // Version counter
        let version = u64::from_le_bytes(data[pos..pos+8].try_into().unwrap());
        pos += 8;

        let mut entries = Vec::with_capacity(count);
        let mut index = FxHashMap::default();

        for i in 0..count {
            // Key
            if pos + 4 > data.len() { return Err(format!("truncated at entry {i}")); }
            let key_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + key_len > data.len() { return Err(format!("truncated key at entry {i}")); }
            let key = String::from_utf8_lossy(&data[pos..pos+key_len]).to_string();
            pos += key_len;

            // Embedding
            let emb_bytes = dim * 4;
            if pos + emb_bytes > data.len() { return Err(format!("truncated embedding at entry {i}")); }
            let mut embedding = Array1::zeros(dim);
            for j in 0..dim {
                embedding[j] = f32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
                pos += 4;
            }

            // Value
            if pos + 4 > data.len() { return Err(format!("truncated at value header {i}")); }
            let val_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
            pos += 4;
            if pos + val_len > data.len() { return Err(format!("truncated value at entry {i}")); }
            let value = data[pos..pos+val_len].to_vec();
            pos += val_len;

            index.insert(key.clone(), i);
            entries.push(StateEntry { key, embedding, value });
        }

        Ok(Self {
            dim,
            entries,
            index,
            key_matrix: None,
            version,
        })
    }

    /// Get all keys (for iteration).
    pub fn keys(&self) -> Vec<&str> {
        self.entries.iter().map(|e| e.key.as_str()).collect()
    }

    /// Get key and value by index (for iteration).
    pub fn iter(&self) -> impl Iterator<Item = (&str, &[u8])> {
        self.entries.iter().map(|e| (e.key.as_str(), e.value.as_slice()))
    }

    /// Stats string for display.
    pub fn stats(&self) -> String {
        let total_bytes: usize = self.entries.iter().map(|e| e.value.len()).sum();
        let emb_bytes = self.entries.len() * self.dim * 4;
        format!("{} entries, {} value bytes, {} embedding bytes, dim={}",
            self.entries.len(), total_bytes, emb_bytes, self.dim)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> String {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap().as_nanos();
        format!("/tmp/rk-test-{pid}-{nanos}-{name}")
    }

    #[test]
    fn new_state_is_empty() {
        let ns = NeuralState::new();
        assert_eq!(ns.len(), 0);
    }

    #[test]
    fn set_get_roundtrip() {
        let mut ns = NeuralState::new();
        ns.set("alpha".into(), b"one".to_vec());
        ns.set("beta".into(), b"two".to_vec());
        assert_eq!(ns.get("alpha"), Some(b"one".as_ref()));
        assert_eq!(ns.get("beta"), Some(b"two".as_ref()));
        assert_eq!(ns.get("gamma"), None);
        assert_eq!(ns.len(), 2);
    }

    #[test]
    fn set_overwrites() {
        let mut ns = NeuralState::new();
        ns.set("k".into(), b"v1".to_vec());
        ns.set("k".into(), b"v2".to_vec());
        assert_eq!(ns.get("k"), Some(b"v2".as_ref()));
        assert_eq!(ns.len(), 1);
    }

    #[test]
    fn delete_removes() {
        let mut ns = NeuralState::new();
        ns.set("a".into(), b"x".to_vec());
        assert!(ns.delete("a"));
        assert!(!ns.delete("a"));
        assert_eq!(ns.get("a"), None);
    }

    #[test]
    fn list_prefix_filters() {
        let mut ns = NeuralState::new();
        ns.set("deploy/web".into(), b"-".to_vec());
        ns.set("deploy/api".into(), b"-".to_vec());
        ns.set("service/web".into(), b"-".to_vec());
        let mut deploys = ns.list_prefix("deploy/");
        deploys.sort();
        assert_eq!(deploys, vec!["deploy/api", "deploy/web"]);
    }

    #[test]
    fn save_load_roundtrip_preserves_entries() {
        let path = tmp("roundtrip.nrns");
        let mut ns = NeuralState::new();
        ns.set("k1".into(), b"hello".to_vec());
        ns.set("k2".into(), vec![0u8, 1, 2, 255]);
        ns.save(&path).expect("save ok");

        let loaded = NeuralState::load(&path).expect("load ok");
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.get("k1"), Some(b"hello".as_ref()));
        assert_eq!(loaded.get("k2"), Some(vec![0u8, 1, 2, 255].as_slice()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_missing_file_errors() {
        let r = NeuralState::load("/tmp/rk-nonexistent-file-that-does-not-exist.nrns");
        assert!(r.is_err());
    }

    #[test]
    fn load_too_small_errors() {
        let path = tmp("tiny.nrns");
        std::fs::write(&path, b"xx").unwrap();
        let r = NeuralState::load(&path);
        assert!(r.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_bad_magic_errors() {
        let path = tmp("badmagic.nrns");
        std::fs::write(&path, vec![0u8; 32]).unwrap();
        let r = NeuralState::load(&path);
        assert!(r.is_err());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stats_reports_entry_count() {
        let mut ns = NeuralState::new();
        ns.set("a".into(), b"x".to_vec());
        ns.set("b".into(), b"yy".to_vec());
        let s = ns.stats();
        assert!(s.contains("2 entries"));
    }
}
