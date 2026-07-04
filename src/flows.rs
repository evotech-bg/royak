//! Traffic observability — a flow tap for connections Royak proxies.
//!
//! Every userspace proxy in Royak (ServiceLB, ingress, cross-node mesh) sees
//! real connections. This module is a small global ring buffer they append a
//! FlowRecord to when a connection closes: who connected, to which service,
//! how many bytes each way, when, and for how long. The API exposes it at
//! `/royak/v1/flows` and the CLI as `royak flows`.
//!
//! Metadata only — source/dest/bytes/timing, not payloads. A payload trace is
//! a separate, explicit opt-in (not built here) because it captures user data.

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const MAX_FLOWS: usize = 2000;

#[derive(Clone, serde::Serialize)]
pub struct FlowRecord {
    /// Which proxy observed it: "servicelb" | "ingress" | "mesh".
    pub via: String,
    /// Client side (host:port or pod name).
    pub source: String,
    /// Destination service or pod.
    pub dest: String,
    /// Destination port.
    pub port: u16,
    /// Bytes client→dest.
    pub bytes_up: u64,
    /// Bytes dest→client.
    pub bytes_down: u64,
    /// Unix seconds when the connection opened.
    pub started: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
}

fn store() -> &'static Mutex<VecDeque<FlowRecord>> {
    static S: OnceLock<Mutex<VecDeque<FlowRecord>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(VecDeque::with_capacity(MAX_FLOWS)))
}

/// Append a completed flow, evicting the oldest past the cap.
pub fn record(f: FlowRecord) {
    if let Ok(mut q) = store().lock() {
        if q.len() >= MAX_FLOWS {
            q.pop_front();
        }
        q.push_back(f);
    }
}

/// Newest-first snapshot, capped at `limit`.
pub fn snapshot(limit: usize) -> Vec<FlowRecord> {
    match store().lock() {
        Ok(q) => q.iter().rev().take(limit).cloned().collect(),
        Err(_) => Vec::new(),
    }
}

/// Aggregate byte totals per destination service — a cheap "top talkers" view.
pub fn totals() -> Vec<(String, u64, u64, u64)> {
    let mut agg: std::collections::HashMap<String, (u64, u64, u64)> = std::collections::HashMap::new();
    if let Ok(q) = store().lock() {
        for f in q.iter() {
            let e = agg.entry(f.dest.clone()).or_insert((0, 0, 0));
            e.0 += 1;
            e.1 += f.bytes_up;
            e.2 += f.bytes_down;
        }
    }
    let mut v: Vec<(String, u64, u64, u64)> =
        agg.into_iter().map(|(k, (n, u, d))| (k, n, u, d)).collect();
    v.sort_by(|a, b| (b.2 + b.3).cmp(&(a.2 + a.3)));
    v
}

/// Unix seconds now (best-effort).
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
