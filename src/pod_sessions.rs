//! Hard admission for Pod diagnostics. This is a resource guard, not a measured
//! production capacity recommendation. Connect's separate limits are unchanged.
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, OnceLock},
};

pub const NODE_LIMIT: usize = 16;
pub const USER_LIMIT: usize = 8;
pub const FORWARD_PORT_LIMIT: usize = 8;
pub const PIPE_DEPTH: usize = 16;
pub const PIPE_CHUNK: usize = 8192;
pub const DOCKER_FRAME_LIMIT: usize = 1_000_000;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Busy {
    User,
    Node,
}
impl Busy {
    pub fn status(self) -> u16 {
        match self {
            Self::User => 429,
            Self::Node => 503,
        }
    }
    pub fn message(self) -> &'static str {
        match self {
            Self::User => "Pod diagnostic session limit for this user",
            Self::Node => "Pod diagnostic session capacity on this node",
        }
    }
}
#[derive(Default)]
struct Counts {
    total: usize,
    users: HashMap<String, usize>,
}
pub struct Limiter {
    counts: Mutex<Counts>,
    node_limit: usize,
    user_limit: usize,
}
impl Limiter {
    fn new(node_limit: usize, user_limit: usize) -> Arc<Self> {
        Arc::new(Self {
            counts: Mutex::new(Counts::default()),
            node_limit,
            user_limit,
        })
    }
    fn acquire(self: &Arc<Self>, user: &str) -> Result<Lease, Busy> {
        let mut counts = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if counts.users.get(user).copied().unwrap_or(0) >= self.user_limit {
            return Err(Busy::User);
        }
        if counts.total >= self.node_limit {
            return Err(Busy::Node);
        }
        counts.total += 1;
        *counts.users.entry(user.into()).or_default() += 1;
        Ok(Lease(Arc::new(Reservation {
            limiter: self.clone(),
            user: user.into(),
        })))
    }
}
struct Reservation {
    limiter: Arc<Limiter>,
    user: String,
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut c = self
            .limiter
            .counts
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        c.total -= 1;
        if let Some(n) = c.users.get_mut(&self.user) {
            *n -= 1;
            if *n == 0 {
                c.users.remove(&self.user);
            }
        }
    }
}
/// Every background reader/writer and blocking job holds a clone. Closing an
/// HTTP stream alone does not free capacity while its real workers still live.
#[derive(Clone)]
pub struct Lease(Arc<Reservation>);
impl Lease {
    pub fn hold(&self) -> Self {
        Self(self.0.clone())
    }
}
pub fn admit(user: &str) -> Result<Lease, Busy> {
    // Fast local state only. Never start Docker/network/scan work from a route.
    if !crate::docker::diagnostic_recovery_ready() { return Err(Busy::Node); }
    limiter().acquire(user)
}
fn limiter() -> &'static Arc<Limiter> {
    static LIMITER: OnceLock<Arc<Limiter>> = OnceLock::new();
    LIMITER.get_or_init(|| Limiter::new(NODE_LIMIT, USER_LIMIT))
}
pub fn usage() -> serde_json::Value {
    let counts = limiter().counts.lock().unwrap_or_else(|e| e.into_inner());
    let recovery = crate::docker::diagnostic_recovery_usage();
    let ready = recovery["state"] == "Ready";
    serde_json::json!({"active_or_closing":ready.then_some(counts.total),
        "users":ready.then_some(counts.users.len()),"current_process_active_or_closing":counts.total,
        "current_process_users":counts.users.len(),"recovery":recovery,"node_limit":NODE_LIMIT,
        "user_limit":USER_LIMIT,"forward_port_limit":FORWARD_PORT_LIMIT})
}

pub fn forward_ports(url: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for (key, value) in url
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("")
        .split('&')
        .filter_map(|q| q.split_once('='))
    {
        if key != "ports" {
            continue;
        }
        // Port lists contain only decimal digits and literal/encoded commas.
        let value = value.replace("%2C", ",").replace("%2c", ",");
        for part in value.split(',') {
            let port = part
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or("invalid forwarded port")?;
            ports.push(port);
            if ports.len() > FORWARD_PORT_LIMIT {
                return Err("at most eight forwarded ports per Pod session".into());
            }
        }
    }
    if ports.is_empty() {
        return Err("at least one forwarded port required".into());
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn per_user_global_and_last_worker_drop_enforce_real_lifetimes() {
        let l = Limiter::new(2, 1);
        let a = l.acquire("a").unwrap();
        let worker = a.hold();
        drop(a);
        assert_eq!(l.acquire("a").err(), Some(Busy::User));
        let b = l.acquire("b").unwrap();
        assert_eq!(l.acquire("c").err(), Some(Busy::Node));
        drop(worker);
        let c = l.acquire("c").unwrap();
        drop(b);
        drop(c);
        let counts = l.counts.lock().unwrap();
        assert_eq!(counts.total, 0);
        assert!(counts.users.is_empty());
    }
    #[test]
    fn invalid_request_lists_do_not_multiply_backend_tasks() {
        assert_eq!(
            forward_ports("/p?ports=80,443&ports=8080").unwrap(),
            vec![80, 443, 8080]
        );
        assert_eq!(forward_ports("/p?ports=80%2C443").unwrap(), vec![80, 443]);
        for url in [
            "/p",
            "/p?ports=0",
            "/p?ports=x",
            "/p?ports=65536",
            "/p?ports=1,2,3,4,5,6,7,8,9",
        ] {
            assert!(forward_ports(url).is_err(), "{url}");
        }
    }
}
