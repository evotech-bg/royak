//! Runtime-only probe state. The container incarnation, not its reusable pod
//! name, owns timers/counters. All decisions are monotonic-clock based.
use std::time::{Duration, Instant};
use crate::reconcile::StoredProbe;

pub const LABEL_HEALTH_SPEC: &str = "royak.health-spec.v1";

#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerHealth {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<StoredProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub readiness: Option<StoredProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub startup: Option<StoredProbe>,
}
impl ContainerHealth {
    pub fn configured(&self) -> bool { self.liveness.is_some() || self.readiness.is_some() || self.startup.is_some() }
}
impl From<&crate::reconcile::StoredContainer> for ContainerHealth {
    fn from(c: &crate::reconcile::StoredContainer) -> Self {
        Self { liveness:c.liveness_probe.clone(),readiness:c.readiness_probe.clone(),startup:c.startup_probe.clone() }
    }
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthEntry { pub docker_name: String, pub health: ContainerHealth }

pub fn decode_spec(raw: &str, pod: &str) -> Result<Vec<HealthEntry>, String> {
    if raw.len() > 65536 { return Err("health specification exceeds 64 KiB".into()); }
    let entries: Vec<HealthEntry> = serde_json::from_str(raw).map_err(|e| format!("invalid immutable health specification: {e}"))?;
    let mut names = std::collections::HashSet::new();
    if entries.is_empty() || entries[0].docker_name != pod || entries.iter().any(|e|
        !(e.docker_name == pod || e.docker_name.starts_with(&format!("{pod}-"))) || !names.insert(e.docker_name.clone())) {
        return Err("immutable health specification does not match pod identity".into());
    }
    Ok(entries)
}

pub fn world_has_probes(w: &crate::reconcile::DesiredWorld) -> bool {
    let has = |c: &crate::reconcile::StoredContainer| c.liveness_probe.is_some() || c.readiness_probe.is_some() || c.startup_probe.is_some();
    w.deployments.values().any(|d| d.containers.iter().chain(d.init_containers.iter()).any(has))
        || w.daemonsets.values().any(|d| has(&d.container))
        || w.jobs.values().any(|d| has(&d.container))
        || w.cronjobs.values().any(|d| has(&d.container))
}

#[derive(Clone, Default, Debug)]
pub struct Check {
    last: Option<Instant>,
    failures: u32,
    successes: u32,
    pub healthy: bool,
}

impl Check {
    pub fn due(&self, now: Instant, origin: Instant, probe: &StoredProbe) -> bool {
        now.saturating_duration_since(origin) >= Duration::from_secs(probe.initial_delay_seconds)
            && self.last.map(|last| now.saturating_duration_since(last) >= Duration::from_secs(probe.period_seconds.max(1))).unwrap_or(true)
    }

    /// Infrastructure UNKNOWN is not an application failure or success. It
    /// removes readiness and advances only the unchanged probe cadence.
    pub fn record_unknown(&mut self, now: Instant) {
        self.last = Some(now);
        self.healthy = false;
        self.successes = 0;
    }

    pub fn record(&mut self, now: Instant, passed: bool, probe: &StoredProbe) -> bool {
        self.last = Some(now);
        if passed {
            self.failures = 0;
            self.successes = self.successes.saturating_add(1);
            if self.successes >= probe.success_threshold.max(1) { self.healthy = true; }
        } else {
            self.successes = 0;
            self.failures = self.failures.saturating_add(1);
            if self.failures >= probe.failure_threshold.max(1) { self.healthy = false; }
        }
        self.failures >= probe.failure_threshold.max(1)
    }
}

#[derive(Clone)]
pub struct PodHealth {
    pub incarnation: String,
    pub started: Instant,
    pub startup_passed: Option<Instant>,
    pub startup: Check,
    pub liveness: Check,
    pub readiness: Check,
}

impl PodHealth {
    pub fn new(incarnation: String, now: Instant, age: Duration) -> Self {
        Self { incarnation, started: now.checked_sub(age).unwrap_or(now), startup_passed: None,
            startup: Check::default(), liveness: Check::default(), readiness: Check::default() }
    }
}

/// Pair Docker's age with the monotonic clock AFTER inspection completes.
/// Pairing it with a pre-I/O timestamp would subtract inspection latency twice
/// and could start probes before their configured initial delay.
pub fn observe_incarnation(
    inspect: impl FnOnce() -> Result<(String, Duration), String>,
) -> Result<(String, Duration, Instant), String> {
    let (incarnation, age) = inspect()?;
    Ok((incarnation, age, Instant::now()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn inspection_latency_cannot_advance_the_probe_origin() {
        let before = Instant::now();
        let (id, age, observed) = observe_incarnation(|| {
            std::thread::sleep(Duration::from_millis(80));
            Ok(("container:incarnation".into(), before.elapsed()))
        }).unwrap();
        let health = PodHealth::new(id, observed, age);
        assert!(health.started >= before);
        assert!(!health.liveness.due(before + Duration::from_secs(5) - Duration::from_millis(10), health.started, &spec()));
    }
    fn spec() -> StoredProbe {
        serde_json::from_value(serde_json::json!({"exec":["true"],"http_get":null,
            "initial_delay_seconds":5,"period_seconds":10,"failure_threshold":3,
            "success_threshold":2,"timeout_seconds":1})).unwrap()
    }
    #[test]
    fn initial_delay_and_period_are_independent_of_tick_frequency() {
        let p = spec(); let now = Instant::now(); let mut c = Check::default();
        assert!(!c.due(now + Duration::from_secs(4), now, &p));
        assert!(c.due(now + Duration::from_secs(5), now, &p));
        c.record(now + Duration::from_secs(5), true, &p);
        assert!(!c.due(now + Duration::from_secs(14), now, &p));
        assert!(c.due(now + Duration::from_secs(15), now, &p));
    }
    #[test]
    fn consecutive_failures_and_successes_reset_on_recovery() {
        let p = spec(); let now = Instant::now(); let mut c = Check::default();
        c.record(now, true, &p); assert!(!c.healthy);
        c.record(now, true, &p); assert!(c.healthy);
        assert!(!c.record(now, false, &p)); assert!(c.healthy);
        c.record(now, true, &p); // a success breaks the failure streak
        assert!(!c.record(now, false, &p));
        assert!(!c.record(now, false, &p));
        assert!(c.record(now, false, &p)); assert!(!c.healthy);
        c.record(now, true, &p); assert!(!c.healthy);
        c.record(now, true, &p); assert!(c.healthy);
    }
    #[test]
    fn infrastructure_unknown_removes_readiness_without_liveness_failure_or_cadence_change() {
        let p=spec();let now=Instant::now();let mut c=Check::default();
        assert!(!c.record(now,false,&p));
        let failures=c.failures;
        c.healthy=true;c.record_unknown(now+Duration::from_secs(1));
        assert_eq!(c.failures,failures);assert!(!c.healthy);
        assert!(!c.due(now+Duration::from_secs(10),now,&p));
        assert!(c.due(now+Duration::from_secs(11),now,&p));
        assert!(!c.record(now+Duration::from_secs(11),false,&p));
    }
    #[test]
    fn replacement_does_not_inherit_startup_or_readiness() {
        let now = Instant::now(); let mut old = PodHealth::new("old:started".into(), now, Duration::ZERO);
        old.startup_passed = Some(now); old.readiness.healthy = true;
        let fresh = PodHealth::new("new:started".into(), now, Duration::ZERO);
        assert_ne!(fresh.incarnation, old.incarnation);
        assert!(fresh.startup_passed.is_none()); assert!(!fresh.readiness.healthy);
    }
    #[test]
    fn immutable_health_identity_is_bounded_and_unambiguous() {
        let entry = HealthEntry { docker_name:"pod".into(),health:Default::default() };
        let raw = serde_json::to_string(&vec![entry.clone()]).unwrap();
        assert_eq!(decode_spec(&raw,"pod").unwrap(), vec![entry.clone()]);
        assert!(decode_spec(&raw,"other").is_err());
        assert!(decode_spec(&serde_json::to_string(&vec![entry.clone(),entry]).unwrap(),"pod").is_err());
        assert!(decode_spec(&" ".repeat(65537),"pod").is_err());
    }
}

