//! Reconcile Loop — the heart of Royak.
//!
//! Every N seconds:
//!   1. Read desired state (from stored specs)
//!   2. Read actual state (from Docker)
//!   3. Diff them
//!   4. Apply actions (create/start/stop/remove containers)
//!
//! This is what Kubernetes does with 2M lines of Go.
//! We do it in ~200 lines of Rust.

use crate::docker;
use crate::spec::{self, Resource};
use crate::brain::OrinBrain;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// Label we add to all Royak-managed containers
const MANAGED_LABEL: &str = "royak.managed";

/// Pipeline stage execution status
#[derive(Clone, PartialEq)]
pub enum StageStatus {
    Pending,
    Running,
    Succeeded,
    Failed,
    Skipped,
}

/// A stored pipeline definition
pub struct StoredPipeline {
    pub name: String,
    pub stages: Vec<StoredStage>,
    pub triggers: Vec<StoredTrigger>,
}

pub struct StoredStage {
    pub name: String,
    pub image: Option<String>,
    pub command: Option<Vec<String>>,
    pub action: Option<String>,
    pub file: Option<String>,
    pub context: Option<String>,      // action: build — repo name or path
    pub dockerfile: Option<String>,   // action: build — Dockerfile name
    pub tag: Option<String>,          // action: build — output image tag
    pub build_args: Vec<(String, String)>, // action: build — Dockerfile ARGs
    pub artifacts: Vec<String>,
    pub depends_on: Option<String>,
    pub env: Vec<String>,
    pub if_condition: Option<String>,  // "branch == main", "always", "failure"
    pub matrix_images: Vec<String>,     // run across these images
    #[allow(dead_code)]
    pub matrix_envs: Vec<String>,       // run with these env vars
}

pub struct StoredTrigger {
    pub trigger_type: String,
    pub path: Option<String>,
}

/// A pipeline run (execution instance)
#[allow(dead_code)]
pub struct PipelineRun {
    pub pipeline: String,
    pub run_id: u64,
    pub stage_status: Vec<(String, StageStatus)>,
    pub started_at: std::time::Instant,
}

impl PipelineRun {
    pub fn is_complete(&self) -> bool {
        self.stage_status.iter().all(|(_, s)| {
            matches!(s, StageStatus::Succeeded | StageStatus::Failed | StageStatus::Skipped)
        })
    }

    pub fn next_runnable(&self) -> Option<String> {
        for (name, status) in &self.stage_status {
            if *status != StageStatus::Pending { continue; }
            return Some(name.clone());
        }
        None
    }
}

/// Cluster node
#[allow(dead_code)]
pub struct ClusterNode {
    pub name: String,
    pub address: String,           // ip:port of the node's API server
    pub cpu_capacity: f32,         // total CPU %
    pub mem_capacity: f32,         // total RAM MB
    pub cpu_used: f32,
    pub mem_used: f32,
    pub pod_count: u32,
    pub status: NodeStatus,
    pub last_heartbeat: u64,       // unix timestamp
    pub neural_token: Vec<f32>,    // FP-TLS identity
    pub joined_at: u64,
}

#[derive(Clone, PartialEq)]
pub enum NodeStatus {
    Ready,
    NotReady,
    Draining,
}

/// Cluster configuration (replaces hardcoded values)
pub struct StoredConfig {
    // LLM
    pub llm_host: String,
    pub llm_model: String,
    pub llm_temperature: f32,
    // Alerts
    pub alert_webhook: Option<String>,
    pub alert_on_anomaly: bool,
    pub alert_on_restart: bool,
    pub alert_on_rollout: bool,
    // Runtime
    pub runtime: String,
    // Pause
    pub pause_default_idle: u64,
    pub pause_enabled: bool,
    // API
    pub api_port: u16,
}

impl Default for StoredConfig {
    fn default() -> Self {
        StoredConfig {
            llm_host: "http://localhost:11434".to_string(),
            llm_model: "llama3.2:3b".to_string(),
            llm_temperature: 0.3,
            alert_webhook: None,
            alert_on_anomaly: true,
            alert_on_restart: true,
            alert_on_rollout: false,
            runtime: "docker".to_string(),
            pause_default_idle: 300,
            pause_enabled: true,
            api_port: 6443,
        }
    }
}

/// Serverless Function (Lambda)
pub struct StoredFunction {
    pub name: String,
    pub image: String,                    // resolved runtime image
    pub command: Option<Vec<String>>,
    pub env: Vec<String>,
    pub http_triggers: Vec<String>,       // paths like "/api/process"
    pub webhook_triggers: Vec<String>,    // paths like "/hooks/order"
    pub schedule_triggers: Vec<String>,   // cron expressions
    pub timeout_secs: u64,
    pub memory_mb: u32,
    pub code: Option<String>,             // inline code
    pub container_id: Option<String>,     // running container (None = cold)
    pub invocations: u64,
    pub last_invoked: Option<u64>,        // unix timestamp
    pub state: FunctionState,
}

#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub enum FunctionState {
    Cold,       // no container, will start on invoke
    Warming,    // container starting
    Hot,        // container running, ready to serve
    Paused,     // container stopped, can restart fast
}

/// Git repository registration
pub struct StoredRepository {
    pub name: String,
    pub url: Option<String>,
    pub path: Option<String>,
    pub branch: String,
    pub secret_ref: Option<String>,
    pub pipeline: Option<String>,     // auto-trigger pipeline on change
    pub last_commit: Option<String>,  // track last seen commit hash
}

/// Stored desired state — replaces etcd (in-memory + persistent JSON)
pub struct DesiredWorld {
    pub deployments: HashMap<String, StoredDeployment>,
    pub daemonsets: HashMap<String, StoredDaemonSet>,
    pub jobs: HashMap<String, StoredJob>,
    pub cronjobs: HashMap<String, StoredCronJob>,
    pub hpas: HashMap<String, StoredHPA>,
    pub services: HashMap<String, StoredService>,
    pub restart_count: HashMap<String, u32>,  // pod name → restart count (CrashLoopBackOff)
    pub startup_ok: std::collections::HashSet<String>,  // pods whose startup probe passed (runtime-only)
    pub netpol_applied: std::collections::HashSet<String>,  // pods with L4 iptables applied (runtime-only)
    pub ingress_classes: std::collections::HashSet<String>,  // registered IngressClass names
    pub limit_ranges: HashMap<String, StoredLimitRange>,  // namespace → defaults
    // Last full manifest per resource ("Deployment/{ns}/{name}") — the source
    // kubectl's client-side apply diffs against (carries last-applied-
    // configuration annotations). Persisted.
    pub manifests: HashMap<String, serde_json::Value>,
    pub ingresses: HashMap<String, StoredIngress>,
    pub network_policies: HashMap<String, StoredNetworkPolicy>,
    pub configmaps: HashMap<String, StoredConfigMap>,
    pub secrets: HashMap<String, StoredSecret>,
    pub pvs: HashMap<String, StoredPV>,
    pub pvcs: HashMap<String, StoredPVC>,
    pub namespaces: Vec<String>,
    #[allow(dead_code)]
    pub pod_health: HashMap<String, PodHealth>,
    pub pending_rollouts: HashMap<String, RolloutState>,
    pub pipelines: HashMap<String, StoredPipeline>,
    pub pipeline_runs: Vec<PipelineRun>,
    pub repositories: HashMap<String, StoredRepository>,
    pub functions: HashMap<String, StoredFunction>,
    pub config: StoredConfig,
    pub nodes: HashMap<String, ClusterNode>,
    pub guards: HashMap<String, Guard>,
    pub operators: HashMap<String, Operator>,
    pub rbac_roles: HashMap<String, RbacRole>,
    pub custom_resources: HashMap<String, CustomResource>,
    pub admission_webhooks: HashMap<String, AdmissionWebhook>,
    pub events: Vec<ClusterEvent>,
    // v0.2 network security:
    pub cluster_ca: Option<crate::net_security::ClusterCA>,
    pub network_audit: Vec<crate::net_security::NetworkAuditEntry>,
    pub net_tracker: crate::net_security::NetworkPatternTracker,
    // v0.2 resource quotas + cert lifecycle:
    pub resource_quotas: HashMap<String, StoredResourceQuota>,
    pub pod_certs: HashMap<String, PodCertStatus>,
    pub storage_classes: HashMap<String, StoredStorageClass>,
}

// ─── RBAC: Role-Based Access Control ───

#[allow(dead_code)]
#[derive(Clone)]
pub struct AdmissionWebhook {
    pub name: String,
    /// HTTP(S) endpoint that receives an AdmissionReview POST.
    pub url: String,
    /// Kinds this webhook validates ("*" = all).
    pub kinds: Vec<String>,
    /// If the webhook is unreachable: "Fail" (deny) or "Ignore" (allow).
    pub failure_policy: String,
}

pub struct StoredLimitRange {
    pub name: String,
    pub namespace: String,
    pub default_cpu: Option<String>,
    pub default_mem: Option<String>,
    pub request_cpu: Option<String>,
    pub request_mem: Option<String>,
}

#[derive(Clone)]
pub struct RbacRole {
    pub name: String,
    pub rules: Vec<RbacRule>,
}

#[allow(dead_code)]
#[derive(Clone)]
pub struct RbacRule {
    pub resources: Vec<String>,     // ["pods", "deployments", "*"]
    pub verbs: Vec<String>,         // ["get", "list", "create", "delete", "*"]
    pub namespaces: Vec<String>,    // ["default", "*"]
}

impl DesiredWorld {
    pub fn check_rbac(&self, role: &str, resource: &str, verb: &str, namespace: &str) -> bool {
        // No roles defined = allow all (open by default).
        if self.rbac_roles.is_empty() { return true; }
        // "admin" is a built-in cluster-superuser: always allowed UNLESS an
        // operator has explicitly defined an "admin" role to restrict it.
        // Without this, defining any Role/RoleBinding would lock out the
        // default (headerless) admin identity — check would find no "admin"
        // role and deny everything.
        if role == "admin" && !self.rbac_roles.contains_key("admin") {
            return true;
        }
        match self.rbac_roles.get(role) {
            Some(r) => r.rules.iter().any(|rule| {
                let res_ok = rule.resources.iter().any(|r| r == "*" || r == resource);
                let verb_ok = rule.verbs.iter().any(|v| v == "*" || v == verb);
                let ns_ok = rule.namespaces.iter().any(|n| n == "*" || n == namespace);
                res_ok && verb_ok && ns_ok
            }),
            None => false,
        }
    }
}

// ─── Resource Limits ───

#[derive(Clone)]
pub struct ResourceLimits {
    pub cpu_request: Option<f32>,    // CPU cores requested (0.5 = half core)
    pub cpu_limit: Option<f32>,      // CPU cores max
    pub mem_request: Option<u64>,    // Memory MB requested
    pub mem_limit: Option<u64>,      // Memory MB max
}

// ─── Deployment Strategies (Canary, Blue-Green) ───

#[derive(Clone)]
pub enum DeployStrategy {
    RollingUpdate { max_surge: u32, max_unavailable: u32 },
    Canary { weight: u32, steps: Vec<CanaryStep> },       // gradual rollout
    BlueGreen { active: String },                          // instant switch
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct CanaryStep {
    pub weight: u32,        // percentage of traffic (10, 25, 50, 100)
    pub pause_seconds: u64, // wait between steps
}


// ─── Cluster Events (kubectl get events) ───

pub struct ClusterEvent {
    pub kind: String,        // "Pod", "Deployment", "Pipeline"
    pub object: String,      // resource name
    pub reason: String,      // "Created", "Scaled", "Unhealthy", "Triggered"
    pub message: String,
    pub event_type: String,  // "Normal", "Warning"
    pub count: u32,
    pub first_seen: String,
    pub last_seen: String,
}

impl DesiredWorld {
    pub fn record_event(&mut self, kind: &str, object: &str, reason: &str, message: &str, event_type: &str) {
        let now = {
            let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
            format!("{}", secs)
        };
        // Deduplicate: if same object+reason exists, increment count
        if let Some(existing) = self.events.iter_mut().find(|e| e.object == object && e.reason == reason) {
            existing.count += 1;
            existing.last_seen = now;
            existing.message = message.to_string();
            return;
        }
        self.events.push(ClusterEvent {
            kind: kind.to_string(), object: object.to_string(),
            reason: reason.to_string(), message: message.to_string(),
            event_type: event_type.to_string(), count: 1,
            first_seen: now.clone(), last_seen: now,
        });
        // Keep max 200 events
        if self.events.len() > 200 { self.events.drain(..100); }
    }
}

// ─── Neural Guards (auto-remediation: brain detect → action) ───

#[allow(dead_code)]
pub struct Guard {
    pub name: String,
    pub rules: Vec<GuardRule>,
    pub hooks: HashMap<String, String>,
}

#[allow(dead_code)]
pub struct GuardRule {
    pub when: String,    // "pod_crash", "high_memory", "high_cpu", "anomaly"
    pub action: String,  // "restart", "scale_up", "exec", "alert"
    pub params: HashMap<String, String>,
}

// ─── AI-First Operators (real K8s-style: CRD + provision + lifecycle) ───
//
// Operator = "DevOps engineer for a specific app, in YAML + hooks"
//
// 1. Defines a Custom Resource (CRD): kind: PostgresCluster
// 2. Provisions pods/services when CR is applied
// 3. Lifecycle hooks: on_create, on_crash, on_scale, on_backup, on_upgrade
// 4. Brain integration: ANOMALY/PREDICT trigger operator-specific actions
//
// K8s operator = 5000 lines Go. Royak operator = YAML + hooks + brain.

#[allow(dead_code)]
pub struct Operator {
    pub name: String,
    pub custom_kind: String,                       // "PostgresCluster", "RedisCluster", etc.
    pub provision: Vec<OperatorComponent>,          // what to create when CR is applied
    pub hooks: HashMap<String, String>,             // lifecycle: on_create, on_crash, on_scale → shell cmd
    pub rules: Vec<GuardRule>,                      // brain-triggered rules specific to this operator
}

#[allow(dead_code)]
pub struct OperatorComponent {
    pub role: String,           // "primary", "replica", "sentinel", "proxy"
    pub image: String,          // "postgres:16", "redis:7-alpine"
    pub replicas: u32,          // how many of this role
    pub env: Vec<String>,       // environment variables
    pub volumes: Vec<String>,   // volume mounts (host:container)
    pub ports: Vec<u16>,        // exposed ports
}

/// Custom Resource instance (created by user, managed by operator)
#[allow(dead_code)]
pub struct CustomResource {
    pub name: String,
    pub kind: String,           // must match an operator's custom_kind
    pub namespace: String,
    pub spec: serde_json::Value, // user-provided spec (replicas, version, etc.)
    pub status: CRStatus,
}

#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub enum CRStatus {
    Pending,
    Provisioning,
    Running,
    Failed,
}

/// Reconcile custom resources: for each CR, find its operator and provision
pub fn reconcile_operators(desired: &mut DesiredWorld, log: &mut Vec<String>) {
    let cr_names: Vec<String> = desired.custom_resources.keys().cloned().collect();

    for cr_name in &cr_names {
        let (kind, ns, spec, status) = {
            let cr = &desired.custom_resources[cr_name];
            (cr.kind.clone(), cr.namespace.clone(), cr.spec.clone(), cr.status.clone())
        };

        // Find the operator for this kind
        let op = desired.operators.values()
            .find(|o| o.custom_kind == kind);

        let op = match op {
            Some(o) => o,
            None => {
                log.push(format!("  [CR] {kind}/{cr_name}: no operator registered for kind '{kind}'"));
                continue;
            }
        };

        // Running CRs: verify components are still healthy, re-provision if crashed
        if status == CRStatus::Running || status == CRStatus::Provisioning {
            let mut all_healthy = true;
            for component in &op.provision {
                let dep_name = format!("{cr_name}-{}", component.role);
                if !desired.deployments.contains_key(&dep_name) {
                    log.push(format!("  [operator/{}] {kind}/{cr_name}: component {dep_name} MISSING — re-provisioning", op.name));
                    all_healthy = false;
                    // Reset to Pending to trigger re-provision
                    if let Some(cr) = desired.custom_resources.get_mut(cr_name) {
                        cr.status = CRStatus::Pending;
                    }
                    break;
                }
            }
            if all_healthy && status == CRStatus::Provisioning {
                // Promotion: all deployments exist → mark as Running
                if let Some(cr) = desired.custom_resources.get_mut(cr_name) {
                    cr.status = CRStatus::Running;
                    log.push(format!("  [operator/{}] {kind}/{cr_name}: promoted to Running ✓", op.name));
                }
            }
            continue;
        }

        if status != CRStatus::Pending { continue; }

        log.push(format!("  [operator/{}] provisioning {kind}/{cr_name}...", op.name));

        // Get replicas from CR spec (override operator defaults)
        let cr_replicas = spec.get("replicas").and_then(|r| r.as_u64()).unwrap_or(0) as u32;

        // Provision each component
        for component in &op.provision {
            let replicas = if cr_replicas > 0 && component.role == "replica" {
                cr_replicas.saturating_sub(1) // -1 because primary counts
            } else {
                component.replicas
            };

            let dep_name = format!("{cr_name}-{}", component.role);
            let mut env = component.env.clone();

            // Inject CR spec values as env vars
            if let Some(obj) = spec.as_object() {
                for (k, v) in obj {
                    if let Some(s) = v.as_str() {
                        env.push(format!("CR_{}={}", k.to_uppercase(), s));
                    }
                }
            }

            // Create deployment for this component
            let containers = vec![StoredContainer {
                name: component.role.clone(),
                image: component.image.clone(),
                command: None,
                env: env.clone(),
                env_from_configmaps: vec![], env_from_secrets: vec![],
                volumes: vec![],
                liveness_probe: None,
                startup_probe: None,
                readiness_probe: None,
            }];

            desired.deployments.insert(dep_name.clone(), StoredDeployment {
                name: dep_name.clone(),
                namespace: ns.clone(),
                replicas: if component.role == "primary" { 1 } else { replicas },
                image: component.image.clone(),
                previous_image: None,
                command: None,
                env,
                init_containers: Vec::new(),
                containers,
                resource_limits: None,
                strategy: None,
                pause_after_idle: None,
                paused: false,
                idle_since: None,
                stateful: false,
                owner_ref: Some(cr_name.clone()),
            });
            log.push(format!("    [{}] {} × {} ✓", component.role, component.image, if component.role == "primary" { 1 } else { replicas }));
        }

        // Run on_create hook if defined (safe: no shell injection)
        if let Some(hook) = op.hooks.get("on_create") {
            let output = safe_exec_hook(hook);
            if !output.is_empty() {
                log.push(format!("    [hook/on_create] {output}"));
            }
        }

        // Mark as provisioning
        if let Some(cr) = desired.custom_resources.get_mut(cr_name) {
            cr.status = CRStatus::Provisioning;
        }
    }
}

/// Cascade-delete selection (pure): names of deployments owned by `cr_name`.
///
/// A deployment is owned iff its `owner_ref` equals `Some(cr_name)`. Deployments
/// with no owner ref (user-created) are never selected, so unrelated workloads
/// are left untouched when a CustomResource is deleted.
pub fn deployments_owned_by(desired: &DesiredWorld, cr_name: &str) -> Vec<String> {
    desired.deployments.values()
        .filter(|d| d.owner_ref.as_deref() == Some(cr_name))
        .map(|d| d.name.clone())
        .collect()
}

/// Rolling update state
#[allow(dead_code)]
pub struct RolloutState {
    pub old_image: String,
    pub new_image: String,
    pub total_replicas: u32,
    pub old_pods: VecDeque<String>,  // container IDs to remove
    pub new_pods_created: u32,
}

pub struct StoredService {
    pub name: String,
    pub namespace: String,
    pub selector: HashMap<String, String>,
    pub ports: Vec<ServicePort>,
    pub service_type: String,  // ClusterIP, NodePort, LoadBalancer
}

pub struct ServicePort {
    pub port: u16,
    pub target_port: u16,
    pub protocol: String,
    pub node_port: Option<u16>,
}

pub struct StoredIngress {
    pub name: String,
    pub namespace: String,
    pub rules: Vec<IngressRule>,
    /// spec.ingressClassName, if set. Royak has a single built-in controller
    /// (the default class "royak") that serves every Ingress, so this is
    /// honored for round-trip/compatibility rather than controller selection.
    pub ingress_class: Option<String>,
}

pub struct IngressRule {
    pub host: String,            // e.g. "app.example.com"
    pub paths: Vec<IngressPath>,
}

pub struct IngressPath {
    pub path: String,            // e.g. "/api"
    pub service: String,         // backend service name
    pub port: u16,               // backend port
}

/// Resource quota — namespace-level limits (CPU, memory, pod count)
pub struct StoredResourceQuota {
    pub name: String,
    pub namespace: String,
    pub hard_cpu: Option<f32>,        // max CPU cores (e.g. 4.0)
    pub hard_memory: Option<u64>,     // max memory MB (e.g. 8192)
    pub hard_pods: Option<u32>,       // max pod count
    pub hard_services: Option<u32>,
    pub hard_configmaps: Option<u32>,
    pub hard_secrets: Option<u32>,
}

/// Pod certificate tracking — for mTLS cert lifecycle
#[allow(dead_code)]
pub struct PodCertStatus {
    pub pod_name: String,
    pub namespace: String,
    pub issued_at: u64,       // unix timestamp
    pub expires_at: u64,      // unix timestamp
    pub fingerprint: String,
    pub revoked: bool,
}

pub struct StoredNetworkPolicy {
    pub name: String,
    pub namespace: String,
    pub pod_selector: String,    // which pods this applies to
    pub ingress_allow: Vec<String>, // allowed source pods/namespaces
    pub egress_allow: Vec<String>,  // allowed destination pods/namespaces
    // v0.2 enhanced security:
    pub ingress_ports: Vec<u16>,    // allowed ingress ports (empty = all)
    pub egress_ports: Vec<u16>,     // allowed egress ports (empty = all)
    pub internal: bool,             // block all external/internet traffic
    pub mtls_required: bool,        // require mTLS for matched pods
    pub deny_all: bool,             // deny all traffic not explicitly allowed
}

#[allow(dead_code)]
pub struct StoredHPA {
    pub name: String,
    pub deployment: String,    // target deployment
    pub min_replicas: u32,
    pub max_replicas: u32,
    pub target_cpu: f32,       // target CPU % (e.g. 70.0)
    pub history: Vec<f32>,     // CPU history for neural prediction
    pub last_scaled: Option<u64>, // unix ts of last scale action (stabilization window)
}

/// Stabilization/cooldown window (seconds). After scaling an HPA's target we
/// hold it for this long before scaling again, so CPU crossing the threshold on
/// consecutive ticks can't thrash the deployment up and down. Symmetric window
/// (K8s uses 300s down / 0s up; a single ~60s window is simpler for this tool).
pub const HPA_STABILIZATION_SECS: u64 = 60;

/// Pure scaling decision for a single HPA. Returns the new replica count, or
/// `None` to hold (either no threshold crossed, or we're still inside the
/// stabilization window). Kept side-effect-free so it is unit-testable.
///
/// `secs_since_last_scale` should be a large value (e.g. `u64::MAX`) when the
/// HPA has never scaled, so the cooldown never blocks the first action.
pub fn hpa_decision(
    current_replicas: u32,
    avg_cpu: f32,
    target_cpu: f32,
    min: u32,
    max: u32,
    secs_since_last_scale: u64,
    stabilization_secs: u64,
) -> Option<u32> {
    // Desired replica count from CPU thresholds (clamped to [min, max]).
    let desired = if avg_cpu > target_cpu && current_replicas < max {
        let ratio = avg_cpu / target_cpu;
        Some(((current_replicas as f32 * ratio).ceil() as u32).min(max))
    } else if avg_cpu < target_cpu * 0.5 && current_replicas > min {
        Some((current_replicas - 1).max(min))
    } else {
        None
    };

    match desired {
        // Only act on a real change, and only once the cooldown has elapsed.
        Some(target) if target != current_replicas => {
            if secs_since_last_scale < stabilization_secs {
                None // inside stabilization window → hold (anti-thrash)
            } else {
                Some(target)
            }
        }
        _ => None,
    }
}

pub struct StoredDaemonSet {
    pub name: String,
    pub namespace: String,
    pub container: StoredContainer,
}

#[allow(dead_code)]
pub struct StoredJob {
    pub name: String,
    pub namespace: String,
    pub container: StoredContainer,
    pub completions: u32,
    pub status: JobStatus,
}

#[allow(dead_code)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

pub struct StoredCronJob {
    pub name: String,
    pub namespace: String,
    pub schedule: String,       // cron format: "*/5 * * * *"
    pub container: StoredContainer,
    pub last_run: Option<u64>,  // unix timestamp
}

pub struct StoredDeployment {
    pub name: String,
    pub namespace: String,
    pub replicas: u32,
    pub init_containers: Vec<StoredContainer>,
    pub containers: Vec<StoredContainer>,
    // Keep legacy single-container fields for compatibility
    pub image: String,
    pub previous_image: Option<String>,  // for rollback after completion
    pub command: Option<Vec<String>>,
    pub env: Vec<String>,
    // Resource limits
    pub resource_limits: Option<ResourceLimits>,
    // Deployment strategy
    pub strategy: Option<DeployStrategy>,
    // Pause/hibernate settings
    pub pause_after_idle: Option<u64>,    // seconds of idle before pause (0 = never)
    pub paused: bool,                      // currently hibernated?
    pub idle_since: Option<u64>,           // tick when idle started
    // StatefulSet semantics: lowest-missing-ordinal creation (one per tick,
    // previous must be running), highest-ordinal-first scale-down, and per-
    // ordinal volumes ("vct:" host prefixes resolved at pod creation).
    pub stateful: bool,
    // Cascade-delete: name of the CustomResource that provisioned this
    // deployment (owner reference). None = user-owned, never GC'd on CR delete.
    pub owner_ref: Option<String>,
}

pub struct StoredContainer {
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub env: Vec<String>,
    pub env_from_configmaps: Vec<String>,  // ConfigMap names to inject as env
    pub env_from_secrets: Vec<String>,     // Secret names to inject as env
    pub volumes: Vec<(String, String)>,    // (host_path, container_path)
    pub liveness_probe: Option<StoredProbe>,
    pub readiness_probe: Option<StoredProbe>,
    pub startup_probe: Option<StoredProbe>,
}

/// Stored health probe configuration
#[derive(Clone)]
#[allow(dead_code)]
pub struct StoredProbe {
    pub http_get: Option<(String, u16)>,   // (path, port)
    pub exec: Option<Vec<String>>,          // command
    pub initial_delay_seconds: u64,
    pub period_seconds: u64,
    pub failure_threshold: u32,
}

/// Per-pod health tracking
#[allow(dead_code)]
pub struct PodHealth {
    pub created_at: std::time::Instant,
    pub liveness_failures: u32,
    pub readiness_failures: u32,
    pub ready: bool,
}

pub struct StoredConfigMap {
    pub name: String,
    pub namespace: String,
    pub data: HashMap<String, String>,
}

pub struct StoredSecret {
    pub name: String,
    pub namespace: String,
    pub data: HashMap<String, String>,
}

pub struct StoredPV {
    pub name: String,
    pub capacity: String,        // "10Gi", "500Mi"
    pub storage_class: String,   // "local", "nfs", "neurofs"
    pub host_path: String,       // actual path on host
    pub access_mode: String,     // "ReadWriteOnce", "ReadWriteMany"
    pub status: PVStatus,
    pub bound_to: Option<String>, // PVC name
}

#[derive(Clone, PartialEq)]
#[allow(dead_code)]
pub enum PVStatus {
    Available,
    Bound,
    Released,
}

pub struct StoredPVC {
    pub name: String,
    pub namespace: String,
    pub storage_class: String,
    pub requested: String,       // "5Gi"
    pub access_mode: String,
    pub bound_pv: Option<String>, // PV name
}

/// StorageClass — dynamic volume provisioner
pub struct StoredStorageClass {
    pub name: String,
    pub provisioner: String,        // "royak/host-path", "royak/tmpfs"
    pub host_path_prefix: String,   // e.g. "/data/royak/volumes"
    pub reclaim_policy: String,     // "Delete" or "Retain"
    pub provisioned_count: u32,
}

impl DesiredWorld {
    pub fn new() -> Self {
        DesiredWorld {
            deployments: HashMap::new(),
            daemonsets: HashMap::new(),
            jobs: HashMap::new(),
            cronjobs: HashMap::new(),
            hpas: HashMap::new(),
            services: HashMap::new(),
            restart_count: HashMap::new(),
            startup_ok: std::collections::HashSet::new(),
            netpol_applied: std::collections::HashSet::new(),
            ingress_classes: std::collections::HashSet::new(),
            limit_ranges: HashMap::new(),
            manifests: HashMap::new(),
            ingresses: HashMap::new(),
            network_policies: HashMap::new(),
            configmaps: HashMap::new(),
            secrets: HashMap::new(),
            pvs: HashMap::new(),
            pvcs: HashMap::new(),
            namespaces: vec!["default".to_string()],
            pod_health: HashMap::new(),
            pending_rollouts: HashMap::new(),
            pipelines: HashMap::new(),
            pipeline_runs: Vec::new(),
            repositories: HashMap::new(),
            functions: HashMap::new(),
            config: StoredConfig::default(),
            nodes: HashMap::new(),
            guards: HashMap::new(),
            operators: HashMap::new(),
            rbac_roles: HashMap::new(),
            custom_resources: HashMap::new(),
            admission_webhooks: HashMap::new(),
            events: Vec::new(),
            cluster_ca: None,
            network_audit: Vec::new(),
            net_tracker: crate::net_security::NetworkPatternTracker::new(),
            resource_quotas: HashMap::new(),
            pod_certs: HashMap::new(),
            storage_classes: HashMap::new(),
        }
    }

    /// Apply a resource spec
    /// Container ports that must be published to ephemeral host ports because a
    /// NodePort or LoadBalancer service selects this deployment. The ServiceLB
    /// proxy forwards service traffic to those ephemeral ports — works even
    /// where container IPs are not host-routable (macOS Docker VMs).
    pub fn nodeport_publish_ports(&self, deployment: &str) -> Vec<u16> {
        let mut ports: Vec<u16> = self.services.values()
            .filter(|s| (s.service_type == "NodePort" || s.service_type == "LoadBalancer")
                && s.selector.get("app").map(|a| a.as_str()) == Some(deployment))
            .flat_map(|s| s.ports.iter().map(|p| p.target_port))
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    pub fn apply(&mut self, resource: &Resource) -> Result<String, String> {
        match resource.kind.as_str() {
            // ReplicaSet gets Deployment semantics (replicas + template, no
            // rollout history of its own). A bare Pod becomes a single-replica
            // deployment — see spec::as_deployment. StatefulSet adds ordered
            // ordinals + per-ordinal volumes on top of the same machinery.
            "Deployment" | "ReplicaSet" | "Pod" | "StatefulSet" => {
                let dep = match spec::as_deployment(resource) {
                    Some(d) => d,
                    None => {
                        if let Some(sv) = &resource.spec {
                            let e = serde_yaml::from_value::<spec::DeploymentSpec>(sv.clone());
                            return Err(format!("Deployment parse: {:?}", e.err()));
                        }
                        return Err("No spec".to_string());
                    }
                };
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());

                // StatefulSet: volumeClaimTemplates map to per-ordinal host dirs,
                // resolved at pod-creation time (same mechanism as the "pvc:"
                // prefix below) — every ordinal keeps its own storage.
                let mut vct_map: HashMap<String, String> = HashMap::new();
                if resource.kind == "StatefulSet" {
                    for vct in dep.volume_claim_templates.as_deref().unwrap_or(&[]) {
                        vct_map.insert(vct.metadata.name.clone(), format!("vct:{}", vct.metadata.name));
                    }
                }

                // Build volume map from pod-level volumes
                let mut volume_map: HashMap<String, String> = dep.template.spec.volumes.as_ref()
                    .map(|vols| vols.iter().filter_map(|v| {
                        if let Some(hp) = &v.host_path {
                            if !validate_path(&hp.path) {
                                eprintln!("  ⚠ [security] blocked unsafe hostPath: {}", hp.path);
                                None
                            } else {
                                Some((v.name.clone(), hp.path.clone()))
                            }
                        } else if v.empty_dir.is_some() {
                            let tmp = format!("/tmp/royak-{}-{}", name, v.name);
                            std::fs::create_dir_all(&tmp).ok();
                            Some((v.name.clone(), tmp))
                        } else if let Some(cm) = &v.config_map {
                            // Materialised at pod-creation time (data may change)
                            Some((v.name.clone(), format!("cmv:{}", cm.name)))
                        } else if let Some(sv) = &v.secret {
                            Some((v.name.clone(), format!("sev:{}", sv.secret_name)))
                        } else if let Some(pvc_ref) = &v.pvc {
                            // Resolve PVC → PV → host path
                            self.pvcs.get(&pvc_ref.claim_name)
                                .and_then(|pvc| pvc.bound_pv.as_ref())
                                .and_then(|pv_name| self.pvs.get(pv_name))
                                .map(|pv| (v.name.clone(), pv.host_path.clone()))
                        } else {
                            None
                        }
                    }).collect())
                    .unwrap_or_default();
                volume_map.extend(vct_map);

                // Parse ALL containers in the pod
                let stored_containers: Vec<StoredContainer> = dep.template.spec.containers.iter().map(|c| {
                    let env: Vec<String> = c.env.as_ref()
                        .map(|vars| vars.iter().filter_map(|e| {
                            e.value.as_ref().map(|v| format!("{}={}", e.name, v))
                        }).collect())
                        .unwrap_or_default();

                    // Resolve volumeMounts → (host_path, container_path)
                    let volumes: Vec<(String, String)> = c.volume_mounts.as_ref()
                        .map(|mounts| mounts.iter().filter_map(|m| {
                            volume_map.get(&m.name).map(|host| (host.clone(), m.mount_path.clone()))
                        }).collect())
                        .unwrap_or_default();

                    // Parse health probes
                    let liveness_probe = c.liveness_probe.as_ref().map(|p| StoredProbe {
                        http_get: p.http_get.as_ref().map(|h| (h.path.clone(), h.port)),
                        exec: p.exec.as_ref().map(|e| e.command.clone()),
                        initial_delay_seconds: p.initial_delay_seconds,
                        period_seconds: p.period_seconds,
                        failure_threshold: p.failure_threshold,
                    });
                    let readiness_probe = c.readiness_probe.as_ref().map(|p| StoredProbe {
                        http_get: p.http_get.as_ref().map(|h| (h.path.clone(), h.port)),
                        exec: p.exec.as_ref().map(|e| e.command.clone()),
                        initial_delay_seconds: p.initial_delay_seconds,
                        period_seconds: p.period_seconds,
                        failure_threshold: p.failure_threshold,
                    });

                    // Parse envFrom references
                    let env_from_configmaps: Vec<String> = c.env_from.as_ref()
                        .map(|refs| refs.iter().filter_map(|r| r.config_map_ref.as_ref().map(|cm| cm.name.clone())).collect())
                        .unwrap_or_default();
                    let env_from_secrets: Vec<String> = c.env_from.as_ref()
                        .map(|refs| refs.iter().filter_map(|r| r.secret_ref.as_ref().map(|s| s.name.clone())).collect())
                        .unwrap_or_default();

                    let startup_probe = c.startup_probe.as_ref().map(|p| StoredProbe {
                        http_get: p.http_get.as_ref().map(|h| (h.path.clone(), h.port)),
                        exec: p.exec.as_ref().map(|e| e.command.clone()),
                        initial_delay_seconds: p.initial_delay_seconds,
                        period_seconds: p.period_seconds,
                        failure_threshold: p.failure_threshold,
                    });
                    StoredContainer {
                        name: c.name.clone(),
                        image: c.image.clone(),
                        command: c.command.clone(),
                        env,
                        env_from_configmaps,
                        env_from_secrets,
                        volumes,
                        liveness_probe,
                        readiness_probe,
                        startup_probe,
                    }
                }).collect();

                // Parse init containers (run before main, must complete)
                let init_containers: Vec<StoredContainer> = dep.template.spec.init_containers.as_ref()
                    .map(|inits| inits.iter().map(|c| {
                        let env: Vec<String> = c.env.as_ref()
                            .map(|vars| vars.iter().filter_map(|e| {
                                e.value.as_ref().map(|v| format!("{}={}", e.name, v))
                            }).collect())
                            .unwrap_or_default();
                        StoredContainer {
                            name: c.name.clone(), image: c.image.clone(),
                            command: c.command.clone(), env, volumes: vec![],
                env_from_configmaps: vec![], env_from_secrets: vec![],
                            liveness_probe: None, readiness_probe: None, startup_probe: None,
                        }
                    }).collect())
                    .unwrap_or_default();

                let first = match stored_containers.first() {
                    Some(c) => c,
                    None => return Err("Deployment has no containers".to_string()),
                };
                let container_count = stored_containers.len();
                let init_count = init_containers.len();
                let new_image = first.image.clone();
                let replicas = dep.replicas.unwrap_or(1);

                // Detect image change → trigger rolling update
                let rolling = if let Some(existing) = self.deployments.get(&name) {
                    if existing.image != new_image && !existing.image.is_empty() {
                        Some(existing.image.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };

                // Parse resource limits from first container spec
                let resource_limits = dep.template.spec.containers.first()
                    .and_then(|c| c.resources.as_ref())
                    .map(|r| {
                        let parse_cpu = |s: &str| -> f32 {
                            if s.ends_with('m') { s.trim_end_matches('m').parse::<f32>().unwrap_or(0.0) / 1000.0 }
                            else { s.parse::<f32>().unwrap_or(0.0) }
                        };
                        let parse_mem = |s: &str| -> u64 {
                            if s.ends_with("Gi") { s.trim_end_matches("Gi").parse::<u64>().unwrap_or(0) * 1024 }
                            else if s.ends_with("Mi") { s.trim_end_matches("Mi").parse::<u64>().unwrap_or(0) }
                            else if s.ends_with('G') { s.trim_end_matches('G').parse::<u64>().unwrap_or(0) * 1024 }
                            else if s.ends_with('M') { s.trim_end_matches('M').parse::<u64>().unwrap_or(0) }
                            else { s.parse::<u64>().unwrap_or(0) }
                        };
                        ResourceLimits {
                            cpu_request: r.requests.as_ref().and_then(|req| req.get("cpu")).map(|s| parse_cpu(s)),
                            cpu_limit: r.limits.as_ref().and_then(|lim| lim.get("cpu")).map(|s| parse_cpu(s)),
                            mem_request: r.requests.as_ref().and_then(|req| req.get("memory")).map(|s| parse_mem(s)),
                            mem_limit: r.limits.as_ref().and_then(|lim| lim.get("memory")).map(|s| parse_mem(s)),
                        }
                    });

                // LimitRange defaults: deployments without explicit limits
                // inherit the namespace defaults (K8s LimitRange semantics).
                let resource_limits = resource_limits.or_else(|| {
                    self.limit_ranges.get(&ns).map(|lr| {
                        let parse_cpu = |s: &str| -> f32 {
                            if s.ends_with('m') { s.trim_end_matches('m').parse::<f32>().unwrap_or(0.0) / 1000.0 }
                            else { s.parse::<f32>().unwrap_or(0.0) }
                        };
                        let parse_mem = |s: &str| -> u64 {
                            if s.ends_with("Gi") { s.trim_end_matches("Gi").parse::<u64>().unwrap_or(0) * 1024 }
                            else if s.ends_with("Mi") { s.trim_end_matches("Mi").parse::<u64>().unwrap_or(0) }
                            else { s.parse::<u64>().unwrap_or(0) }
                        };
                        ResourceLimits {
                            cpu_request: lr.request_cpu.as_deref().map(parse_cpu),
                            cpu_limit: lr.default_cpu.as_deref().map(parse_cpu),
                            mem_request: lr.request_mem.as_deref().map(parse_mem),
                            mem_limit: lr.default_mem.as_deref().map(parse_mem),
                        }
                    })
                });

                // Save previous image for rollback
                let previous_image = self.deployments.get(&name).map(|d| d.image.clone());

                self.deployments.insert(name.clone(), StoredDeployment {
                    name: name.clone(),
                    namespace: ns,
                    replicas,
                    image: new_image.clone(),
                    previous_image,
                    command: first.command.clone(),
                    env: first.env.clone(),
                    init_containers,
                    containers: stored_containers,
                    resource_limits,
                    strategy: dep.strategy.as_ref().map(|s| {
                        match s.strategy_type.as_str() {
                            "Canary" => DeployStrategy::Canary {
                                weight: s.weight.unwrap_or(10),
                                steps: vec![
                                    CanaryStep { weight: s.weight.unwrap_or(10), pause_seconds: 30 },
                                    CanaryStep { weight: 50, pause_seconds: 60 },
                                    CanaryStep { weight: 100, pause_seconds: 0 },
                                ],
                            },
                            "BlueGreen" => DeployStrategy::BlueGreen {
                                active: s.active.clone().unwrap_or("green".to_string()),
                            },
                            _ => DeployStrategy::RollingUpdate {
                                max_surge: s.max_surge.unwrap_or(1),
                                max_unavailable: s.max_unavailable.unwrap_or(0),
                            },
                        }
                    }),
                    pause_after_idle: None,
                    paused: false,
                    idle_since: None,
                    stateful: resource.kind == "StatefulSet",
                    owner_ref: None,
                });

                if let Some(old_image) = rolling {
                    self.pending_rollouts.insert(name.clone(), RolloutState {
                        old_image: old_image.clone(),
                        new_image: new_image.clone(),
                        total_replicas: replicas,
                        old_pods: VecDeque::new(),
                        new_pods_created: 0,
                    });
                    let suffix = if container_count > 1 { format!(" ({container_count} containers)") } else { String::new() };
                    let init_suffix = if init_count > 0 { format!(", {init_count} init") } else { String::new() };
                    Ok(format!("deployment/{name} rolling update{suffix}{init_suffix}: {old_image} → {new_image}"))
                } else {
                    let suffix = if container_count > 1 { format!(" ({container_count} containers)") } else { String::new() };
                    let init_suffix = if init_count > 0 { format!(", {init_count} init") } else { String::new() };
                    let kind_label = match resource.kind.as_str() {
                        "Pod" => "pod (as 1-replica deployment)",
                        "ReplicaSet" => "replicaset (as deployment)",
                        "StatefulSet" => "statefulset (ordered, per-ordinal volumes)",
                        _ => "deployment",
                    };
                    Ok(format!("{kind_label}/{name} applied{suffix}{init_suffix}"))
                }
            }
            "ConfigMap" => {
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let mut data = HashMap::new();
                // K8s-standard top-level `data:` wins; legacy `spec:` is kept as a
                // fallback so pre-existing Royak manifests still work. (Real kubectl
                // ConfigMaps put their keys under `data:`, so reading only `spec:`
                // made them come in empty.)
                for src in [&resource.data, &resource.spec] {
                    if let Some(mapping) = src.as_ref().and_then(|v| v.as_mapping()) {
                        for (k, v) in mapping {
                            if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                                data.entry(key.to_string()).or_insert_with(|| val.to_string());
                            }
                        }
                    }
                }

                // Detect change: if ConfigMap existed before with different data, trigger rolling restart
                let changed = self.configmaps.get(&name)
                    .map(|old| old.data != data)
                    .unwrap_or(false);

                self.configmaps.insert(name.clone(), StoredConfigMap {
                    name: name.clone(),
                    namespace: ns.clone(),
                    data,
                });

                if changed {
                    // Find deployments that reference this ConfigMap and trigger rolling restart
                    let mut restarted = Vec::new();
                    for (dep_name, dep) in &self.deployments {
                        if dep.namespace != ns { continue; }
                        let uses_cm = dep.containers.iter()
                            .any(|c| c.env_from_configmaps.contains(&name));
                        if uses_cm {
                            restarted.push(dep_name.clone());
                        }
                    }
                    // Trigger restart by removing containers (reconcile loop recreates with new env)
                    for dep_name in &restarted {
                        let prefix = format!("rk-{dep_name}-");
                        if let Ok(containers) = crate::docker::list_containers(true) {
                            for c in containers.iter().filter(|c| c.names.iter().any(|n| n.contains(&prefix))) {
                                crate::docker::stop_container(&c.id).ok();
                                crate::docker::remove_container(&c.id, true).ok();
                            }
                        }
                    }
                    if restarted.is_empty() {
                        Ok(format!("configmap/{name} updated ({} keys)", self.configmaps[&name].data.len()))
                    } else {
                        Ok(format!("configmap/{name} updated → rolling restart: {}", restarted.join(", ")))
                    }
                } else {
                    Ok(format!("configmap/{name} applied ({} keys)", self.configmaps[&name].data.len()))
                }
            }

            "Secret" => {
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let mut data = HashMap::new();
                // K8s precedence: stringData: (plaintext) > data: (base64) ; legacy
                // spec: (plaintext) kept last as a fallback for existing Royak
                // manifests. Reading only `spec:` before meant real kubectl Secrets
                // (which use base64 `data:`) came in empty.
                if let Some(mapping) = resource.string_data.as_ref().and_then(|v| v.as_mapping()) {
                    for (k, v) in mapping {
                        if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                            data.entry(key.to_string()).or_insert_with(|| val.to_string());
                        }
                    }
                }
                if let Some(mapping) = resource.data.as_ref().and_then(|v| v.as_mapping()) {
                    for (k, v) in mapping {
                        if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                            // Secret `data:` is base64 in K8s — decode; fall back to
                            // the raw string if it isn't valid base64.
                            let decoded = base64_decode(val).unwrap_or_else(|| val.to_string());
                            data.entry(key.to_string()).or_insert(decoded);
                        }
                    }
                }
                if let Some(mapping) = resource.spec.as_ref().and_then(|v| v.as_mapping()) {
                    for (k, v) in mapping {
                        if let (Some(key), Some(val)) = (k.as_str(), v.as_str()) {
                            data.entry(key.to_string()).or_insert_with(|| val.to_string());
                        }
                    }
                }

                self.secrets.insert(name.clone(), StoredSecret {
                    name: name.clone(),
                    namespace: ns,
                    data,
                });
                Ok(format!("secret/{name} applied ({} keys)", self.secrets[&name].data.len()))
            }

            "Service" => {
                let svc = spec::as_service(resource).ok_or("Cannot parse Service spec")?;
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let ports: Vec<ServicePort> = svc.ports.iter().map(|p| ServicePort {
                    port: p.port,
                    target_port: p.target_port.unwrap_or(p.port),
                    protocol: p.protocol.clone().unwrap_or("TCP".to_string()),
                    node_port: p.node_port,
                }).collect();
                let selector = svc.selector.clone().unwrap_or_default();
                let service_type = svc.service_type.clone().unwrap_or("ClusterIP".to_string());
                let port_desc: Vec<String> = ports.iter().map(|p| format!("{}→{}", p.port, p.target_port)).collect();
                self.services.insert(name.clone(), StoredService {
                    name: name.clone(), namespace: ns, selector, ports, service_type: service_type.clone(),
                });
                Ok(format!("service/{name} ({service_type}, ports: {})", port_desc.join(", ")))
            }

            "Namespace" => {
                let name = resource.metadata.name.clone();
                if !self.namespaces.contains(&name) {
                    self.namespaces.push(name.clone());
                }
                Ok(format!("namespace/{name} created"))
            }

            "StorageClass" => {
                let name = resource.metadata.name.clone();
                let spec = resource.spec.as_ref().ok_or("No spec")?;

                let provisioner = spec.get("provisioner").and_then(|v| v.as_str())
                    .unwrap_or("royak/host-path").to_string();
                let host_path_prefix = spec.get("hostPathPrefix").and_then(|v| v.as_str())
                    .unwrap_or("/data/royak/volumes").to_string();
                let reclaim_policy = spec.get("reclaimPolicy").and_then(|v| v.as_str())
                    .unwrap_or("Delete").to_string();

                self.storage_classes.insert(name.clone(), StoredStorageClass {
                    name: name.clone(),
                    provisioner: provisioner.clone(),
                    host_path_prefix: host_path_prefix.clone(),
                    reclaim_policy: reclaim_policy.clone(),
                    provisioned_count: 0,
                });
                Ok(format!("storageclass/{name} created (provisioner: {provisioner}, path: {host_path_prefix}, reclaim: {reclaim_policy})"))
            }

            "PersistentVolume" => {
                let name = resource.metadata.name.clone();
                let spec = resource.spec.as_ref().ok_or("No spec")?;

                let capacity = spec.get("capacity")
                    .and_then(|c| c.get("storage"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("1Gi").to_string();
                let storage_class = spec.get("storageClassName")
                    .and_then(|s| s.as_str())
                    .unwrap_or("local").to_string();
                let host_path = spec.get("hostPath")
                    .and_then(|h| h.get("path"))
                    .and_then(|p| p.as_str())
                    .unwrap_or("/data").to_string();
                let access_mode = spec.get("accessModes")
                    .and_then(|a| a.as_sequence())
                    .and_then(|s| s.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("ReadWriteOnce").to_string();

                // Create host path directory
                std::fs::create_dir_all(&host_path).ok();

                self.pvs.insert(name.clone(), StoredPV {
                    name: name.clone(),
                    capacity: capacity.clone(),
                    storage_class: storage_class.clone(),
                    host_path,
                    access_mode,
                    status: PVStatus::Available,
                    bound_to: None,
                });
                Ok(format!("pv/{name} created ({capacity}, class={storage_class})"))
            }

            "PersistentVolumeClaim" => {
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let spec = resource.spec.as_ref().ok_or("No spec")?;

                let storage_class = spec.get("storageClassName")
                    .and_then(|s| s.as_str())
                    .unwrap_or("local").to_string();
                let requested = spec.get("resources")
                    .and_then(|r| r.get("requests"))
                    .and_then(|r| r.get("storage"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("1Gi").to_string();
                let access_mode = spec.get("accessModes")
                    .and_then(|a| a.as_sequence())
                    .and_then(|s| s.first())
                    .and_then(|v| v.as_str())
                    .unwrap_or("ReadWriteOnce").to_string();

                // Auto-bind to matching PV
                let mut bound_pv = None;
                for (pv_name, pv) in self.pvs.iter_mut() {
                    if pv.status == PVStatus::Available
                        && pv.storage_class == storage_class
                        && pv.access_mode == access_mode
                    {
                        pv.status = PVStatus::Bound;
                        pv.bound_to = Some(name.clone());
                        bound_pv = Some(pv_name.clone());
                        break;
                    }
                }

                // Dynamic provisioning: if no PV matches, use StorageClass to create one
                if bound_pv.is_none() {
                    if let Some(sc) = self.storage_classes.get_mut(&storage_class) {
                        let pv_name = format!("pv-auto-{}-{}", sc.name, sc.provisioned_count);
                        let host_path = format!("{}/{}/{}", sc.host_path_prefix, ns, name);

                        // Create directory on host (for host-path provisioner)
                        if sc.provisioner == "royak/host-path" {
                            std::fs::create_dir_all(&host_path).ok();
                        }

                        let pv = StoredPV {
                            name: pv_name.clone(),
                            capacity: requested.clone(),
                            storage_class: sc.name.clone(),
                            host_path: host_path.clone(),
                            access_mode: access_mode.clone(),
                            status: PVStatus::Bound,
                            bound_to: Some(name.clone()),
                        };
                        self.pvs.insert(pv_name.clone(), pv);
                        sc.provisioned_count += 1;
                        bound_pv = Some(pv_name);
                        eprintln!("  [storage] auto-provisioned pv from storageclass/{} → {host_path}", sc.name);
                    }
                }

                let status = if bound_pv.is_some() { "Bound" } else { "Pending" };

                self.pvcs.insert(name.clone(), StoredPVC {
                    name: name.clone(),
                    namespace: ns,
                    storage_class,
                    requested: requested.clone(),
                    access_mode,
                    bound_pv: bound_pv.clone(),
                });

                Ok(format!("pvc/{name} {status} ({requested}){}",
                    bound_pv.map(|p| format!(" → pv/{p}")).unwrap_or_default()))
            }

            "DaemonSet" => {
                let dep = spec::as_deployment(resource).ok_or("Invalid DaemonSet spec")?;
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let c = &dep.template.spec.containers[0];
                let env: Vec<String> = c.env.as_ref()
                    .map(|vars| vars.iter().filter_map(|e| e.value.as_ref().map(|v| format!("{}={}", e.name, v))).collect())
                    .unwrap_or_default();

                self.daemonsets.insert(name.clone(), StoredDaemonSet {
                    name: name.clone(),
                    namespace: ns,
                    container: StoredContainer {
                        name: c.name.clone(), image: c.image.clone(),
                        command: c.command.clone(), env, volumes: vec![],
                env_from_configmaps: vec![], env_from_secrets: vec![],
                        liveness_probe: None, readiness_probe: None, startup_probe: None,
                    },
                });
                Ok(format!("daemonset/{name} applied (runs on every node)"))
            }

            "Job" => {
                let dep = spec::as_deployment(resource).ok_or("Invalid Job spec")?;
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let c = &dep.template.spec.containers[0];
                let env: Vec<String> = c.env.as_ref()
                    .map(|vars| vars.iter().filter_map(|e| e.value.as_ref().map(|v| format!("{}={}", e.name, v))).collect())
                    .unwrap_or_default();
                let completions = dep.replicas.unwrap_or(1);

                self.jobs.insert(name.clone(), StoredJob {
                    name: name.clone(),
                    namespace: ns,
                    container: StoredContainer {
                        name: c.name.clone(), image: c.image.clone(),
                        command: c.command.clone(), env, volumes: vec![],
                env_from_configmaps: vec![], env_from_secrets: vec![],
                        liveness_probe: None, readiness_probe: None, startup_probe: None,
                    },
                    completions,
                    status: JobStatus::Pending,
                });
                Ok(format!("job/{name} created (completions: {completions})"))
            }

            "CronJob" => {
                let dep = spec::as_deployment(resource).ok_or("Invalid CronJob spec")?;
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let c = &dep.template.spec.containers[0];
                let env: Vec<String> = c.env.as_ref()
                    .map(|vars| vars.iter().filter_map(|e| e.value.as_ref().map(|v| format!("{}={}", e.name, v))).collect())
                    .unwrap_or_default();
                let schedule = resource.spec.as_ref()
                    .and_then(|s| s.get("schedule"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("*/5 * * * *").to_string();

                self.cronjobs.insert(name.clone(), StoredCronJob {
                    name: name.clone(),
                    namespace: ns,
                    schedule: schedule.clone(),
                    container: StoredContainer {
                        name: c.name.clone(), image: c.image.clone(),
                        command: c.command.clone(), env, volumes: vec![],
                env_from_configmaps: vec![], env_from_secrets: vec![],
                        liveness_probe: None, readiness_probe: None, startup_probe: None,
                    },
                    last_run: None,
                });
                Ok(format!("cronjob/{name} scheduled ({schedule})"))
            }

            // IngressClass: Royak has one built-in controller. Accept the kind
            // for manifest compatibility and register the class name; "royak"
            // is the implicit default. Which controller "owns" a class is moot
            // with a single controller — but the field is no longer dropped.
            "IngressClass" => {
                let name = resource.metadata.name.clone();
                self.ingress_classes.insert(name.clone());
                Ok(format!("ingressclass/{name} registered (served by the built-in controller)"))
            }
            "Ingress" => {
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let spec = resource.spec.as_ref().ok_or("No spec")?;

                let mut rules = Vec::new();
                if let Some(rules_val) = spec.get("rules").and_then(|r| r.as_sequence()) {
                    for rule in rules_val {
                        let host = rule.get("host").and_then(|h| h.as_str()).unwrap_or("*").to_string();
                        let mut paths = Vec::new();
                        if let Some(http) = rule.get("http").and_then(|h| h.get("paths")).and_then(|p| p.as_sequence()) {
                            for p in http {
                                let path = p.get("path").and_then(|v| v.as_str()).unwrap_or("/").to_string();
                                let service = p.get("backend").and_then(|b| b.get("service")).and_then(|s| s.get("name")).and_then(|n| n.as_str()).unwrap_or("").to_string();
                                let port = p.get("backend").and_then(|b| b.get("service")).and_then(|s| s.get("port")).and_then(|p| p.get("number")).and_then(|n| n.as_u64()).unwrap_or(80) as u16;
                                paths.push(IngressPath { path, service, port });
                            }
                        }
                        rules.push(IngressRule { host, paths });
                    }
                }

                let ingress_class = spec.get("ingressClassName").and_then(|v| v.as_str()).map(|s| s.to_string());
                let rule_count = rules.iter().map(|r| r.paths.len()).sum::<usize>();
                let class_note = match &ingress_class {
                    Some(c) if !self.ingress_classes.contains(c) && c != "royak" =>
                        format!(", class={c} (served by the built-in controller)"),
                    Some(c) => format!(", class={c}"),
                    None => String::new(),
                };
                self.ingresses.insert(name.clone(), StoredIngress { name: name.clone(), namespace: ns, rules, ingress_class });
                Ok(format!("ingress/{name} applied ({rule_count} routes{class_note})"))
            }

            "NetworkPolicy" => {
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let spec = resource.spec.as_ref().ok_or("No spec")?;

                let pod_selector = spec.get("podSelector")
                    .and_then(|s| s.get("matchLabels"))
                    .and_then(|l| l.get("app"))
                    .and_then(|a| a.as_str())
                    .unwrap_or("*").to_string();

                let mut ingress_allow = Vec::new();
                if let Some(ingress) = spec.get("ingress").and_then(|i| i.as_sequence()) {
                    for rule in ingress {
                        if let Some(from) = rule.get("from").and_then(|f| f.as_sequence()) {
                            for src in from {
                                if let Some(ns_sel) = src.get("namespaceSelector").and_then(|n| n.get("matchLabels")) {
                                    ingress_allow.push(format!("ns:{}", serde_yaml::to_string(ns_sel).unwrap_or_default().trim()));
                                }
                                if let Some(pod_sel) = src.get("podSelector").and_then(|p| p.get("matchLabels")).and_then(|l| l.get("app")).and_then(|a| a.as_str()) {
                                    ingress_allow.push(format!("app:{pod_sel}"));
                                }
                            }
                        }
                    }
                }

                let mut egress_allow = Vec::new();
                if let Some(egress) = spec.get("egress").and_then(|e| e.as_sequence()) {
                    for rule in egress {
                        if let Some(to) = rule.get("to").and_then(|t| t.as_sequence()) {
                            for dest in to {
                                if let Some(pod_sel) = dest.get("podSelector").and_then(|p| p.get("matchLabels")).and_then(|l| l.get("app")).and_then(|a| a.as_str()) {
                                    egress_allow.push(format!("app:{pod_sel}"));
                                }
                            }
                        }
                    }
                }

                // v0.2: parse enhanced security fields
                let mut ingress_ports = Vec::new();
                let mut egress_ports = Vec::new();
                if let Some(ingress) = spec.get("ingress").and_then(|i| i.as_sequence()) {
                    for rule in ingress {
                        if let Some(ports) = rule.get("ports").and_then(|p| p.as_sequence()) {
                            for p in ports {
                                if let Some(port) = p.get("port").and_then(|v| v.as_u64()) {
                                    ingress_ports.push(port as u16);
                                }
                            }
                        }
                    }
                }
                if let Some(egress) = spec.get("egress").and_then(|e| e.as_sequence()) {
                    for rule in egress {
                        if let Some(ports) = rule.get("ports").and_then(|p| p.as_sequence()) {
                            for p in ports {
                                if let Some(port) = p.get("port").and_then(|v| v.as_u64()) {
                                    egress_ports.push(port as u16);
                                }
                            }
                        }
                    }
                }
                let internal = spec.get("internal").and_then(|v| v.as_bool()).unwrap_or(false);
                let mtls_required = spec.get("mtls").and_then(|v| v.as_bool()).unwrap_or(false);
                let deny_all = spec.get("denyAll").and_then(|v| v.as_bool()).unwrap_or(false);

                self.network_policies.insert(name.clone(), StoredNetworkPolicy {
                    name: name.clone(), namespace: ns, pod_selector,
                    ingress_allow, egress_allow,
                    ingress_ports, egress_ports,
                    internal, mtls_required, deny_all,
                });

                let mut features = Vec::new();
                if internal { features.push("internal"); }
                if mtls_required { features.push("mTLS"); }
                if deny_all { features.push("deny-all"); }
                let features_str = if features.is_empty() { String::new() } else { format!(" [{}]", features.join(", ")) };

                Ok(format!("networkpolicy/{name} applied (selector: {}, {} ingress, {} egress rules){features_str}",
                    self.network_policies[&name].pod_selector,
                    self.network_policies[&name].ingress_allow.len(),
                    self.network_policies[&name].egress_allow.len()))
            }

            "ResourceQuota" => {
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or_else(|| "default".to_string());
                let spec = resource.spec.as_ref().ok_or("No spec")?;

                let hard = spec.get("hard").unwrap_or(spec);
                let parse_cpu = |v: &serde_yaml::Value| -> Option<f32> {
                    // Try as number first (cpu: 4)
                    if let Some(f) = v.as_f64() { return Some(f as f32); }
                    // Try as string
                    if let Some(s) = v.as_str() {
                        // Millicores: "500m" → 0.5
                        if s.ends_with('m') {
                            return s.trim_end_matches('m').parse::<f32>().ok().map(|m| m / 1000.0);
                        }
                        // Cores: "4" → 4.0
                        return s.parse().ok();
                    }
                    None
                };
                let parse_mem = |v: &serde_yaml::Value| -> Option<u64> {
                    if let Some(n) = v.as_u64() { return Some(n); }
                    if let Some(s) = v.as_str() {
                        if let Some(gi) = s.strip_suffix("Gi") { return gi.parse::<u64>().ok().map(|n| n * 1024); }
                        if let Some(mi) = s.strip_suffix("Mi") { return mi.parse::<u64>().ok(); }
                        return s.parse().ok();
                    }
                    None
                };

                let quota = StoredResourceQuota {
                    name: name.clone(),
                    namespace: ns.clone(),
                    hard_cpu: hard.get("cpu").and_then(|v| parse_cpu(v)),
                    hard_memory: hard.get("memory").and_then(|v| parse_mem(v)),
                    hard_pods: hard.get("pods").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).map(|n| n as u32),
                    hard_services: hard.get("services").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).map(|n| n as u32),
                    hard_configmaps: hard.get("configmaps").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).map(|n| n as u32),
                    hard_secrets: hard.get("secrets").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))).map(|n| n as u32),
                };

                let mut limits = Vec::new();
                if let Some(c) = quota.hard_cpu { limits.push(format!("cpu: {c}")); }
                if let Some(m) = quota.hard_memory { limits.push(format!("mem: {m}Mi")); }
                if let Some(p) = quota.hard_pods { limits.push(format!("pods: {p}")); }
                if let Some(s) = quota.hard_services { limits.push(format!("svc: {s}")); }
                self.resource_quotas.insert(format!("{ns}/{name}"), quota);
                Ok(format!("resourcequota/{name} applied (ns={ns}, {})", limits.join(", ")))
            }

            "HorizontalPodAutoscaler" | "HPA" => {
                let name = resource.metadata.name.clone();
                let spec = resource.spec.as_ref().ok_or("No spec")?;

                let deployment = spec.get("scaleTargetRef")
                    .and_then(|s| s.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("").to_string();
                let min_replicas = spec.get("minReplicas")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as u32;
                let max_replicas = spec.get("maxReplicas")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(10) as u32;
                let target_cpu = spec.get("targetCPUUtilizationPercentage")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(70.0) as f32;

                self.hpas.insert(name.clone(), StoredHPA {
                    name: name.clone(),
                    deployment: deployment.clone(),
                    min_replicas,
                    max_replicas,
                    target_cpu,
                    history: Vec::new(),
                    last_scaled: None,
                });
                Ok(format!("hpa/{name} → {deployment} (min={min_replicas}, max={max_replicas}, cpu={target_cpu}%)"))
            }

            "Config" => {
                let spec_val = resource.spec.as_ref().ok_or("No spec")?;
                let cfg: spec::ClusterConfigSpec = serde_yaml::from_value(spec_val.clone())
                    .map_err(|e| format!("Config parse error: {e}"))?;

                let mut changes = Vec::new();

                if let Some(llm) = cfg.llm {
                    if let Some(h) = llm.host { self.config.llm_host = h.clone(); changes.push(format!("llm.host={h}")); }
                    if let Some(m) = llm.model { self.config.llm_model = m.clone(); changes.push(format!("llm.model={m}")); }
                    if let Some(t) = llm.temperature { self.config.llm_temperature = t; changes.push(format!("llm.temp={t}")); }
                }
                if let Some(alerts) = cfg.alerts {
                    if let Some(w) = alerts.webhook { self.config.alert_webhook = Some(w.clone()); changes.push(format!("alerts.webhook={w}")); }
                    if let Some(a) = alerts.on_anomaly { self.config.alert_on_anomaly = a; }
                    if let Some(r) = alerts.on_restart { self.config.alert_on_restart = r; }
                    if let Some(r) = alerts.on_rollout { self.config.alert_on_rollout = r; }
                }
                if let Some(r) = cfg.runtime { self.config.runtime = r.clone(); changes.push(format!("runtime={r}")); }
                if let Some(pause) = cfg.pause {
                    if let Some(d) = pause.default_idle_seconds { self.config.pause_default_idle = d; changes.push(format!("pause.idle={d}s")); }
                    if let Some(e) = pause.enabled { self.config.pause_enabled = e; }
                }
                if let Some(api) = cfg.api {
                    if let Some(p) = api.port { self.config.api_port = p; changes.push(format!("api.port={p}")); }
                }

                Ok(format!("config applied ({})", changes.join(", ")))
            }

            "Function" => {
                let name = resource.metadata.name.clone();
                let spec_val = resource.spec.as_ref().ok_or("No spec")?;
                let func_spec: spec::FunctionSpec = serde_yaml::from_value(spec_val.clone())
                    .map_err(|e| format!("Function parse error: {e}"))?;

                // Resolve runtime to image
                let image = func_spec.image.unwrap_or_else(|| {
                    match func_spec.runtime.as_deref() {
                        Some("python3.12") | Some("python") => "python:3.12-alpine".to_string(),
                        Some("python3.11") => "python:3.11-alpine".to_string(),
                        Some("node20") | Some("node") => "node:20-alpine".to_string(),
                        Some("rust") => "rust:alpine".to_string(),
                        Some("go") => "golang:alpine".to_string(),
                        Some(r) => r.to_string(), // treat as image name
                        None => "alpine:latest".to_string(),
                    }
                });

                let env: Vec<String> = func_spec.env.as_ref()
                    .map(|vars| vars.iter().filter_map(|e| {
                        e.value.as_ref().map(|v| format!("{}={}", e.name, v))
                    }).collect())
                    .unwrap_or_default();

                let mut http_triggers = Vec::new();
                let mut webhook_triggers = Vec::new();
                let mut schedule_triggers = Vec::new();
                if let Some(triggers) = &func_spec.trigger {
                    for t in triggers {
                        if let Some(h) = &t.http { http_triggers.push(h.clone()); }
                        if let Some(w) = &t.webhook { webhook_triggers.push(w.clone()); }
                        if let Some(s) = &t.schedule { schedule_triggers.push(s.clone()); }
                    }
                }

                let timeout = func_spec.timeout.as_deref()
                    .and_then(|t| t.trim_end_matches('s').trim_end_matches('m').parse::<u64>().ok()
                        .map(|v| if func_spec.timeout.as_deref().unwrap_or("").ends_with('m') { v * 60 } else { v }))
                    .unwrap_or(30);

                let memory = func_spec.memory.as_deref()
                    .and_then(|m| m.trim_end_matches("Mi").trim_end_matches("Gi").parse::<u32>().ok()
                        .map(|v| if func_spec.memory.as_deref().unwrap_or("").ends_with("Gi") { v * 1024 } else { v }))
                    .unwrap_or(128);

                let trigger_count = http_triggers.len() + webhook_triggers.len() + schedule_triggers.len();

                self.functions.insert(name.clone(), StoredFunction {
                    name: name.clone(),
                    image: image.clone(),
                    command: func_spec.command.clone().or_else(|| func_spec.handler.map(|h| vec!["sh".to_string(), "-c".to_string(), h])),
                    env,
                    http_triggers,
                    webhook_triggers,
                    schedule_triggers,
                    timeout_secs: timeout,
                    memory_mb: memory,
                    code: func_spec.code,
                    container_id: None,
                    invocations: 0,
                    last_invoked: None,
                    state: FunctionState::Cold,
                });
                Ok(format!("function/{name} deployed ({image}, {trigger_count} triggers, {timeout}s timeout)"))
            }

            "Repository" => {
                let name = resource.metadata.name.clone();
                let spec_val = resource.spec.as_ref().ok_or("No spec")?;
                let repo_spec: spec::RepositorySpec = serde_yaml::from_value(spec_val.clone())
                    .map_err(|e| format!("Repository parse error: {e}"))?;

                let branch = repo_spec.branch.unwrap_or_else(|| "main".to_string());
                let has_pipeline = repo_spec.pipeline.is_some();

                self.repositories.insert(name.clone(), StoredRepository {
                    name: name.clone(),
                    url: repo_spec.url.clone(),
                    path: repo_spec.path.clone(),
                    branch: branch.clone(),
                    secret_ref: repo_spec.secret_ref,
                    pipeline: repo_spec.pipeline,
                    last_commit: None,
                });

                let source = repo_spec.url.or(repo_spec.path).unwrap_or_else(|| "?".to_string());
                let trigger = if has_pipeline { " (auto-trigger)" } else { "" };
                Ok(format!("repository/{name} registered ({source}:{branch}){trigger}"))
            }

            "Pipeline" => {
                let name = resource.metadata.name.clone();
                let spec_val = resource.spec.as_ref().ok_or("No spec")?;
                let pipeline_spec: spec::PipelineSpec = serde_yaml::from_value(spec_val.clone())
                    .map_err(|e| format!("Pipeline parse error: {e}"))?;

                let triggers: Vec<StoredTrigger> = pipeline_spec.trigger.unwrap_or_default()
                    .iter().map(|t| StoredTrigger {
                        trigger_type: t.trigger_type.clone(),
                        path: t.path.clone(),
                    }).collect();

                let stages: Vec<StoredStage> = pipeline_spec.stages.iter().map(|s| {
                    let env: Vec<String> = s.env.as_ref()
                        .map(|vars| vars.iter().filter_map(|e| {
                            e.value.as_ref().map(|v| format!("{}={}", e.name, v))
                        }).collect())
                        .unwrap_or_default();
                    StoredStage {
                        name: s.name.clone(),
                        image: s.image.clone(),
                        command: s.command.clone(),
                        action: s.action.clone(),
                        file: s.file.clone(),
                        context: s.context.clone(),
                        dockerfile: s.dockerfile.clone(),
                        tag: s.tag.clone(),
                        build_args: s.args.as_ref().map(|v| v.iter()
                            .filter_map(|e| e.value.as_ref().map(|val| (e.name.clone(), val.clone())))
                            .collect()).unwrap_or_default(),
                        artifacts: s.artifacts.clone().unwrap_or_default(),
                        depends_on: s.depends_on.clone(),
                        env,
                        if_condition: s.if_condition.clone(),
                        matrix_images: s.matrix.as_ref().and_then(|m| m.image.clone()).unwrap_or_default(),
                        matrix_envs: s.matrix.as_ref().and_then(|m| m.env.clone()).unwrap_or_default(),
                    }
                }).collect();

                let stage_count = stages.len();
                let trigger_count = triggers.len();

                self.pipelines.insert(name.clone(), StoredPipeline {
                    name: name.clone(),
                    stages,
                    triggers,
                });
                Ok(format!("pipeline/{name} defined ({stage_count} stages, {trigger_count} triggers)"))
            }

            // ─── Admission webhooks (validating) ───
            "ValidatingWebhookConfiguration" => {
                let name = resource.metadata.name.clone();
                let sv = resource.spec.as_ref().ok_or("No spec")?;
                let hooks = sv.get("webhooks").and_then(|w| w.as_sequence()).ok_or("needs spec.webhooks")?;
                let first = hooks.first().ok_or("needs at least one webhook")?;
                let url = first.get("clientConfig").and_then(|c| c.get("url")).and_then(|u| u.as_str())
                    .ok_or("webhook needs clientConfig.url (Royak calls the URL directly)")?
                    .to_string();
                let kinds: Vec<String> = first.get("rules").and_then(|r| r.as_sequence())
                    .map(|rules| rules.iter().flat_map(|r| r.get("resources").and_then(|x| x.as_sequence())
                        .map(|s| s.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect::<Vec<_>>())
                        .unwrap_or_default()).collect())
                    .unwrap_or_else(|| vec!["*".to_string()]);
                let failure_policy = first.get("failurePolicy").and_then(|f| f.as_str()).unwrap_or("Fail").to_string();
                self.admission_webhooks.insert(name.clone(), AdmissionWebhook {
                    name: name.clone(), url, kinds, failure_policy,
                });
                Ok(format!("validatingwebhookconfiguration/{name} registered ({} kinds)", self.admission_webhooks[&name].kinds.len()))
            }

            // ─── K8s-native RBAC kinds, mapped onto Royak's role model ───
            // Role/ClusterRole: rules live at the TOP level of the manifest.
            // The role becomes a Royak RbacRole scoped to its namespace
            // (ClusterRole scopes to all namespaces).
            "Role" | "ClusterRole" => {
                let name = resource.metadata.name.clone();
                let ns_scope = if resource.kind == "ClusterRole" {
                    "*".to_string()
                } else {
                    resource.metadata.namespace.clone().unwrap_or("default".to_string())
                };
                let rules_val = resource.rules.as_ref()
                    .and_then(|r| r.as_sequence())
                    .ok_or("Role needs top-level rules")?;
                let rules: Vec<RbacRule> = rules_val.iter().map(|r| {
                    let get_strings = |key: &str| -> Vec<String> {
                        r.get(key).and_then(|v| v.as_sequence())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_else(|| vec!["*".to_string()])
                    };
                    RbacRule {
                        resources: get_strings("resources"),
                        verbs: get_strings("verbs"),
                        namespaces: vec![ns_scope.clone()],
                    }
                }).collect();
                let rule_count = rules.len();
                self.rbac_roles.insert(name.clone(), RbacRole { name: name.clone(), rules });
                Ok(format!("{}/{name} configured ({rule_count} rules, ns={ns_scope})", resource.kind.to_lowercase()))
            }
            // RoleBinding/ClusterRoleBinding: each subject name becomes an
            // alias for the referenced role's rules — Royak resolves the
            // caller's role from its token/header by name.
            "RoleBinding" | "ClusterRoleBinding" => {
                let name = resource.metadata.name.clone();
                let role_name = resource.role_ref.as_ref()
                    .and_then(|r| r.get("name")).and_then(|v| v.as_str())
                    .ok_or("RoleBinding needs roleRef.name")?
                    .to_string();
                let role = self.rbac_roles.get(&role_name)
                    .ok_or(format!("roleRef '{role_name}' not found — apply the Role first"))?
                    .clone();
                let subjects: Vec<String> = resource.subjects.as_ref()
                    .and_then(|s| s.as_sequence())
                    .map(|arr| arr.iter().filter_map(|s| s.get("name").and_then(|v| v.as_str()).map(|s| s.to_string())).collect())
                    .unwrap_or_default();
                if subjects.is_empty() {
                    return Err("RoleBinding needs at least one subject".to_string());
                }
                let n = subjects.len();
                for subject in subjects {
                    self.rbac_roles.insert(subject.clone(), RbacRole { name: subject, rules: role.rules.clone() });
                }
                Ok(format!("rolebinding/{name}: {n} subject(s) bound to role '{role_name}'"))
            }
            // ServiceAccount: accepted for manifest compatibility. Royak's pod
            // identity (per-pod HMAC tokens + mTLS certs) already covers the
            // runtime role; the SA name is usable as an RBAC subject.
            "ServiceAccount" => {
                let name = resource.metadata.name.clone();
                Ok(format!("serviceaccount/{name} registered (use as RBAC subject via RoleBinding)"))
            }
            // LimitRange: default resource limits applied to deployments in the
            // namespace that don't set their own.
            "LimitRange" => {
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let sv = resource.spec.as_ref().ok_or("No spec")?;
                let first_limit = sv.get("limits").and_then(|l| l.as_sequence()).and_then(|s| s.first());
                let get = |section: &str, key: &str| -> Option<String> {
                    first_limit.and_then(|l| l.get(section)).and_then(|d| d.get(key))
                        .and_then(|v| v.as_str()).map(|s| s.to_string())
                };
                let lr = StoredLimitRange {
                    name: name.clone(),
                    namespace: ns.clone(),
                    default_cpu: get("default", "cpu"),
                    default_mem: get("default", "memory"),
                    request_cpu: get("defaultRequest", "cpu"),
                    request_mem: get("defaultRequest", "memory"),
                };
                self.limit_ranges.insert(ns.clone(), lr);
                Ok(format!("limitrange/{name} set for namespace {ns}"))
            }

            // ─── RBAC Role ───
            "RbacRole" => {
                let sv = resource.spec.as_ref().ok_or("No spec")?;
                let name = resource.metadata.name.clone();
                let rules_val = sv.get("rules").and_then(|r| r.as_sequence()).ok_or("RbacRole needs spec.rules")?;
                let rules: Vec<RbacRule> = rules_val.iter().map(|r| {
                    let get_strings = |key: &str| -> Vec<String> {
                        r.get(key).and_then(|v| v.as_sequence())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_else(|| vec!["*".to_string()])
                    };
                    RbacRule {
                        resources: get_strings("resources"),
                        verbs: get_strings("verbs"),
                        namespaces: get_strings("namespaces"),
                    }
                }).collect();
                let rule_count = rules.len();
                self.rbac_roles.insert(name.clone(), RbacRole { name: name.clone(), rules });
                Ok(format!("rbac/{name} configured ({rule_count} rules)"))
            }

            // ─── Guard (auto-remediation) ───
            "Guard" => {
                let sv = resource.spec.as_ref().ok_or("No spec")?;
                let name = resource.metadata.name.clone();
                let empty_rules = vec![];
                let rules_val = sv.get("rules").and_then(|r| r.as_sequence()).unwrap_or(&empty_rules);
                let rules: Vec<GuardRule> = rules_val.iter().map(|r| {
                    let params: HashMap<String, String> = r.get("params")
                        .and_then(|p| p.as_mapping())
                        .map(|m| m.iter().filter_map(|(k, v)| {
                            Some((k.as_str()?.to_string(), v.as_str()?.to_string()))
                        }).collect())
                        .unwrap_or_default();
                    GuardRule {
                        when: r.get("when").and_then(|v| v.as_str()).unwrap_or("anomaly").to_string(),
                        action: r.get("action").and_then(|v| v.as_str()).unwrap_or("restart").to_string(),
                        params,
                    }
                }).collect();
                let hooks: HashMap<String, String> = sv.get("hooks")
                    .and_then(|h| h.as_mapping())
                    .map(|m| m.iter().filter_map(|(k, v)| {
                        Some((k.as_str()?.to_string(), v.as_str()?.to_string()))
                    }).collect())
                    .unwrap_or_default();
                let rule_count = rules.len();
                self.guards.insert(name.clone(), Guard { name: name.clone(), rules, hooks });
                Ok(format!("guard/{name} configured ({rule_count} rules)"))
            }

            // ─── Operator (CRD manager) ───
            "Operator" => {
                let sv = resource.spec.as_ref().ok_or("No spec")?;
                let name = resource.metadata.name.clone();
                let custom_kind = sv.get("customKind").and_then(|v| v.as_str())
                    .ok_or("Operator needs spec.customKind")?.to_string();
                let provision: Vec<OperatorComponent> = sv.get("provision")
                    .and_then(|p| p.as_sequence())
                    .map(|arr| arr.iter().map(|c| {
                        OperatorComponent {
                            role: c.get("role").and_then(|v| v.as_str()).unwrap_or("primary").to_string(),
                            image: c.get("image").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            replicas: c.get("replicas").and_then(|v| v.as_u64()).unwrap_or(1) as u32,
                            env: c.get("env").and_then(|v| v.as_sequence())
                                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default(),
                            volumes: vec![], ports: vec![],
                        }
                    }).collect())
                    .unwrap_or_default();
                let hooks: HashMap<String, String> = sv.get("hooks")
                    .and_then(|h| h.as_mapping())
                    .map(|m| m.iter().filter_map(|(k, v)| {
                        Some((k.as_str()?.to_string(), v.as_str()?.to_string()))
                    }).collect())
                    .unwrap_or_default();
                let comp_count = provision.len();
                self.operators.insert(name.clone(), Operator {
                    name: name.clone(), custom_kind: custom_kind.clone(),
                    provision, hooks, rules: vec![],
                });
                Ok(format!("operator/{name} for kind '{custom_kind}' ({comp_count} components)"))
            }

            // ─── Custom Resource (managed by operator) ───
            "CustomResource" => {
                let sv = resource.spec.as_ref().ok_or("No spec")?;
                let name = resource.metadata.name.clone();
                let cr_kind = resource.metadata.namespace.clone()
                    .or_else(|| sv.get("kind").and_then(|v| v.as_str()).map(|s| s.to_string()))
                    .unwrap_or_default();
                // Use the actual kind from metadata labels or a "kind" field in spec
                let actual_kind = sv.get("resourceKind").and_then(|v| v.as_str())
                    .unwrap_or(&cr_kind).to_string();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let spec_json = serde_json::to_value(sv).unwrap_or(serde_json::json!({}));
                self.custom_resources.insert(name.clone(), CustomResource {
                    name: name.clone(), kind: actual_kind.clone(),
                    namespace: ns, spec: spec_json, status: CRStatus::Pending,
                });
                Ok(format!("cr/{actual_kind}/{name} created (pending operator)"))
            }

            "NeuroPod" => {
                eprintln!("  ⚠ NeuroPod is EXPERIMENTAL (mega-beta). For production use Docker mode.");
                let name = resource.metadata.name.clone();
                let spec = resource.spec.as_ref().ok_or("No spec")?;

                let image = spec.get("image").and_then(|v| v.as_str()).unwrap_or("alpine:latest");
                let disk_mb = spec.get("disk").and_then(|d| d.get("size"))
                    .and_then(|s| s.as_str())
                    .and_then(|s| {
                        if let Some(gi) = s.strip_suffix("Gi") { gi.parse::<u64>().ok().map(|n| n * 1024) }
                        else if let Some(mi) = s.strip_suffix("Mi") { mi.parse::<u64>().ok() }
                        else { s.parse().ok() }
                    })
                    .unwrap_or(1024); // default 1Gi
                let mount_path = spec.get("disk").and_then(|d| d.get("mountPath"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("/data");

                match crate::runtime::NeuroPod::create(&name, image, disk_mb, mount_path) {
                    Ok(mut pod) => {
                        // Gather env
                        let env: Vec<String> = spec.get("env").and_then(|e| e.as_sequence())
                            .map(|seq| seq.iter().filter_map(|v| {
                                let k = v.get("name")?.as_str()?;
                                let val = v.get("value")?.as_str()?;
                                Some(format!("{k}={val}"))
                            }).collect())
                            .unwrap_or_default();

                        let (used, max) = pod.disk_usage();
                        match pod.start(None, &env) {
                            Ok(pid) => Ok(format!("neuropod/{name} created (image={image}, disk={disk_mb}MB sparse, mount={mount_path}, pid={pid}, used={used}B/{max}B)")),
                            Err(e) => Ok(format!("neuropod/{name} created but start failed: {e} (disk ready, retry with watch)")),
                        }
                    }
                    Err(e) => Err(format!("neuropod/{name}: {e}")),
                }
            }

            kind => Err(format!("Unsupported resource kind: {kind}")),
        }
    }

    /// Check if namespace quota allows the current desired state.
    /// Returns Ok(()) if within limits, Err(reason) if quota exceeded.
    pub fn check_quota(&self, namespace: &str, _additional_pods: u32) -> Result<(), String> {
        for quota in self.resource_quotas.values() {
            if quota.namespace != namespace { continue; }

            // Pod count: total desired replicas in namespace
            if let Some(max_pods) = quota.hard_pods {
                let total_desired: u32 = self.deployments.values()
                    .filter(|d| d.namespace == namespace)
                    .map(|d| d.replicas)
                    .sum();
                if total_desired > max_pods {
                    return Err(format!("quota/{}: pods {total_desired}/{max_pods} exceeded",
                        quota.name));
                }
            }

            // CPU quota (sum of all deployment CPU limits × replicas in namespace)
            if let Some(max_cpu) = quota.hard_cpu {
                let current_cpu: f32 = self.deployments.values()
                    .filter(|d| d.namespace == namespace)
                    .map(|d| {
                        let per_pod = d.resource_limits.as_ref().and_then(|r| r.cpu_limit).unwrap_or(0.0);
                        per_pod * d.replicas as f32
                    })
                    .sum();
                if current_cpu > max_cpu {
                    return Err(format!("quota/{}: cpu {current_cpu:.1}/{max_cpu:.1} cores exceeded",
                        quota.name));
                }
            }

            // Memory quota (sum of all deployment memory limits × replicas in namespace)
            if let Some(max_mem) = quota.hard_memory {
                let current_mem: u64 = self.deployments.values()
                    .filter(|d| d.namespace == namespace)
                    .map(|d| {
                        let per_pod = d.resource_limits.as_ref().and_then(|r| r.mem_limit).unwrap_or(0);
                        per_pod * d.replicas as u64
                    })
                    .sum();
                if current_mem > max_mem {
                    return Err(format!("quota/{}: memory {current_mem}/{max_mem} Mi exceeded",
                        quota.name));
                }
            }

            // Service count
            if let Some(max_svc) = quota.hard_services {
                let current = self.services.values().filter(|s| s.namespace == namespace).count() as u32;
                if current > max_svc {
                    return Err(format!("quota/{}: services {current}/{max_svc} exceeded", quota.name));
                }
            }

            // ConfigMap count
            if let Some(max_cm) = quota.hard_configmaps {
                let current = self.configmaps.values().filter(|c| c.namespace == namespace).count() as u32;
                if current > max_cm {
                    return Err(format!("quota/{}: configmaps {current}/{max_cm} exceeded", quota.name));
                }
            }

            // Secret count
            if let Some(max_s) = quota.hard_secrets {
                let current = self.secrets.values().filter(|s| s.namespace == namespace).count() as u32;
                if current > max_s {
                    return Err(format!("quota/{}: secrets {current}/{max_s} exceeded", quota.name));
                }
            }
        }
        Ok(())
    }

    /// Delete any resource by name
    pub fn delete(&mut self, name: &str) -> bool {
        self.deployments.remove(name).is_some()
    }

    /// Delete a resource by type and name
    pub fn delete_resource(&mut self, resource_type: &str, name: &str) -> bool {
        match resource_type {
            "deployments" => self.deployments.remove(name).is_some(),
            "daemonsets" => self.daemonsets.remove(name).is_some(),
            "jobs" => self.jobs.remove(name).is_some(),
            "cronjobs" => self.cronjobs.remove(name).is_some(),
            "hpa" | "horizontalpodautoscalers" => self.hpas.remove(name).is_some(),
            "ingresses" => self.ingresses.remove(name).is_some(),
            "persistentvolumes" | "pvs" => self.pvs.remove(name).is_some(),
            "persistentvolumeclaims" | "pvcs" => {
                if let Some(pvc) = self.pvcs.remove(name) {
                    // Release bound PV
                    if let Some(pv_name) = &pvc.bound_pv {
                        if let Some(pv) = self.pvs.get_mut(pv_name) {
                            pv.status = PVStatus::Released;
                            pv.bound_to = None;
                            // If StorageClass has Delete reclaim policy, remove PV + data
                            if let Some(sc) = self.storage_classes.get(&pv.storage_class) {
                                if sc.reclaim_policy == "Delete" {
                                    std::fs::remove_dir_all(&pv.host_path).ok();
                                    self.pvs.remove(pv_name);
                                }
                            }
                        }
                    }
                    true
                } else { false }
            }
            "functions" => self.functions.remove(name).is_some(),
            "pipelines" => self.pipelines.remove(name).is_some(),
            "repositories" => self.repositories.remove(name).is_some(),
            "guards" => self.guards.remove(name).is_some(),
            "operators" => self.operators.remove(name).is_some(),
            "customresources" => {
                // Cascade-delete (owner-reference GC): removing a CR must clean
                // up the deployments its operator provisioned. Collect owned
                // names first (immutable borrow), then drop them — the reconcile
                // loop tears down their containers on the next cycle.
                let existed = self.custom_resources.remove(name).is_some();
                if existed {
                    for dep_name in deployments_owned_by(self, name) {
                        self.deployments.remove(&dep_name);
                    }
                }
                existed
            }
            "rbacroles" => self.rbac_roles.remove(name).is_some(),
            _ => false,
        }
    }
}

/// Decide which StatefulSet ordinal (if any) may be created THIS tick, honoring
/// the real Kubernetes guarantee: ordinal N+1 is not created until ordinal N is
/// Ready. Also enforces the "at most one new ordinal per tick" throttle by
/// returning at most one ordinal.
///
/// royak names StatefulSet pods `rk-<name>-1 … rk-<name>-N` (1-based), so the
/// lowest ordinal is `1` and it has no predecessor — it is always eligible
/// (this is royak's equivalent of K8s' 0-based "ordinal 0 starts first").
///
/// - `existing`: ordinals whose pod currently exists (any container state)
/// - `ready`:    ordinals whose pod is Ready (see caller for the signal used)
/// - `desired_count`: target replica count
///
/// Returns `Some(ordinal)` for the lowest missing ordinal in `1..=desired_count`
/// when its predecessor is Ready (or it is the first ordinal), else `None`
/// (nothing to create — either the set is complete, or the predecessor of the
/// next-missing ordinal is not yet Ready, so we hold and retry next tick).
pub(crate) fn next_statefulset_ordinal(
    existing: &std::collections::HashSet<u32>,
    ready: &std::collections::HashSet<u32>,
    desired_count: u32,
) -> Option<u32> {
    if desired_count == 0 {
        return None;
    }
    // Lowest missing ordinal — recreate a hole before extending the tail.
    let next = (1..=desired_count).find(|n| !existing.contains(n))?;
    // The first ordinal has no predecessor and is always eligible.
    if next == 1 {
        return Some(1);
    }
    // Gate: the immediately-preceding ordinal must be Ready.
    if ready.contains(&(next - 1)) {
        Some(next)
    } else {
        None
    }
}

/// One reconcile cycle
pub fn reconcile_once(desired: &mut DesiredWorld, brain: &mut OrinBrain) -> Vec<String> {
    reconcile_with_runtime(desired, brain, false)
}

pub fn reconcile_with_runtime(desired: &mut DesiredWorld, brain: &mut OrinBrain, use_neuropod: bool) -> Vec<String> {
    // Auto-detect: if NeuroPod requested OR Docker unavailable → NeuroPod mode (EXPERIMENTAL)
    if use_neuropod || !crate::docker::ping() {
        return reconcile_neuropod(desired, brain);
    }
    // Docker mode: production-ready, 28/28 tests
    let mut log = Vec::new();
    let rt_name = desired.config.runtime.clone();

    // For non-docker runtimes, delegate to trait-based reconciliation
    if rt_name != "docker" {
        return reconcile_via_trait(desired, brain, &rt_name);
    }

    // ─── Docker path (original, direct calls) ───

    // Initialize Cluster CA for mTLS (once, persisted in state)
    if desired.cluster_ca.is_none() {
        match crate::net_security::ClusterCA::generate() {
            Ok(ca) => {
                log.push(format!("  [security] Cluster CA generated (fp: {})", ca.fingerprint));
                desired.cluster_ca = Some(ca);
            }
            Err(e) => log.push(format!("  [warn] CA generation failed: {e}")),
        }
    }

    // Ensure namespace networks exist (pod isolation + DNS)
    if let Err(e) = docker::ensure_network() {
        log.push(format!("  [warn] network: {e}"));
    }
    for ns in &desired.namespaces {
        if let Err(e) = docker::ensure_namespace_network(ns) {
            log.push(format!("  [warn] network rk-{ns}: {e}"));
        }
    }
    // Always ensure default namespace network
    docker::ensure_namespace_network("default").ok();

    // mTLS cert lifecycle: check for expired certs, track status
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut expired_certs = Vec::new();
    for (pod_name, cert) in &desired.pod_certs {
        if cert.revoked { continue; }
        if now_secs > cert.expires_at {
            expired_certs.push(pod_name.clone());
        }
    }
    for pod_name in &expired_certs {
        log.push(format!("  [mtls] ⚠ cert expired: {pod_name} — will re-issue on next reconcile"));
        if let Some(cert) = desired.pod_certs.get_mut(pod_name) {
            cert.revoked = true;
        }
        desired.record_event("Pod", pod_name, "CertExpired", "mTLS certificate expired, marked for rotation", "Warning");
    }

    // 1. Get actual containers from Docker
    let actual = match docker::list_containers(true) {
        Ok(containers) => containers,
        Err(e) => {
            log.push(format!("  [error] Docker: {e}"));
            return log;
        }
    };

    // Filter to royak-managed containers
    // (In real impl, check labels. For now, check name prefix)
    let managed: Vec<&docker::DockerContainer> = actual.iter()
        .filter(|c| c.names.iter().any(|n| n.contains("rk-")))
        .collect();

    // Deferred events: collect during immutable borrow, apply after
    let mut pending_events: Vec<(String, String, String, String, String)> = Vec::new();

    // 2. For each deployment: compare desired vs actual
    for (name, dep) in &desired.deployments {
        // Skip normal scaling if rolling update is in progress for this deployment
        if desired.pending_rollouts.contains_key(name.as_str()) {
            continue;
        }
        let prefix = format!("/rk-{name}-");
        let running: Vec<&&docker::DockerContainer> = managed.iter()
            .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix)) && c.state == "running")
            .collect();
        let stopped: Vec<&&docker::DockerContainer> = managed.iter()
            .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix)) && c.state != "running")
            .collect();

        let current = running.len() as u32;
        let desired_count = dep.replicas;

        if current < desired_count {
            // Scale UP — check quota first
            let needed = desired_count - current;
            if let Err(reason) = desired.check_quota(&dep.namespace, needed) {
                log.push(format!("  [quota] {name}: BLOCKED — {reason}"));
                pending_events.push(("Deployment".into(), name.clone(), "QuotaExceeded".into(), reason, "Warning".into()));
                continue;
            }
            log.push(format!("  [scale] {name}: {current} → {desired_count} (+{needed})"));
            pending_events.push(("Deployment".into(), name.clone(), "ScalingUp".into(), format!("{current} → {desired_count} (+{needed})"), "Normal".into()));

            // Pull all images
            let mut pulled = std::collections::HashSet::new();
            for c in &dep.containers {
                if pulled.insert(c.image.clone()) {
                    if let Err(e) = docker::pull_image(&c.image) {
                        log.push(format!("    [warn] pull {}: {e}", c.image));
                    }
                }
            }

            // Collect all existing container names for collision-free naming
            let all_names: Vec<String> = managed.iter()
                .flat_map(|c| c.names.iter().map(|n| n.trim_start_matches('/').to_string()))
                .collect();

            // StatefulSet: ordered startup — at most one new ordinal per tick,
            // and always the lowest missing one (rk-db-1 is recreated before
            // rk-db-3 is ever considered). Crucially, honor the real K8s
            // guarantee: ordinal N+1 is NOT created until ordinal N is Ready.
            let needed = if dep.stateful { needed.min(1) } else { needed };

            // For a StatefulSet, precompute the single ordinal eligible this
            // tick (or None → hold). We evaluate readiness of each existing
            // ordinal from the live container list using the STRONGEST signal
            // available:
            //   * if the pod's main container defines a readiness probe, we
            //     require a passing probe (and, if a startup probe exists, that
            //     startup has completed);
            //   * otherwise we treat running + started (startup probe passed,
            //     or no startup probe) as Ready.
            // NB: `pod_health.ready` is never persisted and the readiness result
            // in the §2c health loop is only logged, so we evaluate the probe
            // live here rather than relying on stored state.
            // NOTE: stable per-ordinal headless DNS (serviceName-based
            // rk-<name>-<ord>.<svc> records) is still NOT wired — that is a
            // separate, larger networking change and out of scope here.
            let sts_next: Option<u32> = if dep.stateful {
                let sts_prefix = format!("rk-{name}-");
                let readiness = dep.containers.first().and_then(|c| c.readiness_probe.as_ref());
                let startup = dep.containers.first().and_then(|c| c.startup_probe.as_ref());
                let mut existing_ord: std::collections::HashSet<u32> = std::collections::HashSet::new();
                let mut ready_ord: std::collections::HashSet<u32> = std::collections::HashSet::new();
                for c in &managed {
                    let cname = c.names.iter()
                        .map(|n| n.trim_start_matches('/'))
                        .find(|n| n.starts_with(&sts_prefix));
                    let Some(cname) = cname else { continue };
                    let Some(ord) = cname.rsplit('-').next().and_then(|s| s.parse::<u32>().ok()) else { continue };
                    existing_ord.insert(ord);
                    if c.state != "running" { continue; }
                    let started = startup.is_none() || desired.startup_ok.contains(cname);
                    let is_ready = match readiness {
                        Some(probe) => started && check_probe(&c.id[..12.min(c.id.len())], probe),
                        None => started,
                    };
                    if is_ready { ready_ord.insert(ord); }
                }
                let decision = next_statefulset_ordinal(&existing_ord, &ready_ord, desired_count);
                if decision.is_none() && (existing_ord.len() as u32) < desired_count {
                    log.push(format!("  [statefulset] {name}: holding — previous ordinal not Ready yet"));
                }
                decision
            } else {
                None
            };

            for i in 0..needed {
                // Find next available name
                let mut idx = if dep.stateful {
                    match sts_next {
                        Some(o) => o,
                        // Predecessor not Ready (or set complete) → create
                        // nothing this tick; retry on the next reconcile.
                        None => break,
                    }
                } else {
                    current + i + 1
                };
                loop {
                    let candidate = format!("rk-{name}-{idx}");
                    if !all_names.contains(&candidate) { break; }
                    idx += 1;
                }
                let pod_name = format!("rk-{name}-{idx}");

                // Multi-node: pick best node for this pod
                let target_node = if !desired.nodes.is_empty() {
                    pick_node(desired)
                } else {
                    None
                };
                log.push(format!("    [multi-node] {} node(s) known, pick_node({pod_name}) → {:?}",
                    desired.nodes.len(), target_node));
                if let Some(ref node_name) = target_node {
                    if let Some(node) = desired.nodes.get(node_name) {
                        let is_local = node.address.starts_with("127.0.0.1")
                            || node.address.starts_with("localhost")
                            || node.address.is_empty();
                        if !is_local && !node.address.is_empty() {
                            // Remote node: send create request via API
                            let url = format!("http://{}/royak/v1/create-pod", node.address);
                            let body = serde_json::json!({
                                "pod": pod_name,
                                "deployment": name,
                                "image": dep.containers.first().map(|c| c.image.as_str()).unwrap_or(""),
                                "replicas": 1
                            });
                            log.push(format!("    [multi-node] routing {pod_name} → {node_name} ({url})"));
                            // Fire-and-forget over the private subnet — but a
                            // PROPER request. The old hand-rolled HTTP had no Host
                            // header, which the peer's HTTP server rejects, so no
                            // pod was ever actually created remotely.
                            if let Ok(body_str) = serde_json::to_string(&body) {
                                let (u, p, nn) = (url.clone(), pod_name.clone(), node_name.clone());
                                std::thread::spawn(move || {
                                    if let Err(e) = http_post(&u, &body_str, &[("Content-Type", "application/json")]) {
                                        eprintln!("  ⚠ [multi-node] {p} → {nn} create-pod failed: {e}");
                                    }
                                });
                            }
                            // Update node pod count
                            if let Some(n) = desired.nodes.get_mut(node_name) {
                                n.pod_count += 1;
                            }
                            continue; // skip local creation
                        }
                    }
                }
                let mut _main_container_id: Option<String> = None;

                // Run init containers first (must complete before main starts)
                let mut init_ok = true;
                for init in &dep.init_containers {
                    let init_name = format!("{pod_name}-init-{}", init.name);
                    log.push(format!("    [init] {init_name} starting..."));
                    docker::pull_image(&init.image).ok();
                    let cmd_refs: Vec<&str> = init.command.as_ref()
                        .map(|c| c.iter().map(|s| s.as_str()).collect()).unwrap_or_default();
                    let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };
                    let labels = vec![(MANAGED_LABEL, "true"), ("royak.init", "true"), ("royak.pod", pod_name.as_str())];
                    match docker::create_container(&init_name, &init.image, cmd, &init.env, &labels) {
                        Ok(id) => {
                            docker::start_container(&id).ok();
                            // Wait for init container to complete (max 60s)
                            let start = Instant::now();
                            loop {
                                if start.elapsed() > Duration::from_secs(60) {
                                    log.push(format!("    [init] {init_name} TIMEOUT"));
                                    init_ok = false;
                                    break;
                                }
                                if let Ok(containers) = docker::list_containers(true) {
                                    if let Some(c) = containers.iter().find(|c| c.names.iter().any(|n| n.trim_start_matches('/') == init_name)) {
                                        if c.state == "exited" {
                                            log.push(format!("    [init] {init_name} completed ✓"));
                                            docker::remove_container(&id, true).ok();
                                            break;
                                        }
                                    }
                                }
                                std::thread::sleep(Duration::from_millis(500));
                            }
                        }
                        Err(e) => {
                            log.push(format!("    [init] {init_name} failed: {e}"));
                            init_ok = false;
                        }
                    }
                    if !init_ok { break; }
                }

                if !init_ok {
                    log.push(format!("    [error] {pod_name}: init container failed, skipping pod"));
                    continue;
                }

                for (ci, container) in dep.containers.iter().enumerate() {
                    let is_main = ci == 0;
                    let container_name = if is_main {
                        pod_name.clone()
                    } else {
                        format!("{pod_name}-{}", container.name)
                    };

                    // Merge env: container env + envFrom ConfigMaps/Secrets + metadata
                    let mut full_env = container.env.clone();
                    for cm_name in &container.env_from_configmaps {
                        if let Some(cm) = desired.configmaps.get(cm_name) {
                            for (k, v) in &cm.data {
                                full_env.push(format!("{k}={v}"));
                            }
                        }
                    }
                    for secret_name in &container.env_from_secrets {
                        if let Some(secret) = desired.secrets.get(secret_name) {
                            for (k, v) in &secret.data {
                                full_env.push(format!("{k}={v}"));
                            }
                        }
                    }
                    full_env.push(format!("ROYAK_POD_NAME={pod_name}"));
                    full_env.push(format!("ROYAK_CONTAINER={}", container.name));
                    full_env.push(format!("ROYAK_NAMESPACE={}", dep.namespace));
                    full_env.push(format!("ROYAK_DEPLOYMENT={name}"));

                    // v0.2: Pod identity + mTLS certificates
                    if let Some(ref mut ca) = desired.cluster_ca {
                        match ca.issue_pod_cert(&pod_name, &dep.namespace) {
                            Ok(identity) => {
                                full_env.extend(identity.env_vars());
                                let now = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                                desired.pod_certs.insert(pod_name.clone(), PodCertStatus {
                                    pod_name: pod_name.clone(),
                                    namespace: dep.namespace.clone(),
                                    issued_at: now,
                                    expires_at: now + 90 * 86400, // 90 days
                                    fingerprint: format!("{:x}", ca.issued_count),
                                    revoked: false,
                                });
                                log.push(format!("    [mtls] {pod_name} cert issued (CA: {}, expires: 90d)", ca.fingerprint));
                            }
                            Err(e) => {
                                // Fallback: just inject a token without cert
                                let token = crate::net_security::generate_pod_token(&pod_name, &dep.namespace, "cluster");
                                full_env.push(format!("ROYAK_POD_TOKEN={token}"));
                                log.push(format!("    [warn] mtls cert failed: {e}, token-only"));
                            }
                        }
                    } else {
                        // No CA — generate pod token only
                        let token = crate::net_security::generate_pod_token(&pod_name, &dep.namespace, "cluster");
                        full_env.push(format!("ROYAK_POD_TOKEN={token}"));
                    }

                    let cmd_refs: Vec<&str> = container.command.as_ref()
                        .map(|c| c.iter().map(|s| s.as_str()).collect())
                        .unwrap_or_default();
                    let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };

                    let labels = vec![
                        (MANAGED_LABEL, "true"),
                        ("royak.deployment", name.as_str()),
                        ("royak.namespace", dep.namespace.as_str()),
                        ("royak.pod", pod_name.as_str()),
                        if is_main { ("royak.role", "main") } else { ("royak.role", "sidecar") },
                    ];

                    let cpu_lim = dep.resource_limits.as_ref().and_then(|r| r.cpu_limit);
                    let mem_lim = dep.resource_limits.as_ref().and_then(|r| r.mem_limit);

                    // Resolve PVC volumes: find bound PVs and add their host paths
                    let mut all_volumes = container.volumes.clone();
                    for (host_or_pvc, container_path) in &container.volumes {
                        // ConfigMap/Secret projected as files: materialise each
                        // key as a file in a host dir and bind-mount it.
                        // (K8s projects these via kubelet; we use the same
                        // mechanism as our other volumes. Updates land when the
                        // pod is recreated — CM hot-reload triggers that.)
                        if let Some(src_name) = host_or_pvc.strip_prefix("cmv:").map(|n| (n, false))
                            .or_else(|| host_or_pvc.strip_prefix("sev:").map(|n| (n, true)))
                        {
                            let (obj_name, is_secret) = src_name;
                            let kind_dir = if is_secret { "secret" } else { "configmap" };
                            let dir = format!("{}/volumes/{}/{kind_dir}-{obj_name}", royak_data_dir(), dep.namespace);
                            std::fs::create_dir_all(&dir).ok();
                            let data: Option<Vec<(String, String)>> = if is_secret {
                                desired.secrets.get(obj_name).map(|s| s.data.clone().into_iter().collect())
                            } else {
                                desired.configmaps.get(obj_name).map(|c| c.data.clone().into_iter().collect())
                            };
                            if let Some(entries) = data {
                                for (k, val) in entries {
                                    let file = format!("{dir}/{k}");
                                    let _ = std::fs::write(&file, val);
                                    #[cfg(unix)]
                                    if is_secret {
                                        use std::os::unix::fs::PermissionsExt;
                                        let _ = std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600));
                                    }
                                }
                                all_volumes.retain(|(h, _)| h != host_or_pvc);
                                all_volumes.push((dir.clone(), container_path.clone()));
                                log.push(format!("    [volume] {kind_dir}/{obj_name} projected → {container_path}"));
                            } else {
                                log.push(format!("    [warn] volume references missing {kind_dir}/{obj_name}"));
                            }
                            continue;
                        }
                        // StatefulSet volumeClaimTemplate: per-ordinal host dir
                        // (vct:name → /tmp/royak-pvc/{ns}/{dep}-{name}-{ordinal})
                        if let Some(tpl_name) = host_or_pvc.strip_prefix("vct:") {
                            let dir = format!("{}/pvc/{}/{}-{}-{}", royak_data_dir(), dep.namespace, name, tpl_name, idx);
                            std::fs::create_dir_all(&dir).ok();
                            all_volumes.retain(|(h, _)| h != host_or_pvc);
                            all_volumes.push((dir.clone(), container_path.clone()));
                            log.push(format!("    [volume] {tpl_name} (ordinal {idx}) → {dir}"));
                            continue;
                        }
                        // Check if this is a PVC reference (pvc:name format)
                        if let Some(pvc_name) = host_or_pvc.strip_prefix("pvc:") {
                            if let Some(pvc) = desired.pvcs.get(pvc_name) {
                                if let Some(pv_name) = &pvc.bound_pv {
                                    if let Some(pv) = desired.pvs.get(pv_name) {
                                        // Replace pvc: reference with actual host path
                                        all_volumes.retain(|(h, _)| h != host_or_pvc);
                                        all_volumes.push((pv.host_path.clone(), container_path.clone()));
                                        log.push(format!("    [volume] {pvc_name} → {}", pv.host_path));
                                    }
                                }
                            }
                        }
                    }

                    let publish = if is_main { desired.nodeport_publish_ports(name) } else { Vec::new() };
                    match docker::create_container_full(&container_name, &container.image, cmd, &full_env, &labels, &all_volumes, cpu_lim, mem_lim, &publish) {
                        Ok(id) => {
                            let short = &id[..12.min(id.len())];
                            let role = if is_main { "main" } else { "sidecar" };
                            log.push(format!("    [create] {container_name} ({role}) → {short}"));

                            match docker::start_container(&id) {
                                Ok(_) => {
                                    log.push(format!("    [start] {container_name} ✓"));
                                    pending_events.push(("Pod".into(), container_name.clone(), "Created".into(), format!("Container started: {}", container.image), "Normal".into()));
                                    if is_main {
                                        _main_container_id = Some(id.clone());
                                        // Collect all DNS aliases in a single vec: pod name, deployment name,
                                        // and any matching service names in the same namespace. Docker
                                        // ignores aliases added to an already-connected container, so
                                        // all of them must be passed on the first connect call.
                                        let mut alias_strs: Vec<String> = vec![pod_name.clone(), name.to_string()];
                                        for svc in desired.services.values() {
                                            if svc.namespace == dep.namespace
                                                && svc.selector.get("app").map(|s| s.as_str()) == Some(name)
                                            {
                                                alias_strs.push(svc.name.clone());
                                            }
                                        }
                                        let aliases: Vec<&str> = alias_strs.iter().map(|s| s.as_str()).collect();
                                        let ns_net = format!("rk-{}", dep.namespace);
                                        match docker::connect_to_network(&id, &ns_net, &aliases) {
                                            Ok(_) => log.push(format!("    [net] {pod_name} → {ns_net} ({name})")),
                                            Err(_) => {
                                                // Fallback to global network with same aliases
                                                docker::connect_network(&id, &aliases).ok();
                                                log.push(format!("    [net] {pod_name} → royak (fallback)"));
                                            }
                                        }
                                        // Log service alias bindings (for diagnostics)
                                        for svc in desired.services.values() {
                                            if svc.namespace == dep.namespace
                                                && svc.selector.get("app").map(|s| s.as_str()) == Some(name)
                                            {
                                                log.push(format!("    [svc] {pod_name} → dns:{}", svc.name));
                                            }
                                        }
                                    } else {
                                        let aliases = vec![container_name.as_str()];
                                        let ns_net = format!("rk-{}", dep.namespace);
                                        docker::connect_to_network(&id, &ns_net, &aliases).ok();
                                        log.push(format!("    [sidecar] {container_name} joined {ns_net}"));
                                    }
                                }
                                Err(e) => {
                                    log.push(format!("    [error] start {container_name}: {e}"));
                                    pending_events.push(("Pod".into(), container_name.clone(), "StartFailed".into(), format!("{e}"), "Warning".into()));
                                }
                            }
                        }
                        Err(e) => {
                            log.push(format!("    [error] create {container_name}: {e}"));
                            pending_events.push(("Pod".into(), container_name.clone(), "CreateFailed".into(), format!("{e}"), "Warning".into()));
                        }
                    }
                } // end container loop
            } // end pod loop
        } else if current > desired_count {
            // Scale DOWN
            let excess = current - desired_count;
            log.push(format!("  [scale] {name}: {current} → {desired_count} (-{excess})"));
            pending_events.push(("Deployment".into(), name.clone(), "ScalingDown".into(), format!("{current} → {desired_count} (-{excess})"), "Normal".into()));

            // StatefulSet scale-down removes the highest ordinal first
            // (K8s semantics); plain deployments keep Docker's order.
            let victims: Vec<&crate::docker::DockerContainer> = if dep.stateful {
                let ordinal = |c: &crate::docker::DockerContainer| -> u32 {
                    c.names.first()
                        .and_then(|n| n.rsplit('-').next())
                        .and_then(|s| s.parse::<u32>().ok())
                        .unwrap_or(0)
                };
                let mut sorted: Vec<&crate::docker::DockerContainer> =
                    running.iter().map(|c| **c).collect();
                sorted.sort_by_key(|c| std::cmp::Reverse(ordinal(c)));
                sorted.into_iter().take(excess as usize).collect()
            } else {
                running.iter().rev().take(excess as usize).map(|c| **c).collect()
            };
            for container in victims {
                let id = &container.id;
                let cname = container.names.first().map(|s| s.as_str()).unwrap_or("?");
                if let Err(e) = docker::stop_container(id) {
                    log.push(format!("    [warn] stop {cname}: {e}"));
                }
                if let Err(e) = docker::remove_container(id, true) {
                    log.push(format!("    [warn] rm {cname}: {e}"));
                } else {
                    log.push(format!("    [remove] {cname} ✓"));
                }
            }
        } else {
            // All good — reset crash counters for healthy pods
            let prefix = format!("rk-{name}-");
            desired.restart_count.retain(|k, _| !k.starts_with(&prefix));
            log.push(format!("  [ok] {name}: {current}/{desired_count} running"));
        }

        // Clean up stopped/failed containers — with CrashLoopBackOff detection
        for container in &stopped {
            let id = &container.id;
            let cname = container.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
            if container.state == "exited" || container.state == "dead" {
                // Track restart count
                let count = desired.restart_count.entry(cname.to_string()).or_insert(0);
                *count += 1;
                if *count >= 5 {
                    log.push(format!("  [CrashLoopBackOff] {cname}: restarted {} times — stopping", count));
                    pending_events.push(("Pod".into(), cname.to_string(), "CrashLoopBackOff".into(),
                        format!("Container has restarted {} times", count), "Warning".into()));
                    docker::remove_container(id, true).ok();
                    // Don't recreate — the deployment loop will see fewer running pods
                    // but we mark it so it stops trying
                } else {
                    docker::remove_container(id, true).ok();
                    log.push(format!("  [cleanup] removed {cname} ({}), restart #{}", container.state, count));
                }
            }
        }
    }

    // 2b. Rolling updates — zero-downtime image changes (maxSurge=1, maxUnavailable=0)
    let rollout_names: Vec<String> = desired.pending_rollouts.keys().cloned().collect();
    for dep_name in &rollout_names {
        let rollout = match desired.pending_rollouts.get(dep_name) {
            Some(r) => r,
            None => continue,
        };
        let dep = match desired.deployments.get(dep_name.as_str()) {
            Some(d) => d,
            None => continue,
        };

        log.push(format!("  [rollout] {dep_name}: {} → {} ({}/{} done)",
            rollout.old_image, rollout.new_image, rollout.new_pods_created, rollout.total_replicas));

        // Find old pods (running with old image) — exact image match
        let prefix = format!("/rk-{dep_name}-");
        let old_norm = normalize_image(&rollout.old_image);
        let new_norm = normalize_image(&rollout.new_image);

        let old_pods: Vec<&docker::DockerContainer> = managed.iter()
            .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix))
                && c.state == "running"
                && normalize_image(&c.image) == old_norm)
            .copied()
            .collect();

        let new_pods: Vec<&docker::DockerContainer> = managed.iter()
            .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix))
                && c.state == "running"
                && normalize_image(&c.image) == new_norm)
            .copied()
            .collect();

        let new_running = new_pods.len() as u32;

        if new_running >= rollout.total_replicas {
            // Rollout complete — remove any remaining old pods
            for old in &old_pods {
                let cname = old.names.first().map(|s| s.as_str()).unwrap_or("?");
                docker::stop_container(&old.id).ok();
                docker::remove_container(&old.id, true).ok();
                log.push(format!("    [rollout] removed old {cname} ✓"));
            }
            log.push(format!("  [rollout] {dep_name}: COMPLETE ✓ ({} pods on {})",
                rollout.total_replicas, rollout.new_image));
            desired.record_event("Deployment", dep_name, "RolloutComplete", &format!("{} → {} ({} pods)", rollout.old_image, rollout.new_image, rollout.total_replicas), "Normal");
        } else if new_running + 1 > old_pods.len() as u32 + rollout.total_replicas {
            // maxSurge exceeded, wait for readiness of existing new pods
            log.push(format!("  [rollout] {dep_name}: waiting for new pods to become ready..."));
        } else {
            // Step 1: create one new pod (maxSurge=1)
            // Find next available name by checking ALL containers (including non-running)
            let all_names: Vec<String> = managed.iter()
                .flat_map(|c| c.names.iter().map(|n| n.trim_start_matches('/').to_string()))
                .collect();
            let mut next_idx = 1u32;
            loop {
                let candidate = format!("rk-{dep_name}-{next_idx}");
                if !all_names.iter().any(|n| n == &candidate) {
                    break;
                }
                next_idx += 1;
                if next_idx > 100 { break; } // safety limit
            }
            let pod_name = format!("rk-{dep_name}-{next_idx}");

            let container = &dep.containers[0];
            log.push(format!("    [rollout] creating {pod_name} ({})...", rollout.new_image));

            // Pull new image
            if let Err(e) = docker::pull_image(&rollout.new_image) {
                log.push(format!("    [rollout] pull failed: {e}"));
            }

            let mut full_env = container.env.clone();
            full_env.push(format!("ROYAK_POD_NAME={pod_name}"));
            full_env.push(format!("ROYAK_DEPLOYMENT={dep_name}"));

            let cmd_refs: Vec<&str> = container.command.as_ref()
                .map(|c| c.iter().map(|s| s.as_str()).collect()).unwrap_or_default();
            let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };
            let labels = vec![
                (MANAGED_LABEL, "true"),
                ("royak.deployment", dep_name.as_str()),
                ("royak.pod", pod_name.as_str()),
                ("royak.role", "main"),
            ];

            let cpu_lim = dep.resource_limits.as_ref().and_then(|r| r.cpu_limit);
            let mem_lim = dep.resource_limits.as_ref().and_then(|r| r.mem_limit);
            let publish = desired.nodeport_publish_ports(dep_name);
            match docker::create_container_full(&pod_name, &container.image, cmd, &full_env, &labels, &container.volumes, cpu_lim, mem_lim, &publish) {
                Ok(id) => {
                    if docker::start_container(&id).is_ok() {
                        let aliases = vec![pod_name.as_str(), dep_name.as_str()];
                        let ns_net = format!("rk-{}", dep.namespace);
                        docker::connect_to_network(&id, &ns_net, &aliases)
                            .or_else(|_| docker::connect_network(&id, &aliases)).ok();
                        log.push(format!("    [rollout] {pod_name} started ✓"));

                        // Check readiness if probe exists — retry a few times
                        let ready = if let Some(probe) = &container.readiness_probe {
                            std::thread::sleep(Duration::from_secs(probe.initial_delay_seconds.max(2)));
                            let mut ok = false;
                            for _ in 0..3 {
                                if check_probe(&id[..12.min(id.len())], probe) {
                                    ok = true;
                                    break;
                                }
                                std::thread::sleep(Duration::from_secs(2));
                            }
                            ok
                        } else {
                            // No probe = assume ready after 3s
                            std::thread::sleep(Duration::from_secs(3));
                            true
                        };

                        if ready {
                            // Step 2: kill one old pod (maxUnavailable=0 — new is ready first)
                            if let Some(old) = old_pods.first() {
                                let old_name = old.names.first().map(|s| s.as_str()).unwrap_or("?");
                                docker::stop_container(&old.id).ok();
                                docker::remove_container(&old.id, true).ok();
                                log.push(format!("    [rollout] replaced {old_name} → {pod_name} ✓"));
                            }
                        } else {
                            log.push(format!("    [rollout] {pod_name} not ready yet, will retry next tick"));
                        }
                    }
                }
                Err(e) => log.push(format!("    [rollout] error creating {pod_name}: {e}")),
            }
        }
    }

    // Remove completed rollouts
    desired.pending_rollouts.retain(|name, rollout| {
        let prefix = format!("/rk-{name}-");
        let new_norm = normalize_image(&rollout.new_image);
        let new_running = managed.iter()
            .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix))
                && c.state == "running"
                && normalize_image(&c.image) == new_norm)
            .count() as u32;
        new_running < rollout.total_replicas
    });

    // 2b+. Canary and Blue-Green deployment strategies
    let dep_names: Vec<String> = desired.deployments.keys().cloned().collect();
    for dep_name in &dep_names {
        let strategy = desired.deployments.get(dep_name.as_str()).and_then(|d| d.strategy.clone());
        match strategy {
            Some(DeployStrategy::Canary { weight, steps }) => {
                // Canary: run `weight`% of pods with new image, rest with old
                if let Some(rollout) = desired.pending_rollouts.get(dep_name.as_str()) {
                    let total = rollout.total_replicas;
                    // Current step weight (use weight field, advance through steps)
                    let current_weight = if steps.is_empty() { weight } else {
                        let new_running = managed.iter()
                            .filter(|c| c.names.iter().any(|n| n.contains(&format!("rk-{dep_name}-")))
                                && c.state == "running"
                                && normalize_image(&c.image) == normalize_image(&rollout.new_image))
                            .count() as u32;
                        let current_pct = if total > 0 { (new_running * 100) / total } else { 0 };
                        // Find next step to reach
                        steps.iter().find(|s| s.weight > current_pct)
                            .map(|s| s.weight).unwrap_or(100)
                    };
                    let canary_count = (total * current_weight / 100).max(1);
                    log.push(format!("  [canary] {dep_name}: {current_weight}% traffic → {canary_count}/{total} pods with new image"));
                }
            }
            Some(DeployStrategy::BlueGreen { ref active }) => {
                // Blue-Green: maintain two full sets, switch `active` label
                if let Some(rollout) = desired.pending_rollouts.get(dep_name.as_str()) {
                    let prefix = format!("rk-{dep_name}-");
                    let new_norm = normalize_image(&rollout.new_image);
                    let new_ready: Vec<&docker::DockerContainer> = managed.iter()
                        .filter(|c| c.names.iter().any(|n| n.contains(&prefix))
                            && c.state == "running"
                            && normalize_image(&c.image) == new_norm)
                        .copied()
                        .collect();

                    if new_ready.len() as u32 >= rollout.total_replicas {
                        // Green set is fully ready — switch traffic
                        if active == "green" || active == "new" {
                            // Kill old (blue) pods
                            let old_norm = normalize_image(&rollout.old_image);
                            let old_pods: Vec<&docker::DockerContainer> = managed.iter()
                                .filter(|c| c.names.iter().any(|n| n.contains(&prefix))
                                    && normalize_image(&c.image) == old_norm)
                                .copied()
                                .collect();
                            for old in &old_pods {
                                let cname = old.names.first().map(|s| s.as_str()).unwrap_or("?");
                                docker::stop_container(&old.id).ok();
                                docker::remove_container(&old.id, true).ok();
                                log.push(format!("    [blue-green] removed old {cname}"));
                            }
                            log.push(format!("  [blue-green] {dep_name}: switched to green ✓ ({} pods)", rollout.total_replicas));
                        } else {
                            log.push(format!("  [blue-green] {dep_name}: green ready ({} pods), waiting for switch command", new_ready.len()));
                        }
                    } else {
                        log.push(format!("  [blue-green] {dep_name}: green {}/{} ready, blue still active",
                            new_ready.len(), rollout.total_replicas));
                    }
                }
            }
            _ => {} // RollingUpdate handled above, None = default rolling
        }
    }

    // 2c. Health checks — startup, liveness and readiness probes for running pods
    let mut startup_passed: Vec<String> = Vec::new();
    let mut startup_restart: Vec<String> = Vec::new();
    for (name, dep) in &desired.deployments {
        let main_container = dep.containers.first();
        let liveness = main_container.and_then(|c| c.liveness_probe.as_ref());
        let readiness = main_container.and_then(|c| c.readiness_probe.as_ref());
        let startup = main_container.and_then(|c| c.startup_probe.as_ref());

        if liveness.is_none() && readiness.is_none() && startup.is_none() {
            continue;
        }

        let prefix = format!("/rk-{name}-");
        let running_pods: Vec<&&docker::DockerContainer> = managed.iter()
            .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix)) && c.state == "running")
            .collect();

        for container in &running_pods {
            let pod_name = container.names.first()
                .map(|s| s.trim_start_matches('/').to_string())
                .unwrap_or_default();
            let short_id = &container.id[..12.min(container.id.len())];

            // Startup probe gates liveness: until it passes, the pod is
            // "starting" and liveness failures must not restart it (K8s
            // semantics — slow starters get failureThreshold × period grace).
            let started = startup.is_none() || desired.startup_ok.contains(&pod_name);
            if !started {
                let probe = startup.unwrap();
                if check_probe(short_id, probe) {
                    startup_passed.push(pod_name.clone());
                    log.push(format!("  [startup] {pod_name}: started ✓"));
                } else {
                    let key = format!("startup:{pod_name}");
                    let count = desired.restart_count.get(&key).copied().unwrap_or(0) + 1;
                    startup_restart.push(key.clone());
                    if count >= probe.failure_threshold {
                        log.push(format!("  [startup] {pod_name}: FAILED {count}x — restarting"));
                        pending_events.push(("Pod".into(), pod_name.clone(), "Unhealthy".into(), "Startup probe failed — restarting".into(), "Warning".into()));
                        docker::stop_container(&container.id).ok();
                        docker::start_container(&container.id).ok();
                    } else {
                        log.push(format!("  [startup] {pod_name}: not started yet ({count}/{})", probe.failure_threshold));
                    }
                }
                continue; // liveness/readiness wait for startup
            }

            // Liveness probe — restart if failed too many times
            if let Some(probe) = liveness {
                let healthy = check_probe(short_id, probe);
                if !healthy {
                    log.push(format!("  [health] {pod_name}: liveness FAILED — restarting"));
                    pending_events.push(("Pod".into(), pod_name.clone(), "Unhealthy".into(), "Liveness probe failed — restarting".into(), "Warning".into()));
                    docker::stop_container(&container.id).ok();
                    docker::start_container(&container.id).ok();
                } else {
                    log.push(format!("  [health] {pod_name}: liveness ok ✓"));
                }
            }

            // Readiness probe — just report (affects rolling updates)
            if let Some(probe) = readiness {
                let ready = check_probe(short_id, probe);
                if ready {
                    log.push(format!("  [ready] {pod_name}: ready ✓"));
                } else {
                    log.push(format!("  [ready] {pod_name}: NOT ready"));
                }
            }
        }
    }

    // Apply startup-probe bookkeeping collected during the borrow above.
    for pod in startup_passed {
        desired.restart_count.remove(&format!("startup:{pod}"));
        desired.startup_ok.insert(pod);
    }
    for key in startup_restart {
        *desired.restart_count.entry(key).or_insert(0) += 1;
    }

    // 2d. Node health — check heartbeats, mark dead nodes
    let node_logs = check_node_health(desired);
    for line in &node_logs { log.push(line.clone()); }

    // Update local node metrics (match ANY registered node on localhost)
    let pod_count = managed.iter().filter(|c| c.state == "running").count() as u32;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();
    // Refresh OUR OWN node entry every tick so we never mark ourselves NotReady.
    // Match by our node name first (works even with a real advertise address);
    // fall back to a loopback address, then the first node.
    let me = local_node_name();
    let local_name = desired.nodes.get(&me).map(|_| me.clone())
        .or_else(|| desired.nodes.iter().find(|(_, n)| n.address.contains("127.0.0.1")).map(|(n, _)| n.clone()))
        .or_else(|| desired.nodes.keys().next().cloned());
    if let Some(name) = local_name {
        if let Some(local) = desired.nodes.get_mut(&name) {
            local.last_heartbeat = now;
            local.pod_count = pod_count;
            // We are, by definition, alive here — never leave ourselves NotReady
            // (check_node_health only demotes; the endpoint promotes peers).
            local.status = NodeStatus::Ready;
        }
    }

    // 2e. ANOMALY — neural container monitoring (learn patterns, detect deviations)
    // Docker's /stats samples ~1-2s per call; fetching serially over N containers
    // stalled the whole reconcile (which holds the world lock, blocking the API).
    // Fetch all containers' stats in PARALLEL, then feed the brain serially.
    let stat_targets: Vec<(String, String)> = managed.iter()
        .filter(|c| c.state == "running")
        .map(|c| {
            let name = c.names.first().map(|s| s.trim_start_matches('/').to_string()).unwrap_or_default();
            (name, c.id[..12.min(c.id.len())].to_string())
        })
        .collect();
    let stat_handles: Vec<_> = stat_targets.into_iter()
        .map(|(name, short)| std::thread::spawn(move || (name, docker::container_stats_peek(&short))))
        .collect();
    for h in stat_handles {
        // Skip on failure — don't poison baselines with 0.0.
        if let Ok((name, Ok((cpu, mem)))) = h.join() {
            brain.observe(&name, cpu, mem, 0);
        }
    }

    // Check for anomalies + auto-alert via webhooks
    let anomalies = brain.detect_anomalies();
    for (pod, anomaly_type, value, threshold) in &anomalies {
        let msg = match anomaly_type.as_str() {
            "CPU" => format!("⚠ {pod}: CPU {value:.1}% exceeds baseline ({threshold:.1}%)"),
            "MEM" => format!("⚠ {pod}: MEM {value:.0}MB exceeds baseline ({threshold:.0}MB)"),
            "RESTART" => format!("⚠ {pod}: unexpected restart (was {threshold:.0}, now {value:.0})"),
            _ => format!("⚠ {pod}: {anomaly_type} ({value:.1} vs {threshold:.1})"),
        };
        log.push(format!("  [ANOMALY] {msg}"));

        // Auto-invoke alert webhook functions
        let alert_functions: Vec<String> = desired.functions.values()
            .filter(|f| f.webhook_triggers.iter().any(|t| t.contains("alert") || t.contains("notify")))
            .map(|f| f.name.clone())
            .collect();
        for func_name in &alert_functions {
            match invoke_function(desired, func_name) {
                Ok(result) => log.push(format!("    [alert] → {func_name}: {result}")),
                Err(e) => log.push(format!("    [alert] → {func_name} failed: {e}")),
            }
        }

        // Neural Guards: brain detected anomaly → guard acts
        let matching_ops: Vec<(String, String)> = desired.guards.values()
            .flat_map(|op| op.rules.iter()
                .filter(|r| match r.when.as_str() {
                    "anomaly" | "high_cpu" => anomaly_type == "CPU",
                    "high_memory" => anomaly_type == "MEM",
                    "pod_crash" => anomaly_type == "RESTART",
                    _ => r.when == *anomaly_type,
                })
                .map(|r| (op.name.clone(), r.action.clone())))
            .collect();
        for (op_name, action) in &matching_ops {
            log.push(format!("    [operator/{op_name}] → {action} on {pod}"));
            match action.as_str() {
                "restart" => {
                    if let Some(cid) = managed.iter().find(|c| c.names.iter().any(|n| n.contains(pod))) {
                        docker::stop_container(&cid.id).ok();
                        docker::start_container(&cid.id).ok();
                        log.push(format!("    [operator/{op_name}] restarted {pod} ✓"));
                    }
                }
                "scale_up" => {
                    let dep_name = pod.split('-').take(2).collect::<Vec<_>>().join("-").trim_start_matches("rk-").to_string();
                    if let Some(dep) = desired.deployments.get_mut(&dep_name) {
                        dep.replicas += 1;
                        log.push(format!("    [operator/{op_name}] scaled {dep_name} to {} ✓", dep.replicas));
                    }
                }
                _ => {
                    // Check hooks
                    if let Some(op) = desired.guards.get(op_name) {
                        if let Some(hook_cmd) = op.hooks.get(&action.to_string()) {
                            let output = safe_exec_hook(hook_cmd);
                            log.push(format!("    [guard/{op_name}] hook: {output}"));
                        }
                    }
                }
            }
        }
    }

    // 2f. OPERATORS — reconcile custom resources (CRD → provision → lifecycle)
    reconcile_operators(desired, &mut log);

    // 2g. PAUSE — Neural scale-to-zero for idle pods
    let dep_names: Vec<String> = desired.deployments.keys().cloned().collect();
    for dep_name in &dep_names {
        let dep = match desired.deployments.get(dep_name) {
            Some(d) => d,
            None => continue,
        };
        let pause_threshold = match dep.pause_after_idle {
            Some(t) if t > 0 => t,
            _ => continue,
        };

        let prefix = format!("/rk-{dep_name}-");
        let running_pods: Vec<&docker::DockerContainer> = managed.iter()
            .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix)) && c.state == "running")
            .copied()
            .collect();

        if dep.paused {
            // Already paused — nothing to do (wake-up handled by external traffic/watch)
            log.push(format!("  [pause] {dep_name}: hibernated 💤 ({} pods stopped)", dep.replicas));
            continue;
        }

        // Check if all pods are idle (CPU < 1%)
        let all_idle = !running_pods.is_empty() && running_pods.iter().all(|c| {
            let short_id = &c.id[..12.min(c.id.len())];
            docker::container_stats_peek(short_id)
                .map(|(cpu, _)| cpu < 1.0)
                .unwrap_or(false)
        });

        if all_idle {
            let idle_ticks = dep.idle_since.unwrap_or(brain.ticks);
            let idle_duration = (brain.ticks - idle_ticks) * 5; // assume 5s per tick

            if let Some(dep_mut) = desired.deployments.get_mut(dep_name) {
                if dep_mut.idle_since.is_none() {
                    dep_mut.idle_since = Some(brain.ticks);
                }
            }

            if idle_duration >= pause_threshold {
                // Hibernate! Stop all pods but keep state
                log.push(format!("  [pause] {dep_name}: idle for {idle_duration}s — HIBERNATING"));
                for pod in &running_pods {
                    docker::stop_container(&pod.id).ok();
                    let cname = pod.names.first().map(|s| s.as_str()).unwrap_or("?");
                    log.push(format!("    [pause] stopped {cname} 💤"));
                }
                if let Some(dep_mut) = desired.deployments.get_mut(dep_name) {
                    dep_mut.paused = true;
                }
            } else {
                let remaining = pause_threshold - idle_duration;
                log.push(format!("  [pause] {dep_name}: idle ({remaining}s until hibernate)"));
            }
        } else {
            // Not idle — reset counter
            if let Some(dep_mut) = desired.deployments.get_mut(dep_name) {
                dep_mut.idle_since = None;
            }
        }
    }

    // 3. DaemonSets — ensure one pod per "node" (single-node for now = 1 pod)
    for (name, ds) in &desired.daemonsets {
        let prefix = format!("/rk-ds-{name}");
        let running = managed.iter().any(|c| c.names.iter().any(|n| n.starts_with(&prefix)) && c.state == "running");

        if !running {
            let pod_name = format!("rk-ds-{name}");
            log.push(format!("  [daemonset] {name}: deploying to node"));
            docker::pull_image(&ds.container.image).ok();
            let cmd_refs: Vec<&str> = ds.container.command.as_ref()
                .map(|c| c.iter().map(|s| s.as_str()).collect()).unwrap_or_default();
            let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };
            let labels = vec![(MANAGED_LABEL, "true"), ("royak.daemonset", name.as_str())];
            if let Ok(id) = docker::create_container(&pod_name, &ds.container.image, cmd, &ds.container.env, &labels) {
                docker::start_container(&id).ok();
                let ns_net = format!("rk-{}", ds.namespace);
                docker::connect_to_network(&id, &ns_net, &[pod_name.as_str(), name.as_str()])
                    .or_else(|_| docker::connect_network(&id, &[pod_name.as_str(), name.as_str()])).ok();
                log.push(format!("    [start] {pod_name} ✓"));
            }
        } else {
            log.push(format!("  [ok] daemonset/{name}: running"));
        }
    }

    // 4. Jobs — run to completion
    for (name, job) in &desired.jobs {
        let prefix = format!("/rk-job-{name}");
        let exists = managed.iter().any(|c| c.names.iter().any(|n| n.starts_with(&prefix)));
        let completed = managed.iter().any(|c| c.names.iter().any(|n| n.starts_with(&prefix)) && c.state == "exited");

        if !exists {
            let pod_name = format!("rk-job-{name}");
            log.push(format!("  [job] {name}: starting"));
            docker::pull_image(&job.container.image).ok();
            let cmd_refs: Vec<&str> = job.container.command.as_ref()
                .map(|c| c.iter().map(|s| s.as_str()).collect()).unwrap_or_default();
            let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };
            let labels = vec![(MANAGED_LABEL, "true"), ("royak.job", name.as_str())];
            if let Ok(id) = docker::create_container(&pod_name, &job.container.image, cmd, &job.container.env, &labels) {
                docker::start_container(&id).ok();
                log.push(format!("    [start] {pod_name} ✓"));
            }
        } else if completed {
            log.push(format!("  [ok] job/{name}: completed"));
        } else {
            log.push(format!("  [ok] job/{name}: running"));
        }
    }

    // 5. HPA — PREDICTIVE auto-scaling (not just reactive)
    let hpa_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut hpa_scale_actions: Vec<(String, u32)> = Vec::new();
    let mut hpa_scaled_names: Vec<String> = Vec::new();
    for (hpa_key, hpa) in desired.hpas.iter() {
        if let Some(dep) = desired.deployments.get(&hpa.deployment) {
            let prefix = format!("/rk-{}-", hpa.deployment);
            let running_count = managed.iter()
                .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix)) && c.state == "running")
                .count() as u32;

            // Get REAL average CPU across deployment pods
            let avg_cpu = if running_count > 0 {
                let total: f32 = managed.iter()
                    .filter(|c| c.names.iter().any(|n| n.starts_with(&prefix)) && c.state == "running")
                    .filter_map(|c| docker::container_stats_peek(&c.id[..12.min(c.id.len())]).ok())
                    .map(|(cpu, _)| cpu)
                    .sum();
                total / running_count as f32
            } else {
                0.0
            };
            let simulated_cpu = avg_cpu; // renamed for compatibility

            // Record for brain learning
            brain.record_load(&hpa.deployment, simulated_cpu, dep.replicas);

            let current = dep.replicas;
            let trend = brain.trend(&hpa.deployment);

            // PREDICT: check if brain predicts future load spike
            if let Some((predicted_cpu, confidence, suggested)) = brain.predict_load(&hpa.deployment, hpa.target_cpu, hpa.max_replicas) {
                if confidence > 0.3 && suggested != current {
                    log.push(format!("  [PREDICT] {}: trend {trend}, predicted CPU {predicted_cpu:.0}% (conf: {confidence:.0}%), suggest {current} → {suggested}",
                        hpa.deployment));
                }
            }

            // Reactive scaling (immediate need), guarded by a stabilization
            // window so CPU crossing the threshold on consecutive ticks can't
            // thrash the deployment up and down.
            let secs_since_scale = hpa.last_scaled
                .map(|t| hpa_now.saturating_sub(t))
                .unwrap_or(u64::MAX);
            let decision = hpa_decision(
                current, simulated_cpu, hpa.target_cpu,
                hpa.min_replicas, hpa.max_replicas,
                secs_since_scale, HPA_STABILIZATION_SECS,
            );
            match decision {
                Some(target) if target > current => {
                    log.push(format!("  [hpa] {}: CPU {simulated_cpu:.0}% > {:.0}% target → scale {current} → {target} (trend: {trend})",
                        hpa.deployment, hpa.target_cpu));
                    hpa_scale_actions.push((hpa.deployment.clone(), target));
                    hpa_scaled_names.push(hpa_key.clone());
                }
                Some(target) => {
                    log.push(format!("  [hpa] {}: CPU {simulated_cpu:.0}% < {:.0}% → scale down {current} → {target} (trend: {trend})",
                        hpa.deployment, hpa.target_cpu * 0.5));
                    hpa_scale_actions.push((hpa.deployment.clone(), target));
                    hpa_scaled_names.push(hpa_key.clone());
                }
                None => {
                    // Distinguish "held by cooldown" from "nothing to do" for clarity.
                    let would_change = (simulated_cpu > hpa.target_cpu && current < hpa.max_replicas)
                        || (simulated_cpu < hpa.target_cpu * 0.5 && current > hpa.min_replicas);
                    if would_change && secs_since_scale < HPA_STABILIZATION_SECS {
                        log.push(format!("  [hpa] {}: CPU {simulated_cpu:.0}% — holding {current} replicas ({}s into {HPA_STABILIZATION_SECS}s stabilization window)",
                            hpa.deployment, secs_since_scale));
                    } else {
                        log.push(format!("  [hpa] {}: CPU {simulated_cpu:.0}% — {current} replicas ok (trend: {trend})", hpa.deployment));
                    }
                }
            }
        }
    }
    // Apply deferred HPA scale actions
    for (dep_name, target) in hpa_scale_actions {
        if let Some(dep) = desired.deployments.get_mut(&dep_name) {
            dep.replicas = target;
        }
    }
    // Stamp last_scaled so the stabilization window starts now (deferred to
    // avoid a mutable borrow while iterating hpas above).
    for hpa_key in hpa_scaled_names {
        if let Some(hpa) = desired.hpas.get_mut(&hpa_key) {
            hpa.last_scaled = Some(hpa_now);
        }
    }

    // 6. CronJobs — check schedule (simple minute-based check)
    let mut cronjob_runs: Vec<String> = Vec::new();
    for (name, cron) in &desired.cronjobs {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
        let should_run = if let Some(last) = cron.last_run {
            let interval_mins: u64 = cron.schedule.split_whitespace().next()
                .and_then(|s| s.trim_start_matches("*/").parse().ok())
                .unwrap_or(5);
            now - last > interval_mins * 60
        } else {
            true
        };

        if should_run {
            let run_id = (now % 10000) as u32;
            let pod_name = format!("rk-cron-{name}-{run_id}");
            log.push(format!("  [cronjob] {name}: triggering ({}) ", cron.schedule));
            docker::pull_image(&cron.container.image).ok();
            let cmd_refs: Vec<&str> = cron.container.command.as_ref()
                .map(|c| c.iter().map(|s| s.as_str()).collect()).unwrap_or_default();
            let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };
            let labels = vec![(MANAGED_LABEL, "true"), ("royak.cronjob", name.as_str())];
            if let Ok(id) = docker::create_container(&pod_name, &cron.container.image, cmd, &cron.container.env, &labels) {
                docker::start_container(&id).ok();
                log.push(format!("    [start] {pod_name} ✓"));
            }
            cronjob_runs.push(name.clone());
        }
    }
    // Update last_run timestamps (deferred to avoid borrow conflict)
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    for name in cronjob_runs {
        if let Some(cron) = desired.cronjobs.get_mut(&name) {
            cron.last_run = Some(now);
        }
    }

    // 7. Git repo watching — detect new commits, auto-trigger pipelines
    let repo_triggers: Vec<(String, String)> = desired.repositories.iter()
        .filter_map(|(name, repo)| {
            repo.pipeline.as_ref().map(|p| (name.clone(), p.clone()))
        })
        .collect();

    for (repo_name, pipeline_name) in &repo_triggers {
        if let Some(repo) = desired.repositories.get(repo_name) {
            if let Some(path) = &repo.path {
                // Local repo — check git HEAD
                let head = std::process::Command::new("git")
                    .args(["rev-parse", "HEAD"])
                    .current_dir(path)
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .map(|s| s.trim().to_string());

                if let Some(commit) = head {
                    let changed = repo.last_commit.as_ref().map(|lc| lc != &commit).unwrap_or(true);
                    if changed {
                        log.push(format!("  [repo] {repo_name}: new commit {}", &commit[..8.min(commit.len())]));
                        // Update last_commit
                        if let Some(repo_mut) = desired.repositories.get_mut(repo_name) {
                            repo_mut.last_commit = Some(commit);
                        }
                        // Auto-trigger pipeline
                        if desired.pipelines.contains_key(pipeline_name.as_str()) {
                            match start_pipeline(desired, pipeline_name) {
                                Ok(run_id) => log.push(format!("  [repo] triggered pipeline/{pipeline_name} (run #{run_id})")),
                                Err(e) => log.push(format!("  [repo] trigger failed: {e}")),
                            }
                        }
                    }
                }
            } else if let Some(url) = &repo.url {
                // Remote repo — git ls-remote
                let head = std::process::Command::new("git")
                    .args(["ls-remote", url, &format!("refs/heads/{}", repo.branch)])
                    .output()
                    .ok()
                    .and_then(|o| String::from_utf8(o.stdout).ok())
                    .and_then(|s| s.split_whitespace().next().map(|h| h.to_string()));

                if let Some(commit) = head {
                    let changed = repo.last_commit.as_ref().map(|lc| lc != &commit).unwrap_or(true);
                    if changed {
                        log.push(format!("  [repo] {repo_name}: remote commit {}", &commit[..8.min(commit.len())]));
                        if let Some(repo_mut) = desired.repositories.get_mut(repo_name) {
                            repo_mut.last_commit = Some(commit);
                        }
                        if desired.pipelines.contains_key(pipeline_name.as_str()) {
                            match start_pipeline(desired, pipeline_name) {
                                Ok(run_id) => log.push(format!("  [repo] triggered pipeline/{pipeline_name} (run #{run_id})")),
                                Err(e) => log.push(format!("  [repo] trigger failed: {e}")),
                            }
                        }
                    }
                }
            }
        }
    }

    // 8. Pipeline runs — execute stages as Jobs in DAG order

    // Pre-pass: advance in-flight background BUILD stages. Builds run off-thread
    // (not as containers), so the container-based completion detection never
    // fires for them — poll the build registry directly and update their status.
    {
        let mut updates: Vec<(usize, String, StageStatus, String)> = Vec::new();
        for (ri, run) in desired.pipeline_runs.iter().enumerate() {
            let pipeline = match desired.pipelines.get(&run.pipeline) { Some(p) => p, None => continue };
            for s in pipeline.stages.iter().filter(|s| s.action.as_deref() == Some("build")) {
                let running = run.stage_status.iter().any(|(n, st)| n == &s.name && *st == StageStatus::Running);
                if !running { continue; }
                let tag = s.tag.clone().unwrap_or_else(|| format!("royak-{}:{}", run.pipeline, run.run_id));
                let job = format!("rk-build-{}-{}-{}", run.pipeline, run.run_id, s.name);
                match docker::poll_build(&job) {
                    docker::BuildPoll::Done(Ok(_)) => {
                        docker::clear_build(&job);
                        updates.push((ri, s.name.clone(), StageStatus::Succeeded,
                            format!("  [pipeline] {}#{}: stage '{}' built {tag} ✓", run.pipeline, run.run_id, s.name)));
                    }
                    docker::BuildPoll::Done(Err(e)) => {
                        docker::clear_build(&job);
                        let short: String = e.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(&e).chars().take(200).collect();
                        updates.push((ri, s.name.clone(), StageStatus::Failed,
                            format!("  [pipeline] {}#{}: stage '{}' ✗ build failed: {short}", run.pipeline, run.run_id, s.name)));
                    }
                    docker::BuildPoll::NotStarted => {
                        // Process restarted mid-build; the in-memory job is gone.
                        // Reset to Pending so the stage rebuilds (crash-safety).
                        updates.push((ri, s.name.clone(), StageStatus::Pending,
                            format!("  [pipeline] {}#{}: stage '{}' build lost (restart) → retrying", run.pipeline, run.run_id, s.name)));
                    }
                    docker::BuildPoll::Running => {}
                }
            }
        }
        for (ri, sname, st, msg) in updates {
            if let Some(run_mut) = desired.pipeline_runs.get_mut(ri) {
                for (n, s) in run_mut.stage_status.iter_mut() { if n == &sname { *s = st.clone(); } }
            }
            log.push(msg);
        }
    }

    let mut run_idx = 0;
    while run_idx < desired.pipeline_runs.len() {
        let run = &desired.pipeline_runs[run_idx];
        let pipeline_name = run.pipeline.clone();
        let run_id = run.run_id;

        let pipeline = match desired.pipelines.get(&pipeline_name) {
            Some(p) => p,
            None => { run_idx += 1; continue; }
        };

        if run.is_complete() {
            let all_ok = run.stage_status.iter().all(|(_, s)| matches!(s, StageStatus::Succeeded | StageStatus::Skipped));
            let status = if all_ok { "SUCCEEDED" } else { "FAILED" };
            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: {status} ✓"));
            run_idx += 1;
            continue;
        }

        // Find next runnable stage
        let next_stage_name = run.next_runnable();
        if let Some(stage_name) = next_stage_name {
            // Check if dependencies are met
            let stage_def = pipeline.stages.iter().find(|s| s.name == stage_name);
            let deps_met = if let Some(sd) = stage_def {
                if let Some(dep) = &sd.depends_on {
                    run.stage_status.iter().any(|(n, s)| n == dep && *s == StageStatus::Succeeded)
                } else {
                    true
                }
            } else {
                true
            };

            // Check if dependency FAILED → skip this stage
            let dep_failed = if let Some(sd) = stage_def {
                if let Some(dep) = &sd.depends_on {
                    run.stage_status.iter().any(|(n, s)| n == dep && *s == StageStatus::Failed)
                } else {
                    false
                }
            } else {
                false
            };

            if dep_failed {
                // Mark as skipped
                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                    for (n, s) in run_mut.stage_status.iter_mut() {
                        if n == &stage_name { *s = StageStatus::Skipped; }
                    }
                }
                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' SKIPPED (dependency failed)"));
                continue; // check next stage in same tick
            }

            if !deps_met {
                // Check if the dependency is currently running as a container
                let dep_name = stage_def.and_then(|s| s.depends_on.as_ref()).unwrap();
                let job_name = format!("rk-pipe-{pipeline_name}-{run_id}-{dep_name}");
                let dep_running = managed.iter().any(|c|
                    c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && c.state == "running");
                let dep_exited = managed.iter().find(|c|
                    c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && c.state == "exited");

                if let Some(exited) = dep_exited {
                    // Dep finished — check exit code via logs heuristic (exited = succeeded for now)
                    let _ = exited;
                    if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                        for (n, s) in run_mut.stage_status.iter_mut() {
                            if n == dep_name { *s = StageStatus::Succeeded; }
                        }
                    }
                    log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{dep_name}' completed ✓"));
                    continue; // re-evaluate this run
                } else if dep_running {
                    log.push(format!("  [pipeline] {pipeline_name}#{run_id}: waiting for '{dep_name}'..."));
                }
                run_idx += 1;
                continue;
            }

            // Check conditional (if:)
            if let Some(sd) = stage_def {
                if let Some(cond) = &sd.if_condition {
                    let skip = match cond.as_str() {
                        "always" => false,
                        "failure" => {
                            // Only run on prior failure
                            !run.stage_status.iter().any(|(_, s)| *s == StageStatus::Failed)
                        }
                        c if c.starts_with("branch") => {
                            // Simple branch check: "branch == main"
                            // Look up repo branch from any linked repository
                            let target_branch = c.split("==").nth(1).map(|s| s.trim()).unwrap_or("main");
                            let current_branch = desired.repositories.values()
                                .next().map(|r| r.branch.as_str()).unwrap_or("main");
                            current_branch != target_branch
                        }
                        _ => false,
                    };
                    if skip {
                        if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                            for (n, s) in run_mut.stage_status.iter_mut() {
                                if n == &stage_name { *s = StageStatus::Skipped; }
                            }
                        }
                        log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' SKIPPED (condition: {cond})"));
                        continue;
                    }
                }
            }

            // Execute the stage (with matrix expansion)
            if let Some(sd) = stage_def {
                if let Some(action) = &sd.action {
                    // Action stage (e.g., "apply")
                    if action == "apply" {
                        if let Some(file) = &sd.file {
                            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' → apply {file}"));
                            match spec::parse_file(file) {
                                Ok(resources) => {
                                    for r in &resources {
                                        match desired.apply(&r) {
                                            Ok(msg) => log.push(format!("    ✓ {msg}")),
                                            Err(e) => log.push(format!("    ✗ {e}")),
                                        }
                                    }
                                    if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                        for (n, s) in run_mut.stage_status.iter_mut() {
                                            if n == &stage_name { *s = StageStatus::Succeeded; }
                                        }
                                    }
                                }
                                Err(e) => {
                                    log.push(format!("    ✗ apply failed: {e}"));
                                    if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                        for (n, s) in run_mut.stage_status.iter_mut() {
                                            if n == &stage_name { *s = StageStatus::Failed; }
                                        }
                                    }
                                }
                            }
                        }
                    } else if action == "build" {
                        // Build an image from a git context (PaaS: source → image).
                        // The build runs on a background thread so it never blocks
                        // the reconcile loop; we poll it across ticks like a Job.
                        let job = format!("rk-build-{pipeline_name}-{run_id}-{stage_name}");
                        let ctx_name = sd.context.clone();
                        let dockerfile = sd.dockerfile.clone().unwrap_or_else(|| "Dockerfile".to_string());
                        let tag = sd.tag.clone().unwrap_or_else(|| format!("royak-{pipeline_name}:{run_id}"));
                        let build_args = sd.build_args.clone();
                        // `sd` / `pipeline` are not used past this point in this arm.
                        match docker::poll_build(&job) {
                            docker::BuildPoll::NotStarted => {
                                let branch = desired.repositories.values().next()
                                    .map(|r| r.branch.clone()).unwrap_or_else(|| "main".to_string());
                                // Default context = the pipeline's first linked repo.
                                let ctx = ctx_name.or_else(|| desired.repositories.keys().next().cloned());
                                match ctx {
                                    None => {
                                        log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' ✗ build: no context (set stage.context or register a repo)"));
                                        if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                            for (n, s) in run_mut.stage_status.iter_mut() {
                                                if n == &stage_name { *s = StageStatus::Failed; }
                                            }
                                        }
                                    }
                                    Some(cn) => match resolve_build_context(desired, &cn, &branch) {
                                        Ok(dir) => {
                                            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' → build {tag} from {dir} ({dockerfile})"));
                                            docker::start_build(&job, dir, dockerfile, tag, build_args);
                                            if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                                for (n, s) in run_mut.stage_status.iter_mut() {
                                                    if n == &stage_name { *s = StageStatus::Running; }
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' ✗ build context: {e}"));
                                            if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                                for (n, s) in run_mut.stage_status.iter_mut() {
                                                    if n == &stage_name { *s = StageStatus::Failed; }
                                                }
                                            }
                                        }
                                    },
                                }
                            }
                            docker::BuildPoll::Running => {
                                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: building '{stage_name}'..."));
                            }
                            docker::BuildPoll::Done(Ok(_)) => {
                                docker::clear_build(&job);
                                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' built {tag} ✓"));
                                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                    for (n, s) in run_mut.stage_status.iter_mut() {
                                        if n == &stage_name { *s = StageStatus::Succeeded; }
                                    }
                                }
                            }
                            docker::BuildPoll::Done(Err(e)) => {
                                docker::clear_build(&job);
                                let short: String = e.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or(&e).chars().take(200).collect();
                                log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' ✗ build failed: {short}"));
                                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                    for (n, s) in run_mut.stage_status.iter_mut() {
                                        if n == &stage_name { *s = StageStatus::Failed; }
                                    }
                                }
                            }
                        }
                    }
                } else if sd.image.is_some() || !sd.matrix_images.is_empty() {
                    // Container stage — run as Job(s), with matrix expansion
                    let images: Vec<String> = if !sd.matrix_images.is_empty() {
                        sd.matrix_images.clone()
                    } else {
                        vec![sd.image.clone().unwrap_or_default()]
                    };
                    let is_matrix = images.len() > 1;
                    let mut all_done = true;
                    let any_failed = false;

                    for (mi, image) in images.iter().enumerate() {
                    let job_name = if is_matrix {
                        format!("rk-pipe-{pipeline_name}-{run_id}-{stage_name}-m{mi}")
                    } else {
                        format!("rk-pipe-{pipeline_name}-{run_id}-{stage_name}")
                    };

                    // Check if already running/completed
                    let exists = managed.iter().any(|c|
                        c.names.iter().any(|n| n.trim_start_matches('/') == job_name));

                    if !exists {
                        log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' → {image}"));
                        docker::pull_image(image).ok();
                        let cmd_refs: Vec<&str> = sd.command.as_ref()
                            .map(|c| c.iter().map(|s| s.as_str()).collect()).unwrap_or_default();
                        let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };
                        let labels = vec![
                            (MANAGED_LABEL, "true"),
                            ("royak.pipeline", pipeline_name.as_str()),
                            ("royak.stage", stage_name.as_str()),
                        ];
                        // Inject ALL secrets into pipeline stages (like GitHub Actions secrets)
                        let mut full_env = sd.env.clone();
                        for secret in desired.secrets.values() {
                            for (k, v) in &secret.data {
                                full_env.push(format!("{k}={v}"));
                            }
                        }
                        full_env.push(format!("ROYAK_PIPELINE={pipeline_name}"));
                        full_env.push(format!("ROYAK_STAGE={stage_name}"));
                        full_env.push(format!("ROYAK_RUN_ID={run_id}"));
                        match docker::create_container(&job_name, image, cmd, &full_env, &labels) {
                            Ok(id) => {
                                docker::start_container(&id).ok();
                                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                    for (n, s) in run_mut.stage_status.iter_mut() {
                                        if n == &stage_name { *s = StageStatus::Running; }
                                    }
                                }
                                log.push(format!("    [start] {job_name} ✓"));
                            }
                            Err(e) => {
                                log.push(format!("    [error] {job_name}: {e}"));
                                if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                    for (n, s) in run_mut.stage_status.iter_mut() {
                                        if n == &stage_name { *s = StageStatus::Failed; }
                                    }
                                }
                            }
                        }
                    } else {
                        // Check completion
                        let exited = managed.iter().any(|c|
                            c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && c.state == "exited");
                        let still_running = managed.iter().any(|c|
                            c.names.iter().any(|n| n.trim_start_matches('/') == job_name) && c.state == "running");
                        if exited {
                            log.push(format!("    [matrix] {job_name} completed ✓"));
                        } else if still_running {
                            all_done = false;
                        } else {
                            all_done = false;
                        }
                    }
                    } // end matrix loop

                    // Update stage status based on matrix results
                    if is_matrix {
                        if all_done && !any_failed {
                            if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                for (n, s) in run_mut.stage_status.iter_mut() {
                                    if n == &stage_name { *s = StageStatus::Succeeded; }
                                }
                            }
                            log.push(format!("  [pipeline] {pipeline_name}#{run_id}: stage '{stage_name}' ALL matrix jobs completed ✓"));
                        } else if any_failed {
                            if let Some(run_mut) = desired.pipeline_runs.get_mut(run_idx) {
                                for (n, s) in run_mut.stage_status.iter_mut() {
                                    if n == &stage_name { *s = StageStatus::Failed; }
                                }
                            }
                        }
                    }
                }
            }
        }
        run_idx += 1;
    }

    // Clean up completed pipeline runs (keep last 10)
    desired.pipeline_runs.retain(|r| !r.is_complete());

    // Flush deferred events
    for (kind, object, reason, message, event_type) in pending_events {
        desired.record_event(&kind, &object, &reason, &message, &event_type);
    }

    // ─── NetworkPolicy enforcement + neural threat detection ───
    if !desired.network_policies.is_empty() {
        let managed_refs: Vec<&docker::DockerContainer> = managed.iter().map(|c| *c).collect();
        enforce_network_policies(desired, &managed_refs, &mut log);
    }

    // ─── Brain training: learn from this tick's decisions ───
    {
        // Build cluster state snapshot for training
        let pods: Vec<crate::brain::PodState> = managed.iter()
            .filter(|c| c.state == "running")
            .map(|c| {
                let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                let short_id = &c.id[..12.min(c.id.len())];
                let (cpu, mem) = docker::container_stats_peek(short_id).unwrap_or((0.0, 0.0));
                crate::brain::PodState {
                    id: short_id.to_string(), name: name.to_string(),
                    node: "local".to_string(), status: crate::brain::PodStatus::Running,
                    cpu_pct: cpu, mem_mb: mem, restarts: 0, age_secs: 0,
                    image: c.image.clone(),
                }
            })
            .collect();

        let desired_states: Vec<crate::brain::DesiredState> = desired.deployments.values()
            .map(|d| crate::brain::DesiredState {
                name: d.name.clone(), replicas: d.replicas,
                image: d.image.clone(),
                cpu_limit: d.resource_limits.as_ref().and_then(|r| r.cpu_limit).unwrap_or(1.0),
                mem_limit: d.resource_limits.as_ref().and_then(|r| r.mem_limit).unwrap_or(512) as f32,
            })
            .collect();

        if !pods.is_empty() {
            let cluster_state = crate::brain::ClusterState {
                pods, nodes: vec![], desired: desired_states,
            };

            // Get what rules decided this tick
            let decision = brain.tick(&cluster_state);
            let target = brain.decisions_to_target(&cluster_state, &decision.actions);

            // Train one step
            let loss = brain.train_step(&cluster_state, &target, 0.001);
            if brain.train_steps % 10 == 0 {
                log.push(format!("  [brain] trained: step={}, loss={loss:.4}", brain.train_steps));
            }
        }
    }

    // Save brain weights periodically
    if brain.train_steps > 0 && brain.train_steps % 50 == 0 {
        if brain.save_weights(".royak-brain.bin").is_ok() {
            log.push(format!("  [brain] weights saved (step={}, loss={:.4})", brain.train_steps, brain.last_loss));
        }
    }

    log
}

/// Split an iptables rule string into an argv vector.
fn sh(rule: &str) -> Vec<String> {
    rule.split_whitespace().map(|s| s.to_string()).collect()
}

/// Enforce NetworkPolicy rules via Docker network isolation.
///
/// When a NetworkPolicy exists for a namespace:
///   - Pods in that namespace are on `rk-{namespace}` (isolated by default)
///   - ingress_allow entries connect pods to allowed source namespace networks
///   - egress_allow entries connect pods to allowed destination namespace networks
///
/// Without NetworkPolicy, pods communicate freely within their namespace.
fn enforce_network_policies(desired: &mut DesiredWorld, managed: &[&docker::DockerContainer], log: &mut Vec<String>) {
    let policies: Vec<StoredNetworkPolicy> = desired.network_policies.values()
        .map(|p| StoredNetworkPolicy {
            name: p.name.clone(), namespace: p.namespace.clone(),
            pod_selector: p.pod_selector.clone(),
            ingress_allow: p.ingress_allow.clone(), egress_allow: p.egress_allow.clone(),
            ingress_ports: p.ingress_ports.clone(), egress_ports: p.egress_ports.clone(),
            internal: p.internal, mtls_required: p.mtls_required, deny_all: p.deny_all,
        })
        .collect();

    for policy in &policies {
        let target_ns = &policy.namespace;
        let selector = &policy.pod_selector;

        // Find containers matching the policy selector in this namespace
        let matching: Vec<&&docker::DockerContainer> = managed.iter()
            .filter(|c| {
                let in_ns = c.labels.get("royak.namespace").map(|s| s.as_str()) == Some(target_ns.as_str())
                    || (target_ns == "default" && !c.labels.contains_key("royak.namespace"));
                let matches_selector = if selector == "*" {
                    true
                } else {
                    c.names.iter().any(|n| n.contains(selector.as_str()))
                        || c.labels.get("royak.deployment").map(|s| s.as_str()) == Some(selector.as_str())
                };
                in_ns && matches_selector
            })
            .collect();

        if matching.is_empty() { continue; }

        // v0.2: Internal network — block all external traffic
        if policy.internal {
            log.push(format!("  [netpol] {}: INTERNAL mode — no external traffic for {} pods",
                policy.name, matching.len()));
            desired.network_audit.push(crate::net_security::NetworkAuditEntry::new(
                "enforce", target_ns, "external", &policy.name, "blocked_egress"));
        }

        // v0.2: mTLS required flag
        if policy.mtls_required {
            log.push(format!("  [netpol] {}: mTLS REQUIRED for {} pods",
                policy.name, matching.len()));
        }

        // v0.2: Port-level rules
        if !policy.ingress_ports.is_empty() {
            log.push(format!("  [netpol] {}: ingress ports {:?}",
                policy.name, policy.ingress_ports));
        }
        if !policy.egress_ports.is_empty() {
            log.push(format!("  [netpol] {}: egress ports {:?}",
                policy.name, policy.egress_ports));
        }

        // Enforce ingress: connect matching pods to allowed source namespace networks
        for allow_src in &policy.ingress_allow {
            if allow_src == "*" { continue; }

            // Parse "ns:name" format
            let src_ns = allow_src.strip_prefix("ns:").unwrap_or(allow_src);
            let src_net = format!("rk-{src_ns}");
            docker::ensure_namespace_network(src_ns).ok();

            for c in &matching {
                let short_id = &c.id[..12.min(c.id.len())];
                let pod_name = c.names.first().map(|n| n.trim_start_matches('/')).unwrap_or("?");
                match docker::connect_to_network(short_id, &src_net, &[]) {
                    Ok(_) => {
                        log.push(format!("  [netpol] {}: allow ingress {src_ns} → {pod_name}", policy.name));
                        desired.network_audit.push(crate::net_security::NetworkAuditEntry::policy_allow(
                            pod_name, &src_net, &policy.name));
                        desired.net_tracker.observe(pod_name, &src_net);
                    }
                    Err(_) => {} // already connected
                }
            }
        }

        // Enforce egress: connect matching pods to allowed destination namespace networks
        for allow_dst in &policy.egress_allow {
            if allow_dst == "*" { continue; }

            let dst_ns = allow_dst.strip_prefix("ns:").unwrap_or(allow_dst);
            let dst_net = format!("rk-{dst_ns}");
            docker::ensure_namespace_network(dst_ns).ok();

            for c in &matching {
                let short_id = &c.id[..12.min(c.id.len())];
                let pod_name = c.names.first().map(|n| n.trim_start_matches('/')).unwrap_or("?");
                match docker::connect_to_network(short_id, &dst_net, &[]) {
                    Ok(_) => {
                        log.push(format!("  [netpol] {}: allow egress {pod_name} → {dst_ns}", policy.name));
                        desired.network_audit.push(crate::net_security::NetworkAuditEntry::policy_allow(
                            pod_name, &dst_net, &policy.name));
                        desired.net_tracker.observe(pod_name, &dst_net);
                    }
                    Err(_) => {}
                }
            }
        }

        // ── Real L4 enforcement via iptables in each pod's netns ──
        // Only when the policy actually restricts traffic (deny_all / internal
        // / an egress port allow-list). Allow-only policies stay membership-
        // based. We stamp a marker file so we don't re-apply every tick.
        let needs_l4 = policy.deny_all || policy.internal || !policy.egress_ports.is_empty();
        if needs_l4 {
            for c in &matching {
                let short_id = &c.id[..12.min(c.id.len())];
                let pod_name = c.names.first().map(|n| n.trim_start_matches('/')).unwrap_or("?");
                // Key the marker on the CONTAINER ID, not the pod name: a
                // recreated pod (crash/restart) gets a new id + fresh netns with
                // no rules, so it must be re-enforced rather than skipped.
                let marker = format!("netpol:{}:{}", policy.name, short_id);
                if desired.netpol_applied.contains(&marker) { continue; }

                let mut rules: Vec<Vec<String>> = vec![
                    // Start clean, then always allow loopback + established/related
                    // (so replies to permitted outbound and localhost keep working).
                    sh("-F OUTPUT"),
                    sh("-A OUTPUT -o lo -j ACCEPT"),
                    sh("-A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"),
                    // DNS is needed for service discovery; allow it explicitly.
                    sh("-A OUTPUT -p udp --dport 53 -j ACCEPT"),
                    sh("-A OUTPUT -p tcp --dport 53 -j ACCEPT"),
                ];
                if !policy.egress_ports.is_empty() {
                    // Allow-list: permit only the named egress ports, drop the rest.
                    for p in &policy.egress_ports {
                        rules.push(sh(&format!("-A OUTPUT -p tcp --dport {p} -j ACCEPT")));
                    }
                    rules.push(sh("-A OUTPUT -j DROP"));
                } else if policy.deny_all || policy.internal {
                    // deny_all / internal: drop all remaining new outbound.
                    rules.push(sh("-A OUTPUT -j DROP"));
                }

                match crate::docker::apply_netns_iptables(short_id, &rules) {
                    Ok(()) => {
                        desired.netpol_applied.insert(marker);
                        log.push(format!("  [netpol] {}: L4 iptables enforced in {pod_name} netns", policy.name));
                    }
                    Err(e) => log.push(format!("  [netpol] {}: L4 enforce failed for {pod_name}: {e}", policy.name)),
                }
            }
        }

        log.push(format!("  [netpol] {}: enforced on {} pods (ns={target_ns}, selector={selector}{}{}{})",
            policy.name, matching.len(),
            if policy.internal { ", internal" } else { "" },
            if policy.mtls_required { ", mTLS" } else { "" },
            if policy.deny_all { ", deny-all" } else { "" },
        ));
    }

    // Neural threat detection: check for anomalies
    let anomalies = desired.net_tracker.detect_anomalies();
    for (pod, desc, severity) in &anomalies {
        log.push(format!("  [threat] ⚠ {pod}: {desc} (severity: {severity:.1})"));
        desired.network_audit.push(crate::net_security::NetworkAuditEntry::anomaly(pod, desc));
        desired.record_event("Pod", pod, "NetworkAnomaly", desc, "Warning");
    }

    // Trim audit log (keep last 1000 entries)
    if desired.network_audit.len() > 1000 {
        desired.network_audit.drain(..desired.network_audit.len() - 1000);
    }
}

// ─── NeuroPod Reconciler: orchestrate without Docker ───

/// Reconcile loop for NeuroPod runtime — no Docker daemon needed.
/// Creates/manages pods as isolated Linux processes with OverlayFS + namespaces.
pub fn reconcile_neuropod(desired: &mut DesiredWorld, _brain: &mut OrinBrain) -> Vec<String> {
    let mut log = Vec::new();

    // Initialize Cluster CA
    if desired.cluster_ca.is_none() {
        if let Ok(ca) = crate::net_security::ClusterCA::generate() {
            log.push(format!("  [security] Cluster CA generated (fp: {})", ca.fingerprint));
            desired.cluster_ca = Some(ca);
        }
    }

    // Ensure pod bridge network
    if let Err(e) = crate::runtime::ensure_pod_bridge() {
        log.push(format!("  [warn] bridge: {e}"));
    }

    // List existing NeuroPods
    let existing = crate::runtime::NeuroPod::list_all();
    let existing_names: std::collections::HashSet<String> = existing.iter()
        .map(|(name, _, _, _, _)| name.clone()).collect();

    let mut pod_index: u32 = existing.len() as u32;

    // For each deployment: create NeuroPods if needed
    for (name, dep) in &desired.deployments {
        let mut running = 0u32;
        for i in 1..=dep.replicas {
            let pod_name = format!("rk-{name}-{i}");
            if existing_names.contains(&pod_name) {
                // Check if actually running
                let meta_path = dirs_or_home().join(".royak").join("pods").join(&pod_name).join("meta.json");
                if meta_path.exists() {
                    running += 1;
                }
                continue;
            }

            // Quota check
            if let Err(reason) = desired.check_quota(&dep.namespace, 0) {
                log.push(format!("  [quota] {name}: BLOCKED — {reason}"));
                break;
            }

            // Create NeuroPod
            let disk_mb = dep.resource_limits.as_ref()
                .and_then(|r| r.mem_limit)
                .unwrap_or(512); // default 512MB disk
            let mount_path = "/data";

            match crate::runtime::NeuroPod::create(&pod_name, &dep.image, disk_mb, mount_path) {
                Ok(mut pod) => {
                    // Collect env
                    let mut env = dep.env.clone();
                    if let Some(c) = dep.containers.first() {
                        env.extend(c.env.clone());
                    }
                    env.push(format!("ROYAK_POD_NAME={pod_name}"));
                    env.push(format!("ROYAK_NAMESPACE={}", dep.namespace));
                    env.push(format!("ROYAK_DEPLOYMENT={name}"));

                    // Pod identity (mTLS cert + token)
                    if let Some(ref mut ca) = desired.cluster_ca {
                        if let Ok(identity) = ca.issue_pod_cert(&pod_name, &dep.namespace) {
                            env.extend(identity.env_vars());
                            log.push(format!("    [mtls] {pod_name} cert issued"));
                        }
                    }

                    // Set up network
                    pod_index += 1;
                    let ports: Vec<(u16, u16)> = Vec::new(); // TODO: parse from spec
                    match crate::runtime::create_pod_network(&pod_name, pod_index, &ports) {
                        Ok(net) => {
                            env.push(format!("NEUROPOD_IP={}", net.ip));
                            log.push(format!("    [net] {pod_name} → {} (bridge)", net.ip));
                        }
                        Err(e) => log.push(format!("    [net] {pod_name}: {e} (host networking)")),
                    }

                    // Start
                    let cmd_refs: Vec<&str> = dep.containers.first()
                        .and_then(|c| c.command.as_ref())
                        .map(|c| c.iter().map(|s| s.as_str()).collect())
                        .unwrap_or_default();
                    let cmd = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };

                    match pod.start(cmd, &env) {
                        Ok(pid) => {
                            log.push(format!("  [neuropod] {pod_name} started (pid={pid}, image={})", dep.image));
                            running += 1;
                        }
                        Err(e) => log.push(format!("  [neuropod] {pod_name} start failed: {e}")),
                    }
                }
                Err(e) => log.push(format!("  [neuropod] {pod_name} create failed: {e}")),
            }
        }
        log.push(format!("  [ok] {name}: {running}/{} neuropods", dep.replicas));
    }

    log
}

fn dirs_or_home() -> std::path::PathBuf {
    std::env::var("HOME").map(std::path::PathBuf::from).unwrap_or_else(|_| std::path::PathBuf::from("/tmp"))
}

/// Resolve a `build` stage's context into a local directory holding the source.
/// `ctx` is either a registered repository name or a filesystem path. A registered
/// remote repo (url, no local path) is cloned/updated under ~/.royak/repos/<name>,
/// so `git push` → build works end-to-end.
fn resolve_build_context(desired: &DesiredWorld, ctx: &str, branch: &str) -> Result<String, String> {
    if let Some(repo) = desired.repositories.get(ctx) {
        if let Some(p) = &repo.path {
            if std::path::Path::new(p).exists() { return Ok(p.clone()); }
            return Err(format!("repo '{ctx}' path '{p}' does not exist"));
        }
        if let Some(url) = &repo.url {
            let br = if repo.branch.is_empty() { branch } else { repo.branch.as_str() };
            let base = dirs_or_home().join(".royak").join("repos");
            let dest = base.join(ctx);
            let dest_str = dest.to_string_lossy().to_string();
            if dest.join(".git").exists() {
                // Existing checkout — fast-forward to the tip of the branch.
                std::process::Command::new("git")
                    .args(["-C", &dest_str, "fetch", "--depth", "1", "origin", br]).output().ok();
                let reset = std::process::Command::new("git")
                    .args(["-C", &dest_str, "reset", "--hard", &format!("origin/{br}")]).output()
                    .map_err(|e| format!("git reset failed: {e}"))?;
                if !reset.status.success() {
                    return Err(format!("git reset failed: {}", String::from_utf8_lossy(&reset.stderr)));
                }
            } else {
                std::fs::create_dir_all(&base).ok();
                let out = std::process::Command::new("git")
                    .args(["clone", "--depth", "1", "-b", br, url, &dest_str]).output()
                    .map_err(|e| format!("git clone failed: {e}"))?;
                if !out.status.success() {
                    return Err(format!("git clone failed: {}", String::from_utf8_lossy(&out.stderr)));
                }
            }
            return Ok(dest_str);
        }
        return Err(format!("repo '{ctx}' has neither path nor url"));
    }
    // Not a registered repo — treat as a direct filesystem path.
    if std::path::Path::new(ctx).exists() { return Ok(ctx.to_string()); }
    Err(format!("build context '{ctx}' not found (no such repository or path)"))
}

/// Start a pipeline run
pub fn start_pipeline(desired: &mut DesiredWorld, pipeline_name: &str) -> Result<u64, String> {
    let pipeline = desired.pipelines.get(pipeline_name)
        .ok_or_else(|| format!("Pipeline '{}' not found", pipeline_name))?;

    let run_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() % 100000;

    let stage_status: Vec<(String, StageStatus)> = pipeline.stages.iter()
        .map(|s| (s.name.clone(), StageStatus::Pending))
        .collect();

    desired.pipeline_runs.push(PipelineRun {
        pipeline: pipeline_name.to_string(),
        run_id,
        stage_status,
        started_at: Instant::now(),
    });

    desired.record_event("Pipeline", pipeline_name, "Triggered", &format!("Pipeline run #{run_id} started"), "Normal");

    Ok(run_id)
}

/// Run reconcile loop continuously with auto-persistence
#[allow(dead_code)]
pub fn run_loop(desired: &mut DesiredWorld, brain: &mut OrinBrain, interval_secs: u64) {
    println!("  Reconcile loop started (every {interval_secs}s)");
    println!("  Nodes: {} | Heartbeat: every 3 ticks\n", desired.nodes.len());

    loop {
        let start = Instant::now();
        let log = reconcile_once(desired, brain);
        brain.ticks += 1;
        let elapsed = start.elapsed();

        brain.set("cluster.last_tick".to_string(), brain.ticks.to_string());
        brain.set("cluster.last_reconcile_ms".to_string(), format!("{:.1}", elapsed.as_secs_f64() * 1000.0));

        println!("  ── tick {} ({:.1}ms) ──", brain.ticks, elapsed.as_secs_f64() * 1000.0);
        for line in &log {
            println!("{line}");
            // Surface the interesting decisions to the demo's live activity feed.
            let l = line.trim();
            if l.starts_with("[scale]") || l.starts_with("[multi-node]") || l.starts_with("[create]")
                || l.starts_with("[quota]") || l.contains("chaos") || l.contains("recovered")
                || l.contains("healing") || l.contains("pod lost") || l.contains("reconciling")
                || l.contains("rolling update") {
                crate::api::push_activity(l);
            }
        }

        // Node health + heartbeat every 3 ticks (~15s)
        if brain.ticks % 3 == 0 && desired.nodes.len() > 1 {
            let health_log = check_node_health(desired);
            for line in &health_log { println!("{line}"); }
            send_heartbeats(desired, brain);
        }

        std::thread::sleep(Duration::from_secs(interval_secs));
    }
}

/// Shared version of run_loop — API server and reconcile use the SAME DesiredWorld
#[allow(dead_code)]
pub fn run_loop_shared(
    world: std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    brain: &mut OrinBrain,
    interval_secs: u64,
    state_path: &str,
) {
    run_loop_shared_with_runtime(world, brain, interval_secs, state_path, false);
}

pub fn run_loop_shared_with_runtime(
    world: std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    brain: &mut OrinBrain,
    interval_secs: u64,
    state_path: &str,
    use_neuropod: bool,
) {
    // Graceful shutdown: catch SIGTERM/SIGINT
    install_shutdown_handler();

    // Leader election: derive a stable node id per process so lease
    // renewal and takeover can distinguish instances.
    let our_node_id = format!(
        "{}-{}",
        std::env::var("HOSTNAME").or_else(|_| std::env::var("HOST")).unwrap_or_else(|_| "local".to_string()),
        std::process::id()
    );

    {
        let w = world.read().unwrap();
        println!("  Reconcile loop started (every {interval_secs}s, shared state)");
        println!("  Node id:   {our_node_id}");
        println!("  Nodes: {} | Heartbeat: every 3 ticks\n", w.nodes.len());
    }

    let mut was_leader = false;
    loop {
        // Check for shutdown signal
        if SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
            eprintln!("\n  [shutdown] signal received — saving state...");
            let w = world.read().unwrap();
            // Full atomic save (schemaVersion + .nrns + flock) — export_state is the
            // node-sync wire format and is NOT loadable by load_state.
            crate::save_state(state_path, &w);
            // Save brain weights
            brain.save_weights(".royak-brain.bin").ok();
            // Release our lease so another instance can take over immediately.
            if was_leader {
                release_lease(state_path, &our_node_id);
            }
            eprintln!("  [shutdown] state + brain saved to {state_path}");
            eprintln!("  [shutdown] containers preserved (will resume on restart)");
            break;
        }

        // Try to acquire or renew the leader lease. Followers skip mutations
        // and check again next tick (automatic failover on leader crash).
        let is_leader = try_acquire_lease(state_path, &our_node_id);
        if is_leader != was_leader {
            if is_leader {
                println!("  [lease] ★ became leader ({our_node_id})");
            } else {
                println!("  [lease] ← lost leadership; entering standby");
            }
            was_leader = is_leader;
        }
        if !is_leader {
            println!("  ── [standby] another instance holds the lease ──");
            std::thread::sleep(Duration::from_secs(interval_secs));
            continue;
        }

        let start = Instant::now();

        // Lock world briefly for reconciliation
        let log = {
            let mut w = world.write().unwrap();
            reconcile_with_runtime(&mut w, brain, use_neuropod)
        };

        // Publish the lock-free read-model snapshots AFTER releasing the write
        // lock, so ingress requests and the demo dashboard never block on the
        // reconcile lock. One read guard feeds both.
        {
            let w = world.read().unwrap();
            crate::api::publish_ingress_snapshot(&w);
            crate::api::publish_demo_state(&w);
        }

        brain.ticks += 1;
        let elapsed = start.elapsed();
        brain.set("cluster.last_tick".to_string(), brain.ticks.to_string());
        brain.set("cluster.last_reconcile_ms".to_string(), format!("{:.1}", elapsed.as_secs_f64() * 1000.0));

        println!("  ── tick {} ({:.1}ms) ──", brain.ticks, elapsed.as_secs_f64() * 1000.0);
        for line in &log {
            println!("{line}");
            // Surface the interesting decisions to the demo's live activity feed.
            let l = line.trim();
            if l.starts_with("[scale]") || l.starts_with("[multi-node]") || l.starts_with("[create]")
                || l.starts_with("[quota]") || l.contains("chaos") || l.contains("recovered")
                || l.contains("healing") || l.contains("pod lost") || l.contains("reconciling")
                || l.contains("rolling update") {
                crate::api::push_activity(l);
            }
        }

        // Node health + heartbeat every 3 ticks (~15s)
        if brain.ticks % 3 == 0 {
            let node_count = { world.read().unwrap().nodes.len() };
            if node_count > 1 {
                // Health check (quick, needs write lock)
                {
                    let mut w = world.write().unwrap();
                    let health_log = check_node_health(&mut w);
                    for line in &health_log { println!("{line}"); }
                }
                // Heartbeats in background thread (non-blocking)
                let hb_world = std::sync::Arc::clone(&world);
                let hb_brain_identity = brain.neural_identity(
                    &std::env::var("HOSTNAME").or_else(|_| std::env::var("HOST")).unwrap_or_default()
                );
                std::thread::spawn(move || {
                    // Snapshot what we need under a BRIEF read lock, then do the
                    // network POSTs with NO lock held. Holding world.write() across
                    // http_post stalled the whole reconcile + ingress (site down)
                    // whenever a peer was slow — a 37s tick and 502s.
                    let token_b64 = OrinBrain::identity_base64(&hb_brain_identity);
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                    let (body, peers) = {
                        let w = hb_world.read().unwrap();
                        let local_hostname = local_node_name();
                        let local = w.nodes.get(&local_hostname);
                        let cpu = local.map(|n| n.cpu_used).unwrap_or(0.0);
                        let mem = local.map(|n| n.mem_used).unwrap_or(0.0);
                        let pods = local.map(|n| n.pod_count).unwrap_or(0);
                        let body = serde_json::json!({"node": local_hostname, "cpu_used": cpu, "mem_used": mem, "pod_count": pods, "timestamp": now}).to_string();
                        let peers: Vec<(String, String)> = w.nodes.iter()
                            .filter(|(name, _)| **name != local_hostname)
                            .map(|(name, n)| (name.clone(), n.address.clone())).collect();
                        (body, peers)
                    };
                    // Network I/O — lock-free
                    let mut reached = Vec::new();
                    for (name, addr) in &peers {
                        if http_post(&format!("http://{addr}/royak/v1/heartbeat"), &body,
                            &[("X-Royak-Token", token_b64.as_str()), ("Content-Type", "application/json")]).is_ok() {
                            reached.push(name.clone());
                        }
                    }
                    // Brief write lock only to apply the results.
                    if !reached.is_empty() {
                        let mut w = hb_world.write().unwrap();
                        for name in reached {
                            if let Some(node) = w.nodes.get_mut(&name) {
                                node.last_heartbeat = now;
                                node.status = NodeStatus::Ready; // reached it → alive
                            }
                        }
                    }
                });
            }
        }

        // Persist state every tick — full atomic save (schemaVersion + .nrns +
        // flock + 0600). Two historical bugs live here: (1) the loop used to write
        // export_state(), the node-sync wire format load_state cannot parse, so
        // watch-time mutations were silently lost on restart; (2) it saved every
        // 5 ticks, and with slow Docker a tick can take ~10s — a 40-50s loss
        // window on hard kill. A save costs milliseconds next to a reconcile
        // tick, so just save every time. Both fixed in v0.4.0-beta.1.
        {
            let w = world.read().unwrap();
            crate::save_state(state_path, &w);
        }

        std::thread::sleep(Duration::from_secs(interval_secs));
    }
}

/// Global shutdown flag — set by signal handler, checked by reconcile loop
static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Check if shutdown was requested
#[allow(dead_code)]
pub fn is_shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Public wrapper for installing shutdown handler
#[allow(dead_code)]
pub fn install_shutdown_handler_pub() {
    install_shutdown_handler();
}

/// Install signal handlers for graceful shutdown
fn install_shutdown_handler() {
    #[cfg(unix)]
    unsafe {
        extern "C" fn handle_signal(_: libc::c_int) {
            SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        libc::signal(libc::SIGINT, handle_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, handle_signal as *const () as libc::sighandler_t);
    }
}

// ─── Leader Lease (best-effort HA) ───────────────────────────────────────
//
// A tiny file-based lease. All instances pointed at the same state_path
// compete for the file {state_path}.leader. One becomes leader and performs
// reconcile mutations; the rest are standby. If the leader crashes, its
// lease goes stale after LEASE_TTL and the next tick from any standby
// claims it. Not a Raft/Paxos replacement — meant for single-host or
// shared-filesystem setups where "exactly one mutator" is the useful
// guarantee. Real multi-master HA is planned post-v0.3.

const LEASE_TTL_SECS: u64 = 15;

/// Try to acquire or renew the leader lease.
/// Returns true iff the caller is the leader after this call.
pub fn try_acquire_lease(state_path: &str, our_id: &str) -> bool {
    let lease_path = format!("{state_path}.leader");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();

    // Read existing lease, if any.
    if let Ok(content) = std::fs::read_to_string(&lease_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            let leader = v["leader"].as_str().unwrap_or("");
            let acquired = v["acquired_at"].as_u64().unwrap_or(0);
            let age = now.saturating_sub(acquired);

            if leader == our_id {
                // Renew our own lease.
                return write_lease_atomic(&lease_path, our_id, now);
            }
            if age < LEASE_TTL_SECS && !leader.is_empty() {
                // Fresh lease held by someone else — stand by.
                return false;
            }
            // Stale lease — fall through and take over.
        }
    }
    // File missing, unreadable, or stale → claim it.
    write_lease_atomic(&lease_path, our_id, now)
}

/// Explicitly release the lease (used on graceful shutdown).
pub fn release_lease(state_path: &str, our_id: &str) {
    let lease_path = format!("{state_path}.leader");
    if let Ok(content) = std::fs::read_to_string(&lease_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
            if v["leader"].as_str() == Some(our_id) {
                let _ = std::fs::remove_file(&lease_path);
            }
        }
    }
}

fn write_lease_atomic(lease_path: &str, our_id: &str, now: u64) -> bool {
    let tmp = format!("{lease_path}.tmp");
    let body = serde_json::json!({
        "leader": our_id,
        "acquired_at": now,
        "ttl_secs": LEASE_TTL_SECS,
    }).to_string();
    if std::fs::write(&tmp, &body).is_err() {
        return false;
    }
    std::fs::rename(&tmp, lease_path).is_ok()
}

#[cfg(test)]
mod statefulset_ordering_tests {
    use super::next_statefulset_ordinal;
    use std::collections::HashSet;

    fn set(items: &[u32]) -> HashSet<u32> {
        items.iter().copied().collect()
    }

    #[test]
    fn first_ordinal_creates_immediately_even_with_nothing_ready() {
        // No pods exist yet; ordinal 1 (the first, no predecessor) is eligible.
        let existing = set(&[]);
        let ready = set(&[]);
        assert_eq!(next_statefulset_ordinal(&existing, &ready, 3), Some(1));
    }

    #[test]
    fn next_ordinal_blocked_while_predecessor_not_ready() {
        // Ordinal 1 exists but is NOT ready → ordinal 2 must NOT be created.
        let existing = set(&[1]);
        let ready = set(&[]);
        assert_eq!(next_statefulset_ordinal(&existing, &ready, 3), None);
    }

    #[test]
    fn next_ordinal_eligible_once_predecessor_ready() {
        // Ordinal 1 exists AND is ready → ordinal 2 becomes eligible.
        let existing = set(&[1]);
        let ready = set(&[1]);
        assert_eq!(next_statefulset_ordinal(&existing, &ready, 3), Some(2));
    }

    #[test]
    fn only_one_ordinal_per_tick() {
        // Ordinals 1 & 2 ready — only the single next ordinal (3) is returned,
        // never a batch. The Option return type enforces one-per-tick.
        let existing = set(&[1, 2]);
        let ready = set(&[1, 2]);
        assert_eq!(next_statefulset_ordinal(&existing, &ready, 5), Some(3));
    }

    #[test]
    fn deep_gate_third_ordinal_waits_on_second() {
        // 1 ready, 2 exists but not ready → 3 is blocked on 2, not on 1.
        let existing = set(&[1, 2]);
        let ready = set(&[1]);
        assert_eq!(next_statefulset_ordinal(&existing, &ready, 5), None);
    }

    #[test]
    fn complete_set_creates_nothing() {
        let existing = set(&[1, 2, 3]);
        let ready = set(&[1, 2, 3]);
        assert_eq!(next_statefulset_ordinal(&existing, &ready, 3), None);
    }

    #[test]
    fn heals_lowest_hole_first_when_predecessor_ready() {
        // Ordinal 2 crashed/removed (hole). 1 is ready → recreate 2 before 3.
        let existing = set(&[1, 3]);
        let ready = set(&[1, 3]);
        assert_eq!(next_statefulset_ordinal(&existing, &ready, 3), Some(2));
    }

    #[test]
    fn zero_desired_creates_nothing() {
        assert_eq!(next_statefulset_ordinal(&set(&[]), &set(&[]), 0), None);
    }
}

#[cfg(test)]
mod lease_tests {
    use super::*;

    fn tmp(tag: &str) -> String {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        format!("/tmp/rk-lease-{pid}-{nanos}-{tag}")
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.leader"));
        let _ = std::fs::remove_file(format!("{path}.leader.tmp"));
    }

    #[test]
    fn first_acquirer_becomes_leader() {
        let path = tmp("first");
        cleanup(&path);
        assert!(try_acquire_lease(&path, "node-a"));
        cleanup(&path);
    }

    #[test]
    fn base64_decodes_standard_and_falls_back() {
        assert_eq!(super::base64_decode("aGVsbG8=").as_deref(), Some("hello"));
        assert_eq!(super::base64_decode("cGFzc3dvcmQxMjM=").as_deref(), Some("password123"));
        assert_eq!(super::base64_decode("").as_deref(), Some(""));
        // whitespace inside the value is tolerated (kubectl wraps long secrets)
        assert_eq!(super::base64_decode("aGVs\nbG8=").as_deref(), Some("hello"));
        // invalid input → None so the caller keeps the raw string
        assert_eq!(super::base64_decode("not valid!!"), None);
    }

    #[test]
    fn holder_can_renew() {
        let path = tmp("renew");
        cleanup(&path);
        assert!(try_acquire_lease(&path, "node-a"));
        // Same id → renewal
        assert!(try_acquire_lease(&path, "node-a"));
        cleanup(&path);
    }

    #[test]
    fn other_node_becomes_follower() {
        let path = tmp("follower");
        cleanup(&path);
        assert!(try_acquire_lease(&path, "node-a"));
        // B arrives while A's lease is fresh → B is follower
        assert!(!try_acquire_lease(&path, "node-b"));
        cleanup(&path);
    }

    #[test]
    fn stale_lease_is_taken_over() {
        let path = tmp("stale");
        cleanup(&path);
        // Write a lease held by node-a with acquired_at far in the past.
        let ancient = 1000u64; // 1970-epoch-adjacent
        let body = serde_json::json!({
            "leader": "node-a",
            "acquired_at": ancient,
            "ttl_secs": LEASE_TTL_SECS,
        }).to_string();
        std::fs::write(format!("{path}.leader"), body).unwrap();
        // node-b sees the stale lease and takes over
        assert!(try_acquire_lease(&path, "node-b"));
        // Now node-b holds the lease — re-check
        let content = std::fs::read_to_string(format!("{path}.leader")).unwrap();
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["leader"].as_str(), Some("node-b"));
        cleanup(&path);
    }

    #[test]
    fn release_lease_clears_when_owner() {
        let path = tmp("release");
        cleanup(&path);
        assert!(try_acquire_lease(&path, "node-a"));
        release_lease(&path, "node-a");
        assert!(!std::path::Path::new(&format!("{path}.leader")).exists());
        cleanup(&path);
    }

    #[test]
    fn release_lease_noop_when_not_owner() {
        let path = tmp("release-other");
        cleanup(&path);
        assert!(try_acquire_lease(&path, "node-a"));
        // node-b asks to release — should be ignored (a is still leader)
        release_lease(&path, "node-b");
        assert!(std::path::Path::new(&format!("{path}.leader")).exists());
        cleanup(&path);
    }
}

#[cfg(test)]
mod hpa_tests {
    use super::{hpa_decision, HPA_STABILIZATION_SECS};

    const NEVER: u64 = u64::MAX; // never scaled → cooldown never blocks

    #[test]
    fn scales_up_when_over_threshold_and_cooldown_elapsed() {
        // 2 replicas, CPU 140% vs 70% target → ratio 2.0 → 4 replicas.
        let d = hpa_decision(2, 140.0, 70.0, 1, 10, NEVER, HPA_STABILIZATION_SECS);
        assert_eq!(d, Some(4));
        // Also fine when the last scale is older than the window.
        let d2 = hpa_decision(2, 140.0, 70.0, 1, 10, HPA_STABILIZATION_SECS + 1, HPA_STABILIZATION_SECS);
        assert_eq!(d2, Some(4));
    }

    #[test]
    fn holds_within_cooldown_window_the_thrash_case() {
        // Over threshold, but we scaled 10s ago and the window is 60s → hold.
        let up = hpa_decision(2, 140.0, 70.0, 1, 10, 10, HPA_STABILIZATION_SECS);
        assert_eq!(up, None);
        // Symmetric: a scale-down that lands inside the window is also held.
        let down = hpa_decision(4, 10.0, 70.0, 1, 10, 5, HPA_STABILIZATION_SECS);
        assert_eq!(down, None);
    }

    #[test]
    fn scales_down_when_under_half_target() {
        // CPU 20% < 35% (half of 70%) → step down by one.
        let d = hpa_decision(4, 20.0, 70.0, 1, 10, NEVER, HPA_STABILIZATION_SECS);
        assert_eq!(d, Some(3));
    }

    #[test]
    fn holds_when_cpu_in_normal_band() {
        // 50% is above the 35% scale-down floor and below the 70% scale-up line.
        let d = hpa_decision(3, 50.0, 70.0, 1, 10, NEVER, HPA_STABILIZATION_SECS);
        assert_eq!(d, None);
    }

    #[test]
    fn clamps_to_max_on_scale_up() {
        // ratio would ask for far more than max → clamp to 10.
        let d = hpa_decision(8, 700.0, 70.0, 1, 10, NEVER, HPA_STABILIZATION_SECS);
        assert_eq!(d, Some(10));
        // Already at max under high load → no change, no thrash.
        let at_max = hpa_decision(10, 700.0, 70.0, 1, 10, NEVER, HPA_STABILIZATION_SECS);
        assert_eq!(at_max, None);
    }

    #[test]
    fn clamps_to_min_on_scale_down() {
        // At min already, low CPU → hold (can't go below min).
        let at_min = hpa_decision(1, 5.0, 70.0, 1, 10, NEVER, HPA_STABILIZATION_SECS);
        assert_eq!(at_min, None);
        // Stepping down from 2 with min=2 → no change.
        let floor = hpa_decision(2, 5.0, 70.0, 2, 10, NEVER, HPA_STABILIZATION_SECS);
        assert_eq!(floor, None);
    }
}

#[cfg(test)]
mod cascade_delete_tests {
    use super::*;

    /// Minimal deployment with an explicit owner ref (None = user-owned).
    fn dep(name: &str, owner: Option<&str>) -> StoredDeployment {
        StoredDeployment {
            name: name.to_string(),
            namespace: "default".to_string(),
            replicas: 1,
            init_containers: Vec::new(),
            containers: Vec::new(),
            image: "nginx:alpine".to_string(),
            previous_image: None,
            command: None,
            env: Vec::new(),
            resource_limits: None,
            strategy: None,
            pause_after_idle: None,
            paused: false,
            idle_since: None,
            stateful: false,
            owner_ref: owner.map(|s| s.to_string()),
        }
    }

    /// An operator that provisions a single "primary" component for `kind`.
    fn operator(name: &str, kind: &str) -> Operator {
        Operator {
            name: name.to_string(),
            custom_kind: kind.to_string(),
            provision: vec![OperatorComponent {
                role: "primary".to_string(),
                image: "postgres:16".to_string(),
                replicas: 1,
                env: vec![],
                volumes: vec![],
                ports: vec![],
            }],
            hooks: HashMap::new(),
            rules: vec![],
        }
    }

    fn custom_resource(name: &str, kind: &str) -> CustomResource {
        CustomResource {
            name: name.to_string(),
            kind: kind.to_string(),
            namespace: "default".to_string(),
            spec: serde_json::json!({}),
            status: CRStatus::Pending,
        }
    }

    #[test]
    fn provisioning_stamps_owner_ref() {
        let mut world = DesiredWorld::new();
        world.operators.insert("pg-op".into(), operator("pg-op", "PostgresCluster"));
        world.custom_resources.insert("db".into(), custom_resource("db", "PostgresCluster"));

        let mut log = Vec::new();
        reconcile_operators(&mut world, &mut log);

        let provisioned = world.deployments.get("db-primary")
            .expect("operator should provision db-primary");
        assert_eq!(provisioned.owner_ref.as_deref(), Some("db"),
            "provisioned deployment must carry the owning CR as its owner ref");
    }

    #[test]
    fn selection_picks_only_owned_deployments() {
        let mut world = DesiredWorld::new();
        world.deployments.insert("db-primary".into(), dep("db-primary", Some("db")));
        world.deployments.insert("db-replica".into(), dep("db-replica", Some("db")));
        world.deployments.insert("cache-primary".into(), dep("cache-primary", Some("cache")));
        world.deployments.insert("web".into(), dep("web", None));

        let mut owned = deployments_owned_by(&world, "db");
        owned.sort();
        assert_eq!(owned, vec!["db-primary".to_string(), "db-replica".to_string()]);
    }

    #[test]
    fn deleting_cr_removes_exactly_its_owned_deployments() {
        let mut world = DesiredWorld::new();
        world.custom_resources.insert("db".into(), custom_resource("db", "PostgresCluster"));
        world.deployments.insert("db-primary".into(), dep("db-primary", Some("db")));
        world.deployments.insert("db-replica".into(), dep("db-replica", Some("db")));
        world.deployments.insert("cache-primary".into(), dep("cache-primary", Some("cache")));
        world.deployments.insert("web".into(), dep("web", None));

        let deleted = world.delete_resource("customresources", "db");
        assert!(deleted, "CR delete should report success");

        // Owned deployments are gone.
        assert!(!world.deployments.contains_key("db-primary"));
        assert!(!world.deployments.contains_key("db-replica"));
        // Another CR's deployment and the user-owned one are untouched.
        assert!(world.deployments.contains_key("cache-primary"));
        assert!(world.deployments.contains_key("web"));
        assert_eq!(world.deployments.len(), 2);
        // CR itself removed.
        assert!(!world.custom_resources.contains_key("db"));
    }

    #[test]
    fn unowned_deployment_is_never_gcd() {
        let mut world = DesiredWorld::new();
        // A CR named "db" exists, and a user deployment happens to be "db"-ish
        // but has no owner ref — it must survive the cascade.
        world.custom_resources.insert("db".into(), custom_resource("db", "PostgresCluster"));
        world.deployments.insert("db".into(), dep("db", None));

        world.delete_resource("customresources", "db");

        assert!(world.deployments.contains_key("db"),
            "a deployment with no owner ref must never be garbage-collected");
    }

    #[test]
    fn deleting_missing_cr_touches_nothing() {
        let mut world = DesiredWorld::new();
        world.deployments.insert("web".into(), dep("web", Some("ghost")));

        let deleted = world.delete_resource("customresources", "ghost");
        assert!(!deleted, "deleting a non-existent CR returns false");
        // The CR never existed, so no cascade runs — the orphan stays put.
        assert!(world.deployments.contains_key("web"));
    }
}

// ─── UDP Autodiscovery: nodes find each other on the network ───
//
// Protocol:
//   1. Broadcast UDP packet every 10s on port 9443
//   2. Packet = JSON: {"service":"royak","node":"name","api":"host:port","token":"base64"}
//   3. Listener picks up broadcasts from other nodes
//   4. If new node → HTTP state sync automatically
//
// Works on: local network (WiFi, Docker bridge, LAN)
// No external dependencies. Just UDP.

const DISCOVERY_PORT: u16 = 9443;
const DISCOVERY_INTERVAL: u64 = 10;

pub fn autodiscovery(
    world: std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    brain: &OrinBrain,
    api_port: u16,
) {
    use std::net::UdpSocket;

    let hostname = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "unknown".to_string());
    let token_b64 = OrinBrain::identity_base64(&brain.neural_identity(&hostname));

    // Get our IP (best effort — use first non-loopback)
    let local_ip = get_local_ip().unwrap_or_else(|| "0.0.0.0".to_string());
    let api_addr = format!("{local_ip}:{api_port}");

    println!("  ✓ autodiscovery started: {hostname} @ {api_addr}");

    // Bind listener
    let listener = match UdpSocket::bind(format!("0.0.0.0:{DISCOVERY_PORT}")) {
        Ok(s) => {
            s.set_broadcast(true).ok();
            s.set_read_timeout(Some(std::time::Duration::from_secs(DISCOVERY_INTERVAL))).ok();
            s
        }
        Err(e) => {
            eprintln!("  ⚠ autodiscovery bind failed: {e}");
            return;
        }
    };

    // Separate socket for broadcasting (can't broadcast and listen on same socket easily)
    let broadcaster = UdpSocket::bind("0.0.0.0:0").ok();
    if let Some(ref b) = broadcaster {
        b.set_broadcast(true).ok();
    }

    let mut known_nodes: std::collections::HashSet<String> = std::collections::HashSet::new();
    known_nodes.insert(hostname.clone());

    loop {
        // Broadcast our presence
        if let Some(ref b) = broadcaster {
            let announce = serde_json::json!({
                "service": "royak",
                "version": "0.1",
                "node": hostname,
                "api": api_addr,
                "token": token_b64,
            }).to_string();
            b.send_to(announce.as_bytes(), format!("255.255.255.255:{DISCOVERY_PORT}")).ok();
        }

        // Listen for other nodes
        let mut buf = [0u8; 2048];
        match listener.recv_from(&mut buf) {
            Ok((len, src)) => {
                if let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&buf[..len]) {
                    if msg["service"].as_str() == Some("royak") {
                        let peer_node = msg["node"].as_str().unwrap_or("?").to_string();
                        let peer_api = msg["api"].as_str().unwrap_or("").to_string();

                        // Security: verify source IP matches claimed API address
                        let src_ip = src.ip().to_string();
                        let claimed_ip = peer_api.split(':').next().unwrap_or("");
                        let ip_match = src_ip == claimed_ip || claimed_ip == "0.0.0.0";

                        if peer_node != hostname && !known_nodes.contains(&peer_node) && ip_match {
                            println!("  ✦ discovered: {peer_node} @ {peer_api} (from {src}, verified)");
                            known_nodes.insert(peer_node.clone());

                            // Auto-join: sync state with the new node
                            let headers = [("X-Royak-Token", token_b64.as_str())];
                            match http_get(&format!("http://{peer_api}/royak/v1/state"), &headers) {
                                Ok(body) => {
                                    if let Ok(remote) = serde_json::from_str::<serde_json::Value>(&body) {
                                        let mut w = world.write().unwrap();
                                        let merged = merge_state(&mut w, &remote);
                                        if !merged.is_empty() {
                                            println!("  ✓ auto-synced from {peer_node}: {} items", merged.len());
                                        }
                                    }
                                }
                                Err(e) => eprintln!("  ⚠ sync from {peer_node}: {e}"),
                            }

                            // Push our state too
                            let our_state = {
                                let w = world.read().unwrap();
                                export_state(&w).to_string()
                            };
                            http_post(&format!("http://{peer_api}/royak/v1/state"), &our_state,
                                &[("X-Royak-Token", token_b64.as_str()), ("Content-Type", "application/json")]).ok();

                            // Register the peer node locally
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                            let mut w = world.write().unwrap();
                            w.nodes.entry(peer_node.clone()).or_insert(ClusterNode {
                                name: peer_node, address: peer_api,
                                cpu_capacity: 100.0, mem_capacity: 0.0,
                                cpu_used: 0.0, mem_used: 0.0, pod_count: 0,
                                status: NodeStatus::Ready, last_heartbeat: now,
                                neural_token: vec![], joined_at: now,
                            });
                        }
                    }
                }
            }
            Err(_) => {} // timeout — just loop and broadcast again
        }
    }
}

fn get_local_ip() -> Option<String> {
    // Connect to a public address to find our outbound IP (no traffic is sent)
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    socket.local_addr().ok().map(|a| a.ip().to_string())
}

// ─── Security helpers ───

/// Execute a hook command safely (no shell injection)
fn safe_exec_hook(hook: &str) -> String {
    let parts: Vec<&str> = hook.split_whitespace().collect();
    if parts.is_empty() { return String::new(); }
    // Validate: no path traversal, no shell metacharacters
    if hook.contains("..") || hook.contains('`') || hook.contains("$(") || hook.contains(';') || hook.contains('|') || hook.contains('&') {
        return format!("BLOCKED: unsafe characters in hook: {hook}");
    }
    std::process::Command::new(parts[0])
        .args(&parts[1..])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|e| format!("hook error: {e}"))
}

/// Validate resource names (alphanumeric + dash + underscore, max 63 chars)
#[allow(dead_code)]
pub fn validate_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
        && !name.contains("..")
}

/// Validate volume mount paths (no traversal)
pub fn validate_path(path: &str) -> bool {
    !path.contains("..")
        && !path.contains('~')
        && path.starts_with('/')
        && !path.contains("//")
}

// ─── Generic Reconciliation via ContainerRuntime trait ───

fn reconcile_via_trait(desired: &mut DesiredWorld, _brain: &mut OrinBrain, rt_name: &str) -> Vec<String> {
    use crate::runtime::{self, ContainerState};
    let rt = runtime::get_runtime(rt_name);
    let mut log = Vec::new();

    if !rt.ping() {
        log.push(format!("  [error] {} runtime not available", rt.name()));
        return log;
    }

    rt.ensure_network().ok();

    // Get actual containers from runtime
    let actual = match rt.list(true) {
        Ok(cs) => cs,
        Err(e) => { log.push(format!("  [error] {}: {e}", rt.name())); return log; }
    };

    let managed: Vec<&runtime::Container> = actual.iter()
        .filter(|c| c.name.contains("rk-"))
        .collect();

    // Reflect THIS node's real pod count so pick_node penalises us correctly.
    // Without it our pod_count stays 0, we always win our own scheduling, and
    // nothing ever routes to a peer.
    let me_name = local_node_name();
    let local_pods = managed.iter().filter(|c| c.state == ContainerState::Running).count() as u32;
    if let Some(n) = desired.nodes.get_mut(&me_name) { n.pod_count = local_pods; }

    // Cluster-wide pod census: ask each READY peer for its running pods, so a
    // deployment's replicas are counted across ALL nodes (not just local) and
    // pod names stay globally unique. NotReady peers are skipped (unreachable →
    // would stall under the world lock); they re-count once they heartbeat back.
    let mut remote_pods: Vec<String> = Vec::new();
    let mut peer_pod_pairs: Vec<(String, String)> = Vec::new();
    let peer_addrs: Vec<String> = desired.nodes.iter()
        .filter(|(n, node)| **n != me_name && node.status == crate::reconcile::NodeStatus::Ready)
        .map(|(_, node)| node.address.clone())
        .collect();
    for addr in &peer_addrs {
        match http_get(&format!("http://{addr}/royak/v1/pods"), &[]) {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    if let Some(arr) = v["pods"].as_array() {
                        for p in arr.iter().filter_map(|p| p.as_str()) {
                            remote_pods.push(p.to_string());
                            peer_pod_pairs.push((addr.clone(), p.to_string()));
                        }
                    }
                }
            }
            Err(e) => {
                // Unreachable peer: demote to NotReady so we STOP probing it under
                // the world write-lock every tick. `http_get` is now connect-bounded
                // (2s), but even 2s/tick of a dead peer stalls the ingress — so we
                // drop it from the Ready set after ONE failed probe. It re-counts the
                // moment it heartbeats back (check_node_health / heartbeat → Ready).
                if let Some((name, node)) = desired.nodes.iter_mut()
                    .find(|(_, nd)| nd.address == *addr)
                {
                    if node.status == crate::reconcile::NodeStatus::Ready {
                        node.status = crate::reconcile::NodeStatus::NotReady;
                        log.push(format!("  ⚠ [census] peer {name} unreachable ({e}) — marked NotReady"));
                    }
                }
            }
        }
    }
    // Publish the peer census to the ingress so it can round-robin onto pods
    // that live on other nodes (reached via that node's mesh proxy).
    crate::api::set_peer_pods(peer_pod_pairs.clone());

    for (name, dep) in &desired.deployments {
        let prefix = format!("rk-{name}-");
        let running: Vec<&&runtime::Container> = managed.iter()
            .filter(|c| c.name.starts_with(&prefix) && c.state == ContainerState::Running)
            .collect();
        let remote_running = remote_pods.iter().filter(|p| p.starts_with(&prefix)).count() as u32;

        let current = running.len() as u32 + remote_running;
        let target = dep.replicas;

        if current < target {
            let to_create = target - current;
            log.push(format!("  [scale] {name}: {current} → {target} (+{to_create}) [{} local + {remote_running} remote]", running.len()));
            let image = &dep.containers.first().map(|c| c.image.as_str()).unwrap_or(&dep.image);

            if let Err(e) = rt.pull(image) {
                log.push(format!("    [warn] pull {image}: {e}"));
            }

            // Reserve globally-unique names across local AND remote pods.
            let mut taken: Vec<String> = managed.iter().map(|c| c.name.clone()).collect();
            taken.extend(remote_pods.iter().cloned());

            // Per-deployment load balancer: place each new pod on the node running
            // the FEWEST of THIS deployment's pods (self + ready peers), tracking a
            // running tally so a batch spreads evenly instead of all landing on one.
            // (addr, is_local, count-of-this-deployment's-pods)
            let mut node_load: Vec<(String, bool, u32)> = Vec::new();
            node_load.push((String::new(), true, running.len() as u32));
            for (n, node) in desired.nodes.iter() {
                if *n != me_name && node.status == NodeStatus::Ready
                    && !node.address.is_empty() && !node.address.starts_with("127.0.0.1") {
                    let cnt = peer_pod_pairs.iter()
                        .filter(|(a, p)| a == &node.address && p.starts_with(&prefix)).count() as u32;
                    node_load.push((node.address.clone(), false, cnt));
                }
            }

            for _ in 0..to_create {
                let mut idx = 1u32;
                let pod_name = loop {
                    let cand = format!("rk-{name}-{idx}");
                    if !taken.iter().any(|n| n == &cand) { break cand; }
                    idx += 1;
                };
                taken.push(pod_name.clone());

                // Pick the least-loaded node for this pod, then bump its tally.
                let pick = node_load.iter().enumerate()
                    .min_by_key(|(_, (_, _, c))| *c).map(|(i, _)| i).unwrap_or(0);
                node_load[pick].2 += 1;
                let (addr, is_local, _) = node_load[pick].clone();

                if !is_local {
                    // Route to the peer's /royak/v1/create-pod (runs it on its Docker).
                    let url = format!("http://{addr}/royak/v1/create-pod");
                    let body = serde_json::json!({
                        "pod": pod_name, "deployment": name.as_str(),
                        "image": *image, "replicas": 1
                    }).to_string();
                    log.push(format!("    [multi-node] {pod_name} → {addr}"));
                    let (pn, ad) = (pod_name.clone(), addr.clone());
                    std::thread::spawn(move || {
                        if let Err(e) = http_post(&url, &body, &[("Content-Type", "application/json")]) {
                            eprintln!("  ⚠ [multi-node] {pn} → {ad} create-pod failed: {e}");
                        }
                    });
                    continue; // routed to a peer — skip local create
                }

                let labels = [("app", name.as_str()), ("managed-by", "royak")];
                let cmd_opt: Option<&[&str]> = None;
                match rt.create(&pod_name, image, cmd_opt, &dep.env, &labels) {
                    Ok(id) => {
                        if let Err(e) = rt.start(&id) {
                            log.push(format!("    [error] start {pod_name}: {e}"));
                        } else {
                            log.push(format!("    [create] {pod_name} ✓"));
                            rt.connect_network(&id, &[pod_name.as_str(), name.as_str()]).ok();
                        }
                    }
                    Err(e) => log.push(format!("    [error] create {pod_name}: {e}")),
                }
            }
        } else if current > target {
            let to_remove = current - target;
            log.push(format!("  [scale] {name}: {current} → {target} (-{to_remove})"));
            for c in running.iter().rev().take(to_remove as usize) {
                rt.stop(&c.id).ok();
                rt.remove(&c.id, true).ok();
                log.push(format!("    [remove] {} ✓", c.name));
            }
        }
    }

    log
}

/// Check a single probe (liveness or readiness)
/// Normalize Docker image names for comparison.
/// "nginx" == "nginx:latest", "docker.io/library/nginx:latest" == "nginx:latest"
fn normalize_image(image: &str) -> String {
    let img = image
        .trim_start_matches("docker.io/library/")
        .trim_start_matches("docker.io/");
    if img.contains(':') {
        img.to_string()
    } else {
        format!("{img}:latest")
    }
}

fn check_probe(container_id: &str, probe: &StoredProbe) -> bool {
    if let Some((path, port)) = &probe.http_get {
        // HTTP GET probe
        match docker::http_check_container(container_id, path, *port) {
            Ok(healthy) => return healthy,
            Err(_) => return false,
        }
    }
    if let Some(cmd) = &probe.exec {
        // Exec probe
        let cmd_refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        match docker::exec_in_container(container_id, &cmd_refs) {
            Ok((exit_code, _)) => return exit_code == 0,
            Err(_) => return false,
        }
    }
    // No probe configured = healthy
    true
}

// ─── Multi-Node Cluster ───

/// Register the local node in the cluster
/// This process's node name — the key it registers under AND heartbeats as.
/// Must be identical across registration, the heartbeat sender, and the local
/// metric update, or heartbeats won't match by name and every node flaps to
/// NotReady after 30s (which disables multi-node scheduling entirely).
pub fn local_node_name() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            std::process::Command::new("hostname")
                .output().ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| "royak-node-0".to_string())
        })
}

/// The address peers should use to reach THIS node's API. Multi-node pod
/// routing (reconcile → POST /royak/v1/create-pod) needs a routable address
/// here, not 127.0.0.1 / 0.0.0.0. `ROYAK_ADVERTISE_ADDR` (host or host:port)
/// overrides; otherwise falls back to loopback (single-node default).
pub fn advertised_address(api_port: u16) -> String {
    if let Ok(a) = std::env::var("ROYAK_ADVERTISE_ADDR") {
        let a = a.trim();
        if !a.is_empty() {
            return if a.contains(':') { a.to_string() } else { format!("{a}:{api_port}") };
        }
    }
    format!("127.0.0.1:{api_port}")
}

pub fn register_local_node(world: &mut DesiredWorld, brain: &OrinBrain, api_port: u16) {
    let hostname = local_node_name();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();

    let token = brain.neural_identity(&hostname);

    world.nodes.insert(hostname.clone(), ClusterNode {
        name: hostname.clone(),
        address: advertised_address(api_port),
        cpu_capacity: 100.0,
        mem_capacity: get_system_mem(),
        cpu_used: 0.0,
        mem_used: 0.0,
        pod_count: 0,
        status: NodeStatus::Ready,
        last_heartbeat: now,
        neural_token: token,
        joined_at: now,
    });
}

/// Join a remote node to the cluster with REAL networking
pub fn join_cluster(world: &mut DesiredWorld, brain: &OrinBrain, peer_address: &str, local_port: u16) -> Result<String, String> {
    let hostname = local_node_name();

    let our_token = brain.neural_identity(&hostname);
    let token_b64 = OrinBrain::identity_base64(&our_token);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();

    // 1. Register ourselves locally
    world.nodes.insert(hostname.clone(), ClusterNode {
        name: hostname.clone(),
        address: advertised_address(local_port),
        cpu_capacity: 100.0,
        mem_capacity: get_system_mem(),
        cpu_used: 0.0, mem_used: 0.0, pod_count: 0,
        status: NodeStatus::Ready,
        last_heartbeat: now,
        neural_token: our_token,
        joined_at: now,
    });

    // 2. Fetch peer's state via HTTP
    let headers = [("X-Royak-Token", token_b64.as_str())];
    match http_get(&format!("http://{peer_address}/royak/v1/state"), &headers) {
        Ok(body) => {
            if let Ok(remote) = serde_json::from_str::<serde_json::Value>(&body) {
                let merged = merge_state(world, &remote);
                eprintln!("  ✓ state synced from peer: {} items merged", merged.len());
            }
        }
        Err(e) => eprintln!("  ⚠ could not fetch peer state: {e} (peer may not be running API)"),
    }

    // 3. Push our state to the peer
    let our_state = export_state(world);
    match http_post(
        &format!("http://{peer_address}/royak/v1/state"),
        &our_state.to_string(),
        &[("X-Royak-Token", token_b64.as_str()), ("Content-Type", "application/json")],
    ) {
        Ok(_) => eprintln!("  ✓ our state pushed to peer"),
        Err(e) => eprintln!("  ⚠ could not push state to peer: {e}"),
    }

    Ok(format!("{hostname} joined cluster via {peer_address} ({} nodes)", world.nodes.len()))
}

/// Minimal standard-base64 decoder (Secret `data:` values are base64 in K8s).
/// No external crate, matching the project's philosophy. Returns None on an
/// invalid character or non-UTF8 result, so callers can fall back to the raw
/// string. Ignores whitespace and `=` padding.
fn base64_decode(s: &str) -> Option<String> {
    fn sixbit(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut bytes = Vec::new();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for c in s.bytes() {
        if c.is_ascii_whitespace() || c == b'=' { continue; }
        acc = (acc << 6) | sixbit(c)?;
        nbits += 6;
        while nbits >= 8 {
            nbits -= 8;
            bytes.push((acc >> nbits) as u8);
        }
        acc &= (1u32 << nbits) - 1;
    }
    String::from_utf8(bytes).ok()
}

// ─── HTTP Client (raw TCP, same philosophy as docker.rs) ───

/// Connect with a bounded timeout. `std::net::TcpStream::connect` has NO connect
/// timeout — a dead peer (silently-dropped SYNs, e.g. a powered-off cloud VM)
/// blocks the caller for the OS SYN timeout (~10-20s). Every peer HTTP call here
/// runs inside the reconcile tick, under the world write-lock, so an unbounded
/// connect freezes the whole reconcile + ingress (the survivor node goes dark
/// while its dead peer is probed). Bound it hard.
fn connect_with_timeout(addr: &str, timeout: std::time::Duration) -> Result<std::net::TcpStream, String> {
    use std::net::ToSocketAddrs;
    let mut last = format!("no address for {addr}");
    for sa in addr.to_socket_addrs().map_err(|e| format!("resolve {addr}: {e}"))? {
        match std::net::TcpStream::connect_timeout(&sa, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = format!("connect {addr}: {e}"),
        }
    }
    Err(last)
}

fn http_get(url: &str, headers: &[(&str, &str)]) -> Result<String, String> {
    let (host, port, path) = parse_url(url)?;
    let addr = format!("{host}:{port}");
    let mut stream = connect_with_timeout(&addr, std::time::Duration::from_secs(2))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).ok();

    let mut req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (k, v) in headers { req.push_str(&format!("{k}: {v}\r\n")); }
    req.push_str("\r\n");

    use std::io::{Write, Read};
    stream.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).map_err(|e| format!("read: {e}"))?;

    // Extract body after \r\n\r\n
    buf.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .ok_or_else(|| "no HTTP body".to_string())
}

fn http_post(url: &str, body: &str, headers: &[(&str, &str)]) -> Result<String, String> {
    let (host, port, path) = parse_url(url)?;
    let addr = format!("{host}:{port}");
    let mut stream = connect_with_timeout(&addr, std::time::Duration::from_secs(2))?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10))).ok();
    stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).ok();

    let mut req = format!("POST {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nContent-Length: {}\r\n", body.len());
    for (k, v) in headers { req.push_str(&format!("{k}: {v}\r\n")); }
    req.push_str("\r\n");
    req.push_str(body);

    use std::io::{Write, Read};
    stream.write_all(req.as_bytes()).map_err(|e| format!("write: {e}"))?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).map_err(|e| format!("read: {e}"))?;

    buf.split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .ok_or_else(|| "no HTTP body".to_string())
}

fn parse_url(url: &str) -> Result<(String, u16, String), String> {
    let stripped = url.strip_prefix("http://").unwrap_or(url);
    let (host_port, path) = stripped.split_once('/').unwrap_or((stripped, ""));
    let path = format!("/{path}");
    let (host, port) = if host_port.contains(':') {
        let (h, p) = host_port.split_once(':').unwrap();
        (h.to_string(), p.parse::<u16>().map_err(|e| format!("bad port: {e}"))?)
    } else {
        (host_port.to_string(), 80)
    };
    Ok((host, port, path))
}

// ─── State Export / Import / Merge ───

/// Export DesiredWorld as JSON for inter-node sync
/// Base directory for Royak-managed volume data (projected ConfigMaps/
/// Secrets, StatefulSet per-ordinal storage). Must be a path the container
/// runtime can bind-mount with the SAME content the royak process wrote —
/// on macOS that means somewhere under $HOME (Colima and Docker Desktop
/// share /Users into the VM; /tmp is NOT shared). Override: ROYAK_DATA_DIR.
pub fn royak_data_dir() -> String {
    std::env::var("ROYAK_DATA_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        format!("{home}/.royak")
    })
}

pub fn export_state(world: &DesiredWorld) -> serde_json::Value {
    serde_json::json!({
        "nodes": world.nodes.iter().map(|(k, n)| (k.clone(), serde_json::json!({
            "name": n.name, "address": n.address,
            "cpuCapacity": n.cpu_capacity, "memCapacity": n.mem_capacity,
            "cpuUsed": n.cpu_used, "memUsed": n.mem_used,
            "podCount": n.pod_count, "joinedAt": n.joined_at,
            "status": match n.status { NodeStatus::Ready => "Ready", NodeStatus::NotReady => "NotReady", NodeStatus::Draining => "Draining" }
        }))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "deployments": world.deployments.iter().map(|(k, d)| (k.clone(), serde_json::json!({
            "name": d.name, "namespace": d.namespace, "replicas": d.replicas,
            "image": d.image, "paused": d.paused, "ownerRef": d.owner_ref,
            "containers": d.containers.iter().map(|c| serde_json::json!({"name": c.name, "image": c.image, "env": c.env})).collect::<Vec<_>>()
        }))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "configmaps": world.configmaps.iter().map(|(k, c)| (k.clone(), serde_json::json!({
            "name": c.name, "namespace": c.namespace, "data": c.data
        }))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "secrets": world.secrets.iter().map(|(k, s)| (k.clone(), serde_json::json!({
            "name": s.name, "namespace": s.namespace, "data": s.data
        }))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "ingresses": world.ingresses.iter().map(|(k, i)| (k.clone(), serde_json::json!({
            "name": i.name, "namespace": i.namespace,
            "rules": i.rules.iter().map(|r| serde_json::json!({"host": r.host})).collect::<Vec<_>>()
        }))).collect::<serde_json::Map<String, serde_json::Value>>(),
        "namespaces": world.namespaces,
        "pipelines": world.pipelines.keys().collect::<Vec<_>>(),
        "functions": world.functions.keys().collect::<Vec<_>>(),
    })
}

/// Merge remote state into local — union-based, no master
pub fn merge_state(local: &mut DesiredWorld, remote: &serde_json::Value) -> Vec<String> {
    let mut log = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    // Merge nodes
    if let Some(nodes) = remote.get("nodes").and_then(|n| n.as_object()) {
        for (name, val) in nodes {
            if !local.nodes.contains_key(name) {
                local.nodes.insert(name.clone(), ClusterNode {
                    name: val["name"].as_str().unwrap_or(name).to_string(),
                    address: val["address"].as_str().unwrap_or("").to_string(),
                    cpu_capacity: val["cpuCapacity"].as_f64().unwrap_or(100.0) as f32,
                    mem_capacity: val["memCapacity"].as_f64().unwrap_or(0.0) as f32,
                    cpu_used: val["cpuUsed"].as_f64().unwrap_or(0.0) as f32,
                    mem_used: val["memUsed"].as_f64().unwrap_or(0.0) as f32,
                    pod_count: val["podCount"].as_u64().unwrap_or(0) as u32,
                    status: NodeStatus::Ready,
                    last_heartbeat: now,
                    neural_token: vec![],
                    joined_at: val["joinedAt"].as_u64().unwrap_or(now),
                });
                log.push(format!("node/{name} added"));
            } else {
                // Update heartbeat for known nodes
                if let Some(node) = local.nodes.get_mut(name) {
                    node.last_heartbeat = now;
                    node.cpu_used = val["cpuUsed"].as_f64().unwrap_or(node.cpu_used as f64) as f32;
                    node.mem_used = val["memUsed"].as_f64().unwrap_or(node.mem_used as f64) as f32;
                    node.pod_count = val["podCount"].as_u64().unwrap_or(node.pod_count as u64) as u32;
                }
            }
        }
    }

    // Merge namespaces (union)
    if let Some(nss) = remote.get("namespaces").and_then(|n| n.as_array()) {
        for ns in nss {
            if let Some(s) = ns.as_str() {
                if !local.namespaces.contains(&s.to_string()) {
                    local.namespaces.push(s.to_string());
                    log.push(format!("namespace/{s} added"));
                }
            }
        }
    }

    // Merge deployments (union — create locally if missing)
    if let Some(deps) = remote.get("deployments").and_then(|d| d.as_object()) {
        for (name, val) in deps {
            if !local.deployments.contains_key(name) {
                let containers: Vec<StoredContainer> = val.get("containers")
                    .and_then(|c| c.as_array())
                    .map(|arr| arr.iter().map(|c| StoredContainer {
                        name: c["name"].as_str().unwrap_or("main").to_string(),
                        image: c["image"].as_str().unwrap_or("").to_string(),
                        command: None, env: Vec::new(), volumes: Vec::new(),
                        env_from_configmaps: vec![], env_from_secrets: vec![],
                        liveness_probe: None, readiness_probe: None, startup_probe: None,
                    }).collect())
                    .unwrap_or_default();
                let image = containers.first().map(|c| c.image.clone()).unwrap_or_default();
                local.deployments.insert(name.clone(), StoredDeployment {
                    name: val["name"].as_str().unwrap_or(name).to_string(),
                    namespace: val["namespace"].as_str().unwrap_or("default").to_string(),
                    replicas: val["replicas"].as_u64().unwrap_or(1) as u32,
                    image, previous_image: None, command: None, env: Vec::new(),
                    init_containers: Vec::new(), containers,
                    resource_limits: None,
                    strategy: None,
                    pause_after_idle: None, paused: false, idle_since: None, stateful: false,
                    owner_ref: val["ownerRef"].as_str().map(|s| s.to_string()),
                });
                log.push(format!("deployment/{name} synced from peer"));
            }
        }
    }

    // Merge configmaps (union — don't overwrite local secrets)
    if let Some(cms) = remote.get("configmaps").and_then(|c| c.as_object()) {
        for (name, val) in cms {
            if !local.configmaps.contains_key(name) {
                let data: std::collections::HashMap<String, String> = val.get("data")
                    .and_then(|d| d.as_object())
                    .map(|obj| obj.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or("").to_string())).collect())
                    .unwrap_or_default();
                local.configmaps.insert(name.clone(), StoredConfigMap {
                    name: val["name"].as_str().unwrap_or(name).to_string(),
                    namespace: val["namespace"].as_str().unwrap_or("default").to_string(),
                    data,
                });
                log.push(format!("configmap/{name} synced from peer"));
            }
        }
    }

    log
}

/// Send heartbeat to all peer nodes
pub fn send_heartbeats(world: &mut DesiredWorld, brain: &OrinBrain) {
    let local_hostname = local_node_name();
    let token_b64 = OrinBrain::identity_base64(&brain.neural_identity(&local_hostname));

    // Collect peer addresses (skip ourselves)
    let peers: Vec<(String, String)> = world.nodes.iter()
        .filter(|(name, _)| **name != local_hostname)
        .map(|(name, n)| (name.clone(), n.address.clone()))
        .collect();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    // Get our own stats
    let local = world.nodes.get(&local_hostname);
    let cpu = local.map(|n| n.cpu_used).unwrap_or(0.0);
    let mem = local.map(|n| n.mem_used).unwrap_or(0.0);
    let pods = local.map(|n| n.pod_count).unwrap_or(0);

    let body = serde_json::json!({
        "node": local_hostname,
        "cpu_used": cpu, "mem_used": mem, "pod_count": pods,
        "timestamp": now
    }).to_string();

    for (name, addr) in &peers {
        match http_post(
            &format!("http://{addr}/royak/v1/heartbeat"),
            &body,
            &[("X-Royak-Token", token_b64.as_str()), ("Content-Type", "application/json")],
        ) {
            Ok(_) => {
                if let Some(node) = world.nodes.get_mut(name) {
                    node.last_heartbeat = now;
                    // A successful POST means we reached the peer's API → it is
                    // alive and serving. Promote it (check_node_health only
                    // demotes; a fresh heartbeat alone never restores Ready).
                    node.status = NodeStatus::Ready;
                }
            }
            Err(_) => {} // check_node_health will handle stale nodes
        }
    }
}

/// Heartbeat check — mark nodes with stale heartbeat as NotReady
pub fn check_node_health(world: &mut DesiredWorld) -> Vec<String> {
    let mut log = Vec::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default().as_secs();

    // We are running this check → we are alive. Never demote ourselves (the
    // self-heartbeat refresh is racy with two health-check sites + the async
    // heartbeat thread, which made the local node flap to NotReady).
    let me = local_node_name();
    for (name, node) in world.nodes.iter_mut() {
        if *name == me { continue; }
        let age = now.saturating_sub(node.last_heartbeat);
        // 90s, not 30s: heartbeats go every 3 ticks and a docker-bound tick can
        // run ~10s, so 30s sat right on the edge and flapped a healthy peer.
        if age > 90 && node.status == NodeStatus::Ready {
            node.status = NodeStatus::NotReady;
            log.push(format!("  ⚠ [node] {name}: no heartbeat for {age}s — marked NotReady"));
        }
    }
    log
}

/// Pick the best node for a new pod (neural scheduling)
pub fn pick_node(world: &DesiredWorld) -> Option<String> {
    world.nodes.values()
        .filter(|n| n.status == NodeStatus::Ready)
        .max_by(|a, b| {
            let score_a = (a.cpu_capacity - a.cpu_used) * 0.5 + (a.mem_capacity - a.mem_used) * 0.001 - a.pod_count as f32 * 5.0;
            let score_b = (b.cpu_capacity - b.cpu_used) * 0.5 + (b.mem_capacity - b.mem_used) * 0.001 - b.pod_count as f32 * 5.0;
            score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|n| n.name.clone())
}

/// Invoke a function (start container if cold, exec if hot)
pub fn invoke_function(desired: &mut DesiredWorld, name: &str) -> Result<String, String> {
    let func = desired.functions.get(name)
        .ok_or_else(|| format!("Function '{}' not found", name))?;

    let image = func.image.clone();
    let cmd = func.command.clone();
    let env = func.env.clone();
    let timeout = func.timeout_secs;

    let container_name = format!("rk-fn-{name}");

    match func.state {
        FunctionState::Hot => {
            // Already running — exec the handler
            if let Some(ref cid) = func.container_id {
                let short = &cid[..12.min(cid.len())];
                let cmd_refs: Vec<&str> = cmd.as_ref()
                    .map(|c| c.iter().map(|s| s.as_str()).collect())
                    .unwrap_or_else(|| vec!["echo", "OK"]);
                let (code, output) = docker::exec_in_container(short, &cmd_refs)?;
                // Update stats
                if let Some(f) = desired.functions.get_mut(name) {
                    f.invocations += 1;
                    f.last_invoked = Some(std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());
                }
                if code == 0 {
                    Ok(format!("✓ {name} (hot) → exit {code}\n{output}"))
                } else {
                    Err(format!("✗ {name} → exit {code}\n{output}"))
                }
            } else {
                Err("Container ID missing".to_string())
            }
        }
        FunctionState::Cold | FunctionState::Paused => {
            // Cold start — create and run container
            docker::pull_image(&image).ok();

            let cmd_refs: Vec<&str> = cmd.as_ref()
                .map(|c| c.iter().map(|s| s.as_str()).collect())
                .unwrap_or_default();
            let cmd_opt = if cmd_refs.is_empty() { None } else { Some(cmd_refs.as_slice()) };

            let mut full_env = env.clone();
            full_env.push(format!("ROYAK_FUNCTION={name}"));
            full_env.push(format!("ROYAK_TIMEOUT={timeout}"));

            let labels = vec![
                ("royak.managed", "true"),
                ("royak.function", name),
            ];

            // Remove old container if exists
            docker::remove_container(&container_name, true).ok();

            match docker::create_container(&container_name, &image, cmd_opt, &full_env, &labels) {
                Ok(id) => {
                    docker::start_container(&id)?;
                    docker::connect_to_network(&id, "rk-default", &[container_name.as_str(), name])
                        .or_else(|_| docker::connect_network(&id, &[container_name.as_str(), name])).ok();

                    // Wait for completion (function = run to completion)
                    let start = std::time::Instant::now();
                    let timeout_dur = std::time::Duration::from_secs(timeout);
                    loop {
                        if start.elapsed() > timeout_dur {
                            docker::stop_container(&id).ok();
                            docker::remove_container(&id, true).ok();
                            return Err(format!("✗ {name} timed out after {timeout}s"));
                        }
                        if let Ok(containers) = docker::list_containers(true) {
                            if let Some(c) = containers.iter().find(|c| c.id.starts_with(&id[..12.min(id.len())])) {
                                if c.state == "exited" {
                                    break;
                                }
                            }
                        }
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }

                    // Get output. A very fast function (e.g. `echo`) can exit
                    // before Docker flushes its stdout to the logs endpoint, so
                    // an immediate read may come back empty. Retry a few times
                    // on empty output before giving up — deterministic instead
                    // of racy on loaded hosts (e.g. CI runners).
                    let short = &id[..12.min(id.len())];
                    let mut clean = String::new();
                    for attempt in 0..10 {
                        let output = docker::get_logs(short, 100).unwrap_or_default();
                        clean = output.chars()
                            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                            .collect();
                        if !clean.trim().is_empty() || attempt == 9 { break; }
                        std::thread::sleep(std::time::Duration::from_millis(150));
                    }

                    let elapsed = start.elapsed();

                    // Cleanup
                    docker::remove_container(&id, true).ok();

                    // Update stats
                    if let Some(f) = desired.functions.get_mut(name) {
                        f.invocations += 1;
                        f.last_invoked = Some(std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs());
                    }

                    Ok(format!("✓ {name} ({:.0}ms) → {clean}", elapsed.as_secs_f64() * 1000.0))
                }
                Err(e) => Err(format!("✗ {name}: {e}")),
            }
        }
        FunctionState::Warming => {
            Err(format!("{name} is still warming up"))
        }
    }
}

fn get_system_mem() -> f32 {
    // Read system memory (macOS + Linux compatible)
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("sysctl")
            .args(["-n", "hw.memsize"])
            .output().ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<f64>().ok())
            .map(|b| (b / 1_048_576.0) as f32)
            .unwrap_or(8192.0)
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::read_to_string("/proc/meminfo").ok()
            .and_then(|s| s.lines().next().map(|l| l.to_string()))
            .and_then(|l| l.split_whitespace().nth(1)?.parse::<f64>().ok())
            .map(|kb| (kb / 1024.0) as f32)
            .unwrap_or(8192.0)
    }
}
