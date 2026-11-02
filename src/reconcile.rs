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
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredPipeline {
    pub name: String,
    pub stages: Vec<StoredStage>,
    pub triggers: Vec<StoredTrigger>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredTrigger {
    pub trigger_type: String,
    pub path: Option<String>,
}

/// A pipeline run (execution instance)
#[allow(dead_code)]
#[derive(Clone)]
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum NodeStatus {
    Ready,
    NotReady,
    Draining,
}

/// Cluster configuration (replaces hardcoded values)
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
            llm_host: "http://localhost:11433".to_string(),
            llm_model: "mlx-community--Llama-3.2-3B-Instruct-4bit".to_string(),
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub enum FunctionState {
    Cold,       // no container, will start on invoke
    Warming,    // container starting
    Hot,        // container running, ready to serve
    Paused,     // container stopped, can restart fast
}

/// Git repository registration
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone)]
pub struct DesiredWorld {
    /// Monotonic desired-state version. Bumped by every committed change; the
    /// commit path uses it as a compare-and-swap token (see store::commit).
    pub generation: u64,
    /// Identity of the cluster this desired state belongs to. Containers are
    /// labelled with it and only containers of THIS cluster are ever managed.
    pub cluster_id: String,
    pub deployments: HashMap<String, StoredDeployment>,
    pub daemonsets: HashMap<String, StoredDaemonSet>,
    pub jobs: HashMap<String, StoredJob>,
    pub cronjobs: HashMap<String, StoredCronJob>,
    pub hpas: HashMap<String, StoredHPA>,
    pub services: HashMap<String, StoredService>,
    pub restart_count: HashMap<String, u32>,  // pod name → restart count (CrashLoopBackOff)
    pub startup_ok: std::collections::HashSet<String>,  // pods whose startup probe passed (runtime-only)
    pub pod_ready: std::collections::HashSet<String>,   // local pods whose readiness probe passed (runtime-only)
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
    pub storage_identities: crate::storage_identity::Identities,
    pub(crate) storage_node_directory: crate::storage_node_directory::Registry,
    pub backup_registry: crate::backup_engine::Registry,
    #[allow(dead_code)]
    pub pod_health: HashMap<String, crate::probes::PodHealth>,
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
    /// RoleBinding ("ns/name") and ClusterRoleBinding ("name") objects.
    pub rbac_bindings: HashMap<String, RbacBinding>,
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AdmissionWebhook {
    pub name: String,
    /// HTTP(S) endpoint that receives an AdmissionReview POST.
    pub url: String,
    /// Kinds this webhook validates ("*" = all).
    pub kinds: Vec<String>,
    /// If the webhook is unreachable: "Fail" (deny) or "Ignore" (allow).
    pub failure_policy: String,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredLimitRange {
    pub name: String,
    pub namespace: String,
    pub default_cpu: Option<String>,
    pub default_mem: Option<String>,
    pub request_cpu: Option<String>,
    pub request_mem: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RbacRole {
    pub name: String,
    pub rules: Vec<RbacRule>,
    /// Some(ns) for a namespaced Role, None for a ClusterRole or a legacy
    /// Royak `RbacRole` (whose rules carry their own namespace list).
    #[serde(default)]
    pub namespace: Option<String>,
    /// "Role", "ClusterRole" or "RbacRole" (legacy Royak kind).
    #[serde(default)]
    pub kind: String,
}

#[allow(dead_code)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RbacRule {
    pub resources: Vec<String>,     // ["pods", "deployments", "pods/exec", "*"]
    pub verbs: Vec<String>,         // ["get", "list", "create", "delete", "*"]
    pub namespaces: Vec<String>,    // ["default", "*"]
    /// Optional resourceNames restriction (empty = any name).
    #[serde(default)]
    pub resource_names: Vec<String>,
}

/// A RoleBinding / ClusterRoleBinding: grants a role's rules to subjects.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RbacBinding {
    pub name: String,
    /// Some(ns) for a RoleBinding (grants only inside ns), None for a
    /// ClusterRoleBinding (grants cluster-wide).
    pub namespace: Option<String>,
    /// "Role" or "ClusterRole".
    pub role_kind: String,
    pub role_name: String,
    pub subjects: Vec<RbacSubject>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RbacSubject {
    /// "User", "Group" or "ServiceAccount".
    pub kind: String,
    pub name: String,
    /// ServiceAccount namespace.
    #[serde(default)]
    pub namespace: Option<String>,
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ResourceLimits {
    pub cpu_request: Option<f32>,    // CPU cores requested (0.5 = half core)
    pub cpu_limit: Option<f32>,      // CPU cores max
    pub mem_request: Option<u64>,    // Memory MB requested
    pub mem_limit: Option<u64>,      // Memory MB max
}

// ─── Deployment Strategies (Canary, Blue-Green) ───

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum DeployStrategy {
    RollingUpdate { max_surge: u32, max_unavailable: u32 },
    Canary { weight: u32, steps: Vec<CanaryStep> },       // gradual rollout
    BlueGreen { active: String },                          // instant switch
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct CanaryStep {
    pub weight: u32,        // percentage of traffic (10, 25, 50, 100)
    pub pause_seconds: u64, // wait between steps
}


// ─── Cluster Events (kubectl get events) ───

#[derive(Clone)]
pub struct ClusterEvent {
    pub kind: String,        // "Pod", "Deployment", "Pipeline"
    pub object: String,      // resource name
    pub namespace: String,   // namespace of the object ("default" for cluster objects)
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
        // `ns/name` objects carry their namespace; pod names carry it in the
        // stem (`rk-<ns>_<name>-N`); anything else belongs to "default".
        let (namespace, object) = match object.split_once('/') {
            Some((ns, name)) => (ns.to_string(), name),
            None => {
                let ns = object.strip_prefix("rk-").and_then(|r| r.split_once('_')).map(|(ns, _)| ns.to_string())
                    .filter(|ns| crate::store::is_dns_label(ns))
                    .unwrap_or_else(|| crate::store::DEFAULT_NS.to_string());
                (ns, object)
            }
        };
        // Deduplicate: if same object+reason exists, increment count
        if let Some(existing) = self.events.iter_mut().find(|e| e.namespace == namespace && e.object == object && e.reason == reason) {
            existing.count += 1;
            existing.last_seen = now;
            existing.message = message.to_string();
            return;
        }
        self.events.push(ClusterEvent {
            kind: kind.to_string(), object: object.to_string(), namespace,
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Guard {
    pub name: String,
    pub rules: Vec<GuardRule>,
    pub hooks: HashMap<String, String>,
}

#[allow(dead_code)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Operator {
    pub name: String,
    pub custom_kind: String,                       // "PostgresCluster", "RedisCluster", etc.
    pub provision: Vec<OperatorComponent>,          // what to create when CR is applied
    pub hooks: HashMap<String, String>,             // lifecycle: on_create, on_crash, on_scale → shell cmd
    pub rules: Vec<GuardRule>,                      // brain-triggered rules specific to this operator
}

#[allow(dead_code)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomResource {
    pub name: String,
    pub kind: String,           // must match an operator's custom_kind
    pub namespace: String,
    pub spec: serde_json::Value, // user-provided spec (replicas, version, etc.)
    pub status: CRStatus,
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub enum CRStatus {
    Pending,
    Provisioning,
    Running,
    Failed,
}

/// Reconcile custom resources: for each CR, find its operator and provision
pub fn reconcile_operators(desired: &mut DesiredWorld, log: &mut Vec<String>) {
    let cr_keys: Vec<String> = desired.custom_resources.keys().cloned().collect();

    for cr_key in &cr_keys {
        let (kind, ns, spec, status, cr_name) = {
            let cr = &desired.custom_resources[cr_key];
            (cr.kind.clone(), cr.namespace.clone(), cr.spec.clone(), cr.status.clone(), cr.name.clone())
        };
        let cr_name = &cr_name;

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
                if !desired.deployments.contains_key(&crate::store::obj_key(&ns, &dep_name)) {
                    log.push(format!("  [operator/{}] {kind}/{cr_name}: component {dep_name} MISSING — re-provisioning", op.name));
                    all_healthy = false;
                    // Reset to Pending to trigger re-provision
                    if let Some(cr) = desired.custom_resources.get_mut(cr_key) {
                        cr.status = CRStatus::Pending;
                    }
                    break;
                }
            }
            if all_healthy && status == CRStatus::Provisioning {
                // Promotion: all deployments exist → mark as Running
                if let Some(cr) = desired.custom_resources.get_mut(cr_key) {
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
                host_access: None,
                security_context: None,
                name: component.role.clone(),
                image: component.image.clone(),
                command: None,
                env: env.clone(),
                env_from_configmaps: vec![], env_from_secrets: vec![], env_refs: vec![],
                volumes: vec![],
                liveness_probe: None,
                startup_probe: None,
                readiness_probe: None,
            }];

            desired.deployments.insert(crate::store::obj_key(&ns, &dep_name), StoredDeployment {
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
                restart_nonce: 0,
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
        if let Some(cr) = desired.custom_resources.get_mut(cr_key) {
            cr.status = CRStatus::Provisioning;
        }
    }
}

/// Cascade-delete selection (pure): names of deployments owned by `cr_name`.
///
/// A deployment is owned iff its `owner_ref` equals `Some(cr_name)`. Deployments
/// with no owner ref (user-created) are never selected, so unrelated workloads
/// are left untouched when a CustomResource is deleted.
pub fn deployments_owned_by(desired: &DesiredWorld, ns: &str, cr_name: &str) -> Vec<String> {
    desired.deployments.iter()
        .filter(|(_, d)| d.namespace == ns && d.owner_ref.as_deref() == Some(cr_name))
        .map(|(k, _)| k.clone())
        .collect()
}

/// Rolling update state
#[allow(dead_code)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct RolloutState {
    pub old_image: String,
    pub new_image: String,
    pub total_replicas: u32,
    pub old_pods: VecDeque<String>,  // container IDs to remove
    pub new_pods_created: u32,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredService {
    pub name: String,
    pub namespace: String,
    pub selector: HashMap<String, String>,
    pub ports: Vec<ServicePort>,
    pub service_type: String,  // ClusterIP, NodePort, LoadBalancer
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct ServicePort {
    pub port: u16,
    pub target_port: u16,
    pub protocol: String,
    pub node_port: Option<u16>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredIngress {
    pub name: String,
    pub namespace: String,
    pub rules: Vec<IngressRule>,
    /// spec.ingressClassName, if set. Royak has a single built-in controller
    /// (the default class "royak") that serves every Ingress, so this is
    /// honored for round-trip/compatibility rather than controller selection.
    pub ingress_class: Option<String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IngressRule {
    pub host: String,            // e.g. "app.example.com"
    pub paths: Vec<IngressPath>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct IngressPath {
    pub path: String,            // e.g. "/api"
    pub service: String,         // backend service name
    pub port: u16,               // backend port
}

/// Resource quota — namespace-level limits (CPU, memory, pod count)
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone)]
pub struct PodCertStatus {
    pub pod_name: String,
    pub namespace: String,
    pub issued_at: u64,       // unix timestamp
    pub expires_at: u64,      // unix timestamp
    pub fingerprint: String,
    pub revoked: bool,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredHPA {
    pub name: String,
    #[serde(default = "default_ns_string")]
    pub namespace: String,
    pub deployment: String,    // target deployment (same namespace)
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

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredDaemonSet {
    pub name: String,
    pub namespace: String,
    pub container: StoredContainer,
}

#[allow(dead_code)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredJob {
    pub name: String,
    pub namespace: String,
    pub container: StoredContainer,
    pub completions: u32,
    pub status: JobStatus,
}

#[allow(dead_code)]
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredCronJob {
    pub name: String,
    pub namespace: String,
    pub schedule: String,       // cron format: "*/5 * * * *"
    pub container: StoredContainer,
    pub last_run: Option<u64>,  // unix timestamp
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
    /// Bumped when something the pods consume but the spec does not show
    /// changes (a referenced ConfigMap/Secret). Part of the pod template hash,
    /// so a bump rolls the pods through the normal rolling-update path instead
    /// of apply() deleting containers as a side effect.
    #[serde(default)]
    pub restart_nonce: u64,
}

fn default_ns_string() -> String { "default".to_string() }

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredContainer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_access: Option<crate::host_access::Permit>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security_context: Option<crate::security::SecurityContext>,
    pub name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    pub env: Vec<String>,
    pub env_from_configmaps: Vec<String>,  // ConfigMap names to inject as env
    pub env_from_secrets: Vec<String>,     // Secret names to inject as env
    /// `env[].valueFrom` ConfigMap/Secret keys, resolved when the pod is
    /// planned. Omitted when empty so existing pod template hashes are stable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_refs: Vec<EnvKeyRef>,
    pub volumes: Vec<(String, String)>,    // (host_path, container_path)
    pub liveness_probe: Option<StoredProbe>,
    pub readiness_probe: Option<StoredProbe>,
    pub startup_probe: Option<StoredProbe>,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct EnvKeyRef {
    pub name: String,
    pub secret: bool,
    pub object: String,
    pub key: String,
    #[serde(default)]
    pub optional: bool,
}

/// Stored health probe configuration
#[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub struct StoredProbe {
    pub http_get: Option<(String, u16)>,   // (path, port)
    pub exec: Option<Vec<String>>,          // command
    /// TCP connect probe port. Skipped when absent so existing HTTP/exec probes
    /// serialize (and template-hash) exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp_socket: Option<u16>,
    pub initial_delay_seconds: u64,
    pub period_seconds: u64,
    pub failure_threshold: u32,
    #[serde(default = "legacy_probe_timeout", skip_serializing_if = "is_legacy_probe_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "probe_success_default", skip_serializing_if = "is_probe_success_default")]
    pub success_threshold: u32,
}

fn legacy_probe_timeout() -> u64 { 3 }
fn is_legacy_probe_timeout(n: &u64) -> bool { *n == 3 }
fn probe_success_default() -> u32 { 1 }
fn is_probe_success_default(n: &u32) -> bool { *n == 1 }

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredConfigMap {
    pub name: String,
    pub namespace: String,
    pub data: HashMap<String, String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredSecret {
    pub name: String,
    pub namespace: String,
    pub data: HashMap<String, String>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredPV {
    pub name: String,
    pub capacity: String,        // "10Gi", "500Mi"
    pub storage_class: String,   // "local", "nfs", "neurofs"
    pub host_path: String,       // actual path on host
    pub access_mode: String,     // "ReadWriteOnce", "ReadWriteMany"
    pub status: PVStatus,
    pub bound_to: Option<String>, // PVC name
}

#[derive(Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[allow(dead_code)]
pub enum PVStatus {
    Available,
    Bound,
    Released,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredPVC {
    pub name: String,
    pub namespace: String,
    pub storage_class: String,
    pub requested: String,       // "5Gi"
    pub access_mode: String,
    pub bound_pv: Option<String>, // PV name
}

/// StorageClass — dynamic volume provisioner
#[derive(Clone, serde::Serialize, serde::Deserialize)]
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
            generation: 0,
            cluster_id: crate::store::LEGACY_CLUSTER_ID.to_string(),
            deployments: HashMap::new(),
            daemonsets: HashMap::new(),
            jobs: HashMap::new(),
            cronjobs: HashMap::new(),
            hpas: HashMap::new(),
            services: HashMap::new(),
            restart_count: HashMap::new(),
            startup_ok: std::collections::HashSet::new(),
            pod_ready: std::collections::HashSet::new(),
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
            storage_identities: crate::storage_identity::Identities::fresh(),
            storage_node_directory: crate::storage_node_directory::Registry::fresh(),
            backup_registry: crate::backup_engine::Registry::fresh(),
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
            rbac_bindings: HashMap::new(),
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
    pub fn nodeport_publish_ports(&self, ns: &str, deployment: &str) -> Vec<u16> {
        let mut ports: Vec<u16> = self.services.values()
            .filter(|s| (s.service_type == "NodePort" || s.service_type == "LoadBalancer")
                && s.namespace == ns
                && s.selector.get("app").map(|a| a.as_str()) == Some(deployment))
            .flat_map(|s| s.ports.iter().map(|p| p.target_port))
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    pub fn synchronize_storage_identities(&mut self) -> Result<(),String> {
        self.storage_identities.synchronize(&self.namespaces,&self.pvs,&self.pvcs)
    }

    pub fn apply(&mut self, resource: &Resource) -> Result<String, String> {
        self.apply_with_host_access(resource, true)
    }
    pub fn apply_with_host_access(&mut self, resource: &Resource, authorized: bool) -> Result<String, String> {
        if crate::host_access::resource_requires(resource)? && !authorized {
            return Err("host access requires cluster-scoped use hostaccess permission".into());
        }
        let result=self.apply_resource(resource)?;
        self.synchronize_storage_identities()?;
        crate::host_access::issue_resource(self,resource,authorized)?;
        crate::storage_lifecycle::Registry::register_pending(self)?;
        Ok(result)
    }

    fn apply_resource(&mut self, resource: &Resource) -> Result<String, String> {
        // Identity validation: names become store keys ("ns/name") and Docker
        // container names, so they must be valid RFC 1123 names — in
        // particular they can never contain '/' or '_', the separators used to
        // keep namespaces apart.
        let kind = resource.kind.as_str();
        let cluster_scoped = crate::store::is_cluster_scoped_kind(kind);
        if kind != "Config" || !resource.metadata.name.is_empty() {
            if !crate::store::is_dns_subdomain(&resource.metadata.name) {
                return Err(format!("{kind} name {:?} is invalid: must be a lowercase RFC 1123 subdomain (a-z, 0-9, '-', '.')",
                    resource.metadata.name));
            }
        }
        if kind == "Namespace" && !crate::store::is_dns_label(&resource.metadata.name) {
            return Err(format!("namespace name {:?} is invalid: must be a lowercase RFC 1123 label", resource.metadata.name));
        }
        if !cluster_scoped {
            let ns = crate::store::ns_of(resource);
            if !crate::store::is_dns_label(&ns) {
                return Err(format!("namespace {ns:?} is invalid: must be a lowercase RFC 1123 label"));
            }
            // The legacy vct: lowering below discards the template spec. Refuse
            // explicit native/unknown classes before either that loss or an
            // implicit namespace insertion; no fresh native claim is invented.
            if kind == "StatefulSet" {
                if let Some(deployment) = spec::as_deployment(resource) {
                    for template in deployment.volume_claim_templates.as_deref().unwrap_or(&[]) {
                        crate::storage::require_legacy_template_class(self, template)?;
                    }
                }
            }
            // The first native consumer has no policy-capable network effect
            // permit. Refuse BEFORE even implicit namespace mutation; all API
            // apply/patch/replace scratch commits share this admission path.
            if kind=="NetworkPolicy" {
                let selector=resource.spec.as_ref().and_then(|s|s.get("podSelector"))
                    .and_then(|s|s.get("matchLabels")).and_then(|s|s.get("app"))
                    .and_then(|s|s.as_str()).unwrap_or("*");
                crate::workload::managed::require_supported_policy_admission(self,&ns,selector)?;
            }
            // Royak creates namespaces implicitly on first use.
            if !self.namespaces.iter().any(|n| n == &ns) {
                self.namespaces.push(ns);
            }
        }
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
                        if !crate::store::is_dns_label(&vct.metadata.name){return Err("invalid volumeClaimTemplate name".into());}
                        vct_map.insert(vct.metadata.name.clone(), format!("vct:{}", vct.metadata.name));
                    }
                }

                let volume_map = pod_volume_map(dep.template.spec.volumes.as_deref().unwrap_or(&[]), vct_map)?;
                let stored_containers: Vec<StoredContainer> = dep.template.spec.containers.iter()
                    .map(|c| parse_container(c, &volume_map, dep.template.spec.security_context.as_ref())).collect::<Result<_, _>>()?;

                // Init containers (run before main, must complete) get the same
                // full contract as main containers (env, envFrom, volumes).
                let init_containers: Vec<StoredContainer> = dep.template.spec.init_containers.as_ref()
                    .map(|inits| inits.iter().map(|c| {
                        if c.liveness_probe.is_some() || c.readiness_probe.is_some() || c.startup_probe.is_some() {
                            return Err(format!("init container {:?}: regular init containers cannot define probes", c.name));
                        }
                        parse_container(c, &volume_map, dep.template.spec.security_context.as_ref())
                    }).collect::<Result<_, _>>())
                    .transpose()?
                    .unwrap_or_default();

                let first = match stored_containers.first() {
                    Some(c) => c,
                    None => return Err("Deployment has no containers".to_string()),
                };
                let container_count = stored_containers.len();
                let init_count = init_containers.len();
                let new_image = first.image.clone();
                let replicas = dep.replicas.unwrap_or(1);
                let key = crate::store::obj_key(&ns, &name);

                // Detect image change → trigger rolling update
                let rolling = if let Some(existing) = self.deployments.get(&key) {
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
                    self.limit_ranges.values().find(|lr| lr.namespace == ns).map(|lr| {
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

                // Save previous image for rollback; keep the restart nonce so a
                // re-apply of an unchanged spec does not roll the pods.
                let previous_image = self.deployments.get(&key).map(|d| d.image.clone());
                let restart_nonce = self.deployments.get(&key).map(|d| d.restart_nonce).unwrap_or(0);

                self.deployments.insert(key.clone(), StoredDeployment {
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
                    restart_nonce,
                });

                if let Some(old_image) = rolling {
                    self.pending_rollouts.insert(key.clone(), RolloutState {
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

                let key = crate::store::obj_key(&ns, &name);
                // Detect change: if the ConfigMap existed with different data,
                // the pods consuming it must be restarted. That is expressed in
                // desired state (restart nonce) — the reconcile loop rolls them —
                // so a write that is never committed restarts nothing.
                let changed = self.configmaps.get(&key)
                    .map(|old| old.data != data)
                    .unwrap_or(false);
                let n_keys = data.len();
                self.configmaps.insert(key, StoredConfigMap {
                    name: name.clone(),
                    namespace: ns.clone(),
                    data,
                });
                if changed {
                    let restarted = self.bump_consumers(&ns, &name, false);
                    if restarted.is_empty() {
                        Ok(format!("configmap/{name} updated ({n_keys} keys)"))
                    } else {
                        Ok(format!("configmap/{name} updated → rolling restart: {}", restarted.join(", ")))
                    }
                } else {
                    Ok(format!("configmap/{name} applied ({n_keys} keys)"))
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

                let key = crate::store::obj_key(&ns, &name);
                let changed = self.secrets.get(&key).map(|old| old.data != data).unwrap_or(false);
                let n_keys = data.len();
                self.secrets.insert(key, StoredSecret {
                    name: name.clone(),
                    namespace: ns.clone(),
                    data,
                });
                if changed {
                    let restarted = self.bump_consumers(&ns, &name, true);
                    if !restarted.is_empty() {
                        return Ok(format!("secret/{name} updated → rolling restart: {}", restarted.join(", ")));
                    }
                }
                Ok(format!("secret/{name} applied ({n_keys} keys)"))
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
                // A node port is one host socket: two Services may not claim it.
                let key = crate::store::obj_key(&ns, &name);
                let listen_ports = |t: &str, ps: &[ServicePort]| -> Vec<u16> {
                    match t {
                        "NodePort" => ps.iter().filter_map(|p| p.node_port).collect(),
                        "LoadBalancer" => ps.iter().map(|p| p.port).collect(),
                        _ => Vec::new(),
                    }
                };
                for lp in listen_ports(&service_type, &ports) {
                    if lp == 0 {
                        return Err(format!("service/{name}: port 0 cannot be exposed on the node"));
                    }
                    if let Some((other, _)) = self.services.iter()
                        .find(|(k, o)| **k != key && listen_ports(&o.service_type, &o.ports).contains(&lp)) {
                        return Err(format!("service/{name}: node port {lp} is already allocated to service {other}"));
                    }
                }
                let port_desc: Vec<String> = ports.iter().map(|p| format!("{}→{}", p.port, p.target_port)).collect();
                self.services.insert(key, StoredService {
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

                let provisioner = crate::storage::string_field(spec, &["provisioner"], "royak/host-path")?;
                let native=provisioner==crate::storage_lifecycle::PROVISIONER;
                let host_path_prefix = crate::storage::string_field(spec, &["hostPathPrefix"], if native {""} else {"/data/royak/volumes"})?;
                let reclaim_policy = crate::storage::string_field(spec, &["reclaimPolicy"], "Delete")?;

                if provisioner != "royak/host-path" && !native {
                    return Err(format!("storageclass/{name}: unsupported provisioner {provisioner:?}; no storage driver is installed"));
                }
                if native && !host_path_prefix.is_empty() {
                    return Err("managed storage never accepts a user-supplied host path".into());
                }
                if !native && crate::host_access::validate_public_path(&host_path_prefix).is_err() {
                    return Err(format!("storageclass/{name}: unsafe hostPathPrefix"));
                }
                if !matches!(reclaim_policy.as_str(), "Retain" | "Delete") {
                    return Err(format!("storageclass/{name}: reclaimPolicy must be Retain or Delete"));
                }
                if let Some(existing) = self.storage_classes.get(&name) {
                    if existing.provisioner != provisioner || existing.host_path_prefix != host_path_prefix
                        || existing.reclaim_policy != reclaim_policy {
                        return Err(format!("storageclass/{name}: provisioning and retention settings are immutable"));
                    }
                    return Ok(format!("storageclass/{name} unchanged"));
                }

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

                let capacity = crate::storage::string_field(spec, &["capacity", "storage"], "1Gi")?;
                let capacity_bytes = crate::storage::capacity_bytes(&capacity)?;
                let storage_class = crate::storage::string_field(spec, &["storageClassName"], "local")?;
                if self.storage_classes.get(&storage_class).is_some_and(|s|s.provisioner==crate::storage_lifecycle::PROVISIONER) {
                    return Err("managed PV metadata is controller-owned; create a PersistentVolumeClaim instead".into());
                }
                let host_path = crate::storage::string_field(spec, &["hostPath", "path"], "/data")?;
                let access_mode = crate::storage::access_mode(spec)?;

                if crate::host_access::validate_public_path(&host_path).is_err() {
                    return Err(format!("pv/{name}: unsafe hostPath {host_path}"));
                }
                // Reapply is not a release/adoption operation. In particular,
                // it cannot turn a Bound or Released volume back to Available.
                if let Some(existing) = self.pvs.get(&name) {
                    if crate::storage::capacity_bytes(&existing.capacity)? != capacity_bytes
                        || existing.storage_class != storage_class || existing.host_path != host_path
                        || existing.access_mode != access_mode {
                        return Err(format!("pv/{name}: capacity, class, path and access mode are immutable; expansion is not implemented"));
                    }
                    return Ok(format!("pv/{name} unchanged"));
                }
                // The host directory is created when a pod mounts it (or after
                // the commit, see materialize_storage) — never during apply,
                // which may run on a scratch copy that is then rejected.
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

                let storage_class = crate::storage::string_field(spec, &["storageClassName"], "local")?;
                let requested = crate::storage::string_field(spec, &["resources", "requests", "storage"], "1Gi")?;
                let requested_bytes = crate::storage::capacity_bytes(&requested)?;
                let access_mode = crate::storage::access_mode(spec)?;

                let key = crate::store::obj_key(&ns, &name);
                if self.storage_classes.get(&storage_class).is_some_and(|s|s.provisioner==crate::storage_lifecycle::PROVISIONER)
                    && access_mode!="ReadWriteOnce" {
                    return Err("managed replicated volumes require ReadWriteOnce and one active writer pod".into());
                }
                // Re-applying a bound claim keeps its binding.
                if let Some(existing) = self.pvcs.get(&key) {
                    if let Some(pv) = existing.bound_pv.clone() {
                        if existing.storage_class != storage_class || existing.access_mode != access_mode
                            || crate::storage::capacity_bytes(&existing.requested)? != requested_bytes {
                            return Err(format!("pvc/{name}: a bound claim is immutable; expansion is not implemented"));
                        }
                        let volume = self.pvs.get(&pv).ok_or_else(|| format!("pvc/{name}: bound PV is missing"))?;
                        if volume.status != PVStatus::Bound || volume.bound_to.as_deref() != Some(key.as_str())
                            || volume.storage_class != storage_class || volume.access_mode != access_mode
                            || crate::storage::capacity_bytes(&volume.capacity)? < requested_bytes {
                            return Err(format!("pvc/{name}: inconsistent PV binding; refusing to adopt storage"));
                        }
                        return Ok(format!("pvc/{name} Bound ({requested}) → pv/{pv}"));
                    }
                }
                // Auto-bind to matching PV
                let mut bound_pv = None;
                for (pv_name, pv) in self.pvs.iter_mut() {
                    if pv.status == PVStatus::Available
                        && pv.bound_to.is_none()
                        && pv.storage_class == storage_class
                        && pv.access_mode == access_mode
                        && crate::storage::capacity_bytes(&pv.capacity).is_ok_and(|n| n >= requested_bytes)
                    {
                        pv.status = PVStatus::Bound;
                        pv.bound_to = Some(key.clone());
                        bound_pv = Some(pv_name.clone());
                        break;
                    }
                }

                // Dynamic provisioning: if no PV matches, use StorageClass to create one
                if bound_pv.is_none() {
                    if let Some(sc) = self.storage_classes.get_mut(&storage_class) {
                        let native=sc.provisioner==crate::storage_lifecycle::PROVISIONER;
                        if !native && (sc.provisioner != "royak/host-path" || !validate_path(&sc.host_path_prefix)) {
                            return Err(format!("pvc/{name}: unsupported or unsafe provisioner"));
                        }
                        let count = sc.provisioned_count.checked_add(1).ok_or("storage class provision counter exhausted")?;
                        // Fresh data identity even when the same claim/class is
                        // deleted and recreated. Retained paths are never reused.
                        let identity = format!("{:032x}", rand::random::<u128>());
                        let pv_name = format!("pv-auto-{identity}");
                        if self.pvs.contains_key(&pv_name) { return Err("storage identity collision; retry admission".into()); }
                        let host_path = if native {String::new()} else {format!("{}/{}/{name}-{identity}", sc.host_path_prefix, ns)};
                        // Directory is created after commit (materialize_storage).

                        let pv = StoredPV {
                            name: pv_name.clone(),
                            capacity: requested.clone(),
                            storage_class: sc.name.clone(),
                            host_path: host_path.clone(),
                            access_mode: access_mode.clone(),
                            status: PVStatus::Bound,
                            bound_to: Some(key.clone()),
                        };
                        self.pvs.insert(pv_name.clone(), pv);
                        sc.provisioned_count = count;
                        bound_pv = Some(pv_name);
                        let _ = &host_path;
                    }
                }

                let status = if bound_pv.is_some() { "Bound" } else { "Pending" };

                self.pvcs.insert(key, StoredPVC {
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
                validate_single_container_probe_scope(&dep.template.spec)?;
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let c = dep.template.spec.containers.first().ok_or("DaemonSet has no containers")?;
                let volume_map = pod_volume_map(dep.template.spec.volumes.as_deref().unwrap_or(&[]), HashMap::new())?;
                self.daemonsets.insert(crate::store::obj_key(&ns, &name), StoredDaemonSet {
                    name: name.clone(),
                    namespace: ns,
                    container: parse_container(c, &volume_map, dep.template.spec.security_context.as_ref())?,
                });
                Ok(format!("daemonset/{name} applied (runs on every node)"))
            }

            "Job" => {
                let dep = spec::as_deployment(resource).ok_or("Invalid Job spec")?;
                validate_single_container_probe_scope(&dep.template.spec)?;
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let c = dep.template.spec.containers.first().ok_or("Job has no containers")?;
                let volume_map = pod_volume_map(dep.template.spec.volumes.as_deref().unwrap_or(&[]), HashMap::new())?;
                let completions = dep.replicas.unwrap_or(1);

                self.jobs.insert(crate::store::obj_key(&ns, &name), StoredJob {
                    name: name.clone(),
                    namespace: ns,
                    container: parse_container(c, &volume_map, dep.template.spec.security_context.as_ref())?,
                    completions,
                    status: JobStatus::Pending,
                });
                Ok(format!("job/{name} created (completions: {completions})"))
            }

            "CronJob" => {
                let dep = spec::as_deployment(resource).ok_or("Invalid CronJob spec")?;
                validate_single_container_probe_scope(&dep.template.spec)?;
                let name = resource.metadata.name.clone();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let c = dep.template.spec.containers.first().ok_or("CronJob has no containers")?;
                let volume_map = pod_volume_map(dep.template.spec.volumes.as_deref().unwrap_or(&[]), HashMap::new())?;
                let key = crate::store::obj_key(&ns, &name);
                // Re-applying keeps the run bookkeeping.
                let last_run = self.cronjobs.get(&key).and_then(|c| c.last_run);
                let schedule = resource.spec.as_ref()
                    .and_then(|s| s.get("schedule"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("*/5 * * * *").to_string();

                self.cronjobs.insert(key, StoredCronJob {
                    name: name.clone(),
                    namespace: ns,
                    schedule: schedule.clone(),
                    container: parse_container(c, &volume_map, dep.template.spec.security_context.as_ref())?,
                    last_run,
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
                self.ingresses.insert(crate::store::obj_key(&ns, &name), StoredIngress { name: name.clone(), namespace: ns, rules, ingress_class });
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

                let key = crate::store::obj_key(&ns, &name);
                self.network_policies.insert(key.clone(), StoredNetworkPolicy {
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
                    self.network_policies[&key].pod_selector,
                    self.network_policies[&key].ingress_allow.len(),
                    self.network_policies[&key].egress_allow.len()))
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
                let ns = crate::store::ns_of(resource);
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

                let key = crate::store::obj_key(&ns, &name);
                let (history, last_scaled) = self.hpas.get(&key)
                    .map(|h| (h.history.clone(), h.last_scaled)).unwrap_or_default();
                self.hpas.insert(key, StoredHPA {
                    name: name.clone(),
                    namespace: ns,
                    deployment: deployment.clone(),
                    min_replicas,
                    max_replicas,
                    target_cpu,
                    history,
                    last_scaled,
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
                if let Some(bad) = http_triggers.iter().chain(&webhook_triggers).find(|p| !crate::auth::is_function_trigger_path(p)) {
                    return Err(format!("Function {name}: trigger path {bad} is reserved (it is a Kubernetes, Royak or system endpoint); use e.g. /fn/... or /hooks/..."));
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
                    // K8s semantics: a missing list grants nothing (not "*").
                    let get_strings = |key: &str| -> Vec<String> {
                        r.get(key).and_then(|v| v.as_sequence())
                            .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default()
                    };
                    RbacRule {
                        resources: get_strings("resources"),
                        verbs: get_strings("verbs"),
                        namespaces: vec![ns_scope.clone()],
                        resource_names: get_strings("resourceNames"),
                    }
                }).collect();
                let rule_count = rules.len();
                let (key, namespace) = if resource.kind == "ClusterRole" {
                    (name.clone(), None)
                } else {
                    (crate::store::obj_key(&ns_scope, &name), Some(ns_scope.clone()))
                };
                self.rbac_roles.insert(key, RbacRole { name: name.clone(), rules, namespace, kind: resource.kind.clone() });
                Ok(format!("{}/{name} configured ({rule_count} rules, ns={ns_scope})", resource.kind.to_lowercase()))
            }
            // RoleBinding/ClusterRoleBinding: stored as bindings and resolved at
            // authorization time (auth::authorize) — subjects are User, Group
            // or ServiceAccount identities established by authentication.
            "RoleBinding" | "ClusterRoleBinding" => {
                let name = resource.metadata.name.clone();
                let role_ref = resource.role_ref.as_ref().ok_or("RoleBinding needs roleRef")?;
                let role_name = role_ref.get("name").and_then(|v| v.as_str())
                    .ok_or("RoleBinding needs roleRef.name")?
                    .to_string();
                let role_kind = role_ref.get("kind").and_then(|v| v.as_str()).unwrap_or("ClusterRole").to_string();
                if role_kind != "Role" && role_kind != "ClusterRole" {
                    return Err(format!("roleRef.kind must be Role or ClusterRole, got {role_kind}"));
                }
                if resource.kind == "ClusterRoleBinding" && role_kind != "ClusterRole" {
                    return Err("ClusterRoleBinding may only reference a ClusterRole".to_string());
                }
                let subjects: Vec<RbacSubject> = resource.subjects.as_ref()
                    .and_then(|s| s.as_sequence())
                    .map(|arr| arr.iter().filter_map(|s| {
                        let name = s.get("name").and_then(|v| v.as_str())?.to_string();
                        let kind = s.get("kind").and_then(|v| v.as_str()).unwrap_or("User").to_string();
                        let namespace = s.get("namespace").and_then(|v| v.as_str()).map(|s| s.to_string());
                        Some(RbacSubject { kind, name, namespace })
                    }).collect())
                    .unwrap_or_default();
                if subjects.is_empty() {
                    return Err("RoleBinding needs at least one subject".to_string());
                }
                if let Some(bad) = subjects.iter().find(|s| !matches!(s.kind.as_str(), "User" | "Group" | "ServiceAccount")) {
                    return Err(format!("unsupported subject kind {}", bad.kind));
                }
                let n = subjects.len();
                let (key, namespace) = if resource.kind == "ClusterRoleBinding" {
                    (name.clone(), None)
                } else {
                    let ns = crate::store::ns_of(resource);
                    (crate::store::obj_key(&ns, &name), Some(ns))
                };
                self.rbac_bindings.insert(key, RbacBinding { name: name.clone(), namespace, role_kind: role_kind.clone(), role_name: role_name.clone(), subjects });
                Ok(format!("{}/{name}: {n} subject(s) bound to {} '{role_name}'", resource.kind.to_lowercase(), role_kind.to_lowercase()))
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
                self.limit_ranges.insert(crate::store::obj_key(&ns, &name), lr);
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
                        resource_names: Vec::new(),
                    }
                }).collect();
                let rule_count = rules.len();
                self.rbac_roles.insert(name.clone(), RbacRole { name: name.clone(), rules, namespace: None, kind: "RbacRole".to_string() });
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
                // The custom kind comes from spec.resourceKind or spec.kind.
                let actual_kind = sv.get("resourceKind").and_then(|v| v.as_str())
                    .or_else(|| sv.get("kind").and_then(|v| v.as_str()))
                    .ok_or("CustomResource needs spec.resourceKind")?
                    .to_string();
                let ns = resource.metadata.namespace.clone().unwrap_or("default".to_string());
                let spec_json = serde_json::to_value(sv).unwrap_or(serde_json::json!({}));
                let key = crate::store::obj_key(&ns, &name);
                // Re-applying an unchanged CR keeps its lifecycle status.
                let status = self.custom_resources.get(&key)
                    .filter(|cr| cr.spec == spec_json && cr.kind == actual_kind)
                    .map(|cr| cr.status.clone()).unwrap_or(CRStatus::Pending);
                self.custom_resources.insert(key, CustomResource {
                    name: name.clone(), kind: actual_kind.clone(),
                    namespace: ns, spec: spec_json, status,
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

    /// Mark every deployment in `ns` that consumes ConfigMap/Secret `name`
    /// (envFrom or projected volume) for a rolling restart. Returns the names.
    pub fn bump_consumers(&mut self, ns: &str, name: &str, is_secret: bool) -> Vec<String> {
        let vol_ref = if is_secret { format!("sev:{name}") } else { format!("cmv:{name}") };
        let mut restarted = Vec::new();
        for dep in self.deployments.values_mut() {
            if dep.namespace != ns { continue; }
            let uses = dep.containers.iter().chain(dep.init_containers.iter()).any(|c| {
                let env_ref = if is_secret { &c.env_from_secrets } else { &c.env_from_configmaps };
                env_ref.iter().any(|n| n == name) || c.volumes.iter().any(|(h, _)| h == &vol_ref)
            });
            if uses {
                dep.restart_nonce += 1;
                restarted.push(dep.name.clone());
            }
        }
        restarted.sort();
        restarted
    }

    /// Delete a namespaced or cluster-scoped object. `ns` is ignored for
    /// cluster-scoped kinds. Returns None if it did not exist; otherwise the
    /// host paths that must be removed once the deletion is committed (a PVC
    /// whose StorageClass reclaim policy is Delete). Never touches the disk or
    /// Docker itself — the caller does that only after a successful commit,
    /// and the reconcile loop garbage-collects the containers.
    pub fn delete_resource(&mut self, resource_type: &str, ns: &str, name: &str) -> Option<Vec<String>> {
        if self.validate_storage_delete(resource_type,ns,name).is_err() { return None; }
        let result=self.delete_resource_inner(resource_type,ns,name);
        if result.is_some() {
            // A commit validates the resulting identities before publishing;
            // do not discard old identities to mask a namespace mismatch.
            let _ = self.synchronize_storage_identities();
        }
        result
    }

    /// Admission must not remove a claimed PV, nor erase arbitrary legacy host
    /// paths while writers may still be using them. A real driver needs durable
    /// detach/fencing acknowledgements before honoring Delete. Until that
    /// lifecycle is implemented, legacy Delete fails explicitly instead of
    /// acknowledging deletion and removing a directory behind a running pod.
    pub fn validate_storage_delete(&self, kind: &str, ns: &str, name: &str) -> Result<(),String> {
        match kind {
            "persistentvolumes"|"persistentvolume"|"pvs"|"pv" => {
                if self.pvs.get(name).is_some_and(|v|v.status==PVStatus::Bound)
                    || self.pvcs.values().any(|c|c.bound_pv.as_deref()==Some(name)) {
                    return Err("persistentvolume is still claimed; delete/detach the claim before removing PV metadata".into());
                }
            },
            "persistentvolumeclaims"|"persistentvolumeclaim"|"pvcs"|"pvc" => {
                if let Some(c)=self.pvcs.get(&crate::store::obj_key(ns,name)) {
                    if let Some(pv)=&c.bound_pv {
                        if let Some(uid)=self.storage_identities.volumes.get(pv) {
                            if !self.storage_identities.lifecycle.may_remove_metadata(uid) {
                                return Err("managed volume needs verified release/detach/fencing before metadata deletion".into());
                            }
                        }
                        let pv=self.pvs.get(pv).ok_or("claim binding is inconsistent; refusing data deletion")?;
                        if self.storage_classes.get(&pv.storage_class).is_some_and(|sc|sc.provisioner=="royak/host-path" && sc.reclaim_policy=="Delete") {
                            return Err("legacy host-path Delete reclaim is not qualified: no durable detach/fencing proof; data was NOT removed".into());
                        }
                    }
                }
            },
            "storageclasses"|"storageclass" => {
                if self.pvs.values().filter(|pv|pv.storage_class==name).any(|pv|
                    self.storage_identities.lifecycle.for_pv(&self.storage_identities,&pv.name)
                        .is_some_and(|v|!matches!(v.phase(),crate::storage_lifecycle::Phase::Released|crate::storage_lifecycle::Phase::Deleted))) {
                    return Err("storage class still owns managed volume lifecycle records".into());
                }
            },
            "namespaces"|"namespace"|"ns" => {
                for c in self.pvcs.values().filter(|c|c.namespace==name) {
                    self.validate_storage_delete("pvc",name,&c.name)?;
                }
            },
            _=>{},
        }
        Ok(())
    }

    fn delete_resource_inner(&mut self, resource_type: &str, ns: &str, name: &str) -> Option<Vec<String>> {
        use crate::store::obj_key;
        let key = obj_key(ns, name);
        let none = || Some(Vec::new());
        match resource_type {
            "deployments" | "deployment" | "statefulsets" | "statefulset" | "replicasets" | "replicaset" | "pods_deployment" => {
                let d = self.deployments.remove(&key)?;
                self.pending_rollouts.remove(&key);
                for kind in ["Deployment", "StatefulSet", "ReplicaSet", "Pod"] {
                    self.manifests.remove(&format!("{kind}/{ns}/{name}"));
                }
                // HPAs targeting it stay (K8s semantics) but have nothing to scale.
                let _ = d;
                none()
            }
            "daemonsets" | "daemonset" => self.daemonsets.remove(&key).and_then(|_| none()),
            "jobs" | "job" => self.jobs.remove(&key).and_then(|_| none()),
            "cronjobs" | "cronjob" => self.cronjobs.remove(&key).and_then(|_| none()),
            "hpa" | "horizontalpodautoscalers" | "horizontalpodautoscaler" => self.hpas.remove(&key).and_then(|_| none()),
            "services" | "service" | "svc" => self.services.remove(&key).and_then(|_| none()),
            "configmaps" | "configmap" | "cm" => self.configmaps.remove(&key).and_then(|_| none()),
            "secrets" | "secret" => self.secrets.remove(&key).and_then(|_| none()),
            "ingresses" | "ingress" | "ing" => self.ingresses.remove(&key).and_then(|_| none()),
            "networkpolicies" | "networkpolicy" | "netpol" => self.network_policies.remove(&key).and_then(|_| none()),
            "resourcequotas" | "resourcequota" | "quota" => self.resource_quotas.remove(&key).and_then(|_| none()),
            "limitranges" | "limitrange" => self.limit_ranges.remove(&key).and_then(|_| none()),
            "roles" | "role" => self.rbac_roles.remove(&key).and_then(|_| none()),
            "rolebindings" | "rolebinding" => self.rbac_bindings.remove(&key).and_then(|_| none()),
            "clusterroles" | "clusterrole" => self.rbac_roles.remove(name).and_then(|_| none()),
            "clusterrolebindings" | "clusterrolebinding" => self.rbac_bindings.remove(name).and_then(|_| none()),
            "persistentvolumes" | "persistentvolume" | "pvs" | "pv" => self.pvs.remove(name).and_then(|_| none()),
            "persistentvolumeclaims" | "persistentvolumeclaim" | "pvcs" | "pvc" => {
                if let Some(uid)=self.pvcs.get(&key).and_then(|c|c.bound_pv.as_ref())
                    .and_then(|pv|self.storage_identities.volumes.get(pv)).cloned() {
                    if self.storage_identities.lifecycle.cancel_unstarted(&uid).is_err() {return None;}
                }
                let pvc = self.pvcs.remove(&key)?;
                let mut cleanup = Vec::new();
                if let Some(pv_name) = &pvc.bound_pv {
                    let mut drop_pv = false;
                    if let Some(pv) = self.pvs.get_mut(pv_name) {
                        pv.status = PVStatus::Released;
                        pv.bound_to = None;
                        // StorageClass reclaim policy Delete → PV and data go.
                        if let Some(sc) = self.storage_classes.get(&pv.storage_class) {
                            if sc.reclaim_policy == "Delete" {
                                if sc.provisioner=="royak/host-path" {cleanup.push(pv.host_path.clone());}
                                drop_pv = true;
                            }
                        }
                    }
                    if drop_pv { self.pvs.remove(pv_name); }
                }
                Some(cleanup)
            }
            "storageclasses" | "storageclass" => self.storage_classes.remove(name).and_then(|_| none()),
            "ingressclasses" | "ingressclass" => if self.ingress_classes.remove(name) { none() } else { None },
            "validatingwebhookconfigurations" | "validatingwebhookconfiguration" => self.admission_webhooks.remove(name).and_then(|_| none()),
            "functions" | "function" => self.functions.remove(name).and_then(|_| none()),
            "pipelines" | "pipeline" => self.pipelines.remove(name).and_then(|_| none()),
            "repositories" | "repository" | "repo" => self.repositories.remove(name).and_then(|_| none()),
            "guards" | "guard" => self.guards.remove(name).and_then(|_| none()),
            "operators" | "operator" => self.operators.remove(name).and_then(|_| none()),
            "rbacroles" | "rbacrole" => self.rbac_roles.remove(name).and_then(|_| none()),
            "customresources" | "customresource" | "cr" => {
                // Cascade-delete (owner-reference GC): removing a CR also removes
                // the deployments its operator provisioned in the same namespace.
                self.custom_resources.remove(&key)?;
                for dep_key in deployments_owned_by(self, ns, name) {
                    self.deployments.remove(&dep_key);
                    self.pending_rollouts.remove(&dep_key);
                }
                none()
            }
            "namespaces" | "namespace" | "ns" => {
                if name == crate::store::DEFAULT_NS {
                    return None; // the default namespace cannot be deleted
                }
                if !self.namespaces.iter().any(|n| n == name) { return None; }
                Some(self.delete_namespace(name))
            }
            _ => None,
        }
    }

    /// Cascade-delete a namespace and every namespaced object in it. Returns
    /// host paths to clean up after commit.
    fn delete_namespace(&mut self, ns: &str) -> Vec<String> {
        let prefix = format!("{ns}/");
        let in_ns = |k: &String| k.starts_with(&prefix);
        let mut cleanup = Vec::new();
        let pvc_keys: Vec<String> = self.pvcs.keys().filter(|k| in_ns(k)).cloned().collect();
        for k in pvc_keys {
            let (_, name) = crate::store::split_key(&k);
            let name = name.to_string();
            if let Some(mut c) = self.delete_resource("pvcs", ns, &name) { cleanup.append(&mut c); }
        }
        self.deployments.retain(|k, _| !in_ns(k));
        self.pending_rollouts.retain(|k, _| !in_ns(k));
        self.daemonsets.retain(|k, _| !in_ns(k));
        self.jobs.retain(|k, _| !in_ns(k));
        self.cronjobs.retain(|k, _| !in_ns(k));
        self.hpas.retain(|k, _| !in_ns(k));
        self.services.retain(|k, _| !in_ns(k));
        self.configmaps.retain(|k, _| !in_ns(k));
        self.secrets.retain(|k, _| !in_ns(k));
        self.ingresses.retain(|k, _| !in_ns(k));
        self.network_policies.retain(|k, _| !in_ns(k));
        self.resource_quotas.retain(|k, _| !in_ns(k));
        self.limit_ranges.retain(|k, _| !in_ns(k));
        self.custom_resources.retain(|k, _| !in_ns(k));
        self.rbac_roles.retain(|k, _| !in_ns(k));
        self.rbac_bindings.retain(|k, _| !in_ns(k));
        let manifest_mid = format!("/{ns}/");
        self.manifests.retain(|k, _| !k.contains(&manifest_mid));
        self.namespaces.retain(|n| n != ns);
        cleanup
    }

    /// Host directories implied by committed desired state that must exist
    /// before pods can mount them (dynamically provisioned host-path PVs).
    /// Idempotent; called after commits and by the reconcile loop.
    pub fn materialize_storage(&self) {
        for pvc in self.pvcs.values() {
            let Ok(pv) = crate::storage::bound_volume(self, &pvc.namespace, &pvc.name) else { continue };
            let provisioner = self.storage_classes.get(&pv.storage_class).map(|sc| sc.provisioner.as_str());
            if matches!(provisioner, None | Some("royak/host-path")) && crate::host_access::validate_resolved_public_path(&pv.host_path).is_ok() {
                if let Err(e) = std::fs::create_dir_all(&pv.host_path) {
                    eprintln!("  ⚠ [storage] cannot create {}: {e}", pv.host_path);
                }
            }
        }
    }
}

/// Remove host paths released by a committed deletion (PVC reclaim=Delete).
pub fn cleanup_paths(paths: &[String]) {
    for p in paths {
        if validate_path(p) {
            if let Err(e) = std::fs::remove_dir_all(p) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("  ⚠ [storage] cannot remove {p}: {e}");
                }
            }
        }
    }
}

/// Map pod-level volume names to the host-side reference stored with each
/// mount. Host paths are stored as-is; everything resolved at pod creation
/// uses a prefix: `emptydir:`, `cmv:` (ConfigMap), `sev:` (Secret), `pvc:`,
/// `vct:` (StatefulSet volumeClaimTemplate).
fn pod_volume_map(vols: &[spec::VolumeSpec], vct_map: HashMap<String, String>) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    for v in vols {
        if !crate::store::is_dns_label(&v.name) || map.contains_key(&v.name) {
            return Err("volume names must be unique RFC1123 labels".into());
        }
        if [v.host_path.is_some(),v.empty_dir.is_some(),v.config_map.is_some(),v.secret.is_some(),v.pvc.is_some()].into_iter().filter(|v|*v).count()!=1 {
            return Err("volume must define exactly one supported source".into());
        }
        if let Some(hp) = &v.host_path {
            if crate::host_access::validate_public_path(&hp.path).is_err() {
                return Err(format!("volume {}: unsafe hostPath {:?} rejected", v.name, hp.path));
            }
            map.insert(v.name.clone(), hp.path.clone());
        } else if v.empty_dir.is_some() {
            map.insert(v.name.clone(), format!("emptydir:{}", v.name));
        } else if let Some(cm) = &v.config_map {
            map.insert(v.name.clone(), format!("cmv:{}", cm.name));
        } else if let Some(sv) = &v.secret {
            map.insert(v.name.clone(), format!("sev:{}", sv.secret_name));
        } else if let Some(pvc_ref) = &v.pvc {
            // Resolved at pod creation against the claim in the pod's own
            // namespace — never against a same-named claim elsewhere.
            map.insert(v.name.clone(), format!("pvc:{}", pvc_ref.claim_name));
        }
    }
    map.extend(vct_map);
    Ok(map)
}

/// Validate and store a probe. A probe must have exactly one supported
/// handler — an empty, ambiguous or unsupported probe is rejected here rather
/// than silently counting as healthy at runtime.
fn parse_probe(kind: &str, p: &spec::ProbeSpec) -> Result<StoredProbe, String> {
    if !crate::security::runtime_supported() {
        return Err(format!("{kind}: health probes require Docker runtime; experimental NeuroPod does not execute them"));
    }
    if p.period_seconds == 0 || p.timeout_seconds == 0 || p.failure_threshold == 0 || p.success_threshold == 0 {
        return Err(format!("{kind}: periodSeconds, timeoutSeconds and thresholds must be positive"));
    }
    if [p.period_seconds, p.timeout_seconds, p.initial_delay_seconds, p.failure_threshold as u64, p.success_threshold as u64]
        .iter().any(|n| *n > i32::MAX as u64) {
        return Err(format!("{kind}: probe timing/threshold value exceeds int32 range"));
    }
    if !kind.ends_with("readinessProbe") && p.success_threshold != 1 {
        return Err(format!("{kind}: successThreshold must be 1 for startup/liveness"));
    }
    let port = |what: &str, port: &spec::ProbePort| -> Result<u16, String> {
        match port {
            spec::ProbePort::Number(n) if (1..=65535).contains(n) => Ok(*n as u16),
            spec::ProbePort::Number(n) => Err(format!("{kind}: {what} port {n} is out of range (1-65535)")),
            spec::ProbePort::Name(name) => Err(format!(
                "{kind}: {what} uses named port {name:?}; Royak does not resolve named ports — use the port number")),
        }
    };
    if p.grpc.is_some() {
        return Err(format!("{kind}: grpc probes are not supported (use httpGet, tcpSocket or exec)"));
    }
    let handlers = [p.http_get.is_some(), p.exec.is_some(), p.tcp_socket.is_some()].iter().filter(|h| **h).count();
    if handlers == 0 {
        return Err(format!("{kind}: no handler — set exactly one of httpGet, tcpSocket or exec"));
    }
    if handlers > 1 {
        return Err(format!("{kind}: set exactly one of httpGet, tcpSocket or exec"));
    }
    let http_get = match &p.http_get {
        Some(h) => {
            if h.scheme.as_deref().unwrap_or("HTTP") != "HTTP" {
                return Err(format!("{kind}: only HTTP probes are supported; HTTPS scheme is not implemented"));
            }
            Some((h.path.clone(), port("httpGet", &h.port)?))
        }
        None => None,
    };
    let exec = match &p.exec {
        Some(e) if e.command.is_empty() || e.command[0].trim().is_empty() => {
            return Err(format!("{kind}: exec command is empty"));
        }
        Some(e) => Some(e.command.clone()),
        None => None,
    };
    let tcp_socket = match &p.tcp_socket {
        Some(t) => Some(port("tcpSocket", &t.port)?),
        None => None,
    };
    Ok(StoredProbe {
        http_get,
        exec,
        tcp_socket,
        initial_delay_seconds: p.initial_delay_seconds,
        period_seconds: p.period_seconds,
        failure_threshold: p.failure_threshold,
        timeout_seconds: p.timeout_seconds,
        success_threshold: p.success_threshold,
    })
}

/// The full stored container contract (shared by every workload kind).
fn validate_single_container_probe_scope(pod: &spec::PodSpec) -> Result<(), String> {
    if pod.containers.iter().skip(1).chain(pod.init_containers.iter().flatten()).any(|c|
        c.liveness_probe.is_some() || c.readiness_probe.is_some() || c.startup_probe.is_some()) {
        return Err("DaemonSet/Job/CronJob support probes only on their single modelled regular container; additional and init-container probes are unsupported".into());
    }
    Ok(())
}

fn parse_container(c: &spec::ContainerSpec, volume_map: &HashMap<String, String>, pod_security: Option<&crate::security::PodSecurityContext>) -> Result<StoredContainer, String> {
    if !crate::store::is_dns_label(&c.name){return Err("container name must be an RFC1123 label".into());}
    let env: Vec<String> = c.env.as_ref()
        .map(|vars| vars.iter().filter_map(|e| e.value.as_ref().map(|v| format!("{}={}", e.name, v))).collect())
        .unwrap_or_default();
    let volumes: Vec<(String, String)> = c.volume_mounts.as_ref()
        .map(|mounts| mounts.iter().filter_map(|m| {
            volume_map.get(&m.name).map(|host| (host.clone(), m.mount_path.clone()))
        }).collect())
        .unwrap_or_default();
    let env_refs: Vec<EnvKeyRef> = c.env.as_ref()
        .map(|vars| vars.iter().filter(|e| e.value.is_none()).filter_map(|e| {
            let src = e.value_from.as_ref()?;
            let (r, secret) = match (&src.config_map_key_ref, &src.secret_key_ref) {
                (Some(r), _) => (r, false),
                (None, Some(r)) => (r, true),
                _ => return None,
            };
            Some(EnvKeyRef { name: e.name.clone(), secret, object: r.name.clone(), key: r.key.clone(), optional: r.optional })
        }).collect())
        .unwrap_or_default();
    // Kubernetes `args` follow `command`; with no `command` they replace the
    // image CMD and keep its ENTRYPOINT (Royak's command is the Docker Cmd).
    let command = match (&c.command, &c.args) {
        (Some(cmd), Some(args)) => Some(cmd.iter().chain(args.iter()).cloned().collect()),
        (Some(cmd), None) => Some(cmd.clone()),
        (None, Some(args)) => Some(args.clone()),
        (None, None) => None,
    };
    let env_from_configmaps: Vec<String> = c.env_from.as_ref()
        .map(|refs| refs.iter().filter_map(|r| r.config_map_ref.as_ref().map(|cm| cm.name.clone())).collect())
        .unwrap_or_default();
    let env_from_secrets: Vec<String> = c.env_from.as_ref()
        .map(|refs| refs.iter().filter_map(|r| r.secret_ref.as_ref().map(|s| s.name.clone())).collect())
        .unwrap_or_default();
    Ok(StoredContainer {
        host_access: None,
        security_context: crate::security::SecurityContext::effective(pod_security, c.security_context.as_ref())?,
        name: c.name.clone(),
        image: c.image.clone(),
        command,
        env,
        env_from_configmaps,
        env_from_secrets,
        env_refs,
        volumes,
        liveness_probe: c.liveness_probe.as_ref().map(|p| parse_probe(&format!("container {:?} livenessProbe", c.name), p)).transpose()?,
        readiness_probe: c.readiness_probe.as_ref().map(|p| parse_probe(&format!("container {:?} readinessProbe", c.name), p)).transpose()?,
        startup_probe: c.startup_probe.as_ref().map(|p| parse_probe(&format!("container {:?} startupProbe", c.name), p)).transpose()?,
    })
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
    reconcile_with_observer(desired, brain, use_neuropod, &mut |_| true)
}


/// Pure scheduling observation, not authority for any runtime effect. Both
/// unsupported entrypoints use this EXACT list for creation/healthy counting.
fn unsupported_runtime_workloads(desired: &DesiredWorld, runtime: &str) -> (Vec<String>, Vec<String>) {
    let mut admitted = Vec::new();
    let mut log = Vec::new();
    for (key, deployment) in &desired.deployments {
        match crate::storage::observe_unsupported_runtime_storage(desired, &deployment.namespace,
            &deployment.init_containers, &deployment.containers) {
            crate::storage::UnsupportedRuntimeStorage::ProvenLegacy => admitted.push(key.clone()),
            crate::storage::UnsupportedRuntimeStorage::Managed => log.push(format!(
                "  [storage] {key}: {runtime} cannot mount managed PVCs; refusing workload without substituting an empty disk")),
            crate::storage::UnsupportedRuntimeStorage::Unresolved => log.push(format!(
                "  [storage] {key}: current PVC identity/binding is unresolved; refusing {runtime} fallback")),
        }
    }
    (admitted, log)
}

fn runtime_docker_available() -> bool {
    #[cfg(test)]
    if let Some(available) = unsupported_storage_runtime_tests::docker_ping() { return available; }
    crate::docker::ping()
}

fn reconcile_with_observer(desired: &mut DesiredWorld, brain: &mut OrinBrain, use_neuropod: bool,
    publish_health: &mut dyn FnMut(&DesiredWorld) -> bool) -> Vec<String> {
    // Auto-detect: if NeuroPod requested OR Docker unavailable → NeuroPod mode (EXPERIMENTAL)
    if use_neuropod || !runtime_docker_available() {
        return reconcile_neuropod(desired, brain);
    }
    // Docker mode: production-ready, 28/28 tests
    let rt_name = desired.config.runtime.clone();

    // For non-docker runtimes, delegate to trait-based reconciliation
    if rt_name != "docker" {
        return reconcile_via_trait(desired, brain, &rt_name);
    }
    docker_tick::reconcile_docker(desired, brain, publish_health)
}

#[path = "reconcile_docker.rs"]
mod docker_tick;
pub use docker_tick::{local_views, node_get, node_post, our_containers, remote_delete_pod};

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

        // A restored/out-of-band policy can bypass ordinary admission. Do
        // not attempt even namespace-network setup for an ambiguous native
        // selection, nor call this a network revocation/fencing proof.
        if crate::workload::managed::require_supported_policy_admission(desired,target_ns,selector).is_err(){
            log.push(format!("  [netpol] {}: UNKNOWN unsupported native selection; no policy effects/enforced claim",policy.name));
            continue;
        }

        // Find containers matching the policy selector in this namespace
        let selected: Vec<&&docker::DockerContainer> = managed.iter()
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

        // Native policy is NOT implemented by legacy namespace membership or
        // a NET_ADMIN helper. Restored/out-of-band unsupported policy is an
        // explicit UNKNOWN, never a false `enforced` audit/marker/count.
        let mut unsupported_native=false;
        let matching:Vec<_>=selected.into_iter().filter(|c|{
            let native=crate::docker::managed::registered_target(&c.id)
                ||[crate::workload::managed::LABEL_WRITER,crate::workload::managed::LABEL_OPERATION,
                    crate::workload::managed::LABEL_NONCE].iter().any(|key|c.labels.contains_key(*key))
                ||c.names.iter().any(|name|desired.storage_identities.lifecycle.contains_writer_pod(
                    target_ns,name.trim_start_matches('/')))
                ||c.labels.get("royak.pod").is_some_and(|pod|
                    desired.storage_identities.lifecycle.contains_writer_pod(target_ns,pod));
            if native{unsupported_native=true;log.push(format!("  [netpol] {}: UNKNOWN unsupported native policy for {}; no legacy network/helper effect",
                policy.name,c.id));}
            !native
        }).collect();

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

        log.push(format!("  [netpol] {}: {} on {} legacy pods (ns={target_ns}, selector={selector}{}{}{})",
            policy.name, if unsupported_native{"legacy-only processing; native UNKNOWN"}else{"enforced"},matching.len(),
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
    let (admitted, mut log) = unsupported_runtime_workloads(desired, "NeuroPod");
    if admitted.is_empty() && !log.is_empty() { return log; }
    // Test-only trap is at the last edge before any filesystem/GC/bridge/disk
    // effect. Production has no override or substitute runtime capability.
    #[cfg(test)]
    if let Some(rows) = unsupported_storage_runtime_tests::before_effect("neuropod", &admitted) {
        log.extend(rows); return log;
    }
    let pods_root=dirs_or_home().join(".royak/pods");
    let scope=crate::neuropod_gc::Owner::current(desired,"default","scope");
    let records=crate::neuropod_gc::inventory(&pods_root);
    for record in &records {
        if !record.owner.same_scope(&scope) || record.owner.generation>desired.generation {continue;}
        let record_key=crate::store::obj_key(&record.owner.namespace,&record.owner.deployment);
        let dep=desired.deployments.get(&record_key);
        // Current blocked workloads retain their old experimental resources;
        // they are neither counted healthy nor reclaimed as a fallback effect.
        if dep.is_some() && !admitted.contains(&record_key) { continue; }
        let wanted=dep.map(|d|(1..=d.replicas).any(|i|record.name==format!("{}-{i}",crate::store::pod_stem(&d.namespace,&d.name)))).unwrap_or(false);
        if !wanted {
            match crate::neuropod_gc::reclaim(record,&scope) {
                Ok(archive)=>log.push(format!("  [neuropod-gc] {} reclaimed; data retained at {}",record.name,archive.display())),
                Err(error)=>log.push(format!("  [neuropod-gc] {} cleanup deferred: {error}",record.name)),
            }
        }
    }
    if crate::security::world_has_constraints(desired) {
        log.push("  [security] NeuroPod cannot enforce securityContext; refusing pod creation".into());return log;
    }
    if crate::probes::world_has_probes(desired) {
        log.push("  [probe] NeuroPod does not execute health probes; refusing silent unenforced startup".into());return log;
    }

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

    let mut used_ips:std::collections::HashSet<String>=existing.iter().filter_map(|(name,_,_,_,_)|
        crate::neuropod_gc::read_meta(&pods_root.join(name)).ok().and_then(|m|m["network"]["ip"].as_str().map(str::to_string))).collect();

    // Only the exact admitted legacy keys can reach this runtime's effects.
    for name in &admitted {
        let dep = &desired.deployments[name];
        let mut running = 0u32;
        for i in 1..=dep.replicas {
            // Same per-namespace stem as Docker pods ("ns/name" keys must never
            // reach a pod, directory or netns name).
            let pod_name = format!("{}-{i}", crate::store::pod_stem(&dep.namespace, &dep.name));
            if existing_names.contains(&pod_name) {
                let meta=crate::neuropod_gc::read_meta(&pods_root.join(&pod_name));
                let owned=meta.as_ref().ok().and_then(|m|serde_json::from_value::<crate::neuropod_gc::Owner>(m["owner"].clone()).ok()).map(|o|o.same_scope(&scope)&&o.namespace==dep.namespace&&o.deployment==dep.name).unwrap_or(false);
                if owned && meta.as_ref().map(crate::neuropod_gc::process_running).unwrap_or(false){running+=1;}
                else{log.push(format!("  [neuropod] {pod_name}: occupied or cleanup pending; not adopted"));}
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

            if pods_root.join(&pod_name).symlink_metadata().is_ok(){log.push(format!("  [neuropod] {pod_name}: unmanaged path collision; creation refused"));continue;}
            let owner=crate::neuropod_gc::Owner::current(desired,&dep.namespace,&dep.name);
            let Some(pod_index)=crate::runtime::next_pod_network_index(&used_ips) else {log.push(format!("  [neuropod] {pod_name}: pod network address capacity reached"));continue;};
            match crate::runtime::NeuroPod::create_owned(&pod_name, &dep.image, disk_mb, mount_path,owner) {
                Ok(mut pod) => {
                    // Collect env
                    let mut env = dep.env.clone();
                    if let Some(c) = dep.containers.first() {
                        env.extend(c.env.clone());
                    }
                    env.push(format!("ROYAK_POD_NAME={pod_name}"));
                    env.push(format!("ROYAK_NAMESPACE={}", dep.namespace));
                    env.push(format!("ROYAK_DEPLOYMENT={}", dep.name));

                    // Pod identity (mTLS cert + token)
                    if let Some(ref mut ca) = desired.cluster_ca {
                        if let Ok(identity) = ca.issue_pod_cert(&pod_name, &dep.namespace) {
                            env.extend(identity.env_vars());
                            log.push(format!("    [mtls] {pod_name} cert issued"));
                        }
                    }

                    // Set up network
                    let ports: Vec<(u16, u16)> = Vec::new(); // TODO: parse from spec
                    match crate::runtime::create_pod_network(&pod_name, pod_index, &ports) {
                        Ok(net) => {
                            used_ips.insert(net.ip.clone());
                            env.push(format!("NEUROPOD_IP={}", net.ip));
                            log.push(format!("    [net] {pod_name} → {} (bridge)", net.ip));
                            if let Err(error)=pod.set_network(net.clone()){crate::runtime::destroy_pod_network(&net);log.push(format!("  [neuropod] {pod_name}: network metadata failed: {error}"));continue;}
                        }
                        Err(e) => {log.push(format!("    [net] {pod_name}: {e}; managed startup refused"));continue;},
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
/// Lines worth surfacing in the demo's live activity feed.
fn push_interesting(log: &[String]) {
    for line in log {
        println!("{line}");
        let l = line.trim();
        if l.starts_with("[scale]") || l.starts_with("[multi-node]") || l.starts_with("[create]")
            || l.starts_with("[quota]") || l.contains("chaos") || l.contains("recovered")
            || l.contains("healing") || l.contains("pod lost") || l.contains("reconciling")
            || l.contains("rollout") || l.starts_with("[cleanup]") {
            crate::api::push_activity(l);
        }
    }
}

/// The state-file owner lock of this process (single-node mode). Held for the
/// life of the process; a second `watch` on the same state stays in standby
/// until this one exits (the kernel releases the flock on any exit, SIGKILL
/// included — no TTL, no clock, no two writers).
static OWNER_LOCK: std::sync::Mutex<Option<crate::persist::OwnerLock>> = std::sync::Mutex::new(None);

/// Try to become the owner of `state_path`. On success, (re)load the state the
/// previous owner left and install it, so a standby never acts on stale state.
pub fn try_take_ownership(world: &std::sync::Arc<std::sync::RwLock<DesiredWorld>>, state_path: &str) -> Result<bool, String> {
    if crate::store::owns_state() {
        return Ok(true);
    }
    let Some(lock) = crate::persist::try_own(state_path)? else { return Ok(false) };
    let loaded = crate::persist::load(state_path)?;
    if loaded.fresh {
        // A new cluster's identity (cluster id → container ownership) is
        // durable from the first second, not from the first write.
        crate::persist::save(state_path, &loaded.state, &[])?;
    }
    if let Some(v) = loaded.migrated_from {
        // Persist the migrated form now (original kept as .v1.bak) so the
        // on-disk file and the served state are the same thing from tick one.
        crate::persist::backup_before_migration(state_path, v)?;
        crate::persist::save(state_path, &loaded.state, &[])?;
        println!("  [migrate] {state_path}: schema v{v} → v{} written (backup: {state_path}.v{}.bak)", crate::persist::SCHEMA_VERSION, v.max(1));
    }
    {
        let mut w = world.write().unwrap_or_else(|e| e.into_inner());
        w.install_state(loaded.state);
    }
    *OWNER_LOCK.lock().unwrap_or_else(|e| e.into_inner()) = Some(lock);
    crate::store::set_owns_state(true);
    Ok(true)
}

/// One reconcile tick with the commit contract applied to the loop itself.
///
/// Slow Docker/peer operations run on a detached snapshot. Committed desired
/// state stays readable during graceful stops; only runtime observations merge
/// back, and desired mutations still pass through the durable CAS commit.
/// `commit_lock` retains the existing ordering against local API writes.
pub fn reconcile_tick(
    world: &std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    brain: &mut OrinBrain,
    use_neuropod: bool,
) -> Vec<String> {
    reconcile_tick_with(world, |working, publish| reconcile_with_observer(working, brain, use_neuropod, publish))
}

fn merge_tick_health(live: &mut DesiredWorld, base: &DesiredWorld, observed: &DesiredWorld) -> bool {
    if live.generation != base.generation || live.cluster_id != base.cluster_id { return false; }
    live.restart_count = observed.restart_count.clone();
    live.startup_ok = observed.startup_ok.clone();
    live.pod_ready = observed.pod_ready.clone();
    live.pod_health = observed.pod_health.clone();
    true
}

fn merge_tick_observations(live: &mut DesiredWorld, base: &DesiredWorld, observed: &DesiredWorld) -> bool {
    if !merge_tick_health(live, base, observed) { return false; }
    live.netpol_applied = observed.netpol_applied.clone();
    live.cluster_ca = observed.cluster_ca.clone();
    live.pod_certs = observed.pod_certs.clone();
    live.network_audit = observed.network_audit.clone();
    live.net_tracker = observed.net_tracker.clone();
    let me = local_node_name();
    if let Some(local) = observed.nodes.get(&me) { live.nodes.insert(me.clone(), local.clone()); }
    // Heartbeats continue while the tick does I/O. Never replace a fresh peer
    // address/stats/heartbeat with its older snapshot or demote a fresh peer.
    for (name, node) in &observed.nodes {
        if name == &me { continue; }
        if let (Some(before), Some(current)) = (base.nodes.get(name), live.nodes.get_mut(name)) {
            if current.last_heartbeat == before.last_heartbeat && current.address == before.address {
                current.status = node.status.clone();
            }
        }
    }
    // Runtime API events may arrive without a desired-state commit. Merge only
    // this tick's count delta, preserving concurrent events and their messages.
    for event in &observed.events {
        let same = |e: &&ClusterEvent| e.namespace == event.namespace && e.object == event.object && e.reason == event.reason;
        let old = base.events.iter().find(same).map(|e| e.count).unwrap_or(0);
        let delta = event.count.saturating_sub(old);
        if delta == 0 { continue; }
        if let Some(current) = live.events.iter_mut().find(|e| e.namespace == event.namespace && e.object == event.object && e.reason == event.reason) {
            if current.count == old || current.last_seen < event.last_seen {
                current.last_seen = event.last_seen.clone(); current.message = event.message.clone();
            }
            current.count = current.count.saturating_add(delta);
        } else {
            let mut added = event.clone(); added.count = delta; live.events.push(added);
        }
    }
    if live.events.len() > 200 { live.events.drain(..live.events.len() - 200); }
    // A pipeline may also be triggered through the runtime API during I/O.
    for run in &observed.pipeline_runs {
        let same = |r: &&PipelineRun| r.pipeline == run.pipeline && r.run_id == run.run_id && r.started_at == run.started_at;
        let before = base.pipeline_runs.iter().find(same);
        if let Some(current) = live.pipeline_runs.iter_mut().find(|r| r.pipeline == run.pipeline && r.run_id == run.run_id && r.started_at == run.started_at) {
            for (name, status) in &run.stage_status {
                let old = before.and_then(|b| b.stage_status.iter().find(|(n, _)| n == name)).map(|(_, s)| s);
                if let Some((_, current_status)) = current.stage_status.iter_mut().find(|(n, _)| n == name) {
                    if old == Some(&*current_status) && old != Some(status) { *current_status = status.clone(); }
                }
            }
        } else if before.is_none() { live.pipeline_runs.push(run.clone()); }
    }
    true
}

fn reconcile_tick_with(
    world: &std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    run: impl FnOnce(&mut DesiredWorld, &mut dyn FnMut(&DesiredWorld) -> bool) -> Vec<String>,
) -> Vec<String> {
    let _serial = crate::store::commit_lock().lock().unwrap_or_else(|e| e.into_inner());
    let before = world.read().unwrap_or_else(|e| e.into_inner()).clone();
    let base = before.to_state();
    let mut working = before.clone();
    let mut publish = |observed: &DesiredWorld| merge_tick_health(
        &mut world.write().unwrap_or_else(|e| e.into_inner()), &before, observed);
    let mut log = run(&mut working, &mut publish);
    let after = working.to_state();
    if !merge_tick_observations(&mut world.write().unwrap_or_else(|e| e.into_inner()), &before, &working) {
        log.push("  [warn] reconcile snapshot superseded by committed state; observations discarded".into());
        return log;
    }
    if after.same_content(&base) {
        return log;
    }
    if !crate::raft_node::is_cluster_scheduler() {
        return log; // followers never write desired state
    }
    let mut next = after;
    next.generation = base.generation + 1;
    match crate::store::commit_state(world, base.generation, next) {
        Ok(()) => {}
        Err(e) => log.push(format!("  [warn] reconcile bookkeeping not committed (will retry): {e:?}")),
    }
    log
}

#[cfg(test)]
mod tick_snapshot_tests {
    use super::*;
    use std::sync::{Arc, RwLock};

    #[test]
    fn replacement_readiness_is_visible_before_slow_retirement_without_desired_leak() {
        let world = Arc::new(RwLock::new(DesiredWorld::new()));
        let worker_world = world.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || reconcile_tick_with(&worker_world, |working, publish| {
            working.pod_ready.insert("replacement".into());
            working.namespaces.push("not-committed".into());
            assert!(publish(working));
            tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(200)); // old pod retirement
            working.namespaces.pop();
            Vec::new()
        }));
        rx.recv().unwrap();
        let live = world.try_read().expect("retirement I/O must not block readers");
        assert!(live.pod_ready.contains("replacement"));
        assert!(!live.namespaces.iter().any(|n| n == "not-committed"));
        drop(live);
        worker.join().unwrap();
    }

    #[test]
    fn slow_tick_keeps_committed_state_readable() {
        let world = Arc::new(RwLock::new(DesiredWorld::new()));
        let worker_world = world.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || reconcile_tick_with(&worker_world, |working, _| {
            tx.send(()).unwrap();
            std::thread::sleep(Duration::from_millis(300));
            working.pod_ready.insert("observed-pod".into());
            Vec::new()
        }));
        rx.recv().unwrap();
        assert!(world.try_read().is_ok(), "slow container operations must not monopolize committed-state readers");
        worker.join().unwrap();
        assert!(world.read().unwrap().pod_ready.contains("observed-pod"));
    }

    #[test]
    fn publishing_observations_cannot_publish_desired_mutations() {
        let mut live = DesiredWorld::new();
        let base = live.clone();
        let mut observed = base.clone();
        observed.namespaces.push("not-committed".into());
        observed.pod_ready.insert("actual-pod".into());
        assert!(merge_tick_observations(&mut live, &base, &observed));
        assert!(live.to_state().same_content(&base.to_state()));
        assert!(live.pod_ready.contains("actual-pod"));
    }

    #[test]
    fn stale_tick_cannot_overwrite_newer_committed_state_or_observations() {
        let mut live = DesiredWorld::new();
        let base = live.clone();
        let mut observed = base.clone();
        observed.pod_ready.insert("obsolete".into());
        live.generation += 1;
        live.pod_ready.insert("fresh".into());
        assert!(!merge_tick_observations(&mut live, &base, &observed));
        assert!(live.pod_ready.contains("fresh"));
        assert!(!live.pod_ready.contains("obsolete"));
    }

    #[test]
    fn runtime_event_merge_preserves_concurrent_api_events_and_counts() {
        let mut live = DesiredWorld::new();
        live.record_event("Pod", "a", "Created", "base", "Normal");
        let base = live.clone();
        let mut observed = base.clone();
        observed.record_event("Pod", "a", "Created", "tick", "Normal");
        live.record_event("Pod", "a", "Created", "api", "Normal");
        live.record_event("Pipeline", "b", "Triggered", "api-only", "Normal");
        assert!(merge_tick_observations(&mut live, &base, &observed));
        assert_eq!(live.events.iter().find(|e| e.object == "a").unwrap().count, 3);
        assert!(live.events.iter().any(|e| e.object == "b" && e.message == "api-only"));
    }

    #[test]
    fn runtime_pipeline_merge_preserves_concurrent_triggers_and_stage_updates() {
        let mut live = DesiredWorld::new();
        live.pipeline_runs.push(PipelineRun { pipeline: "build".into(), run_id: 1,
            stage_status: vec![("test".into(), StageStatus::Pending)], started_at: Instant::now() });
        let base = live.clone();
        let mut observed = base.clone();
        observed.pipeline_runs[0].stage_status[0].1 = StageStatus::Succeeded;
        live.pipeline_runs.push(PipelineRun { pipeline: "build".into(), run_id: 2,
            stage_status: vec![], started_at: Instant::now() });
        assert!(merge_tick_observations(&mut live, &base, &observed));
        assert_eq!(live.pipeline_runs.len(), 2);
        assert!(live.pipeline_runs[0].stage_status[0].1 == StageStatus::Succeeded);
    }

    #[test]
    fn runtime_merge_cannot_demote_a_peer_with_a_fresh_heartbeat() {
        let mut live = DesiredWorld::new();
        let peer = format!("peer-other-than-{}", local_node_name());
        record_peer(&mut live, &NodeHello { node: peer.clone(), address: "10.0.0.2:6443".into(),
            cpu_used: 1.0, mem_used: 1.0, mem_capacity: 100.0, pod_count: 1 });
        let base = live.clone();
        let mut observed = base.clone();
        observed.nodes.get_mut(&peer).unwrap().status = NodeStatus::NotReady;
        let fresh = live.nodes.get_mut(&peer).unwrap();
        fresh.last_heartbeat += 1;
        fresh.address = "10.0.0.3:6443".into();
        assert!(merge_tick_observations(&mut live, &base, &observed));
        assert!(live.nodes[&peer].status == NodeStatus::Ready);
        assert_eq!(live.nodes[&peer].address, "10.0.0.3:6443");
    }
}

pub fn run_loop_shared_with_runtime(
    world: std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    brain: &mut OrinBrain,
    interval_secs: u64,
    state_path: &str,
    use_neuropod: bool,
) {
    install_shutdown_handler();
    let clustered = crate::raft_node::is_clustered();
    {
        let w = world.read().unwrap_or_else(|e| e.into_inner());
        println!("  Reconcile loop started (every {interval_secs}s, {} mode)", if clustered { "Raft cluster" } else { "single-node" });
        println!("  Node: {} | cluster id: {}\n", local_node_name(), w.cluster_id);
    }

    let mut announced_standby = false;
    loop {
        if SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
            // Nothing to flush: every desired-state change was durable before
            // it became visible. Containers keep running.
            brain.save_weights(".royak-brain.bin").ok();
            eprintln!("\n  [shutdown] state is already durable; containers preserved");
            break;
        }

        if clustered && !crate::raft_node::RAFT_READY.load(std::sync::atomic::Ordering::Acquire) {
            std::thread::sleep(Duration::from_millis(500));
            continue;
        }
        if !clustered {
            match try_take_ownership(&world, state_path) {
                Ok(true) => {
                    if announced_standby {
                        println!("  [owner] ★ acquired state ownership of {state_path} — reloaded state");
                        announced_standby = false;
                    }
                }
                Ok(false) => {
                    if !announced_standby {
                        println!("  ── [standby] another process owns {state_path}; waiting ──");
                        announced_standby = true;
                    }
                    sleep_unless_shutdown(Duration::from_secs(interval_secs));
                    continue;
                }
                Err(e) => {
                    // Unreadable / corrupt state: never act on a guess.
                    eprintln!("  ✗ [owner] cannot take ownership of {state_path}: {e}");
                    sleep_unless_shutdown(Duration::from_secs(interval_secs));
                    continue;
                }
            }
        }

        let start = Instant::now();
        let log = reconcile_tick(&world, brain, use_neuropod);
        {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            crate::api::publish_ingress_snapshot(&w);
            crate::api::publish_demo_state(&w);
        }
        brain.ticks += 1;
        let elapsed = start.elapsed();
        brain.set("cluster.last_tick".to_string(), brain.ticks.to_string());
        brain.set("cluster.last_reconcile_ms".to_string(), format!("{:.1}", elapsed.as_secs_f64() * 1000.0));
        println!("  ── tick {} ({:.1}ms) ──", brain.ticks, elapsed.as_secs_f64() * 1000.0);
        push_interesting(&log);

        sleep_unless_shutdown(Duration::from_secs(interval_secs));
    }
}

/// Sleep up to `d`, waking early when a shutdown signal arrives (so SIGTERM
/// is honoured within ~100 ms, not after a whole reconcile interval).
fn sleep_unless_shutdown(d: Duration) {
    let end = Instant::now() + d;
    while !SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed) {
        let now = Instant::now();
        if now >= end { break; }
        std::thread::sleep((end - now).min(Duration::from_millis(100)));
    }
}

/// Global shutdown flag — set by signal handler, checked by reconcile loop
static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

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
            restart_nonce: 0,
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
        world.custom_resources.insert("default/db".into(), custom_resource("db", "PostgresCluster"));

        let mut log = Vec::new();
        reconcile_operators(&mut world, &mut log);

        let provisioned = world.deployments.get("default/db-primary")
            .expect("operator should provision db-primary");
        assert_eq!(provisioned.owner_ref.as_deref(), Some("db"),
            "provisioned deployment must carry the owning CR as its owner ref");
    }

    #[test]
    fn selection_picks_only_owned_deployments() {
        let mut world = DesiredWorld::new();
        world.deployments.insert("default/db-primary".into(), dep("db-primary", Some("db")));
        world.deployments.insert("default/db-replica".into(), dep("db-replica", Some("db")));
        world.deployments.insert("default/cache-primary".into(), dep("cache-primary", Some("cache")));
        world.deployments.insert("default/web".into(), dep("web", None));

        let mut owned = deployments_owned_by(&world, "default", "db");
        owned.sort();
        assert_eq!(owned, vec!["default/db-primary".to_string(), "default/db-replica".to_string()]);
    }

    #[test]
    fn deleting_cr_removes_exactly_its_owned_deployments() {
        let mut world = DesiredWorld::new();
        world.custom_resources.insert("default/db".into(), custom_resource("db", "PostgresCluster"));
        world.deployments.insert("default/db-primary".into(), dep("db-primary", Some("db")));
        world.deployments.insert("default/db-replica".into(), dep("db-replica", Some("db")));
        world.deployments.insert("default/cache-primary".into(), dep("cache-primary", Some("cache")));
        world.deployments.insert("default/web".into(), dep("web", None));

        let deleted = world.delete_resource("customresources", "default", "db");
        assert!(deleted.is_some(), "CR delete should report success");

        // Owned deployments are gone.
        assert!(!world.deployments.contains_key("default/db-primary"));
        assert!(!world.deployments.contains_key("default/db-replica"));
        // Another CR's deployment and the user-owned one are untouched.
        assert!(world.deployments.contains_key("default/cache-primary"));
        assert!(world.deployments.contains_key("default/web"));
        assert_eq!(world.deployments.len(), 2);
        // CR itself removed.
        assert!(!world.custom_resources.contains_key("default/db"));
    }

    #[test]
    fn unowned_deployment_is_never_gcd() {
        let mut world = DesiredWorld::new();
        // A CR named "db" exists, and a user deployment happens to be "db"-ish
        // but has no owner ref — it must survive the cascade.
        world.custom_resources.insert("default/db".into(), custom_resource("db", "PostgresCluster"));
        world.deployments.insert("default/db".into(), dep("db", None));

        world.delete_resource("customresources", "default", "db");

        assert!(world.deployments.contains_key("default/db"),
            "a deployment with no owner ref must never be garbage-collected");
    }

    #[test]
    fn deleting_missing_cr_touches_nothing() {
        let mut world = DesiredWorld::new();
        world.deployments.insert("default/web".into(), dep("web", Some("ghost")));

        let deleted = world.delete_resource("customresources", "default", "ghost");
        assert!(deleted.is_none(), "deleting a non-existent CR returns None");
        // The CR never existed, so no cascade runs — the orphan stays put.
        assert!(world.deployments.contains_key("default/web"));
    }

    fn node(name: &str, addr: &str) -> ClusterNode {
        ClusterNode {
            name: name.into(), address: addr.into(),
            cpu_capacity: 100.0, mem_capacity: 8.0, cpu_used: 0.0, mem_used: 0.0,
            pod_count: 0, status: NodeStatus::Ready, last_heartbeat: 0,
            neural_token: vec![], joined_at: 0,
        }
    }

    // A verified heartbeat adds the peer to the census with its advertised
    // address (the scheduler dispatches to that address), refreshes it, and
    // never registers ourselves as a peer.
    #[test]
    fn verified_hello_federates_census_with_address() {
        let mut local = DesiredWorld::new();
        local.nodes.insert(local_node_name(), node(&local_node_name(), "192.168.5.1:6443"));
        let hello = NodeHello { node: "node2-test".into(), address: "192.168.5.3:6443".into(),
            cpu_used: 1.0, mem_used: 2.0, mem_capacity: 8.0, pod_count: 3 };
        record_peer(&mut local, &hello);
        assert_eq!(local.nodes.len(), 2, "census federated to both nodes");
        let n2 = local.nodes.get("node2-test").expect("node2 present");
        assert_eq!(n2.address, "192.168.5.3:6443");
        assert_eq!(n2.pod_count, 3);
        record_peer(&mut local, &hello);
        assert_eq!(local.nodes.len(), 2, "re-federation stays at two nodes");
        let me = NodeHello { node: local_node_name(), address: "1.2.3.4:1".into(),
            cpu_used: 0.0, mem_used: 0.0, mem_capacity: 0.0, pod_count: 0 };
        record_peer(&mut local, &me);
        assert_eq!(local.nodes[&local_node_name()].address, "192.168.5.1:6443", "a peer cannot rewrite our own entry");
    }

    #[test]
    fn stale_peer_goes_not_ready() {
        let mut w = DesiredWorld::new();
        w.nodes.insert("old-peer".into(), node("old-peer", "10.0.0.9:1"));
        let log = check_node_health(&mut w);
        assert_eq!(w.nodes["old-peer"].status, NodeStatus::NotReady, "{log:?}");
    }

    // Single-node (the demo) must be completely unaffected: with CLUSTER_MODE
    // off (its default) the reconcile loop always schedules, exactly as before
    // Raft existed. If this ever flips, single-node deployments stop scaling.
    #[test]
    fn single_node_always_schedules() {
        assert!(crate::raft_node::is_cluster_scheduler(),
            "single-node must always be the scheduler (no Raft gate)");
    }
}

// ─── UDP Autodiscovery: nodes find each other on the network ───
//
// Opt-in (`watch --discover`) and only with a cluster secret. Every
// DISCOVERY_INTERVAL a node broadcasts {"service":"royak","node","api"} on UDP
// 9443. A broadcast is only a hint: the listener then sends a SIGNED heartbeat
// to the announced address, and the peer enters the census only if it answers
// a signed request (i.e. it holds the cluster secret). Desired state is never
// exchanged — it lives in Raft.

const DISCOVERY_PORT: u16 = 9443;
const DISCOVERY_INTERVAL: u64 = 10;

pub fn autodiscovery(
    world: std::sync::Arc<std::sync::RwLock<DesiredWorld>>,
    api_port: u16,
) {
    use std::net::UdpSocket;

    if crate::auth::cluster_secret().is_none() {
        eprintln!("  ⚠ autodiscovery disabled: ROYAK_CLUSTER_SECRET is required to verify peers");
        return;
    }
    let hostname = local_node_name();
    let api_addr = {
        let adv = advertised_address(api_port);
        if adv.starts_with("127.0.0.1") {
            format!("{}:{api_port}", get_local_ip().unwrap_or_else(|| "0.0.0.0".to_string()))
        } else { adv }
    };
    println!("  ✓ autodiscovery started: {hostname} @ {api_addr}");

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
    let broadcaster = UdpSocket::bind("0.0.0.0:0").ok();
    if let Some(ref b) = broadcaster { b.set_broadcast(true).ok(); }

    loop {
        if let Some(ref b) = broadcaster {
            let announce = serde_json::json!({"service": "royak", "node": hostname, "api": api_addr}).to_string();
            b.send_to(announce.as_bytes(), format!("255.255.255.255:{DISCOVERY_PORT}")).ok();
        }
        let mut buf = [0u8; 2048];
        if let Ok((len, src)) = listener.recv_from(&mut buf) {
            let Ok(msg) = serde_json::from_slice::<serde_json::Value>(&buf[..len]) else { continue };
            if msg["service"].as_str() != Some("royak") { continue; }
            let peer_node = msg["node"].as_str().unwrap_or("").to_string();
            let peer_api = msg["api"].as_str().unwrap_or("").to_string();
            let claimed_ip = peer_api.split(':').next().unwrap_or("");
            if peer_node.is_empty() || peer_node == hostname || claimed_ip != src.ip().to_string() { continue; }
            if world.read().unwrap_or_else(|e| e.into_inner()).nodes.contains_key(&peer_node) { continue; }
            let hello = { local_hello(&world.read().unwrap_or_else(|e| e.into_inner())) };
            let body = serde_json::to_string(&hello).unwrap_or_default();
            match node_post(&peer_api, "/royak/v1/heartbeat", &body, Duration::from_secs(3))
                .and_then(|b| serde_json::from_str::<NodeHello>(&b).map_err(|e| e.to_string())) {
                Ok(mut peer) if peer.node == peer_node => {
                    if peer.address.is_empty() { peer.address = peer_api.clone(); }
                    println!("  ✦ discovered: {peer_node} @ {peer_api} (verified by signed heartbeat)");
                    record_peer(&mut world.write().unwrap_or_else(|e| e.into_inner()), &peer);
                }
                Ok(_) => eprintln!("  ⚠ discovery: {peer_api} answered with a different node name — ignored"),
                Err(e) => eprintln!("  ⚠ discovery: {peer_node} @ {peer_api} not verified: {e}"),
            }
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

/// Reconcile for the experimental non-Docker runtimes ("light", "cri").
///
/// Local, single-node only: these runtimes cannot list container labels, so
/// ownership is by exact pod name (`<stem>-<n>` of a deployment that exists in
/// desired state) — never by a loose `rk-` prefix — and nothing else is ever
/// stopped or removed. Cluster placement, probes, rollouts and the unified
/// workload contract are Docker-only.
fn reconcile_via_trait(desired: &mut DesiredWorld, _brain: &mut OrinBrain, rt_name: &str) -> Vec<String> {
    let (admitted, mut log) = unsupported_runtime_workloads(desired, rt_name);
    if admitted.is_empty() && !log.is_empty() { return log; }
    // Even the legacy runtime factory can create directories. Never construct
    // it for blocked-only work; the test trap is BEFORE that first effect.
    #[cfg(test)]
    if let Some(rows) = unsupported_storage_runtime_tests::before_effect(rt_name, &admitted) {
        log.extend(rows); return log;
    }
    use crate::runtime::{self, ContainerState};
    let rt = runtime::get_runtime(rt_name);
    if crate::raft_node::is_clustered() {
        log.push(format!("  [error] runtime {rt_name} is single-node only; cluster mode requires the docker runtime"));
        return log;
    }
    if !rt.ping() {
        log.push(format!("  [error] {} runtime not available", rt.name()));
        return log;
    }
    rt.ensure_network().ok();
    let actual = match rt.list(true) {
        Ok(cs) => cs,
        Err(e) => { log.push(format!("  [error] {}: {e}", rt.name())); return log; }
    };
    let owned_by = |c: &runtime::Container, stem: &str| -> bool {
        c.name.strip_prefix(stem).and_then(|r| r.strip_prefix('-')).map(|n| !n.is_empty() && n.chars().all(|ch| ch.is_ascii_digit())).unwrap_or(false)
    };
    let me_name = local_node_name();
    let mut local_pods = 0u32;
    for key in admitted {
        let dep = desired.deployments[&key].clone();
        let stem = crate::store::pod_stem(&dep.namespace, &dep.name);
        let running: Vec<&runtime::Container> = actual.iter()
            .filter(|c| owned_by(c, &stem) && c.state == ContainerState::Running).collect();
        local_pods += running.len() as u32;
        let (current, target) = (running.len() as u32, dep.replicas);
        if current < target {
            log.push(format!("  [scale] {key}: {current} → {target} (+{})", target - current));
            let image = dep.containers.first().map(|c| c.image.clone()).unwrap_or_else(|| dep.image.clone());
            if let Err(e) = rt.pull(&image) { log.push(format!("    [warn] pull {image}: {e}")); }
            let mut taken: Vec<String> = actual.iter().map(|c| c.name.clone()).collect();
            for _ in current..target {
                let mut idx = 1u32;
                let pod_name = loop {
                    let cand = format!("{stem}-{idx}");
                    if !taken.contains(&cand) { break cand; }
                    idx += 1;
                };
                taken.push(pod_name.clone());
                let labels = [(crate::store::LABEL_MANAGED, "true"), (crate::store::LABEL_NAMESPACE, dep.namespace.as_str()), (crate::store::LABEL_DEPLOYMENT, dep.name.as_str())];
                let env = dep.containers.first().map(|c| c.env.clone()).unwrap_or_default();
                match rt.create(&pod_name, &image, None, &env, &labels) {
                    Ok(id) => match rt.start(&id) {
                        Ok(()) => {
                            log.push(format!("    [create] {pod_name} ✓"));
                            rt.connect_network(&id, &[pod_name.as_str()]).ok();
                        }
                        Err(e) => log.push(format!("    [error] start {pod_name}: {e}")),
                    },
                    Err(e) => log.push(format!("    [error] create {pod_name}: {e}")),
                }
            }
        } else if current > target {
            log.push(format!("  [scale] {key}: {current} → {target} (-{})", current - target));
            for c in running.iter().rev().take((current - target) as usize) {
                rt.stop(&c.id).ok();
                rt.remove(&c.id, true).ok();
                log.push(format!("    [remove] {} ✓", c.name));
            }
        }
    }
    if let Some(n) = desired.nodes.get_mut(&me_name) { n.pod_count = local_pods; }
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

/// Run one probe. Only a handler that actually ran and passed counts as
/// healthy: errors, timeouts, missing tools and handler-less probes all fail.
fn check_probe(container_id: &str, probe: &StoredProbe) -> Option<bool> {
    let timeout = std::time::Duration::from_secs(probe.timeout_seconds.max(1));
    let result = if let Some((path, port)) = &probe.http_get {
        docker::http_check_container(container_id, path, *port, timeout)
    } else if let Some(port) = probe.tcp_socket {
        docker::tcp_check_container(container_id, port, timeout)
    } else if let Some(cmd) = &probe.exec {
        let cmd_refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        docker::probe_exec(container_id, &cmd_refs, timeout).map(|code| code == 0)
    } else {
        Err("probe has no handler".to_string())
    };
    match result {
        Ok(healthy) => Some(healthy),
        Err(e) => {
            eprintln!("  [probe] {container_id}: {e}");
            if docker::exec_admission_unknown(&e) { None } else { Some(false) }
        }
    }
}

// ─── Multi-Node Cluster ───

/// Register the local node in the cluster
/// This process's node name — the key it registers under AND heartbeats as.
/// Must be identical across registration, the heartbeat sender, and the local
/// metric update, or heartbeats won't match by name and every node flaps to
/// NotReady after 30s (which disables multi-node scheduling entirely).
pub fn local_node_name() -> String {
    if let Ok(n) = std::env::var("ROYAK_NODE_NAME") {
        if !n.trim().is_empty() { return n.trim().to_string(); }
    }
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

// ─── Cluster census (signed node-to-node) ──────────────────────────────────
//
// Nodes find each other through the static `--peers` list (and, opt-in, UDP
// autodiscovery) and then talk ONLY through HMAC-signed requests
// (`auth::node_headers` / `auth::verify_node`). Two exchanges, every
// CENSUS_INTERVAL:
//   * POST /royak/v1/heartbeat  — "I am <node> at <address>", answered with the
//     peer's own hello. Keeps `world.nodes` (runtime census, never replicated
//     state) fresh.
//   * GET  /royak/v1/pods       — the peer's pods as `placement::PodView`s,
//     stored in the placement census the scheduler counts from.
// Desired state is never exchanged here: it travels only through Raft.

const CENSUS_INTERVAL: Duration = Duration::from_secs(2);
/// A peer not heard from for this long is NotReady (no new placements; its
/// census report is dropped so its pods are re-created elsewhere).
pub const NODE_TIMEOUT_SECS: u64 = 20;

/// What a node says about itself on every heartbeat.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NodeHello {
    pub node: String,
    pub address: String,
    #[serde(default)]
    pub cpu_used: f32,
    #[serde(default)]
    pub mem_used: f32,
    #[serde(default)]
    pub mem_capacity: f32,
    #[serde(default)]
    pub pod_count: u32,
}

pub fn local_hello(world: &DesiredWorld) -> NodeHello {
    let me = local_node_name();
    let n = world.nodes.get(&me);
    NodeHello {
        node: me,
        address: n.map(|n| n.address.clone()).unwrap_or_default(),
        cpu_used: n.map(|n| n.cpu_used).unwrap_or(0.0),
        mem_used: n.map(|n| n.mem_used).unwrap_or(0.0),
        mem_capacity: n.map(|n| n.mem_capacity).unwrap_or(0.0),
        pod_count: n.map(|n| n.pod_count).unwrap_or(0),
    }
}

/// Record a verified peer in the census (it just proved cluster membership).
pub fn record_peer(world: &mut DesiredWorld, hello: &NodeHello) {
    if hello.node == local_node_name() || hello.node.is_empty() {
        return;
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let n = world.nodes.entry(hello.node.clone()).or_insert_with(|| ClusterNode {
        name: hello.node.clone(), address: hello.address.clone(),
        cpu_capacity: 100.0, mem_capacity: hello.mem_capacity,
        cpu_used: 0.0, mem_used: 0.0, pod_count: 0,
        status: NodeStatus::Ready, last_heartbeat: now,
        neural_token: vec![], joined_at: now,
    });
    if !hello.address.is_empty() { n.address = hello.address.clone(); }
    n.cpu_used = hello.cpu_used;
    n.mem_used = hello.mem_used;
    n.mem_capacity = hello.mem_capacity;
    n.pod_count = hello.pod_count;
    n.last_heartbeat = now;
    if n.status == NodeStatus::NotReady { n.status = NodeStatus::Ready; }
}

/// Background census: heartbeat every known peer and pull its pod list. All
/// network I/O happens without the world lock.
pub fn spawn_cluster_census(world: std::sync::Arc<std::sync::RwLock<DesiredWorld>>, seed_peers: Vec<String>) {
    crate::placement::set_expected_peers(&seed_peers);
    std::thread::spawn(move || loop {
        let me = local_node_name();
        let (hello, mut targets) = {
            let w = world.read().unwrap_or_else(|e| e.into_inner());
            let targets: Vec<String> = w.nodes.iter()
                .filter(|(n, node)| **n != me && !node.address.is_empty())
                .map(|(_, node)| node.address.clone()).collect();
            (local_hello(&w), targets)
        };
        for p in &seed_peers {
            if !targets.contains(p) { targets.push(p.clone()); }
        }
        let body = serde_json::to_string(&hello).unwrap_or_default();
        for addr in targets {
            let peer = match node_post(&addr, "/royak/v1/heartbeat", &body, Duration::from_secs(3))
                .and_then(|b| serde_json::from_str::<NodeHello>(&b).map_err(|e| format!("bad hello: {e}"))) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if peer.node == me { continue; }
            {
                let mut w = world.write().unwrap_or_else(|e| e.into_inner());
                let mut peer = peer.clone();
                if peer.address.is_empty() { peer.address = addr.clone(); }
                record_peer(&mut w, &peer);
            }
            if let Ok(b) = node_get(&addr, "/royak/v1/pods", Duration::from_secs(5)) {
                if let Ok(pods) = serde_json::from_str::<Vec<crate::placement::PodView>>(&b) {
                    crate::placement::set_peer_report(&peer.node, &addr, pods);
                }
            }
        }
        {
            let mut w = world.write().unwrap_or_else(|e| e.into_inner());
            for line in check_node_health(&mut w) { println!("{line}"); }
            for (name, node) in w.nodes.iter() {
                if node.status != NodeStatus::Ready { crate::placement::drop_peer_report(name); }
            }
        }
        std::thread::sleep(CENSUS_INTERVAL);
    });
}

/// CLI helper: every peer's pods as `(node, pod)` via signed `GET /royak/v1/pods`.
/// Needs the cluster secret; without it peers are skipped.
pub fn peer_pod_inventory(world: &DesiredWorld) -> Vec<(String, String)> {
    let me = local_node_name();
    let mut out = Vec::new();
    for (nname, node) in &world.nodes {
        if *nname == me || node.address.is_empty() { continue; }
        if let Ok(b) = node_get(&node.address, "/royak/v1/pods", Duration::from_secs(5)) {
            if let Ok(pods) = serde_json::from_str::<Vec<crate::placement::PodView>>(&b) {
                out.extend(pods.into_iter().map(|p| (nname.clone(), p.pod)));
            }
        }
    }
    out
}

/// CLI helper: which peer runs `pod_name`? `(node, address)`, or None.
pub fn find_pod_node(world: &DesiredWorld, pod_name: &str) -> Option<(String, String, String)> {
    let me = local_node_name();
    let want = pod_name.trim_start_matches('/');
    for (nname, node) in &world.nodes {
        if *nname == me || node.address.is_empty() { continue; }
        if let Ok(b) = node_get(&node.address, "/royak/v1/pods", Duration::from_secs(5)) {
            if let Ok(pods) = serde_json::from_str::<Vec<crate::placement::PodView>>(&b) {
                if let Some(p) = pods.into_iter().find(|p| p.pod == want) {
                    return Some((nname.clone(), node.address.clone(), p.namespace));
                }
            }
        }
    }
    None
}

/// Trusted local node operator (already has the private state/cluster key).
/// HTTP users never call this helper: their verified identity is forwarded.
pub fn fetch_remote_logs(world:&DesiredWorld,peer_addr:&str,ns:&str,pod_name:&str)->Result<String,String>{
    let namespace_uid=world.storage_identities.namespaces.get(ns).cloned().ok_or("namespace identity missing")?;
    let request=crate::pod_access::LogRequest{namespace:ns.into(),namespace_uid,pod:pod_name.into(),container:None,tail:200,
        user:format!("node-operator:{}",crate::store::node_name()),groups:vec![crate::auth::MASTERS_GROUP.into()]};
    let raw=node_post(peer_addr,"/royak/v2/pod-logs",&serde_json::to_string(&request).map_err(|e|e.to_string())?,Duration::from_secs(15))?;
    let (status,body):(u16,String)=serde_json::from_str(&raw).map_err(|_|"invalid caller-bound log response")?;
    if status==200 {Ok(body)}else{Err(format!("peer logs HTTP {status}: {body}"))}
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

// ─── State Export / Import / Merge ───

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
        // Heartbeats run every CENSUS_INTERVAL on their own thread (never
        // behind a reconcile tick), so NODE_TIMEOUT_SECS is many missed beats.
        if age > NODE_TIMEOUT_SECS && node.status == NodeStatus::Ready {
            node.status = NodeStatus::NotReady;
            log.push(format!("  ⚠ [node] {name}: no heartbeat for {age}s — marked NotReady"));
        }
    }
    log
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
            // Cold start — create and run container. Invocation runs under
            // the desired-state lock, so a missing image is pulled in the
            // background and the caller retries.
            match docker::ensure_image_nonblocking(&image) {
                docker::ImageState::Present => {}
                docker::ImageState::Pulling => return Err(format!("image {image} is being pulled; retry the invocation shortly")),
                docker::ImageState::Failed(e) => return Err(format!("image {image} unavailable: {e}")),
            }

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

#[cfg(test)]
mod storage_binding_tests {
    use super::*;

    fn apply(w: &mut DesiredWorld, kind: &str, ns: &str, name: &str, spec: serde_json::Value) -> Result<String, String> {
        let r: Resource = serde_json::from_value(serde_json::json!({
            "kind": kind, "metadata": {"name": name, "namespace": ns}, "spec": spec
        })).unwrap();
        w.apply(&r)
    }
    fn pv(w: &mut DesiredWorld, name: &str, size: &str) -> Result<String, String> {
        apply(w, "PersistentVolume", "default", name, serde_json::json!({
            "capacity": {"storage": size}, "hostPath": {"path": format!("/tmp/royak-binding-tests/{name}")}
        }))
    }
    fn claim(w: &mut DesiredWorld, ns: &str, name: &str, size: &str) -> Result<String, String> {
        apply(w, "PersistentVolumeClaim", ns, name, serde_json::json!({"resources": {"requests": {"storage": size}}}))
    }

    #[test]
    fn small_pv_never_satisfies_larger_claim() {
        let mut w = DesiredWorld::new();
        pv(&mut w, "small", "512Mi").unwrap();
        claim(&mut w, "a", "data", "1Gi").unwrap();
        assert!(w.pvcs["a/data"].bound_pv.is_none());
        assert!(w.pvs["small"].status == PVStatus::Available);
        pv(&mut w, "large", "2Gi").unwrap();
        claim(&mut w, "a", "data", "1Gi").unwrap();
        assert_eq!(w.pvcs["a/data"].bound_pv.as_deref(), Some("large"));
    }

    #[test]
    fn pv_reapply_preserves_binding_and_rejects_mutation() {
        let mut w = DesiredWorld::new();
        pv(&mut w, "disk", "1Gi").unwrap();
        claim(&mut w, "a", "data", "1Gi").unwrap();
        pv(&mut w, "disk", "1Gi").unwrap();
        assert!(w.pvs["disk"].status == PVStatus::Bound);
        assert_eq!(w.pvs["disk"].bound_to.as_deref(), Some("a/data"));
        assert!(pv(&mut w, "disk", "2Gi").is_err());
        claim(&mut w, "b", "data", "1Gi").unwrap();
        assert!(w.pvcs["b/data"].bound_pv.is_none());
    }

    #[test]
    fn bound_claim_is_immutable_and_requires_reciprocal_binding() {
        let mut w = DesiredWorld::new();
        pv(&mut w, "disk", "1Gi").unwrap();
        claim(&mut w, "a", "data", "1Gi").unwrap();
        assert!(claim(&mut w, "a", "data", "2Gi").is_err());
        assert_eq!(w.pvcs["a/data"].requested, "1Gi");
        w.pvs.get_mut("disk").unwrap().bound_to = Some("b/data".into());
        assert!(claim(&mut w, "a", "data", "1Gi").is_err());
    }

    #[test]
    fn released_volume_cannot_be_rearmed_by_reapply() {
        let mut w = DesiredWorld::new();
        pv(&mut w, "disk", "1Gi").unwrap();
        claim(&mut w, "a", "data", "1Gi").unwrap();
        w.delete_resource("pvc", "a", "data").unwrap();
        pv(&mut w, "disk", "1Gi").unwrap();
        assert!(w.pvs["disk"].status == PVStatus::Released);
        claim(&mut w, "b", "data", "1Gi").unwrap();
        assert!(w.pvcs["b/data"].bound_pv.is_none());
    }

    #[test]
    fn storage_class_reapply_preserves_counter_and_incarnation_paths() {
        let mut w = DesiredWorld::new();
        let sc = serde_json::json!({"hostPathPrefix": "/tmp/royak-binding-tests", "reclaimPolicy": "Retain"});
        apply(&mut w, "StorageClass", "default", "local", sc.clone()).unwrap();
        claim(&mut w, "a", "data", "1Gi").unwrap();
        let first = w.pvcs["a/data"].bound_pv.clone().unwrap();
        let first_path = w.pvs[&first].host_path.clone();
        apply(&mut w, "StorageClass", "default", "local", sc).unwrap();
        w.delete_resource("pvc", "a", "data").unwrap();
        claim(&mut w, "a", "data", "1Gi").unwrap();
        let second = w.pvcs["a/data"].bound_pv.clone().unwrap();
        assert_ne!(first, second);
        assert_ne!(first_path, w.pvs[&second].host_path);
        assert!(w.pvs[&first].status == PVStatus::Released);
    }

    #[test]
    fn invalid_quantities_and_unsupported_storage_modes_fail_closed() {
        let mut w = DesiredWorld::new();
        for size in ["0", "-1Gi", "1.5Gi", "1MiB", "18446744073709551616", "16Ei"] {
            assert!(pv(&mut w, "disk", size).is_err(), "{size}");
            assert!(claim(&mut w, "a", "data", size).is_err(), "{size}");
        }
        assert!(apply(&mut w, "StorageClass", "default", "other", serde_json::json!({"provisioner": "foreign/driver"})).is_err());
        assert!(apply(&mut w, "StorageClass", "default", "other", serde_json::json!({"reclaimPolicy": "Bogus"})).is_err());
        assert!(apply(&mut w, "PersistentVolumeClaim", "a", "data", serde_json::json!({"accessModes": ["ReadWriteOnce", "ReadWriteMany"]})).is_err());
        assert!(apply(&mut w, "PersistentVolumeClaim", "a", "data", serde_json::json!({"accessModes": ["Unknown"]})).is_err());
        for value in [serde_json::Value::Null, serde_json::json!(1024), serde_json::json!({}), serde_json::json!([])] {
            assert!(apply(&mut w, "PersistentVolume", "default", "disk", serde_json::json!({"capacity": {"storage": value}})).is_err());
            assert!(apply(&mut w, "PersistentVolumeClaim", "a", "data", serde_json::json!({"resources": {"requests": {"storage": value}}})).is_err());
        }
    }

    #[test]
    fn loaded_inconsistent_or_cross_namespace_binding_is_not_mountable() {
        let mut w = DesiredWorld::new();
        pv(&mut w, "disk", "1Gi").unwrap();
        claim(&mut w, "a", "data", "1Gi").unwrap();
        assert!(crate::storage::bound_volume(&w, "a", "data").is_ok());
        assert!(crate::storage::bound_volume(&w, "b", "data").is_err());
        w.pvcs.insert("b/data".into(), w.pvcs["a/data"].clone());
        assert!(crate::storage::bound_volume(&w, "b", "data").is_err());
        w.pvs.get_mut("disk").unwrap().capacity = "512Mi".into();
        assert!(crate::storage::bound_volume(&w, "a", "data").is_err());
        w.pvs.get_mut("disk").unwrap().capacity = "1Gi".into();
        w.pvs.get_mut("disk").unwrap().status = PVStatus::Released;
        assert!(crate::storage::bound_volume(&w, "a", "data").is_err());
    }

    #[test]
    fn claimed_pv_deletion_and_unsafe_legacy_delete_reclaim_are_rejected_atomically() {
        let mut w=DesiredWorld::new();
        let sc=serde_json::json!({"reclaimPolicy":"Delete","hostPathPrefix":"/tmp/royak-binding-tests"});
        apply(&mut w,"StorageClass","","local",sc).unwrap();
        claim(&mut w,"a","data","1Gi").unwrap();
        let pv=w.pvcs["a/data"].bound_pv.clone().unwrap();let before=w.to_state().to_canonical_json();
        assert!(w.validate_storage_delete("pv","",&pv).is_err());
        assert!(w.delete_resource("pv","",&pv).is_none());
        assert!(w.validate_storage_delete("pvc","a","data").is_err());
        assert!(w.delete_resource("pvc","a","data").is_none());
        assert!(w.validate_storage_delete("namespace","","a").is_err());
        assert!(w.delete_resource("namespace","","a").is_none());
        assert_eq!(before,w.to_state().to_canonical_json());
    }
}


/// Modeled boundary fixtures only. They cannot supply production permissions,
/// and never execute a host runtime. Each test thread scopes/restores its own
/// trace even during unwinding; the outer suite remains default-parallel.
#[cfg(test)]
mod unsupported_storage_runtime_tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Clone)]
    struct Trace {
        docker_available: bool,
        pings: usize,
        effects: Vec<(String, Vec<String>)>,
    }
    std::thread_local! {
        static TRACE: RefCell<Option<Trace>> = const { RefCell::new(None) };
    }
    struct Scope { previous: Option<Trace> }
    impl Scope {
        fn install(docker_available: bool) -> Self {
            let next=Trace {docker_available,pings:0,effects:Vec::new()};
            Self {previous:TRACE.with(|slot|slot.replace(Some(next)))}
        }
        fn trace(&self) -> Trace {
            TRACE.with(|slot|slot.borrow().as_ref().unwrap().clone())
        }
    }
    impl Drop for Scope {
        fn drop(&mut self) {
            TRACE.with(|slot|{slot.replace(self.previous.take());});
        }
    }
    pub(super) fn docker_ping() -> Option<bool> {
        TRACE.with(|slot| {
            let mut slot=slot.borrow_mut();
            slot.as_mut().map(|trace| {trace.pings+=1;trace.docker_available})
        })
    }
    pub(super) fn before_effect(runtime: &str, admitted: &[String]) -> Option<Vec<String>> {
        TRACE.with(|slot| {
            let mut slot=slot.borrow_mut();
            slot.as_mut().map(|trace| {
                trace.effects.push((runtime.into(),admitted.to_vec()));
                vec!["  [modeled-boundary] no host runtime effects executed".into()]
            })
        })
    }

    fn put(world: &mut DesiredWorld, kind: &str, namespace: &str, name: &str,
        spec: serde_json::Value) {
        let resource=serde_json::from_value(serde_json::json!({
            "kind":kind,"metadata":{"name":name,"namespace":namespace},"spec":spec
        })).unwrap();
        world.apply(&resource).unwrap();
    }
    fn native_world(in_init: bool) -> DesiredWorld {
        let mut world=DesiredWorld::new();
        put(&mut world,"StorageClass","","native",serde_json::json!({
            "provisioner":crate::storage_lifecycle::PROVISIONER,"reclaimPolicy":"Retain"}));
        put(&mut world,"PersistentVolumeClaim","a","data",serde_json::json!({
            "storageClassName":"native","resources":{"requests":{"storage":"64Mi"}}}));
        let mount=serde_json::json!([{"name":"data","mountPath":"/data"}]);
        let main=if in_init {serde_json::json!({"name":"main","image":"busybox:1.36"})}
            else {serde_json::json!({"name":"main","image":"busybox:1.36","volumeMounts":mount})};
        let init=if in_init {serde_json::json!([{"name":"setup","image":"busybox:1.36",
            "volumeMounts":mount}])} else {serde_json::json!([])};
        put(&mut world,"Deployment","a","native",serde_json::json!({
            "replicas":1,"template":{"spec":{"containers":[main],"initContainers":init,
            "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data"}}]}}}));
        world
    }
    fn add_legacy(world: &mut DesiredWorld) {
        put(world,"StorageClass","","legacy",serde_json::json!({
            "provisioner":"royak/host-path","hostPathPrefix":"/srv/royak-legacy-observation",
            "reclaimPolicy":"Retain"}));
        put(world,"PersistentVolumeClaim","a","old",serde_json::json!({
            "storageClassName":"legacy","resources":{"requests":{"storage":"64Mi"}}}));
        put(world,"Deployment","a","old",serde_json::json!({
            "replicas":1,"template":{"spec":{
                "containers":[{"name":"main","image":"busybox:1.36",
                    "volumeMounts":[{"name":"old","mountPath":"/data"}]}],
                "volumes":[{"name":"old","persistentVolumeClaim":{"claimName":"old"}}]}}}));
    }
    fn state(world: &DesiredWorld) -> serde_json::Value {
        serde_json::to_value(world.to_state()).unwrap()
    }
    fn assert_blocked(log: &[String], scope: &Scope) {
        assert!(log.iter().any(|line|line.contains("[storage]")&&line.contains("refusing")));
        assert!(scope.trace().effects.is_empty(),
            "blocked-only workload reached the pre-host effect boundary");
        assert!(!log.iter().any(|line|line.contains("[ok]")));
    }

    #[test]
    fn direct_neuropod_refuses_native_main_and_init_before_any_effect_boundary() {
        for in_init in [false,true] {
            let mut world=native_world(in_init);let before=state(&world);
            let scope=Scope::install(false);
            let log=reconcile_neuropod(&mut world,&mut OrinBrain::new(32,4));
            assert_blocked(&log,&scope);
            assert_eq!(scope.trace().pings,0);
            assert_eq!(before,state(&world));
        }
    }
    #[test]
    fn direct_trait_refuses_native_main_and_init_before_runtime_factory() {
        for runtime in ["light","cri"] {
            for in_init in [false,true] {
                let mut world=native_world(in_init);let before=state(&world);
                let scope=Scope::install(false);
                let log=reconcile_via_trait(&mut world,&mut OrinBrain::new(32,4),runtime);
                assert_blocked(&log,&scope);
                assert_eq!(scope.trace().pings,0);
                assert_eq!(before,state(&world));
            }
        }
    }
    #[test]
    fn actual_auto_docker_down_route_refuses_before_neuropod_effect_boundary() {
        for in_init in [false,true] {
            let mut world=native_world(in_init);let before=state(&world);
            let scope=Scope::install(false);
            let log=reconcile_with_runtime(&mut world,&mut OrinBrain::new(32,4),false);
            assert_blocked(&log,&scope);
            assert_eq!(scope.trace().pings,1);
            assert_eq!(before,state(&world));
        }
    }
    #[test]
    fn actual_explicit_neuropod_route_does_not_probe_docker_or_run_blocked_work() {
        let mut world=native_world(false);
        let scope=Scope::install(true);
        let log=reconcile_with_runtime(&mut world,&mut OrinBrain::new(32,4),true);
        assert_blocked(&log,&scope);
        assert_eq!(scope.trace().pings,0);
    }
    #[test]
    fn both_direct_mixed_routes_admit_only_exact_proven_legacy_keys() {
        for runtime in ["neuropod","light","cri"] {
            let mut world=native_world(true);add_legacy(&mut world);let before=state(&world);
            let scope=Scope::install(false);
            let log=if runtime=="neuropod" {
                reconcile_neuropod(&mut world,&mut OrinBrain::new(32,4))
            } else {
                reconcile_via_trait(&mut world,&mut OrinBrain::new(32,4),runtime)
            };
            assert!(log.iter().any(|line|line.contains("a/native")&&line.contains("refusing")));
            assert_eq!(scope.trace().effects,vec![(runtime.into(),vec!["a/old".into()])]);
            assert_eq!(before,state(&world));
        }
    }
    #[test]
    fn actual_auto_fallback_mixed_route_passes_only_legacy_effect_keys() {
        let mut world=native_world(false);add_legacy(&mut world);let before=state(&world);
        let scope=Scope::install(false);
        let log=reconcile_with_runtime(&mut world,&mut OrinBrain::new(32,4),false);
        assert!(log.iter().any(|line|line.contains("a/native")&&line.contains("refusing")));
        assert_eq!(scope.trace().pings,1);
        assert_eq!(scope.trace().effects,vec![("neuropod".into(),vec!["a/old".into()])]);
        assert_eq!(before,state(&world));
    }
    #[test]
    fn unresolved_metadata_is_not_a_legacy_direct_or_fallback_escape() {
        for entry in ["neuropod","light","auto"] {
            let mut world=native_world(false);world.storage_classes.remove("native");
            let before=state(&world);let scope=Scope::install(false);
            let log=match entry {
                "neuropod"=>reconcile_neuropod(&mut world,&mut OrinBrain::new(32,4)),
                "light"=>reconcile_via_trait(&mut world,&mut OrinBrain::new(32,4),"light"),
                _=>reconcile_with_runtime(&mut world,&mut OrinBrain::new(32,4),false),
            };
            assert_blocked(&log,&scope);
            assert!(log.iter().any(|line|line.contains("unresolved")));
            assert_eq!(before,state(&world));
        }
    }
    #[test]
    fn scoped_effect_trap_restores_outer_trace_even_after_panic() {
        let outer=Scope::install(false);
        let result=std::panic::catch_unwind(|| {
            let _inner=Scope::install(true);
            assert_eq!(docker_ping(),Some(true));
            panic!("modeled fixture unwind");
        });
        assert!(result.is_err());
        assert_eq!(docker_ping(),Some(false));
        assert_eq!(outer.trace().pings,1);
        assert!(outer.trace().effects.is_empty());
    }



    fn add_classless_static_legacy(world: &mut DesiredWorld) {
        put(world,"PersistentVolume","","static-old",serde_json::json!({
            "capacity":{"storage":"64Mi"},"storageClassName":"",
            "hostPath":{"path":"/srv/royak-static-observation"}}));
        put(world,"PersistentVolumeClaim","a","classless",serde_json::json!({
            "storageClassName":"","resources":{"requests":{"storage":"64Mi"}}}));
        put(world,"Deployment","a","classless",serde_json::json!({
            "replicas":1,"template":{"spec":{
                "containers":[{"name":"main","image":"busybox:1.36",
                    "volumeMounts":[{"name":"old","mountPath":"/data"}]}],
                "volumes":[{"name":"old","persistentVolumeClaim":{"claimName":"classless"}}]}}}));
    }
    #[test]
    fn classless_legacy_mixed_direct_and_auto_routes_keep_only_static_legacy_key() {
        for entry in ["neuropod","light","auto"] {
            let mut world=native_world(true);add_classless_static_legacy(&mut world);
            let before=state(&world);let scope=Scope::install(false);
            let log=match entry {
                "neuropod"=>reconcile_neuropod(&mut world,&mut OrinBrain::new(32,4)),
                "light"=>reconcile_via_trait(&mut world,&mut OrinBrain::new(32,4),"light"),
                _=>reconcile_with_runtime(&mut world,&mut OrinBrain::new(32,4),false),
            };
            let runtime=if entry=="light" {"light"} else {"neuropod"};
            assert!(log.iter().any(|line|line.contains("a/native")&&line.contains("refusing")));
            assert_eq!(scope.trace().effects,vec![(runtime.into(),vec!["a/classless".into()])]);
            assert_eq!(before,state(&world));
        }
    }
    #[test]
    fn cleared_native_classes_remain_blocked_before_direct_and_auto_effects() {
        for entry in ["neuropod","light","auto"] {
            let mut world=native_world(false);
            let pv=world.pvcs["a/data"].bound_pv.clone().unwrap();
            world.pvcs.get_mut("a/data").unwrap().storage_class.clear();
            world.pvs.get_mut(&pv).unwrap().storage_class.clear();
            world.pvs.get_mut(&pv).unwrap().host_path="/srv/forged-native-public-path".into();
            let before=state(&world);let scope=Scope::install(false);
            let log=match entry {
                "neuropod"=>reconcile_neuropod(&mut world,&mut OrinBrain::new(32,4)),
                "light"=>reconcile_via_trait(&mut world,&mut OrinBrain::new(32,4),"light"),
                _=>reconcile_with_runtime(&mut world,&mut OrinBrain::new(32,4),false),
            };
            assert_blocked(&log,&scope);
            assert!(log.iter().any(|line|line.contains("unresolved")));
            assert_eq!(before,state(&world));
        }
    }
    #[test]
    fn source_binding_keeps_traps_before_host_and_effect_loops_on_exact_admitted_keys() {
        let source=include_str!("reconcile.rs");
        let neuropod=source.split("pub fn reconcile_neuropod(").nth(1).unwrap()
            .split("\nfn dirs_or_home(").next().unwrap();
        let trait_runtime=source.split("fn reconcile_via_trait(").nth(1).unwrap()
            .split("\n/// Check a single probe").next().unwrap();
        for (body,first_host) in [(neuropod,"let pods_root="),(trait_runtime,"runtime::get_runtime(")] {
            let admission=body.find("unsupported_runtime_workloads(").unwrap();
            let early_return=body.find("admitted.is_empty() && !log.is_empty()").unwrap();
            let trap=body.find("unsupported_storage_runtime_tests::before_effect(").unwrap();
            let host=body.find(first_host).unwrap();
            assert!(admission<early_return && early_return<trap && trap<host);
        }
        assert!(neuropod.contains("for name in &admitted {"));
        assert!(!neuropod.contains("for (name, dep) in &desired.deployments"));
        assert!(neuropod.contains("if dep.is_some() && !admitted.contains(&record_key) { continue; }"));
        assert!(trait_runtime.contains("for key in admitted {"));
        assert!(!trait_runtime.contains("let keys: Vec<String> = desired.deployments.keys()"));
        let apply=source.split("fn apply_resource(").nth(1).unwrap();
        assert!(apply.find("require_legacy_template_class(self, template)?").unwrap()
            < apply.find("self.namespaces.push(ns)").unwrap());
    }
    fn stateful(class: Option<serde_json::Value>) -> Resource {
        let mut volume_spec=serde_json::json!({"resources":{"requests":{"storage":"64Mi"}}});
        if let Some(class)=class {volume_spec["storageClassName"]=class;}
        serde_json::from_value(serde_json::json!({
            "kind":"StatefulSet","metadata":{"name":"db","namespace":"new"},
            "spec":{"replicas":1,"volumeClaimTemplates":[
                {"metadata":{"name":"data"},"spec":volume_spec}],
                "template":{"spec":{"containers":[{"name":"main","image":"busybox:1.36",
                    "volumeMounts":[{"name":"data","mountPath":"/data"}]}]}}}
        })).unwrap()
    }
    #[test]
    fn native_vct_is_refused_before_erasure_or_new_namespace_mutation() {
        let mut world=native_world(false);let before=state(&world);
        let error=world.apply(&stateful(Some(serde_json::json!("native")))).unwrap_err();
        assert!(error.contains("native volumeClaimTemplates"));
        assert_eq!(before,state(&world));
        assert!(!world.deployments.contains_key("new/db"));
        assert!(!world.namespaces.iter().any(|namespace|namespace=="new"));
    }
    #[test]
    fn unknown_and_malformed_explicit_vct_classes_never_default_legacy() {
        for class in [serde_json::json!("missing"),serde_json::json!(""),
            serde_json::json!(null),serde_json::json!(false),serde_json::json!([])] {
            let mut world=native_world(false);let before=state(&world);
            assert!(world.apply(&stateful(Some(class))).is_err());
            assert_eq!(before,state(&world));
        }
    }
    #[test]
    fn explicit_known_legacy_and_absent_vct_class_keep_legacy_only_lowering() {
        for class in [Some(serde_json::json!("legacy")),None] {
            let mut world=native_world(false);add_legacy(&mut world);
            let claims=world.pvcs.len();let volumes=world.pvs.len();
            world.apply(&stateful(class)).unwrap();
            let deployment=&world.deployments["new/db"];
            assert!(deployment.stateful);
            assert_eq!(deployment.containers[0].volumes[0].0,"vct:data");
            assert_eq!(world.pvcs.len(),claims);
            assert_eq!(world.pvs.len(),volumes);
        }
    }
}

#[cfg(test)]
mod probe_tests {
    use super::*;

    fn apply_yaml(yaml: &str) -> Result<DesiredWorld, String> {
        let mut w = DesiredWorld::new();
        for r in crate::spec::parse_yaml(yaml)? { w.apply(&r)?; }
        Ok(w)
    }

    fn dep_with_readiness(probe: &str) -> String {
        format!(r#"
apiVersion: apps/v1
kind: Deployment
metadata: {{name: web}}
spec:
  template:
    spec:
      containers:
      - name: c
        image: busybox:1.36
        readinessProbe:
{probe}
"#)
    }

    fn readiness_json(w: &DesiredWorld) -> serde_json::Value {
        serde_json::to_value(w.deployments["default/web"].containers[0].readiness_probe.as_ref().unwrap()).unwrap()
    }

    fn no_handler() -> StoredProbe {
        serde_json::from_value(serde_json::json!({
            "http_get": null, "exec": null,
            "initial_delay_seconds": 0, "period_seconds": 10, "failure_threshold": 3
        })).unwrap()
    }

    #[test]
    fn probe_without_a_handler_is_never_healthy() {
        // Regression: check_probe used to fall through to `true`.
        assert_eq!(check_probe("no-such-container", &no_handler()), Some(false));
    }

    #[test]
    fn tcp_socket_readiness_is_parsed_and_stored() {
        let w = apply_yaml(&dep_with_readiness("          tcpSocket: {port: 8080}\n          periodSeconds: 2")).unwrap();
        let p = readiness_json(&w);
        assert_eq!(p["tcp_socket"], serde_json::json!(8080), "{p}");
        assert_eq!(p["period_seconds"], serde_json::json!(2));
    }

    #[test]
    fn tcp_socket_survives_a_persistence_roundtrip() {
        let w = apply_yaml(&dep_with_readiness("          tcpSocket: {port: 8080}")).unwrap();
        let json = serde_json::to_string(&w.deployments["default/web"]).unwrap();
        let back: StoredDeployment = serde_json::from_str(&json).unwrap();
        let p = serde_json::to_value(back.containers[0].readiness_probe.as_ref().unwrap()).unwrap();
        assert_eq!(p["tcp_socket"], serde_json::json!(8080));
    }

    #[test]
    fn probes_without_tcp_keep_their_serialized_form() {
        // Template hashes are computed over the serialized container: adding
        // the tcp field must not roll every existing HTTP/exec deployment.
        let w = apply_yaml(&dep_with_readiness("          httpGet: {path: /, port: 80}")).unwrap();
        assert!(!serde_json::to_string(&w.deployments["default/web"].containers[0]).unwrap().contains("tcp_socket"));
    }

    #[test]
    fn invalid_or_unsupported_probes_are_rejected_at_apply() {
        for (probe, needle) in [
            ("          periodSeconds: 5", "no handler"),
            ("          grpc: {port: 9000}", "grpc"),
            ("          tcpSocket: {port: http}", "named port"),
            ("          httpGet: {path: /, port: http}", "named port"),
            ("          tcpSocket: {port: 0}", "port"),
            ("          exec: {command: []}", "empty"),
            ("          tcpSocket: {port: 80}\n          httpGet: {path: /, port: 80}", "exactly one"),
            ("          exec: {command: ['true']}\n          periodSeconds: 0", "positive"),
            ("          exec: {command: ['true']}\n          timeoutSeconds: 0", "positive"),
            ("          exec: {command: ['true']}\n          failureThreshold: 0", "positive"),
            ("          exec: {command: ['true']}\n          successThreshold: 0", "positive"),
            ("          exec: {command: ['true']}\n          terminationGracePeriodSeconds: 2", "unknown field"),
            ("          httpGet: {path: /, port: 80, scheme: HTTPS}", "HTTPS"),
            ("          httpGet: {path: /, port: 80, host: example.test}", "unknown field"),
        ] {
            let e = match apply_yaml(&dep_with_readiness(probe)) {
                Ok(_) => panic!("probe accepted: {probe}"),
                Err(e) => e,
            };
            assert!(e.contains(needle), "probe {probe:?}: error {e:?} should mention {needle:?}");
        }
    }

    #[test]
    fn valid_http_and_exec_probes_are_still_accepted() {
        apply_yaml(&dep_with_readiness("          httpGet: {path: /healthz, port: 8080}")).unwrap();
        apply_yaml(&dep_with_readiness("          exec: {command: [cat, /tmp/ready]}")).unwrap();
        apply_yaml(&dep_with_readiness("          httpGet: {port: 8080, scheme: HTTP}")).unwrap();
    }

    #[test]
    fn regular_init_container_probes_are_rejected() {
        let yaml = "kind: Deployment\nmetadata: {name: web}\nspec:\n  template:\n    spec:\n      initContainers:\n      - name: init\n        image: alpine:3.22\n        readinessProbe: {exec: {command: ['true']}}\n      containers: [{name: main, image: 'alpine:3.22'}]\n";
        let error = apply_yaml(yaml).err().unwrap();
        assert!(error.contains("regular init containers cannot define probes"), "{error}");
    }
    #[test]
    fn single_container_controllers_refuse_unmodelled_probe_targets() {
        for kind in ["DaemonSet", "Job", "CronJob"] {
            for shape in ["containers:\n      - {name: main, image: alpine}\n      - {name: extra, image: alpine, readinessProbe: {exec: {command: ['true']}}}",
                "initContainers:\n      - {name: init, image: alpine, startupProbe: {exec: {command: ['true']}}}\n      containers: [{name: main, image: alpine}]"] {
                let yaml = format!("kind: {kind}\nmetadata: {{name: web}}\nspec:\n  template:\n    spec:\n      {shape}\n");
                let error = apply_yaml(&yaml).err().expect("unsupported probe target must be refused");
                assert!(error.contains("single modelled regular container"), "{kind}: {error}");
            }
        }
    }
}

