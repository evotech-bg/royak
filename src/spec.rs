//! Spec parser — Kubernetes-compatible YAML specs.
//!
//! Supports: Deployment, Service, ConfigMap, Namespace
//! Compatible enough that existing K8s YAML files work.

use serde::Deserialize;
use std::collections::HashMap;

/// Top-level K8s resource
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct Resource {
    #[serde(rename = "apiVersion")]
    pub api_version: Option<String>,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: Option<serde_yaml::Value>,
    // K8s RBAC kinds carry these at the TOP level, not under .spec
    pub rules: Option<serde_yaml::Value>,
    pub subjects: Option<serde_yaml::Value>,
    #[serde(rename = "roleRef")]
    pub role_ref: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Metadata {
    #[serde(default)]
    pub name: String,
    pub namespace: Option<String>,
    pub labels: Option<HashMap<String, String>>,
}

/// Deployment spec (also used for DaemonSet, Job, CronJob)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct DeploymentSpec {
    pub replicas: Option<u32>,
    pub selector: Option<serde_yaml::Value>,
    pub template: PodTemplate,
    pub strategy: Option<StrategySpec>,
    pub schedule: Option<String>,  // CronJob only
    pub completions: Option<u32>,  // Job only
    // StatefulSet only
    #[serde(rename = "serviceName")]
    pub service_name: Option<String>,
    #[serde(rename = "volumeClaimTemplates")]
    pub volume_claim_templates: Option<Vec<VolumeClaimTemplate>>,
}

/// StatefulSet volumeClaimTemplate — each pod ordinal gets its own volume.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct VolumeClaimTemplate {
    pub metadata: Metadata,
    pub spec: Option<serde_yaml::Value>,
}

#[derive(Debug, Deserialize)]
pub struct StrategySpec {
    #[serde(rename = "type")]
    pub strategy_type: String,        // "RollingUpdate", "Canary", "BlueGreen"
    #[serde(default)]
    pub weight: Option<u32>,          // Canary: initial traffic weight %
    #[serde(rename = "maxSurge", default)]
    pub max_surge: Option<u32>,       // RollingUpdate
    #[serde(rename = "maxUnavailable", default)]
    pub max_unavailable: Option<u32>, // RollingUpdate
    #[serde(default)]
    pub active: Option<String>,       // BlueGreen: "blue" or "green"
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PodTemplate {
    pub metadata: Option<Metadata>,
    pub spec: PodSpec,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PodSpec {
    #[serde(rename = "initContainers")]
    pub init_containers: Option<Vec<ContainerSpec>>,
    pub containers: Vec<ContainerSpec>,
    pub volumes: Option<Vec<VolumeSpec>>,
    #[serde(rename = "restartPolicy")]
    pub restart_policy: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ContainerSpec {
    pub name: String,
    pub image: String,
    pub ports: Option<Vec<PortSpec>>,
    pub env: Option<Vec<EnvVar>>,
    #[serde(rename = "envFrom", default)]
    pub env_from: Option<Vec<EnvFromSpec>>,
    pub command: Option<Vec<String>>,
    pub resources: Option<ResourceSpec>,
    #[serde(rename = "volumeMounts")]
    pub volume_mounts: Option<Vec<VolumeMount>>,
    #[serde(rename = "livenessProbe")]
    pub liveness_probe: Option<ProbeSpec>,
    #[serde(rename = "readinessProbe")]
    pub readiness_probe: Option<ProbeSpec>,
    #[serde(rename = "startupProbe")]
    pub startup_probe: Option<ProbeSpec>,
}

#[derive(Debug, Deserialize)]
pub struct EnvFromSpec {
    #[serde(rename = "configMapRef")]
    pub config_map_ref: Option<NameRef>,
    #[serde(rename = "secretRef")]
    pub secret_ref: Option<NameRef>,
}

#[derive(Debug, Deserialize)]
pub struct NameRef {
    pub name: String,
}

/// Health probe spec (K8s compatible)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ProbeSpec {
    #[serde(rename = "httpGet")]
    pub http_get: Option<HttpGetProbe>,
    pub exec: Option<ExecProbe>,
    #[serde(rename = "initialDelaySeconds", default)]
    pub initial_delay_seconds: u64,
    #[serde(rename = "periodSeconds", default = "default_period")]
    pub period_seconds: u64,
    #[serde(rename = "failureThreshold", default = "default_failure_threshold")]
    pub failure_threshold: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HttpGetProbe {
    pub path: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecProbe {
    pub command: Vec<String>,
}

fn default_period() -> u64 { 10 }
fn default_failure_threshold() -> u32 { 3 }

/// Cluster config — everything configurable, nothing hardcoded
#[derive(Debug, Deserialize)]
#[allow(dead_code, unused)]
pub struct ClusterConfigSpec {
    pub llm: Option<LlmConfig>,
    pub alerts: Option<AlertConfig>,
    pub runtime: Option<String>,         // "docker", "cri-o", "neurodock"
    pub pause: Option<PauseConfig>,
    pub api: Option<ApiConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct LlmConfig {
    pub provider: Option<String>,        // "ollama", "openai", "local"
    pub host: Option<String>,            // "http://10.77.0.1:11434"
    pub model: Option<String>,           // "qwen2.5:32b", "llama3.2:3b"
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct AlertConfig {
    pub webhook: Option<String>,         // "/hooks/alert"
    pub channels: Option<Vec<String>>,   // ["slack", "telegram"]
    pub on_anomaly: Option<bool>,
    pub on_restart: Option<bool>,
    pub on_rollout: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PauseConfig {
    pub default_idle_seconds: Option<u64>,  // default for all deployments
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct ApiConfig {
    pub port: Option<u16>,
    pub cors: Option<bool>,
}

/// Function spec — serverless Lambda (NeuroDock native)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct FunctionSpec {
    pub runtime: Option<String>,          // "python3.12", "node20", "rust", or image name
    pub handler: Option<String>,          // "main.handler" or command
    pub image: Option<String>,            // explicit image (overrides runtime)
    pub command: Option<Vec<String>>,     // explicit command
    pub trigger: Option<Vec<FunctionTrigger>>,
    pub timeout: Option<String>,          // "30s", "5m"
    pub memory: Option<String>,           // "128Mi", "256Mi"
    pub env: Option<Vec<EnvVar>>,
    pub code: Option<String>,             // inline code (for simple functions)
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct FunctionTrigger {
    pub http: Option<String>,             // "/api/process"
    pub webhook: Option<String>,          // "/hooks/order"
    pub schedule: Option<String>,         // "*/5 * * * *"
}

/// Repository spec — git repo registration
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RepositorySpec {
    pub url: Option<String>,          // remote URL (https/ssh)
    pub path: Option<String>,          // local path
    pub branch: Option<String>,        // branch to watch (default: main)
    #[serde(rename = "secretRef")]
    pub secret_ref: Option<String>,    // Secret with credentials
    pub pipeline: Option<String>,      // auto-trigger this pipeline on push
}

/// Pipeline spec — integrated CI/CD (K8s doesn't have this!)
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PipelineSpec {
    pub trigger: Option<Vec<PipelineTrigger>>,
    pub stages: Vec<PipelineStage>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PipelineTrigger {
    #[serde(rename = "type")]
    pub trigger_type: String,       // "webhook", "watch", "manual"
    pub path: Option<String>,       // webhook path or file path
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct PipelineStage {
    pub name: String,
    pub image: Option<String>,
    pub command: Option<Vec<String>>,
    pub action: Option<String>,     // "apply" for deploy stages
    pub file: Option<String>,       // for action: apply
    pub artifacts: Option<Vec<String>>,
    #[serde(rename = "dependsOn")]
    pub depends_on: Option<String>, // stage name this depends on
    pub env: Option<Vec<EnvVar>>,
    /// Conditional: "branch == main", "always", "failure"
    #[serde(rename = "if")]
    pub if_condition: Option<String>,
    /// Matrix: run across multiple values
    pub matrix: Option<MatrixSpec>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MatrixSpec {
    /// e.g. image: ["python:3.10", "python:3.11", "python:3.12"]
    pub image: Option<Vec<String>>,
    /// e.g. env: ["DEBUG=1", "DEBUG=0"]
    pub env: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct VolumeSpec {
    pub name: String,
    #[serde(rename = "hostPath")]
    pub host_path: Option<HostPath>,
    #[serde(rename = "persistentVolumeClaim")]
    pub pvc: Option<PvcRef>,
    #[serde(rename = "emptyDir")]
    pub empty_dir: Option<serde_yaml::Value>,
    #[serde(rename = "configMap")]
    pub config_map: Option<NamedRef>,
    pub secret: Option<SecretVolRef>,
}

#[derive(Debug, Deserialize)]
pub struct NamedRef {
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct SecretVolRef {
    #[serde(rename = "secretName")]
    pub secret_name: String,
}

#[derive(Debug, Deserialize)]
pub struct HostPath {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct PvcRef {
    #[serde(rename = "claimName")]
    pub claim_name: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct VolumeMount {
    pub name: String,
    #[serde(rename = "mountPath")]
    pub mount_path: String,
    #[serde(rename = "readOnly")]
    pub read_only: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PortSpec {
    #[serde(rename = "containerPort")]
    pub container_port: u16,
    pub protocol: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ResourceSpec {
    pub limits: Option<HashMap<String, String>>,
    pub requests: Option<HashMap<String, String>>,
}

/// Service spec
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ServiceSpec {
    pub selector: Option<HashMap<String, String>>,
    pub ports: Vec<ServicePort>,
    #[serde(rename = "type")]
    pub service_type: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct ServicePort {
    pub port: u16,
    #[serde(rename = "targetPort")]
    pub target_port: Option<u16>,
    pub protocol: Option<String>,
    pub name: Option<String>,
    #[serde(rename = "nodePort")]
    pub node_port: Option<u16>,
}

/// Parse a YAML file into resources
pub fn parse_file(path: &str) -> Result<Vec<Resource>, String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| format!("Cannot read {path}: {e}"))?;
    parse_yaml(&content)
}

/// Parse YAML string (supports multi-document with ---)
pub fn parse_yaml(yaml: &str) -> Result<Vec<Resource>, String> {
    let mut resources = Vec::new();

    for doc in yaml.split("\n---") {
        let trimmed = doc.trim();
        if trimmed.is_empty() {
            continue;
        }
        // Skip documents that are ONLY comments (no actual content)
        let has_content = trimmed.lines().any(|l| {
            let l = l.trim();
            !l.is_empty() && !l.starts_with('#')
        });
        if !has_content {
            continue;
        }
        match serde_yaml::from_str::<Resource>(trimmed) {
            Ok(r) => resources.push(r),
            Err(e) => {
                eprintln!("  [parse] Skipping document: {e}");
            }
        }
    }

    if resources.is_empty() {
        Err("No valid resources found in YAML".to_string())
    } else {
        Ok(resources)
    }
}

/// Extract DeploymentSpec from a Resource (works for Deployment, ReplicaSet,
/// DaemonSet, Job, CronJob — and bare Pod, which becomes a single-replica
/// deployment with the pod spec inlined).
pub fn as_deployment(r: &Resource) -> Option<DeploymentSpec> {
    if r.kind == "Pod" {
        // A bare Pod carries the PodSpec directly under .spec (no template).
        let spec = r.spec.as_ref()?;
        let pod_spec: PodSpec = serde_yaml::from_value(spec.clone()).ok()?;
        return Some(DeploymentSpec {
            replicas: Some(1),
            selector: None,
            template: PodTemplate { metadata: None, spec: pod_spec },
            strategy: None,
            schedule: None,
            completions: None,
            service_name: None,
            volume_claim_templates: None,
        });
    }
    let valid = ["Deployment", "ReplicaSet", "StatefulSet", "DaemonSet", "Job", "CronJob"];
    if !valid.contains(&r.kind.as_str()) { return None; }
    let spec = r.spec.as_ref()?;
    serde_yaml::from_value(spec.clone()).ok()
}

/// Extract ServiceSpec from a Resource
#[allow(dead_code)]
pub fn as_service(r: &Resource) -> Option<ServiceSpec> {
    if r.kind != "Service" { return None; }
    let spec = r.spec.as_ref()?;
    serde_yaml::from_value(spec.clone()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yaml_errors() {
        assert!(parse_yaml("").is_err());
        assert!(parse_yaml("   \n\n  ").is_err());
    }

    #[test]
    fn single_deployment_parses() {
        let yaml = r#"
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 3
  template:
    spec:
      containers:
        - name: nginx
          image: nginx:alpine
"#;
        let rs = parse_yaml(yaml).expect("parse ok");
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].kind, "Deployment");
        assert_eq!(rs[0].metadata.name, "web");
    }

    #[test]
    fn multi_document_parses() {
        let yaml = r#"
kind: ConfigMap
metadata:
  name: cm1
spec:
  k: v
---
kind: Secret
metadata:
  name: s1
spec:
  k: v
"#;
        let rs = parse_yaml(yaml).expect("parse ok");
        assert_eq!(rs.len(), 2);
        assert_eq!(rs[0].kind, "ConfigMap");
        assert_eq!(rs[1].kind, "Secret");
    }

    #[test]
    fn leading_separator_tolerated() {
        let yaml = "---\nkind: ConfigMap\nmetadata:\n  name: cm\nspec:\n  k: v";
        let rs = parse_yaml(yaml).expect("parse ok");
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].metadata.name, "cm");
    }

    #[test]
    fn comment_only_doc_skipped() {
        let yaml = r#"
# just a comment
# nothing else
---
kind: ConfigMap
metadata:
  name: real
spec:
  k: v
"#;
        let rs = parse_yaml(yaml).expect("parse ok");
        assert_eq!(rs.len(), 1);
        assert_eq!(rs[0].metadata.name, "real");
    }

    #[test]
    fn comment_on_first_line_no_skip() {
        // Historical bug: a leading comment used to cause entire doc to be skipped.
        let yaml = "# leading comment\nkind: ConfigMap\nmetadata:\n  name: cm\nspec:\n  k: v";
        let rs = parse_yaml(yaml).expect("parse ok");
        assert_eq!(rs.len(), 1);
    }

    #[test]
    fn malformed_doc_is_skipped_not_fatal() {
        let yaml = r#"
kind: ConfigMap
metadata:
  name: good
spec:
  k: v
---
not: valid: yaml: here: at: all: ][
---
kind: Secret
metadata:
  name: also_good
spec:
  k: v
"#;
        let rs = parse_yaml(yaml).expect("parse ok");
        // At minimum the well-formed ones must come through; the malformed is tolerated.
        assert!(rs.iter().any(|r| r.metadata.name == "good"));
        assert!(rs.iter().any(|r| r.metadata.name == "also_good"));
    }

    #[test]
    fn as_deployment_accepts_deployment_daemonset_job() {
        for kind in ["Deployment", "DaemonSet", "Job", "CronJob"] {
            let yaml = format!(
                "kind: {kind}\nmetadata:\n  name: x\nspec:\n  replicas: 1\n  template:\n    spec:\n      containers:\n        - name: c\n          image: alpine"
            );
            let rs = parse_yaml(&yaml).expect("parse ok");
            assert!(as_deployment(&rs[0]).is_some(), "as_deployment failed for {kind}");
        }
    }

    #[test]
    fn as_deployment_rejects_non_workload_kinds() {
        let yaml = "kind: Service\nmetadata:\n  name: s\nspec:\n  ports: []";
        let rs = parse_yaml(yaml).expect("parse ok");
        assert!(as_deployment(&rs[0]).is_none());
    }

    #[test]
    fn as_service_only_for_service_kind() {
        let yaml = "kind: Service\nmetadata:\n  name: s\nspec:\n  ports: []";
        let rs = parse_yaml(yaml).expect("parse ok");
        assert!(as_service(&rs[0]).is_some());

        let yaml2 = "kind: ConfigMap\nmetadata:\n  name: c\nspec:\n  k: v";
        let rs2 = parse_yaml(yaml2).expect("parse ok");
        assert!(as_service(&rs2[0]).is_none());
    }
}
