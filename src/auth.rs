//! Authentication and authorization for the Royak API, and authentication of
//! node-to-node calls.
//!
//! **Users** authenticate with a bearer token. Identities come only from the
//! configured token table; no request header can choose or upgrade a role:
//!   * `ROYAK_TOKEN`      — one admin token (user `admin`, group `system:masters`)
//!   * `ROYAK_TOKEN_FILE` — Kubernetes static token CSV: `token,user,uid,"g1,g2"`
//!   * neither            — an admin token is generated once at
//!     `{data_dir}/admin.token` (0600) and written into the generated kubeconfig.
//!
//! `ROYAK_AUTH=insecure-dev` disables authentication (every caller is an
//! admin). It is an explicit, loudly logged opt-in for local experiments.
//!
//! **Authorization** is evaluated in one place ([`authorize`]) against
//! Kubernetes-style RBAC: Role/ClusterRole + RoleBinding/ClusterRoleBinding
//! (User, Group, ServiceAccount subjects), plus the built-in cluster roles
//! `cluster-admin`, `admin`, `edit` and `view`. Group `system:masters` is
//! always allowed.
//!
//! **Nodes** authenticate every internal call (state sync, heartbeat, pod
//! create/delete/inventory/logs, Raft RPC) with HMAC-SHA256 over the request,
//! keyed by the shared cluster secret (`ROYAK_CLUSTER_SECRET` or
//! `ROYAK_CLUSTER_SECRET_FILE`). Requests outside a ±30 s window or replayed
//! within it are rejected. Payloads that carry Secret values are additionally
//! encrypted (AES-256-GCM) with a key derived from the same secret.

use crate::reconcile::{DesiredWorld, RbacRule};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

pub const MASTERS_GROUP: &str = "system:masters";
pub const AUTHENTICATED_GROUP: &str = "system:authenticated";

/// An authenticated caller.
#[derive(Clone, Debug, PartialEq)]
pub struct Identity {
    pub user: String,
    pub groups: Vec<String>,
}

impl Identity {
    pub fn is_master(&self) -> bool {
        self.groups.iter().any(|g| g == MASTERS_GROUP)
    }
}

#[derive(Clone)]
struct TokenEntry {
    user: String,
    groups: Vec<String>,
}

enum Mode {
    Tokens(HashMap<[u8; 32], TokenEntry>),
    InsecureDev,
}

static MODE: OnceLock<Mode> = OnceLock::new();
static ADMIN_TOKEN: OnceLock<Option<String>> = OnceLock::new();

fn digest(token: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"royak-token-v1\0");
    h.update(token.as_bytes());
    h.finalize().into()
}

/// Parse a Kubernetes static token file (`token,user,uid[,"group1,group2"]`).
pub fn parse_token_csv(text: &str) -> Result<Vec<(String, String, Vec<String>)>, String> {
    let mut out = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        // split on the first three commas; the 4th field may be quoted and contain commas
        let mut fields = Vec::new();
        let mut rest = line;
        for _ in 0..3 {
            match rest.split_once(',') {
                Some((a, b)) => { fields.push(a.trim().to_string()); rest = b; }
                None => { fields.push(rest.trim().to_string()); rest = ""; break; }
            }
        }
        if !rest.is_empty() || fields.len() == 3 { fields.push(rest.trim().to_string()); }
        if fields.len() < 3 || fields[0].is_empty() || fields[1].is_empty() {
            return Err(format!("token file line {}: expected token,user,uid[,groups]", i + 1));
        }
        if fields[0].len() < 16 {
            return Err(format!("token file line {}: token shorter than 16 characters", i + 1));
        }
        let groups = fields.get(3).map(|g| g.trim_matches('"'))
            .map(|g| g.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_default();
        out.push((fields[0].clone(), fields[1].clone(), groups));
    }
    Ok(out)
}

fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut raw = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn write_private(path: &str, content: &str) -> Result<(), String> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("create {path}: {e}"))?;
    f.write_all(content.as_bytes()).map_err(|e| format!("write {path}: {e}"))?;
    f.sync_all().map_err(|e| format!("fsync {path}: {e}"))
}

/// Configure user authentication. Called once at server start; returns the
/// admin token (if one is managed by Royak) so the kubeconfig can carry it.
pub fn init_user_auth(data_dir: &str) -> Result<Option<String>, String> {
    if MODE.get().is_some() {
        return Ok(ADMIN_TOKEN.get().cloned().flatten());
    }
    let mode_env = std::env::var("ROYAK_AUTH").unwrap_or_default();
    if mode_env == "insecure-dev" {
        eprintln!("  ⚠ [auth] ROYAK_AUTH=insecure-dev: AUTHENTICATION DISABLED — every caller is cluster-admin. Never expose this API.");
        let _ = MODE.set(Mode::InsecureDev);
        let _ = ADMIN_TOKEN.set(None);
        return Ok(None);
    }
    if !mode_env.is_empty() && mode_env != "token" {
        return Err(format!("unknown ROYAK_AUTH={mode_env:?} (expected \"token\" or \"insecure-dev\")"));
    }
    let mut table = HashMap::new();
    let mut admin_token = None;
    if let Ok(t) = std::env::var("ROYAK_TOKEN") {
        let t = t.trim().to_string();
        if t.len() < 16 {
            return Err("ROYAK_TOKEN must be at least 16 characters".into());
        }
        table.insert(digest(&t), TokenEntry { user: "admin".into(), groups: vec![MASTERS_GROUP.into()] });
        admin_token = Some(t);
    }
    if let Ok(path) = std::env::var("ROYAK_TOKEN_FILE") {
        let text = std::fs::read_to_string(&path).map_err(|e| format!("ROYAK_TOKEN_FILE {path}: {e}"))?;
        for (tok, user, groups) in parse_token_csv(&text)? {
            table.insert(digest(&tok), TokenEntry { user, groups });
        }
    }
    if table.is_empty() {
        std::fs::create_dir_all(data_dir).map_err(|e| format!("create {data_dir}: {e}"))?;
        let path = format!("{data_dir}/admin.token");
        let tok = match std::fs::read_to_string(&path) {
            Ok(s) if s.trim().len() >= 16 => s.trim().to_string(),
            Ok(_) => return Err(format!("{path} exists but holds no valid token")),
            Err(_) => {
                let t = random_hex(32);
                write_private(&path, &t)?;
                eprintln!("  [auth] generated admin token: {path} (0600)");
                t
            }
        };
        table.insert(digest(&tok), TokenEntry { user: "admin".into(), groups: vec![MASTERS_GROUP.into()] });
        admin_token = Some(tok);
    }
    eprintln!("  [auth] bearer-token authentication on ({} identities)", table.len());
    let _ = MODE.set(Mode::Tokens(table));
    let _ = ADMIN_TOKEN.set(admin_token.clone());
    Ok(admin_token)
}

/// Resolve the caller from the `Authorization` header. `None` = anonymous or
/// invalid credentials (never an elevated identity).
pub fn authenticate(authorization: Option<&str>) -> Option<Identity> {
    match MODE.get() {
        Some(Mode::InsecureDev) => Some(Identity { user: "insecure-dev".into(), groups: vec![MASTERS_GROUP.into(), AUTHENTICATED_GROUP.into()] }),
        Some(Mode::Tokens(table)) => {
            let tok = authorization?.trim().strip_prefix("Bearer ")?.trim();
            if tok.is_empty() { return None; }
            table.get(&digest(tok)).map(|e| {
                let mut groups = e.groups.clone();
                groups.push(AUTHENTICATED_GROUP.into());
                Identity { user: e.user.clone(), groups }
            })
        }
        // Not initialised (e.g. offline CLI paths, unit tests): nobody.
        None => None,
    }
}

// ─── Request classification ────────────────────────────────────────────────

/// What a request does, in RBAC terms.
#[derive(Clone, Debug, PartialEq)]
pub struct Attrs {
    pub verb: String,
    pub resource: String,
    pub subresource: Option<String>,
    pub namespace: Option<String>,
    pub name: Option<String>,
}

impl Attrs {
    fn new(verb: &str, resource: &str, sub: Option<&str>, ns: Option<&str>, name: Option<&str>) -> Attrs {
        Attrs {
            verb: verb.into(),
            resource: resource.into(),
            subresource: sub.map(|s| s.into()),
            namespace: ns.map(|s| s.into()),
            name: name.map(|s| s.into()),
        }
    }
    pub fn describe(&self) -> String {
        let r = match &self.subresource { Some(s) => format!("{}/{s}", self.resource), None => self.resource.clone() };
        let n = self.name.as_deref().map(|n| format!(" {n:?}")).unwrap_or_default();
        match &self.namespace {
            Some(ns) => format!("{} {r}{n} in namespace {ns:?}", self.verb),
            None => format!("{} {r}{n} (cluster-wide)", self.verb),
        }
    }
}

/// How a request must be authorized.
#[derive(Debug, PartialEq)]
pub enum Access {
    /// No credentials needed (health, version, static dashboard, demo sandbox).
    Public,
    /// Node-to-node endpoint: HMAC node signature required, user tokens rejected.
    Node,
    /// Any authenticated user (API discovery).
    Authenticated,
    /// RBAC check against these attributes.
    Rbac(Attrs),
}

/// Split a Kubernetes REST path into (namespace, resource, name, subresource).
pub fn parse_k8s_path(path: &str) -> Option<(Option<&str>, &str, Option<&str>, Option<&str>)> {
    let segs: Vec<&str> = path.trim_start_matches('/').trim_end_matches('/').split('/').collect();
    // An empty segment ("//") is never a valid group, version, namespace,
    // resource or name; refusing it keeps the router and the gate in step.
    if segs.iter().any(|s| s.is_empty()) {
        return None;
    }
    let rest: &[&str] = match segs.as_slice() {
        ["api", "v1", rest @ ..] => rest,
        ["apis", _group, _version, rest @ ..] => rest,
        _ => return None,
    };
    match rest {
        ["namespaces", ns, res, name, sub] => Some((Some(ns), res, Some(name), Some(sub))),
        ["namespaces", ns, res, name] => Some((Some(ns), res, Some(name), None)),
        // Namespace status is a subresource of the cluster-scoped namespace,
        // not a namespaced resource called "status".
        ["namespaces", name, "status"] => Some((None, "namespaces", Some(name), Some("status"))),
        ["namespaces", ns, res] => Some((Some(ns), res, None, None)),
        ["namespaces", name] => Some((None, "namespaces", Some(name), None)),
        [res, name, sub] => Some((None, res, Some(name), Some(sub))),
        [res, name] => Some((None, res, Some(name), None)),
        [res] => Some((None, res, None, None)),
        _ => None,
    }
}

/// A Function trigger may only live on a path whose authorization IS the
/// functions/invoke permission. Anything the gate maps to another decision
/// (a Kubernetes resource, discovery, health, node or Royak endpoints) can
/// never be shadowed by a trigger. The router uses the same check, so the
/// gate and the router cannot disagree about what a path is.
pub fn is_function_trigger_path(path: &str) -> bool {
    let invoke = Access::Rbac(Attrs::new("create", "functions", Some("invoke"), None, None));
    path.starts_with('/') && !path.starts_with("/hooks/repo/")
        && ["GET", "POST", "PUT", "DELETE", "PATCH"].iter()
            .all(|m| classify(m, path, &HashMap::new(), false) == invoke)
}

/// `/apis/<group>` or `/apis/<group>/<version>` exactly (no empty segments).
fn is_group_discovery(path: &str) -> bool {
    let segs: Vec<&str> = path.trim_start_matches('/').trim_end_matches('/').split('/').collect();
    segs.first() == Some(&"apis") && (2..=3).contains(&segs.len()) && segs.iter().all(|s| !s.is_empty())
}

pub fn demo_enabled() -> bool {
    std::env::var("ROYAK_DEMO").map(|v| v == "1" || v == "true").unwrap_or(false)
}

fn query_get<'a>(query: &'a HashMap<String, String>, k: &str) -> Option<&'a str> {
    query.get(k).map(|s| s.as_str()).filter(|s| !s.is_empty())
}

/// Decide how a request must be authorized. Every path the server serves maps
/// to exactly one decision here; anything unknown requires cluster-admin-level
/// access to a pseudo-resource (deny by default for non-masters).
pub fn classify(method: &str, path: &str, query: &HashMap<String, String>, websocket: bool) -> Access {
    let ns_q = query_get(query, "namespace");
    match (method, path) {
        ("GET", "/healthz" | "/readyz" | "/livez" | "/version") => return Access::Public,
        ("GET", "/" | "/dashboard") => return Access::Public,
        ("GET", "/demo/state" | "/demo/info") | ("POST", "/demo/scale" | "/demo/kill") if demo_enabled() => return Access::Public,
        _ => {}
    }
    if path.starts_with("/royak/v1/raft/") && path != "/royak/v1/raft/status" {
        return Access::Node;
    }
    match (method, path) {
        ("POST", "/royak/v1/heartbeat") | ("POST", "/royak/v1/create-pod")
        | ("POST", "/royak/v1/delete-pod") | ("GET", "/royak/v1/pods") => return Access::Node,
        ("GET", p) if p.starts_with("/royak/v1/pod-logs/") => return Access::Node,
        ("GET", "/api" | "/apis" | "/api/v1" | "/openapi/v2" | "/openapi/v3") => return Access::Authenticated,
        ("GET", p) if is_group_discovery(p) => return Access::Authenticated,
        ("GET", p) if p.starts_with("/openapi/") => return Access::Authenticated,
        _ => {}
    }
    // Royak's own (non-Kubernetes) endpoints
    let rb = |verb: &str, res: &str, sub: Option<&str>, ns: Option<&str>, name: Option<&str>| Access::Rbac(Attrs::new(verb, res, sub, ns, name));
    match (method, path) {
        ("GET", "/demo/state" | "/demo/info") => return rb("get", "deployments", None, ns_q, None),
        ("POST", "/demo/scale" | "/demo/kill") => return rb("update", "deployments", Some("scale"), Some(crate::store::DEFAULT_NS), None),
        ("GET", "/royak/v1/raft/status") => return rb("get", "nodes", None, None, None),
        ("GET", "/royak/v1/flows" | "/royak/v1/brain" | "/metrics" | "/royak/v1/top/nodes") => return rb("get", "nodes", None, None, None),
        ("GET", "/royak/v1/pipelines") => return rb("list", "pipelines", None, None, None),
        ("GET", "/royak/v1/top/pods") => return rb("list", "pods", None, ns_q, None),
        ("GET", "/royak/v1/logs") => return rb("get", "pods", Some("log"), ns_q, None),
        _ => {}
    }
    if let Some(name) = path.strip_prefix("/royak/v1/rollout/") {
        return rb("get", "deployments", None, Some(ns_q.unwrap_or(crate::store::DEFAULT_NS)), Some(name));
    }
    if let Some(rest) = path.strip_prefix("/royak/v1/describe/") {
        let mut it = rest.splitn(2, '/');
        let res = it.next().unwrap_or("");
        let name = it.next();
        let plural = match res { "deployment" => "deployments", "pod" => "pods", "node" => "nodes", other => other };
        let ns = if plural == "nodes" { None } else { Some(ns_q.unwrap_or(crate::store::DEFAULT_NS)) };
        return rb("get", plural, None, ns, name);
    }
    if path.starts_with("/hooks/repo/") {
        return rb("create", "pipelines", Some("trigger"), None, path.strip_prefix("/hooks/repo/"));
    }
    if path.starts_with("/hooks/") {
        return rb("create", "functions", Some("invoke"), None, None);
    }

    let Some((ns, res, name, sub)) = parse_k8s_path(path) else {
        // Unknown path (including function HTTP triggers): needs the
        // functions/invoke permission, which only admins hold by default.
        return rb("create", "functions", Some("invoke"), None, None);
    };
    let watch = matches!(query_get(query, "watch"), Some("true" | "1"));
    let follow_ws = websocket;
    let _ = follow_ws;
    let verb = match (method, name, sub) {
        (_, _, Some("exec" | "attach" | "portforward")) => "create",
        ("GET", _, _) if watch => "watch",
        ("GET", Some(_), _) => "get",
        ("GET", None, _) => "list",
        ("POST", _, _) => "create",
        ("PUT", _, _) => "update",
        ("PATCH", _, _) => "patch",
        ("DELETE", Some(_), _) => "delete",
        ("DELETE", None, _) => "deletecollection",
        _ => "unknown",
    };
    let resource = if res == "namespaces" && ns.is_none() { "namespaces" } else { res };
    let ns = if resource == "namespaces" && ns.is_none() { name } else { ns };
    let ns = if crate::store::is_cluster_scoped_kind_plural(resource) { None } else { ns };
    Access::Rbac(Attrs::new(verb, resource, sub, ns, name))
}

// ─── Authorization ─────────────────────────────────────────────────────────

const READ_VERBS: &[&str] = &["get", "list", "watch"];
const ALL_VERBS: &[&str] = &["*"];

fn rule(verbs: &[&str], resources: &[&str]) -> RbacRule {
    RbacRule {
        verbs: verbs.iter().map(|s| s.to_string()).collect(),
        resources: resources.iter().map(|s| s.to_string()).collect(),
        namespaces: vec!["*".into()],
        resource_names: vec![],
    }
}

/// Rules of the built-in cluster roles.
fn builtin_cluster_role(name: &str) -> Option<Vec<RbacRule>> {
    Some(match name {
        "cluster-admin" => vec![rule(ALL_VERBS, &["*"])],
        // namespace admin: everything incl. namespaced RBAC, but cluster-scoped
        // objects only matter through a ClusterRoleBinding.
        "admin" => vec![rule(ALL_VERBS, &["*"])],
        "edit" => vec![
            rule(ALL_VERBS, &[
                "pods", "pods/exec", "pods/attach", "pods/portforward", "pods/log",
                "deployments", "deployments/scale", "statefulsets", "statefulsets/scale", "replicasets",
                "daemonsets", "jobs", "cronjobs", "services", "endpoints", "configmaps", "secrets",
                "persistentvolumeclaims", "ingresses", "networkpolicies", "horizontalpodautoscalers",
                "events", "customresources",
            ]),
            rule(READ_VERBS, &["namespaces", "limitranges", "resourcequotas", "roles", "rolebindings"]),
        ],
        "view" => vec![
            rule(READ_VERBS, &[
                "pods", "pods/log", "deployments", "deployments/scale", "statefulsets", "replicasets",
                "daemonsets", "jobs", "cronjobs", "services", "endpoints", "configmaps",
                "persistentvolumeclaims", "ingresses", "networkpolicies", "horizontalpodautoscalers",
                "events", "namespaces", "limitranges", "resourcequotas", "customresources", "pipelines",
                "functions", "nodes",
            ]),
        ],
        _ => return None,
    })
}

fn rule_allows(r: &RbacRule, a: &Attrs) -> bool {
    let verb_ok = r.verbs.iter().any(|v| v == "*" || v == &a.verb);
    let full = match &a.subresource { Some(s) => format!("{}/{s}", a.resource), None => a.resource.clone() };
    let res_ok = r.resources.iter().any(|x| x == "*" || x == &full
        || (a.subresource.is_none() && x == &a.resource)
        || (x.ends_with("/*") && a.subresource.is_some() && x.trim_end_matches("/*") == a.resource));
    let name_ok = r.resource_names.is_empty()
        || a.name.as_ref().map(|n| r.resource_names.contains(n)).unwrap_or(false);
    verb_ok && res_ok && name_ok
}

fn subject_matches(s: &crate::reconcile::RbacSubject, id: &Identity, binding_ns: Option<&str>) -> bool {
    match s.kind.as_str() {
        "User" => s.name == id.user,
        "Group" => id.groups.iter().any(|g| g == &s.name),
        "ServiceAccount" => {
            let ns = s.namespace.as_deref().or(binding_ns).unwrap_or(crate::store::DEFAULT_NS);
            id.user == format!("system:serviceaccount:{ns}:{}", s.name)
        }
        _ => false,
    }
}

/// The central authorization decision.
pub fn authorize(world: &DesiredWorld, id: &Identity, a: &Attrs) -> bool {
    if id.is_master() {
        return true;
    }
    for b in world.rbac_bindings.values() {
        if !b.subjects.iter().any(|s| subject_matches(s, id, b.namespace.as_deref())) {
            continue;
        }
        // A RoleBinding grants only inside its own namespace.
        if let Some(bns) = &b.namespace {
            if a.namespace.as_deref() != Some(bns.as_str()) {
                continue;
            }
        }
        let rules: Vec<RbacRule> = if b.role_kind == "Role" {
            let Some(bns) = &b.namespace else { continue };
            world.rbac_roles.get(&crate::store::obj_key(bns, &b.role_name)).map(|r| r.rules.clone()).unwrap_or_default()
        } else if let Some(r) = world.rbac_roles.get(&b.role_name).filter(|r| r.kind == "ClusterRole") {
            r.rules.clone()
        } else {
            builtin_cluster_role(&b.role_name).unwrap_or_default()
        };
        if rules.iter().any(|r| rule_allows(r, a)) {
            return true;
        }
    }
    // Legacy Royak `RbacRole` objects: a role named X applies to user X, with
    // the namespace list carried by each rule.
    if let Some(role) = world.rbac_roles.get(&id.user).filter(|r| r.kind == "RbacRole" || r.kind.is_empty()) {
        for r in &role.rules {
            let ns_ok = r.namespaces.iter().any(|n| n == "*")
                || a.namespace.as_ref().map(|ns| r.namespaces.contains(ns)).unwrap_or(false);
            if ns_ok && rule_allows(r, a) {
                return true;
            }
        }
    }
    false
}

/// Kubernetes plural resource name for a manifest kind.
pub fn resource_for_kind(kind: &str) -> String {
    match kind {
        "Ingress" => "ingresses".into(),
        "NetworkPolicy" => "networkpolicies".into(),
        "PersistentVolume" => "persistentvolumes".into(),
        "PersistentVolumeClaim" => "persistentvolumeclaims".into(),
        "StorageClass" => "storageclasses".into(),
        "HorizontalPodAutoscaler" => "horizontalpodautoscalers".into(),
        "IngressClass" => "ingressclasses".into(),
        "RbacRole" => "rbacroles".into(),
        "Repository" => "repositories".into(),
        "Policy" => "policies".into(),
        "ResourceQuota" => "resourcequotas".into(),
        "LimitRange" => "limitranges".into(),
        "CustomResourceDefinition" => "customresourcedefinitions".into(),
        k => format!("{}s", k.to_lowercase()),
    }
}

// ─── Node authentication ───────────────────────────────────────────────────

static CLUSTER_SECRET: OnceLock<Option<Vec<u8>>> = OnceLock::new();

/// The shared cluster secret, from `ROYAK_CLUSTER_SECRET` or the file named by
/// `ROYAK_CLUSTER_SECRET_FILE`. Never generated: nodes of one cluster must be
/// given the same secret deliberately.
pub fn cluster_secret() -> Option<&'static [u8]> {
    CLUSTER_SECRET.get_or_init(|| {
        if let Ok(s) = std::env::var("ROYAK_CLUSTER_SECRET") {
            let s = s.trim().to_string();
            if !s.is_empty() { return Some(s.into_bytes()); }
        }
        if let Ok(p) = std::env::var("ROYAK_CLUSTER_SECRET_FILE") {
            if let Ok(s) = std::fs::read_to_string(&p) {
                let s = s.trim().to_string();
                if !s.is_empty() { return Some(s.into_bytes()); }
            }
        }
        None
    }).as_deref()
}

/// Validate the secret for cluster mode. Returns an error that should stop
/// the process when a multi-node feature is on without a usable secret.
pub fn require_cluster_secret() -> Result<(), String> {
    match cluster_secret() {
        None => Err("cluster mode needs ROYAK_CLUSTER_SECRET (or ROYAK_CLUSTER_SECRET_FILE): the same random value (≥32 chars) on every node".into()),
        Some(s) if s.len() < 32 => Err("ROYAK_CLUSTER_SECRET must be at least 32 characters".into()),
        Some(_) => Ok(()),
    }
}

/// Cluster id derived from the cluster secret: nodes sharing a secret agree on
/// it without coordination, and it reveals nothing about the secret.
pub fn derived_cluster_id() -> Option<String> {
    let secret = cluster_secret()?;
    let mut m = HmacSha256::new_from_slice(secret).ok()?;
    m.update(b"royak-cluster-id-v1");
    Some(m.finalize().into_bytes().iter().take(6).map(|b| format!("{b:02x}")).collect())
}

pub const HDR_NODE: &str = "x-royak-node";
pub const HDR_TS: &str = "x-royak-timestamp";
pub const HDR_NONCE: &str = "x-royak-nonce";
pub const HDR_SIG: &str = "x-royak-signature";
const SKEW_SECS: i64 = 30;

fn now_secs() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn sign_input(method: &str, path: &str, ts: i64, nonce: &str, node: &str, body: &[u8]) -> Vec<u8> {
    let body_hash: String = Sha256::digest(body).iter().map(|b| format!("{b:02x}")).collect();
    format!("royak-node-v1\n{method}\n{path}\n{ts}\n{nonce}\n{node}\n{body_hash}").into_bytes()
}

fn mac(secret: &[u8]) -> HmacSha256 {
    HmacSha256::new_from_slice(secret).expect("hmac accepts any key length")
}

/// Headers that authenticate a node-to-node request (`path` includes the query).
pub fn node_headers(method: &str, path: &str, body: &[u8]) -> Result<Vec<(&'static str, String)>, String> {
    let secret = cluster_secret().ok_or("no cluster secret configured")?;
    let node = crate::store::node_name();
    let ts = now_secs();
    let nonce = random_hex(12);
    let mut m = mac(secret);
    m.update(&sign_input(method, path, ts, &nonce, &node, body));
    let sig: String = m.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
    Ok(vec![(HDR_NODE, node), (HDR_TS, ts.to_string()), (HDR_NONCE, nonce), (HDR_SIG, sig)])
}

fn replay_cache() -> &'static std::sync::Mutex<HashMap<String, i64>> {
    static C: OnceLock<std::sync::Mutex<HashMap<String, i64>>> = OnceLock::new();
    C.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 { return None; }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

/// Verify a node-signed request. Returns the calling node's name.
pub fn verify_node(method: &str, path: &str, header: impl Fn(&str) -> Option<String>, body: &[u8]) -> Result<String, String> {
    let secret = cluster_secret().ok_or("this node has no cluster secret; node endpoints are disabled")?;
    let node = header(HDR_NODE).ok_or("missing node signature")?;
    let ts: i64 = header(HDR_TS).and_then(|t| t.parse().ok()).ok_or("missing or bad timestamp")?;
    let nonce = header(HDR_NONCE).filter(|n| !n.is_empty() && n.len() <= 64).ok_or("missing nonce")?;
    let sig = header(HDR_SIG).and_then(|s| hex_decode(&s)).ok_or("missing or bad signature")?;
    let now = now_secs();
    if (now - ts).abs() > SKEW_SECS {
        return Err(format!("timestamp outside ±{SKEW_SECS}s window"));
    }
    let mut m = mac(secret);
    m.update(&sign_input(method, path, ts, &nonce, &node, body));
    m.verify_slice(&sig).map_err(|_| "bad signature".to_string())?;
    let mut cache = replay_cache().lock().unwrap_or_else(|e| e.into_inner());
    cache.retain(|_, t| (now - *t).abs() <= SKEW_SECS * 2);
    let key = format!("{node}\n{nonce}");
    if cache.insert(key, ts).is_some() {
        return Err("replayed request".into());
    }
    Ok(node)
}

// ─── Encryption with the cluster secret ────────────────────────────────────

fn derived_key(purpose: &[u8]) -> Result<[u8; 32], String> {
    let secret = cluster_secret().ok_or("no cluster secret configured")?;
    let mut m = mac(secret);
    m.update(b"royak-seal-v1\0");
    m.update(purpose);
    Ok(m.finalize().into_bytes().into())
}

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

fn unb64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

pub fn seal_with_key(key: &[u8; 32], plaintext: &[u8]) -> String {
    use aes_gcm::aead::{Aead, KeyInit};
    use rand::RngCore;
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = aes_gcm::Aes256Gcm::new_from_slice(key).expect("32-byte key")
        .encrypt(aes_gcm::Nonce::from_slice(&nonce), plaintext).expect("aes-gcm encrypt");
    let mut buf = nonce.to_vec();
    buf.extend_from_slice(&ct);
    b64(&buf)
}

pub fn unseal_with_key(key: &[u8; 32], sealed: &str) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::{Aead, KeyInit};
    let raw = unb64(sealed).ok_or("sealed payload is not base64")?;
    if raw.len() < 12 + 16 { return Err("sealed payload too short".into()); }
    aes_gcm::Aes256Gcm::new_from_slice(key).expect("32-byte key")
        .decrypt(aes_gcm::Nonce::from_slice(&raw[..12]), &raw[12..])
        .map_err(|_| "decryption failed (wrong key or tampered data)".to_string())
}

pub fn seal_for_cluster(purpose: &[u8], plaintext: &[u8]) -> Result<String, String> {
    Ok(seal_with_key(&derived_key(purpose)?, plaintext))
}

pub fn unseal_for_cluster(purpose: &[u8], sealed: &str) -> Result<Vec<u8>, String> {
    unseal_with_key(&derived_key(purpose)?, sealed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q() -> HashMap<String, String> { HashMap::new() }

    fn world(yaml: &str) -> DesiredWorld {
        let mut w = DesiredWorld::new();
        for r in crate::spec::parse_yaml(yaml).unwrap() { w.apply(&r).unwrap(); }
        w
    }

    fn user(name: &str) -> Identity {
        Identity { user: name.into(), groups: vec![AUTHENTICATED_GROUP.into()] }
    }

    fn attrs(method: &str, path: &str) -> Attrs {
        match classify(method, path, &q(), false) {
            Access::Rbac(a) => a,
            other => panic!("{method} {path} → {other:?}"),
        }
    }

    #[test]
    fn empty_path_segments_cannot_reach_resources_through_discovery() {
        // The gate and the router must read a path the same way: an empty
        // segment ("//") must not turn a resource request into "discovery".
        for p in ["/apis///secrets", "/apis///secrets/db", "/apis/x//secrets", "/apis//v1/secrets",
                  "/api//v1/secrets", "/api/v1//secrets", "/api/v1/namespaces//secrets"] {
            assert_ne!(classify("GET", p, &q(), false), Access::Authenticated, "{p} must not be discovery");
            assert_eq!(parse_k8s_path(p), None, "{p} must not parse as a resource");
        }
        // Real discovery still works.
        assert_eq!(classify("GET", "/apis/apps/v1", &q(), false), Access::Authenticated);
        assert_eq!(classify("GET", "/apis/apps", &q(), false), Access::Authenticated);
        assert_eq!(parse_k8s_path("/apis/apps/v1/namespaces/a/deployments"), Some((Some("a"), "deployments", None, None)));
    }

    #[test]
    fn get_on_pods_exec_does_not_grant_exec() {
        let r = RbacRule { verbs: vec!["get".into()], resources: vec!["pods/exec".into()], namespaces: vec!["*".into()], resource_names: vec![] };
        assert!(!rule_allows(&r, &Attrs::new("create", "pods", Some("exec"), Some("a"), Some("p"))));
        let r = RbacRule { verbs: vec!["create".into()], resources: vec!["pods/exec".into()], namespaces: vec!["*".into()], resource_names: vec![] };
        assert!(rule_allows(&r, &Attrs::new("create", "pods", Some("exec"), Some("a"), Some("p"))));
    }

    #[test]
    fn function_triggers_cannot_shadow_other_endpoints() {
        for ok in ["/api/hello", "/api/date", "/hooks/greet", "/fn/resize"] {
            assert!(is_function_trigger_path(ok), "{ok} should be a valid trigger");
        }
        for bad in ["/api/v1/configmaps", "/api/v1/namespaces/a/secrets", "/apis/apps/v1/deployments",
                    "/apis/apps", "/api", "/healthz", "/version", "/", "/hooks/repo/x", "/royak/v1/pods",
                    "/royak/v1/heartbeat", "/openapi/v2", "relative"] {
            assert!(!is_function_trigger_path(bad), "{bad} must not be accepted as a trigger");
        }
    }

    #[test]
    fn namespace_status_is_a_namespace_subresource() {
        assert_eq!(parse_k8s_path("/api/v1/namespaces/team/status"), Some((None, "namespaces", Some("team"), Some("status"))));
        assert_eq!(parse_k8s_path("/api/v1/namespaces/team/pods"), Some((Some("team"), "pods", None, None)));
    }

    const BINDINGS: &str = r#"
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {name: viewers}
roleRef: {kind: ClusterRole, name: view}
subjects: [{kind: User, name: viewer}]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: deployers, namespace: team-a}
roleRef: {kind: ClusterRole, name: edit}
subjects: [{kind: Group, name: team-a-deployers}]
"#;

    #[test]
    fn classification_covers_sensitive_paths() {
        assert_eq!(attrs("GET", "/api/v1/namespaces/a/pods/p/log"), Attrs::new("get", "pods", Some("log"), Some("a"), Some("p")));
        assert_eq!(attrs("POST", "/api/v1/namespaces/a/pods/p/exec"), Attrs::new("create", "pods", Some("exec"), Some("a"), Some("p")));
        assert_eq!(attrs("GET", "/api/v1/namespaces/a/pods/p/exec"), Attrs::new("create", "pods", Some("exec"), Some("a"), Some("p")));
        assert_eq!(attrs("GET", "/api/v1/namespaces/a/pods/p/portforward"), Attrs::new("create", "pods", Some("portforward"), Some("a"), Some("p")));
        assert_eq!(attrs("PATCH", "/apis/apps/v1/namespaces/a/deployments/web/scale"), Attrs::new("patch", "deployments", Some("scale"), Some("a"), Some("web")));
        // Namespaces are cluster-scoped: deleting one is never a namespaced permission.
        assert_eq!(attrs("DELETE", "/api/v1/namespaces/b"), Attrs::new("delete", "namespaces", None, None, Some("b")));
        assert_eq!(attrs("GET", "/api/v1/nodes"), Attrs::new("list", "nodes", None, None, None));
        let mut wq = q();
        wq.insert("watch".into(), "true".into());
        assert!(matches!(classify("GET", "/api/v1/namespaces/a/pods", &wq, false), Access::Rbac(a) if a.verb == "watch"));
        assert_eq!(classify("GET", "/healthz", &q(), false), Access::Public);
        assert_eq!(classify("POST", "/royak/v1/create-pod", &q(), false), Access::Node);
        assert_eq!(classify("POST", "/royak/v1/raft/append-entries", &q(), false), Access::Node);
        assert_eq!(classify("GET", "/api", &q(), false), Access::Authenticated);
        // unknown paths are never public
        assert!(matches!(classify("POST", "/my-function", &q(), false), Access::Rbac(_)));
        assert!(matches!(classify("POST", "/hooks/x", &q(), false), Access::Rbac(_)));
    }

    #[test]
    fn viewer_reads_only_and_never_secrets() {
        let w = world(BINDINGS);
        let v = user("viewer");
        assert!(authorize(&w, &v, &attrs("GET", "/api/v1/namespaces/a/pods")));
        assert!(authorize(&w, &v, &attrs("GET", "/apis/apps/v1/namespaces/a/deployments/web")));
        assert!(authorize(&w, &v, &attrs("GET", "/api/v1/namespaces/a/pods/p/log")));
        for (m, p) in [
            ("POST", "/apis/apps/v1/namespaces/a/deployments"),
            ("PUT", "/apis/apps/v1/namespaces/a/deployments/web"),
            ("PATCH", "/apis/apps/v1/namespaces/a/deployments/web"),
            ("PATCH", "/apis/apps/v1/namespaces/a/deployments/web/scale"),
            ("DELETE", "/apis/apps/v1/namespaces/a/deployments/web"),
            ("POST", "/api/v1/namespaces/a/pods/p/exec"),
            ("GET", "/api/v1/namespaces/a/pods/p/portforward"),
            ("GET", "/api/v1/namespaces/a/secrets"),
            ("GET", "/api/v1/namespaces/a/secrets/s"),
        ] {
            assert!(!authorize(&w, &v, &attrs(m, p)), "viewer must not {m} {p}");
        }
    }

    #[test]
    fn deployer_is_confined_to_its_namespace() {
        let w = world(BINDINGS);
        let d = Identity { user: "ci".into(), groups: vec!["team-a-deployers".into(), AUTHENTICATED_GROUP.into()] };
        assert!(authorize(&w, &d, &attrs("POST", "/apis/apps/v1/namespaces/team-a/deployments")));
        assert!(authorize(&w, &d, &attrs("PATCH", "/apis/apps/v1/namespaces/team-a/deployments/web/scale")));
        assert!(authorize(&w, &d, &attrs("DELETE", "/apis/apps/v1/namespaces/team-a/deployments/web")));
        assert!(authorize(&w, &d, &attrs("POST", "/api/v1/namespaces/team-a/pods/p/exec")));
        assert!(!authorize(&w, &d, &attrs("POST", "/apis/apps/v1/namespaces/team-b/deployments")));
        assert!(!authorize(&w, &d, &attrs("DELETE", "/apis/apps/v1/namespaces/default/deployments/web")));
        assert!(!authorize(&w, &d, &attrs("GET", "/api/v1/nodes")), "a RoleBinding never grants cluster-scoped access");
        assert!(!authorize(&w, &d, &attrs("POST", "/apis/rbac.authorization.k8s.io/v1/namespaces/team-a/rolebindings")));
        assert!(!authorize(&w, &d, &attrs("DELETE", "/api/v1/namespaces/team-a")));
        // Pipelines and functions run arbitrary containers cluster-wide: admin only.
        assert!(!authorize(&w, &d, &attrs("POST", "/hooks/repo/app")));
        assert!(!authorize(&w, &d, &attrs("GET", "/royak/v1/pipelines")));
    }

    #[test]
    fn unbound_identity_gets_nothing() {
        let w = world(BINDINGS);
        assert!(!authorize(&w, &user("nobody"), &attrs("GET", "/api/v1/namespaces/a/pods")));
        // a user may not name itself into a group
        assert!(!authorize(&w, &user("team-a-deployers"), &attrs("POST", "/apis/apps/v1/namespaces/team-a/deployments")));
    }

    #[test]
    fn token_csv_parses_groups() {
        let rows = parse_token_csv("# c\nabcdefghijklmnop1234,alice,1,\"g1,g2\"\nqrstuvwxyzabcdef5678,bob,2\n").unwrap();
        assert_eq!(rows[0], ("abcdefghijklmnop1234".into(), "alice".into(), vec!["g1".to_string(), "g2".into()]));
        assert_eq!(rows[1].2, Vec::<String>::new());
        assert!(parse_token_csv("short,alice,1").is_err());
    }

    #[test]
    fn seal_roundtrip_and_tamper_detection() {
        let key = [7u8; 32];
        let s = seal_with_key(&key, b"secret value");
        assert_eq!(unseal_with_key(&key, &s).unwrap(), b"secret value");
        assert!(unseal_with_key(&[8u8; 32], &s).is_err());
        let mut raw = unb64(&s).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        assert!(unseal_with_key(&key, &b64(&raw)).is_err());
    }

    #[test]
    fn node_signature_input_binds_every_field() {
        let a = sign_input("POST", "/royak/v1/create-pod", 1, "n", "node-a", b"x");
        assert_ne!(a, sign_input("POST", "/royak/v1/delete-pod", 1, "n", "node-a", b"x"));
        assert_ne!(a, sign_input("POST", "/royak/v1/create-pod", 2, "n", "node-a", b"x"));
        assert_ne!(a, sign_input("POST", "/royak/v1/create-pod", 1, "m", "node-a", b"x"));
        assert_ne!(a, sign_input("POST", "/royak/v1/create-pod", 1, "n", "node-b", b"x"));
        assert_ne!(a, sign_input("POST", "/royak/v1/create-pod", 1, "n", "node-a", b"y"));
    }
}
