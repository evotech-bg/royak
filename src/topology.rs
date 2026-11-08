//! A read-only, RBAC-filtered graph. Edges describe their evidence, not
//! imaginary packet flow. No secret/config values, tokens or commands leave here.
use std::collections::{BTreeMap, BTreeSet};
use serde::Serialize;
use crate::{placement::PodView, reconcile::{DesiredWorld, StoredContainer}};

pub struct Observation { pub view: PodView, pub source: String, pub age_ms: u64 }

#[derive(Serialize)]
pub struct Node {
    pub id: String, pub kind: String, pub namespace: String, pub name: String,
    pub status: String, pub evidence: String, pub facts: Vec<(String, String)>,
}
#[derive(Serialize)]
pub struct Edge { pub from: String, pub to: String, pub relation: String, pub evidence: String }
#[derive(Serialize)]
pub struct Graph {
    pub schema_version: u32, pub generation: u64, pub observed_at_unix_ms: u128,
    pub nodes: Vec<Node>, pub edges: Vec<Edge>, pub warnings: Vec<String>,
    pub truncated: bool, pub read_only: bool,
}

fn id(kind: &str, ns: &str, name: &str) -> String {
    serde_json::to_string(&(kind, ns, name)).unwrap()
}

struct Builder { nodes: BTreeMap<String, Node>, edges: BTreeMap<(String, String, String), Edge>, truncated: bool }
impl Builder {
    fn add(&mut self, kind: &str, ns: &str, name: &str, status: &str, evidence: &str, facts: Vec<(String, String)>) -> String {
        let key = id(kind, ns, name);
        if self.nodes.len() >= 500 && !self.nodes.contains_key(&key) { self.truncated = true; return key; }
        self.nodes.insert(key.clone(), Node { id: key.clone(), kind: kind.into(), namespace: ns.into(), name: name.into(),
            status: status.into(), evidence: evidence.into(), facts });
        key
    }
    fn reference(&mut self, kind: &str, ns: &str, name: &str, permitted: bool) -> String {
        let key = id(kind, ns, name);
        if !self.nodes.contains_key(&key) {
            self.add(kind, ns, name, if permitted { "Missing" } else { "Unknown" },
                if permitted { "referenced but absent from this snapshot" } else { "reference only; listing not permitted" }, vec![]);
        }
        key
    }
    fn edge(&mut self, from: String, to: String, relation: &str, evidence: &str) {
        if self.edges.len() >= 2000 { self.truncated = true; return; }
        if self.nodes.contains_key(&from) && self.nodes.contains_key(&to) {
            self.edges.insert((from.clone(), to.clone(), relation.into()), Edge { from, to, relation: relation.into(), evidence: evidence.into() });
        }
    }
    fn dependencies(&mut self, from: &str, ns: &str, c: &StoredContainer, can: &impl Fn(&str, bool) -> bool) {
        for name in &c.env_from_configmaps {
            let to = self.reference("ConfigMap", ns, name, can("configmaps", false));
            self.edge(from.into(), to, "reads configuration", "desired envFrom reference");
        }
        for name in &c.env_from_secrets {
            let to = self.reference("Secret", ns, name, can("secrets", false));
            self.edge(from.into(), to, "reads secret", "desired envFrom reference; values excluded");
        }
        for r in &c.env_refs {
            let (kind, resource) = if r.secret { ("Secret", "secrets") } else { ("ConfigMap", "configmaps") };
            let to = self.reference(kind, ns, &r.object, can(resource, false));
            self.edge(from.into(), to, "reads key reference", "desired valueFrom reference; keys and values excluded");
        }
        for (source, _) in &c.volumes {
            for (prefix, kind, resource) in [("cmv:", "ConfigMap", "configmaps"), ("sev:", "Secret", "secrets"), ("pvc:", "PVC", "persistentvolumeclaims")] {
                if let Some(name) = source.strip_prefix(prefix) {
                    let to = self.reference(kind, ns, name, can(resource, false));
                    self.edge(from.into(), to, "mounts", "desired volume reference; content and host paths excluded");
                }
            }
        }
    }
}

pub fn build(w: &DesiredWorld, observations: &[Observation], ns: Option<&str>, can: impl Fn(&str, bool) -> bool, local_ok: bool) -> Graph {
    let scope = |namespace: &str| ns.map(|n| n == namespace).unwrap_or(true);
    let mut b = Builder { nodes: BTreeMap::new(), edges: BTreeMap::new(), truncated: false };
    let mut warnings = vec!["Desired references are not proof of successful traffic. Peer census can be up to 15 seconds old; this is not an atomic distributed snapshot.".into()];
    if !local_ok { warnings.push("Local Docker observation unavailable; workload health is unknown.".into()); }
    for (resource, cluster) in [("nodes", true), ("deployments", false), ("daemonsets", false), ("jobs", false), ("cronjobs", false),
        ("services", false), ("ingresses", false), ("configmaps", false), ("secrets", false), ("persistentvolumeclaims", false), ("networkpolicies", false)] {
        if !can(resource, cluster) { warnings.push(format!("Not permitted to list {resource}; any displayed targets are references only.")); }
    }
    if can("nodes", true) {
        for n in w.nodes.values() {
            b.add("Node", "", &n.name, &format!("{:?}", n.status), "node heartbeat", vec![("API address".into(), n.address.clone()),
                ("Last heartbeat (Unix seconds)".into(), n.last_heartbeat.to_string())]);
        }
    }
    if can("configmaps", false) { for c in w.configmaps.values().filter(|c| scope(&c.namespace)) { b.add("ConfigMap", &c.namespace, &c.name, "Configured", "desired state; values excluded", vec![]); } }
    if can("secrets", false) { for c in w.secrets.values().filter(|c| scope(&c.namespace)) { b.add("Secret", &c.namespace, &c.name, "Configured", "desired state; values excluded", vec![]); } }
    if can("persistentvolumeclaims", false) { for c in w.pvcs.values().filter(|c| scope(&c.namespace)) {
        b.add("PVC", &c.namespace, &c.name, if c.bound_pv.is_some() { "Bound" } else { "Pending" }, "desired binding; not a durability check",
            vec![("Requested".into(), c.requested.clone()), ("Storage class".into(), c.storage_class.clone())]);
    } }
    let pods: Vec<_> = observations.iter().filter(|p| scope(&p.view.namespace)).collect();
    let mut signatures = BTreeMap::new();
    let mut conflicts = BTreeSet::new();
    for p in &pods {
        let v = &p.view;
        let key = id("Pod", &v.namespace, &v.pod);
        let signature = (&v.node, &v.image, v.running, v.ready);
        if let Some(old) = signatures.insert(key.clone(), signature) { if old != signature { conflicts.insert(key); } }
    }
    if !conflicts.is_empty() { warnings.push("Conflicting observations for duplicate pod identities; inspect placement edges and sources before treating replicas as healthy.".into()); }
    for d in w.deployments.values().filter(|d| scope(&d.namespace)) {
        let (kind, resource) = if d.stateful { ("StatefulSet", "statefulsets") } else { ("Deployment", "deployments") };
        if !can(resource, false) { continue; }
        let own: Vec<_> = pods.iter().filter(|p| p.view.namespace == d.namespace && p.view.kind == "deployment" && p.view.owner == d.name).collect();
        let conflict = own.iter().any(|p| conflicts.contains(&id("Pod", &p.view.namespace, &p.view.pod)));
        let ready = own.iter().filter(|p| p.view.ready && p.view.running && !conflicts.contains(&id("Pod", &p.view.namespace, &p.view.pod)))
            .map(|p| &p.view.pod).collect::<BTreeSet<_>>().len();
        b.add(kind, &d.namespace, &d.name, if conflict { "Conflict" } else if !local_ok { "Unknown" } else if ready == d.replicas as usize { "Ready" } else { "Degraded" }, "desired replicas compared with observed pods",
            vec![("Desired replicas".into(), d.replicas.to_string()), ("Observed ready".into(), ready.to_string())]);
    }
    for (kind, resource, values) in [
        ("DaemonSet", "daemonsets", w.daemonsets.values().map(|d| (&d.namespace, &d.name)).collect::<Vec<_>>()),
        ("Job", "jobs", w.jobs.values().map(|d| (&d.namespace, &d.name)).collect()),
        ("CronJob", "cronjobs", w.cronjobs.values().map(|d| (&d.namespace, &d.name)).collect()),
    ] { if can(resource, false) { for (namespace, name) in values.into_iter().filter(|(ns, _)| scope(ns)) { b.add(kind, namespace, name, "Configured", "desired controller; inspect pods for runtime state", vec![]); } } }
    if can("services", false) { for s in w.services.values().filter(|s| scope(&s.namespace)) {
        b.add("Service", &s.namespace, &s.name, "Configured", "desired service selector, not a traffic observation", vec![("Type".into(), s.service_type.clone()),
            ("Ports".into(), s.ports.iter().map(|p| format!("{} → {}", p.port, p.target_port)).collect::<Vec<_>>().join(", "))]);
    } }
    if can("ingresses", false) { for i in w.ingresses.values().filter(|i| scope(&i.namespace)) {
        b.add("Ingress", &i.namespace, &i.name, "Configured", "desired routing rules", vec![]);
    } }
    if can("networkpolicies", false) { for p in w.network_policies.values().filter(|p| scope(&p.namespace)) {
        b.add("NetworkPolicy", &p.namespace, &p.name, "Configured", "desired policy; not proof of rule activation or full Kubernetes enforcement",
            vec![("Pod selector".into(), p.pod_selector.clone()), ("Deny all".into(), p.deny_all.to_string())]);
    } }
    if can("horizontalpodautoscalers", false) { for h in w.hpas.values().filter(|h| scope(&h.namespace)) {
        b.add("HPA", &h.namespace, &h.name, "Configured", "desired autoscaling policy, not prediction",
            vec![("Replica bounds".into(), format!("{}–{}", h.min_replicas, h.max_replicas))]);
    } }
    for p in &pods {
        let v = &p.view;
        let pod_id = id("Pod", &v.namespace, &v.pod);
        let key = if conflicts.contains(&pod_id) {
            if let Some(existing) = b.nodes.get_mut(&pod_id) {
                existing.facts.push(("Conflicting observation".into(), format!("{} on {} ({}ms old)", p.source, v.node, p.age_ms)));
                pod_id
            } else {
                b.add("Pod", &v.namespace, &v.pod, "Conflict", "contradictory observations; not a healthy replica",
                    vec![("Observation".into(), format!("{} on {} ({}ms old)", p.source, v.node, p.age_ms))])
            }
        } else {
            b.add("Pod", &v.namespace, &v.pod, if !v.running { "Stopped" } else if v.ready { "Ready" } else { "NotReady" }, &p.source,
                vec![("Image".into(), v.image.clone()), ("Observation age (ms)".into(), p.age_ms.to_string())])
        };
        if !v.node.is_empty() {
            let to = b.reference("Node", "", &v.node, can("nodes", true));
            b.edge(key.clone(), to, "runs on", "observed placement");
        }
        let (kind, resource) = match v.kind.as_str() {
            "deployment" if can("statefulsets", false) && w.deployments.get(&crate::store::obj_key(&v.namespace, &v.owner)).map(|d| d.stateful).unwrap_or(false) => ("StatefulSet", "statefulsets"),
            "deployment" => ("Deployment", "deployments"), "daemonset" => ("DaemonSet", "daemonsets"), "job" => ("Job", "jobs"), "cronjob" => ("CronJob", "cronjobs"), _ => ("Workload", "deployments"),
        };
        if !v.owner.is_empty() {
            let owner = b.reference(kind, &v.namespace, &v.owner, can(resource, false));
            b.edge(owner, key, "owns", "observed Royak ownership labels");
        }
    }
    if can("ingresses", false) { for i in w.ingresses.values().filter(|i| scope(&i.namespace)) { for rule in &i.rules { for path in &rule.paths {
        let target = b.reference("Service", &i.namespace, &path.service, can("services", false));
        b.edge(id("Ingress", &i.namespace, &i.name), target, "routes to", &format!("desired {}{} → port {}", rule.host, path.path, path.port));
    } } } }
    if can("services", false) { for s in w.services.values().filter(|s| scope(&s.namespace)) {
        // Royak's current service resolver selects the app owner; do not invent
        // Kubernetes arbitrary-label-selector support in this diagnostic view.
        if let Some(app) = s.selector.get("app") { for p in &pods { if p.view.namespace == s.namespace && &p.view.owner == app {
            b.edge(id("Service", &s.namespace, &s.name), id("Pod", &p.view.namespace, &p.view.pod), "selects", "desired app selector matched to observed owner; not proof of traffic");
        } } }
    } }
    for d in w.deployments.values().filter(|d| scope(&d.namespace)) {
        let (kind, resource) = if d.stateful { ("StatefulSet", "statefulsets") } else { ("Deployment", "deployments") };
        if can(resource, false) { for c in d.containers.iter().chain(d.init_containers.iter()) { b.dependencies(&id(kind, &d.namespace, &d.name), &d.namespace, c, &can); } }
    }
    for (kind, resource, values) in [
        ("DaemonSet", "daemonsets", w.daemonsets.values().map(|d| (&d.namespace, &d.name, &d.container)).collect::<Vec<_>>()),
        ("Job", "jobs", w.jobs.values().map(|d| (&d.namespace, &d.name, &d.container)).collect()),
        ("CronJob", "cronjobs", w.cronjobs.values().map(|d| (&d.namespace, &d.name, &d.container)).collect()),
    ] { if can(resource, false) { for (namespace, name, c) in values.into_iter().filter(|(ns, _, _)| scope(ns)) { b.dependencies(&id(kind, namespace, name), namespace, c, &can); } } }
    if can("horizontalpodautoscalers", false) { for h in w.hpas.values().filter(|h| scope(&h.namespace)) {
        let to = b.reference("Deployment", &h.namespace, &h.deployment, can("deployments", false));
        b.edge(id("HPA", &h.namespace, &h.name), to, "scales", "desired target reference");
    } }
    Graph { schema_version: 1, generation: w.generation,
        observed_at_unix_ms: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis(),
        nodes: b.nodes.into_values().collect(), edges: b.edges.into_values().collect(), warnings,
        truncated: b.truncated, read_only: true }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn apply(w: &mut DesiredWorld, yaml: &str) {
        for resource in crate::spec::parse_yaml(yaml).unwrap() { w.apply(&resource).unwrap(); }
    }
    #[test]
    fn namespace_and_secret_values_never_leak() {
        let mut w = DesiredWorld::new();
        for ns in ["a", "b"] {
            apply(&mut w, &format!("kind: Deployment\nmetadata: {{name: same, namespace: {ns}}}\nspec:\n  template:\n    spec:\n      containers:\n      - name: c\n        image: alpine:3.22\n        envFrom: [{{secretRef: {{name: credentials}}}}]\n"));
            apply(&mut w, &format!("kind: Secret\nmetadata: {{name: credentials, namespace: {ns}}}\nstringData: {{password: DO_NOT_EXPORT_ME}}\n"));
        }
        let g = build(&w, &[], Some("a"), |r, _| r != "secrets", true);
        let raw = serde_json::to_string(&g).unwrap();
        assert!(!raw.contains("DO_NOT_EXPORT_ME"));
        assert!(g.nodes.iter().all(|n| n.namespace != "b"));
        assert_eq!(g.nodes.iter().find(|n| n.kind == "Secret").unwrap().status, "Unknown");
        assert!(g.edges.iter().all(|e| g.nodes.iter().any(|n| n.id == e.from) && g.nodes.iter().any(|n| n.id == e.to)));
        assert!(!serde_json::to_string(&build(&w, &[], None, |_, _| true, true)).unwrap().contains("DO_NOT_EXPORT_ME"));
    }
    #[test]
    fn unavailable_observation_is_not_healthy_empty_cluster() {
        let mut w = DesiredWorld::new();
        apply(&mut w, "kind: Deployment\nmetadata: {name: web}\nspec:\n  replicas: 0\n  template:\n    spec:\n      containers: [{name: c, image: 'alpine:3.22'}]\n");
        let g = build(&w, &[], None, |_, _| true, false);
        assert_eq!(g.nodes[0].status, "Unknown");
        assert!(g.warnings.iter().any(|s| s.contains("unavailable")));
    }
    #[test]
    fn observed_placement_and_missing_route_targets_are_explicit() {
        let mut w = DesiredWorld::new();
        w.ingresses.insert("a/web".into(), crate::reconcile::StoredIngress {
            name: "web".into(), namespace: "a".into(), ingress_class: None,
            rules: vec![crate::reconcile::IngressRule { host: "local.test".into(), paths: vec![crate::reconcile::IngressPath {
                path: "/".into(), service: "missing".into(), port: 8080,
            }] }],
        });
        let view = PodView { pod: "rk-a_web-1".into(), namespace: "a".into(), node: "worker-2".into(),
            kind: "deployment".into(), owner: "web".into(), template: "t".into(), image: "alpine:3.22".into(),
            running: true, ready: false, pending: false, published: None };
        let g = build(&w, &[Observation { view, source: "peer census".into(), age_ms: 4000 }], Some("a"), |r, _| r != "nodes", true);
        assert_eq!(g.nodes.iter().find(|n| n.kind == "Pod").unwrap().status, "NotReady");
        assert_eq!(g.nodes.iter().find(|n| n.kind == "Node").unwrap().status, "Unknown");
        assert_eq!(g.nodes.iter().find(|n| n.kind == "Service").unwrap().status, "Missing");
        assert!(g.edges.iter().any(|e| e.relation == "runs on" && e.evidence == "observed placement"));
        assert!(g.edges.iter().any(|e| e.relation == "routes to" && e.evidence.starts_with("desired")));
    }
    #[test]
    fn duplicate_identity_on_two_nodes_is_not_silently_overwritten() {
        let w = DesiredWorld::new();
        let one = PodView { pod: "same".into(), node: "a".into(), namespace: "lab".into(), kind: "deployment".into(), owner: "web".into(),
            template: "t".into(), image: "alpine:3.22".into(), running: true, ready: true, pending: false, published: None };
        let mut two = one.clone(); two.node = "b".into();
        let g = build(&w, &[Observation {view:one,source:"local".into(),age_ms:0},Observation {view:two,source:"peer".into(),age_ms:10}], None, |_,_|true, true);
        assert_eq!(g.nodes.iter().filter(|n| n.kind == "Pod").count(), 1);
        assert_eq!(g.nodes.iter().find(|n| n.kind == "Pod").unwrap().status, "Conflict");
        assert_eq!(g.edges.iter().filter(|e| e.relation == "runs on").count(), 2);
    }
}
