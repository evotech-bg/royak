//! The pod launch contract — the ONE way desired state becomes containers.
//!
//! `plan_pod` resolves everything a pod needs from desired state (on the
//! scheduler): image, command, env (including `envFrom` ConfigMaps/Secrets of
//! the pod's own namespace), resource limits, ConfigMap/Secret volumes (their
//! data is carried inside the plan), emptyDir, host-local volumes, DNS
//! aliases, pod identity. `launch_pod` turns that plan into containers on the
//! node that runs it. The local reconcile loop, the rolling-update path and the
//! remote `/royak/v1/create-pod` receiver all call the same two functions, so a
//! pod placed on a peer is the same pod it would have been locally.
//!
//! Host-local storage (hostPath, PersistentVolumeClaim, StatefulSet volume
//! claim templates) only exists on the node that has the directory. A plan that
//! needs it is marked `host_local` and is never placed on another node — Royak
//! has no distributed storage and does not pretend to.

use crate::docker;
use crate::reconcile::{DesiredWorld, PodCertStatus, ResourceLimits, StoredContainer};
use crate::store;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Where a mount's host side comes from.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum MountSource {
    /// A directory that exists only on the node that owns it.
    HostPath { path: String },
    /// Fresh per-pod scratch directory, created on the node that runs the pod.
    EmptyDir { name: String },
    /// ConfigMap/Secret projected as files; the data travels with the plan.
    Projected { name: String, secret: bool, files: BTreeMap<String, String> },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MountLaunch {
    pub source: MountSource,
    pub container_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ContainerLaunch {
    /// Name inside the pod (the manifest's container name).
    pub name: String,
    /// Docker container name.
    pub docker_name: String,
    pub image: String,
    pub command: Option<Vec<String>>,
    /// Fully resolved environment.
    pub env: Vec<String>,
    pub mounts: Vec<MountLaunch>,
    pub cpu_limit: Option<f32>,
    pub mem_limit_mb: Option<u64>,
    /// Container ports published to ephemeral host ports (NodePort/LB).
    pub publish: Vec<u16>,
    /// "main", "sidecar" or "init".
    pub role: String,
}

/// Everything needed to start one pod, independent of the node that runs it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PodLaunch {
    pub cluster_id: String,
    /// Node that will run the pod (the receiver of a remote plan overrides it
    /// with its own name — a node only ever labels pods as its own).
    pub node: String,
    pub namespace: String,
    /// "deployment", "daemonset", "job" or "cronjob".
    pub kind: String,
    pub owner: String,
    pub pod: String,
    pub ordinal: Option<u32>,
    /// Pod template hash; pods whose hash differs from the current one are
    /// replaced by a rolling update.
    pub template: String,
    /// Desired-state generation the plan was made from. A node only
    /// garbage-collects an ownerless pod once its own state is at least this
    /// new (so a pod created by a leader that is ahead is not killed early).
    pub generation: u64,
    pub init_containers: Vec<ContainerLaunch>,
    pub containers: Vec<ContainerLaunch>,
    /// DNS aliases of the main container on the namespace network.
    pub aliases: Vec<String>,
    pub host_local: bool,
}

/// What to plan: one pod of a workload.
pub struct PodSource<'a> {
    pub kind: &'a str,
    pub namespace: &'a str,
    pub owner: &'a str,
    pub init_containers: &'a [StoredContainer],
    pub containers: &'a [StoredContainer],
    pub limits: Option<&'a ResourceLimits>,
    pub restart_nonce: u64,
}

/// Owner label for each workload kind.
pub fn owner_label(kind: &str) -> &'static str {
    match kind {
        "daemonset" => "royak.daemonset",
        "job" => "royak.job",
        "cronjob" => "royak.cronjob",
        _ => store::LABEL_DEPLOYMENT,
    }
}

pub const LABEL_TEMPLATE: &str = "royak.template";
pub const LABEL_GENERATION: &str = "royak.generation";
pub const LABEL_ORDINAL: &str = "royak.ordinal";

/// Stable hash of everything that defines a pod. A change (image, env,
/// command, volumes, limits, restart nonce) means existing pods are out of
/// date and get rolled.
pub fn template_hash(src: &PodSource) -> String {
    use sha2::{Digest, Sha256};
    let canon = serde_json::json!({
        "init": src.init_containers,
        "containers": src.containers,
        "limits": src.limits,
        "nonce": src.restart_nonce,
    });
    let digest = Sha256::digest(canon.to_string().as_bytes());
    digest.iter().take(6).map(|b| format!("{b:02x}")).collect()
}

/// True if the pod needs storage that only exists on this node.
pub fn needs_host_local(containers: &[StoredContainer], init: &[StoredContainer]) -> bool {
    containers.iter().chain(init.iter()).any(|c| c.volumes.iter().any(|(h, _)| {
        !(h.starts_with("cmv:") || h.starts_with("sev:") || h.starts_with("emptydir:"))
    }))
}

/// Resolve a pod plan from desired state.
pub fn plan_pod(
    world: &mut DesiredWorld,
    src: &PodSource,
    pod: &str,
    ordinal: Option<u32>,
    node: &str,
) -> Result<PodLaunch, String> {
    let ns = src.namespace;
    let mut identity_env = vec![
        format!("ROYAK_POD_NAME={pod}"),
        format!("ROYAK_NAMESPACE={ns}"),
    ];
    if src.kind == "deployment" {
        identity_env.push(format!("ROYAK_DEPLOYMENT={}", src.owner));
    } else {
        identity_env.push(format!("ROYAK_OWNER={}/{}", src.kind, src.owner));
    }

    // Pod identity: one mTLS certificate per pod, shared by its containers.
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    match world.cluster_ca.as_mut().map(|ca| (ca.issue_pod_cert(pod, ns), ca.issued_count)) {
        Some((Ok(identity), issued)) => {
            identity_env.extend(identity.env_vars());
            world.pod_certs.insert(pod.to_string(), PodCertStatus {
                pod_name: pod.to_string(),
                namespace: ns.to_string(),
                issued_at: now,
                expires_at: now + 90 * 86400,
                fingerprint: format!("{issued:x}"),
                revoked: false,
            });
        }
        _ => {
            let token = crate::net_security::generate_pod_token(pod, ns, "cluster");
            identity_env.push(format!("ROYAK_POD_TOKEN={token}"));
        }
    }

    let template = template_hash(src);
    let publish_main = if src.kind == "deployment" { world.nodeport_publish_ports(ns, src.owner) } else { Vec::new() };
    let cpu = src.limits.and_then(|r| r.cpu_limit);
    let mem = src.limits.and_then(|r| r.mem_limit);

    let mut host_local = false;
    let mut plan_container = |c: &StoredContainer, role: &str, docker_name: String| -> Result<ContainerLaunch, String> {
        let mut env = c.env.clone();
        for cm in &c.env_from_configmaps {
            let data = &world.configmaps.get(&store::obj_key(ns, cm))
                .ok_or_else(|| format!("envFrom: configmap {cm:?} not found in namespace {ns:?}"))?.data;
            let mut kv: Vec<_> = data.iter().collect();
            kv.sort();
            env.extend(kv.into_iter().map(|(k, v)| format!("{k}={v}")));
        }
        for s in &c.env_from_secrets {
            let data = &world.secrets.get(&store::obj_key(ns, s))
                .ok_or_else(|| format!("envFrom: secret {s:?} not found in namespace {ns:?}"))?.data;
            let mut kv: Vec<_> = data.iter().collect();
            kv.sort();
            env.extend(kv.into_iter().map(|(k, v)| format!("{k}={v}")));
        }
        for r in &c.env_refs {
            let data = if r.secret {
                world.secrets.get(&store::obj_key(ns, &r.object)).map(|s| &s.data)
            } else {
                world.configmaps.get(&store::obj_key(ns, &r.object)).map(|m| &m.data)
            };
            let kind = if r.secret { "secret" } else { "configmap" };
            match data.and_then(|d| d.get(&r.key)) {
                Some(v) => env.push(format!("{}={v}", r.name)),
                None if r.optional => {}
                None => return Err(format!("env {}: {kind} {:?} key {:?} not found in namespace {ns:?}", r.name, r.object, r.key)),
            }
        }
        env.extend(identity_env.iter().cloned());
        env.push(format!("ROYAK_CONTAINER={}", c.name));

        let mut mounts = Vec::new();
        for (host, cpath) in &c.volumes {
            let source = if let Some(n) = host.strip_prefix("cmv:") {
                let cm = world.configmaps.get(&store::obj_key(ns, n))
                    .ok_or_else(|| format!("volume: configmap {n:?} not found in namespace {ns:?}"))?;
                MountSource::Projected { name: n.to_string(), secret: false, files: cm.data.iter().map(|(k, v)| (k.clone(), v.clone())).collect() }
            } else if let Some(n) = host.strip_prefix("sev:") {
                let s = world.secrets.get(&store::obj_key(ns, n))
                    .ok_or_else(|| format!("volume: secret {n:?} not found in namespace {ns:?}"))?;
                MountSource::Projected { name: n.to_string(), secret: true, files: s.data.iter().map(|(k, v)| (k.clone(), v.clone())).collect() }
            } else if let Some(n) = host.strip_prefix("emptydir:") {
                MountSource::EmptyDir { name: n.to_string() }
            } else if let Some(claim) = host.strip_prefix("pvc:") {
                let pvc = world.pvcs.get(&store::obj_key(ns, claim))
                    .ok_or_else(|| format!("volume: persistentvolumeclaim {claim:?} not found in namespace {ns:?}"))?;
                let pv_name = pvc.bound_pv.as_ref()
                    .ok_or_else(|| format!("volume: persistentvolumeclaim {claim:?} is not bound"))?;
                let pv = world.pvs.get(pv_name).ok_or_else(|| format!("volume: pv {pv_name:?} missing"))?;
                host_local = true;
                MountSource::HostPath { path: pv.host_path.clone() }
            } else if let Some(tpl) = host.strip_prefix("vct:") {
                let ord = ordinal.ok_or("volumeClaimTemplate used outside a StatefulSet")?;
                host_local = true;
                MountSource::HostPath { path: format!("{}/pvc/{ns}/{}-{tpl}-{ord}", crate::reconcile::royak_data_dir(), src.owner) }
            } else {
                if !crate::reconcile::validate_path(host) {
                    return Err(format!("volume: unsafe host path {host:?}"));
                }
                host_local = true;
                MountSource::HostPath { path: host.clone() }
            };
            mounts.push(MountLaunch { source, container_path: cpath.clone() });
        }
        Ok(ContainerLaunch {
            name: c.name.clone(),
            docker_name,
            image: c.image.clone(),
            command: c.command.clone(),
            env,
            mounts,
            cpu_limit: cpu,
            mem_limit_mb: mem,
            publish: if role == "main" { publish_main.clone() } else { Vec::new() },
            role: role.to_string(),
        })
    };

    let mut init_containers = Vec::new();
    for c in src.init_containers {
        init_containers.push(plan_container(c, "init", format!("{pod}-init-{}", c.name))?);
    }
    let mut containers = Vec::new();
    for (i, c) in src.containers.iter().enumerate() {
        let (role, dn) = if i == 0 { ("main", pod.to_string()) } else { ("sidecar", format!("{pod}-{}", c.name)) };
        containers.push(plan_container(c, role, dn)?);
    }
    if containers.is_empty() {
        return Err("pod has no containers".to_string());
    }

    let mut aliases = vec![pod.to_string()];
    if src.kind == "deployment" || src.kind == "daemonset" {
        aliases.push(src.owner.to_string());
    }
    if src.kind == "deployment" {
        let mut svc: Vec<String> = world.services.values()
            .filter(|s| s.namespace == ns && s.selector.get("app").map(|a| a.as_str()) == Some(src.owner))
            .map(|s| s.name.clone()).collect();
        svc.sort();
        aliases.extend(svc);
    }

    Ok(PodLaunch {
        cluster_id: world.cluster_id.clone(),
        node: node.to_string(),
        namespace: ns.to_string(),
        kind: src.kind.to_string(),
        owner: src.owner.to_string(),
        pod: pod.to_string(),
        ordinal,
        template,
        generation: world.generation,
        init_containers,
        containers,
        aliases,
        host_local,
    })
}

/// Per-pod scratch directory on the node running the pod.
pub fn pod_dir(ns: &str, pod: &str) -> String {
    format!("{}/pods/{ns}/{pod}", crate::reconcile::royak_data_dir())
}

fn labels_for(l: &PodLaunch, role: &str) -> Vec<(String, String)> {
    let mut v = vec![
        (store::LABEL_MANAGED.to_string(), "true".to_string()),
        (store::LABEL_CLUSTER.to_string(), l.cluster_id.clone()),
        (store::LABEL_NODE.to_string(), l.node.clone()),
        (store::LABEL_NAMESPACE.to_string(), l.namespace.clone()),
        (owner_label(&l.kind).to_string(), l.owner.clone()),
        (store::LABEL_POD.to_string(), l.pod.clone()),
        (store::LABEL_ROLE.to_string(), role.to_string()),
        (LABEL_TEMPLATE.to_string(), l.template.clone()),
        (LABEL_GENERATION.to_string(), l.generation.to_string()),
        ("app".to_string(), l.owner.clone()),
    ];
    if let Some(o) = l.ordinal { v.push((LABEL_ORDINAL.to_string(), o.to_string())); }
    v
}

fn materialize(l: &PodLaunch, c: &ContainerLaunch) -> Result<Vec<(String, String)>, String> {
    let mut binds = Vec::new();
    let pdir = pod_dir(&l.namespace, &l.pod);
    for m in &c.mounts {
        let host = match &m.source {
            MountSource::HostPath { path } => {
                if path.starts_with(&crate::reconcile::royak_data_dir()) {
                    std::fs::create_dir_all(path).map_err(|e| format!("create {path}: {e}"))?;
                }
                path.clone()
            }
            MountSource::EmptyDir { name } => {
                let d = format!("{pdir}/empty-{name}");
                std::fs::create_dir_all(&d).map_err(|e| format!("create {d}: {e}"))?;
                d
            }
            MountSource::Projected { name, secret, files } => {
                let d = format!("{pdir}/{}-{name}", if *secret { "secret" } else { "configmap" });
                let _ = std::fs::remove_dir_all(&d); // stale keys must not survive
                std::fs::create_dir_all(&d).map_err(|e| format!("create {d}: {e}"))?;
                for (k, v) in files {
                    if k.contains('/') || k.contains("..") || k.is_empty() {
                        return Err(format!("projected key {k:?} is not a valid file name"));
                    }
                    let f = format!("{d}/{k}");
                    std::fs::write(&f, v).map_err(|e| format!("write {f}: {e}"))?;
                    #[cfg(unix)]
                    if *secret {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).ok();
                    }
                }
                d
            }
        };
        binds.push((host, m.container_path.clone()));
    }
    Ok(binds)
}

fn create_one(l: &PodLaunch, c: &ContainerLaunch) -> Result<String, String> {
    let binds = materialize(l, c)?;
    let labels = labels_for(l, &c.role);
    let label_refs: Vec<(&str, &str)> = labels.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let cmd: Option<Vec<&str>> = c.command.as_ref().filter(|c| !c.is_empty()).map(|c| c.iter().map(|s| s.as_str()).collect());
    docker::create_container_full(&c.docker_name, &c.image, cmd.as_deref(), &c.env, &label_refs,
        &binds, c.cpu_limit, c.mem_limit_mb, &c.publish)
}

/// Start the pod described by `l` on this node's Docker. All-or-nothing: on
/// any failure every container created for the pod is removed again and the
/// error is returned.
pub fn launch_pod(l: &PodLaunch) -> Result<(), String> {
    // 1. Images must be present. Missing ones are pulled in the background
    //    (this runs under the desired-state lock — it must never wait for a
    //    registry); the pod is created on a later tick once they are here. A
    //    failed pull is a clear, reported failure — never a half-created pod.
    let mut seen = std::collections::HashSet::new();
    for c in l.init_containers.iter().chain(l.containers.iter()) {
        if seen.insert(c.image.clone()) {
            match docker::ensure_image_nonblocking(&c.image) {
                docker::ImageState::Present => {}
                docker::ImageState::Pulling => return Err(format!("image {:?} is being pulled on node {}; the pod starts once it is present", c.image, l.node)),
                docker::ImageState::Failed(e) => return Err(format!("image {:?} unavailable on node {}: {e}", c.image, l.node)),
            }
        }
    }
    let net = docker::ensure_namespace_network(&l.namespace)?;

    // 2. Init containers, in order, each must exit 0. Every container joins
    //    the namespace network BEFORE it starts, so its DNS works from the
    //    first instruction and a fast-exiting container never races the connect.
    for c in &l.init_containers {
        let id = create_one(l, c)?;
        let res = (|| {
            docker::connect_to_network_checked(&id, &net, &[c.docker_name.as_str()])?;
            docker::start_container_checked(&id)?;
            let started = std::time::Instant::now();
            loop {
                if let Some(code) = docker::container_exit_code(&id) {
                    if code == 0 { return Ok(()); }
                    return Err(format!("init container {} exited with code {code}", c.name));
                }
                if started.elapsed() > std::time::Duration::from_secs(120) {
                    return Err(format!("init container {} timed out", c.name));
                }
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
        })();
        docker::remove_container(&id, true).ok();
        res?;
    }

    // 3. Main + sidecars: create all, attach, then start.
    let mut created: Vec<String> = Vec::new();
    let res = (|| {
        for c in &l.containers {
            let id = create_one(l, c)?;
            created.push(id.clone());
            let aliases: Vec<&str> = if c.role == "main" {
                l.aliases.iter().map(|s| s.as_str()).collect()
            } else {
                vec![c.docker_name.as_str()]
            };
            docker::connect_to_network_checked(&id, &net, &aliases)?;
        }
        for id in &created {
            docker::start_container_checked(id)?;
        }
        Ok::<(), String>(())
    })();
    if let Err(e) = res {
        for id in &created { docker::remove_container(id, true).ok(); }
        return Err(e);
    }
    Ok(())
}

/// Remove every container of a pod (main, sidecars, leftover init) and its
/// scratch directory.
pub fn remove_pod(ours: &[&docker::DockerContainer], ns: &str, pod: &str) {
    for c in ours.iter().filter(|c| c.labels.get(store::LABEL_POD).map(|p| p == pod).unwrap_or(false)
        && c.labels.get(store::LABEL_NAMESPACE).map(|n| n.as_str()).unwrap_or(store::DEFAULT_NS) == ns)
    {
        docker::stop_container(&c.id).ok();
        docker::remove_container(&c.id, true).ok();
    }
    let _ = std::fs::remove_dir_all(pod_dir(ns, pod));
}

/// This node's pods (main containers) as census entries.
pub fn local_pod_views(ours: &[&docker::DockerContainer], node: &str, known_default_deployments: &[&str]) -> Vec<crate::placement::PodView> {
    let mut out = Vec::new();
    for c in ours {
        let role = c.labels.get(store::LABEL_ROLE).map(|s| s.as_str()).unwrap_or("main");
        if role != "main" || c.labels.contains_key("royak.init") { continue; }
        let name = c.names.first().map(|n| n.trim_start_matches('/').to_string()).unwrap_or_default();
        let (kind, owner) = if let Some(d) = c.labels.get(store::LABEL_DEPLOYMENT) {
            ("deployment", d.clone())
        } else if let Some(d) = c.labels.get("royak.daemonset") {
            ("daemonset", d.clone())
        } else if let Some(d) = c.labels.get("royak.job") {
            ("job", d.clone())
        } else if let Some(d) = c.labels.get("royak.cronjob") {
            ("cronjob", d.clone())
        } else if let Some(o) = store::pod_owner(c, known_default_deployments) {
            ("deployment", o.deployment)
        } else {
            continue;
        };
        out.push(crate::placement::PodView {
            pod: c.labels.get(store::LABEL_POD).cloned().unwrap_or(name),
            node: node.to_string(),
            namespace: c.labels.get(store::LABEL_NAMESPACE).cloned().unwrap_or_else(|| store::DEFAULT_NS.to_string()),
            kind: kind.to_string(),
            owner,
            template: c.labels.get(LABEL_TEMPLATE).cloned().unwrap_or_default(),
            image: c.image.clone(),
            running: c.state == "running",
            ready: c.state == "running",
            pending: false,
        });
    }
    out
}

// ─── Transport (remote placement) ──────────────────────────────────────────

/// Seal a plan for transport to a peer: the plan carries resolved Secret
/// values, so it is encrypted (AES-256-GCM, key derived from the cluster
/// secret) in addition to the request being HMAC-signed.
pub fn seal_launch(l: &PodLaunch) -> Result<String, String> {
    let json = serde_json::to_vec(l).map_err(|e| e.to_string())?;
    crate::auth::seal_for_cluster(b"royak-pod-launch-v1", &json)
}

pub fn unseal_launch(sealed: &str) -> Result<PodLaunch, String> {
    let bytes = crate::auth::unseal_for_cluster(b"royak-pod-launch-v1", sealed)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("bad pod plan: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn world_with(yaml: &str) -> DesiredWorld {
        let mut w = DesiredWorld::new();
        for r in crate::spec::parse_yaml(yaml).unwrap() { w.apply(&r).unwrap(); }
        w
    }

    const TWO_NS: &str = r#"
apiVersion: v1
kind: ConfigMap
metadata: {name: cfg, namespace: a}
data: {COLOR: red}
---
apiVersion: v1
kind: ConfigMap
metadata: {name: cfg, namespace: b}
data: {COLOR: blue}
---
apiVersion: v1
kind: Secret
metadata: {name: sec, namespace: a}
stringData: {PASSWORD: pa}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: a}
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: c
        image: busybox:1.36
        command: ["sh", "-c", "sleep 3600"]
        env: [{name: K, value: v}]
        envFrom: [{configMapRef: {name: cfg}}, {secretRef: {name: sec}}]
        resources: {limits: {cpu: "250m", memory: "64Mi"}}
        volumeMounts: [{name: conf, mountPath: /etc/conf}, {name: scratch, mountPath: /scratch}]
      volumes:
      - {name: conf, configMap: {name: cfg}}
      - {name: scratch, emptyDir: {}}
"#;

    #[test]
    fn args_and_env_key_refs_travel_in_the_plan() {
        let yaml = r#"
apiVersion: v1
kind: ConfigMap
metadata: {name: cfg, namespace: a}
data: {GREETING: hi}
---
apiVersion: v1
kind: Secret
metadata: {name: sec, namespace: a}
stringData: {TOKEN: t0k}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: web, namespace: a}
spec:
  replicas: 1
  template:
    spec:
      containers:
      - name: c
        image: alpine:3.22
        command: ["/bin/sh", "-c"]
        args: ["echo $GREETING"]
        env:
        - {name: MODE, value: lit}
        - {name: GREETING, valueFrom: {configMapKeyRef: {name: cfg, key: GREETING}}}
        - {name: TOKEN, valueFrom: {secretKeyRef: {name: sec, key: TOKEN}}}
        - {name: OPT, valueFrom: {configMapKeyRef: {name: cfg, key: NOPE, optional: true}}}
"#;
        let mut w = world_with(yaml);
        let dep = w.deployments["a/web"].clone();
        let src = PodSource { kind: "deployment", namespace: "a", owner: "web",
            init_containers: &dep.init_containers, containers: &dep.containers,
            limits: dep.resource_limits.as_ref(), restart_nonce: dep.restart_nonce };
        let p = plan_pod(&mut w, &src, "rk-a_web-1", None, "n1").unwrap();
        let c = &p.containers[0];
        assert_eq!(c.command.as_deref(), Some(&["/bin/sh".to_string(), "-c".into(), "echo $GREETING".into()][..]));
        for want in ["MODE=lit", "GREETING=hi", "TOKEN=t0k"] {
            assert!(c.env.contains(&want.to_string()), "missing {want}: {:?}", c.env);
        }
        assert!(!c.env.iter().any(|e| e.starts_with("OPT=")), "optional missing key is skipped");

        // A required key that does not exist refuses the plan (no half-configured pod).
        w.configmaps.get_mut("a/cfg").unwrap().data.remove("GREETING");
        let e = plan_pod(&mut w, &src, "rk-a_web-1", None, "n1").unwrap_err();
        assert!(e.contains("GREETING"), "{e}");
    }

    #[test]
    fn containers_without_key_refs_keep_their_template_hash_shape() {
        let w = world_with(TWO_NS);
        let json = serde_json::to_string(&w.deployments["a/web"].containers[0]).unwrap();
        assert!(!json.contains("env_refs"), "empty env_refs must not change existing template hashes");
    }

    #[test]
    fn plan_resolves_the_full_contract_from_the_pods_namespace() {
        let mut w = world_with(TWO_NS);
        let dep = w.deployments["a/web"].clone();
        let src = PodSource { kind: "deployment", namespace: "a", owner: "web",
            init_containers: &dep.init_containers, containers: &dep.containers,
            limits: dep.resource_limits.as_ref(), restart_nonce: dep.restart_nonce };
        let p = plan_pod(&mut w, &src, "rk-a_web-1", None, "n1").unwrap();
        let c = &p.containers[0];
        assert_eq!(c.command.as_deref(), Some(&["sh".to_string(), "-c".into(), "sleep 3600".into()][..]));
        assert!(c.env.contains(&"K=v".to_string()));
        assert!(c.env.contains(&"COLOR=red".to_string()), "envFrom resolves ns a's configmap, not ns b's");
        assert!(!c.env.contains(&"COLOR=blue".to_string()));
        assert!(c.env.contains(&"PASSWORD=pa".to_string()));
        assert!(c.env.contains(&"ROYAK_NAMESPACE=a".to_string()));
        assert_eq!(c.cpu_limit, Some(0.25));
        assert_eq!(c.mem_limit_mb, Some(64));
        assert!(matches!(&c.mounts[0].source, MountSource::Projected { files, .. } if files.get("COLOR").map(|s| s.as_str()) == Some("red")));
        assert!(matches!(&c.mounts[1].source, MountSource::EmptyDir { .. }));
        assert!(!p.host_local, "configmap + emptyDir pods may run on any node");
        assert_eq!(p.namespace, "a");
        assert!(p.aliases.contains(&"web".to_string()));
    }

    #[test]
    fn missing_reference_fails_instead_of_starting_a_broken_pod() {
        let mut w = world_with(TWO_NS);
        w.secrets.remove("a/sec");
        let dep = w.deployments["a/web"].clone();
        let src = PodSource { kind: "deployment", namespace: "a", owner: "web",
            init_containers: &dep.init_containers, containers: &dep.containers,
            limits: dep.resource_limits.as_ref(), restart_nonce: 0 };
        let e = plan_pod(&mut w, &src, "rk-a_web-1", None, "n1").unwrap_err();
        assert!(e.contains("secret \"sec\" not found in namespace \"a\""), "{e}");
    }

    #[test]
    fn host_paths_and_claims_are_host_local() {
        let mut w = world_with(r#"
apiVersion: apps/v1
kind: Deployment
metadata: {name: db}
spec:
  template:
    spec:
      containers:
      - {name: c, image: busybox:1.36, volumeMounts: [{name: d, mountPath: /d}]}
      volumes:
      - {name: d, hostPath: {path: /srv/data}}
"#);
        let dep = w.deployments["default/db"].clone();
        assert!(needs_host_local(&dep.containers, &dep.init_containers));
        let src = PodSource { kind: "deployment", namespace: "default", owner: "db",
            init_containers: &dep.init_containers, containers: &dep.containers, limits: None, restart_nonce: 0 };
        assert!(plan_pod(&mut w, &src, "rk-db-1", None, "n1").unwrap().host_local);
    }

    #[test]
    fn template_hash_changes_with_spec_and_nonce_only() {
        let w = world_with(TWO_NS);
        let dep = w.deployments["a/web"].clone();
        let mk = |nonce| PodSource { kind: "deployment", namespace: "a", owner: "web",
            init_containers: &dep.init_containers, containers: &dep.containers,
            limits: dep.resource_limits.as_ref(), restart_nonce: nonce };
        assert_eq!(template_hash(&mk(0)), template_hash(&mk(0)));
        assert_ne!(template_hash(&mk(0)), template_hash(&mk(1)));
        let mut changed = dep.containers.clone();
        changed[0].image = "busybox:1.37".into();
        let src2 = PodSource { containers: &changed, ..mk(0) };
        assert_ne!(template_hash(&mk(0)), template_hash(&src2));
    }

    #[test]
    fn configmap_change_bumps_only_consumers_in_the_same_namespace() {
        let mut w = world_with(TWO_NS);
        let before = w.deployments["a/web"].restart_nonce;
        for r in crate::spec::parse_yaml("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cfg, namespace: b}\ndata: {COLOR: green}\n").unwrap() {
            w.apply(&r).unwrap();
        }
        assert_eq!(w.deployments["a/web"].restart_nonce, before, "ns b configmap change must not restart ns a pods");
        for r in crate::spec::parse_yaml("apiVersion: v1\nkind: ConfigMap\nmetadata: {name: cfg, namespace: a}\ndata: {COLOR: green}\n").unwrap() {
            w.apply(&r).unwrap();
        }
        assert_eq!(w.deployments["a/web"].restart_nonce, before + 1);
    }
}
