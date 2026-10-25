//! Royak — AI-first container orchestrator.
//!
//! Usage:
//!   royak apply deployment.yaml    # deploy containers
//!   royak get pods                 # list managed containers
//!   royak get nodes                # node info
//!   royak delete deployment/web    # remove deployment
//!   royak brain                    # neural brain stats
//!   royak watch                    # reconcile loop (like controller-manager)
//!   royak demo                     # simulated demo

mod brain;
mod docker;
mod spec;
mod reconcile;
mod api;
mod runtime;
mod neural_state;
mod net_security;
mod microvm;
mod cluster_mesh;
mod mesh_crypto;
mod consensus;
mod raft_node;
mod servicelb;
mod flows;
mod store;
mod placement;
mod workload;
mod auth;
mod persist;
mod node_rpc;

use brain::OrinBrain;
use reconcile::DesiredWorld;
use clap::{Parser, Subcommand};
use std::sync::{Arc, RwLock};

#[derive(Parser)]
#[command(name = "royak")]
#[command(about = "Container orchestrator — one tiny binary, zero etcd (BETA)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Apply a resource spec (Deployment, Service, etc.)
    Apply { file: String },
    /// Get resources (get pods, get deployments, get deployment/web -o yaml)
    Get {
        resource: String,
        /// Output format: table (default), yaml, json
        #[arg(short, long, default_value = "table")]
        output: String,
    },
    /// Delete a resource (deployment/x, configmap/x, secret/x, namespace/x)
    Delete {
        /// Resource like deployment/web, namespace/production, or -f file.yaml
        resource: String,
    },
    /// Show neural brain stats
    Brain,
    /// Start reconcile loop (watches and fixes cluster state)
    Watch {
        #[arg(long, default_value = "5")]
        interval: u64,
        /// Enable UDP autodiscovery (nodes find each other automatically)
        #[arg(long)]
        discover: bool,
        /// Enable HTTPS with auto-generated self-signed certificate
        #[arg(long)]
        tls: bool,
        /// Runtime: "docker" (default) or "neuropod" (no Docker needed)
        #[arg(long, default_value = "docker")]
        runtime: String,
        /// Override API port (otherwise read from cluster config, default 6443)
        #[arg(long)]
        port: Option<u16>,
        /// Ingress controller port (default 80/443 with --tls; override to
        /// avoid root privileges for non-privileged testing). 0 disables.
        #[arg(long)]
        ingress_port: Option<u16>,
        /// This node's Raft id (enables consensus mode; requires --peers)
        #[arg(long)]
        node_id: Option<u64>,
        /// Peer raft nodes as id@host:port, comma-separated (e.g. 2@127.0.0.1:6444,3@127.0.0.1:6445)
        #[arg(long, default_value = "")]
        peers: String,
        /// Initialise the cluster from this node (run on exactly one node)
        #[arg(long)]
        bootstrap: bool,
    },
    /// Show logs for a pod (or --all for all pods, --deployment for deployment)
    Logs {
        /// Pod name, "all", or deployment name (omit to list pods)
        pod: Option<String>,
        #[arg(long, default_value = "20")]
        tail: u32,
        /// Show stderr only
        #[arg(long)]
        stderr: bool,
    },
    /// Forward a local port to a pod port (like kubectl port-forward)
    PortForward {
        /// Pod name (rk-<deployment>-<n>)
        pod: String,
        /// Port mapping local:remote (e.g. 8080:80)
        ports: String,
    },
    /// Show observed traffic flows (queries a running `royak api`)
    Flows {
        /// API server to query
        #[arg(long, default_value = "http://localhost:6443")]
        server: String,
        /// Show top-talkers summary instead of the flow list
        #[arg(long)]
        top: bool,
    },
    /// Wake a paused/hibernated deployment
    Wake {
        /// deployment name
        deployment: String,
    },
    /// Scale a deployment
    Scale {
        /// deployment/name
        deployment: String,
        /// Number of replicas
        replicas: u32,
    },
    /// Pipeline operations (run, status, list)
    Pipeline {
        #[command(subcommand)]
        action: PipelineAction,
    },
    /// Ask the AI about your cluster (Ollama LLM integration)
    Ask {
        /// Question in natural language
        question: Vec<String>,
        /// Ollama host
        #[arg(long, default_value = "http://10.77.0.1:11434")]
        ollama: String,
        /// Model
        #[arg(long, default_value = "qwen2.5:32b")]
        model: String,
    },
    /// Invoke a serverless function
    Invoke {
        /// Function name
        name: String,
    },
    /// List functions
    Functions,
    /// Node operations (join, list, drain)
    Node {
        #[command(subcommand)]
        action: NodeAction,
    },
    /// Start K8s-compatible API server (kubectl/k9s work against this)
    Api {
        #[arg(long, default_value = "6443")]
        port: u16,
    },
    /// Repository operations (add, list, remove)
    Repo {
        #[command(subcommand)]
        action: RepoAction,
    },
    /// Rollback a deployment to its previous image
    Rollback { deployment: String },
    /// Backup cluster state to file
    Backup {
        #[arg(default_value = "royak-backup.json")]
        file: String,
    },
    /// Restore cluster state from backup
    Restore { file: String },
    /// Run simulated demo
    Demo,
    /// Pull an OCI image (test light runtime)
    Pull {
        image: String,
        #[arg(long, default_value = "docker")]
        runtime: String,
    },
    /// Start the mesh proxy (cross-node service routing — v0.3 MVP)
    Mesh {
        #[arg(long, default_value_t = cluster_mesh::DEFAULT_MESH_PORT)]
        port: u16,
    },
}

#[derive(Subcommand)]
enum NodeAction {
    /// Join an existing cluster
    Join {
        /// Address of existing node (ip:port)
        peer: String,
        /// Local API port
        #[arg(long, default_value = "6443")]
        port: u16,
    },
    /// List cluster nodes
    List,
    /// Drain a node (move all pods off, mark unschedulable)
    Drain { name: String },
}

#[derive(Subcommand)]
enum RepoAction {
    /// Register a git repository
    Add {
        /// Repository name
        name: String,
        /// Path (local) or URL (remote)
        source: String,
        /// Branch to watch
        #[arg(long, default_value = "main")]
        branch: String,
        /// Pipeline to auto-trigger on new commits
        #[arg(long)]
        pipeline: Option<String>,
    },
    /// List registered repositories
    List,
    /// Remove a repository
    Remove { name: String },
}

#[derive(Subcommand)]
enum PipelineAction {
    /// Run a pipeline
    Run { name: String },
    /// Show pipeline run status
    Status,
    /// List defined pipelines
    List,
}

fn main() {
    env_logger::init();
    // Two rustls crypto backends end up in the dependency graph (ring, and
    // aws-lc-rs via tokio-rustls defaults); without an explicit choice the
    // first TLS handshake panics. Royak uses ring.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Optional: redirect output to log file (set ROYAK_LOG=/var/log/royak.log)
    if let Ok(log_path) = std::env::var("ROYAK_LOG") {
        if !log_path.is_empty() {
            if let Ok(file) = std::fs::OpenOptions::new().create(true).append(true).open(&log_path) {
                // Redirect stderr to log file (reconcile loop output goes to stderr)
                #[cfg(unix)]
                {
                    use std::os::unix::io::AsRawFd;
                    unsafe { libc::dup2(file.as_raw_fd(), 2); } // stderr → file
                }
                eprintln!("── Royak started at {} ──",
                    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs().to_string()).unwrap_or_default());
            }
        }
    }

    let cli = Cli::parse();

    println!("╔══════════════════════════════════════════════════╗");
    println!("║  Royak v0.4-beta — Container Orchestrator        ║");
    println!("║  A swarm of containers. One tiny binary.         ║");
    println!("╚══════════════════════════════════════════════════╝");

    // Check Docker (skip for NeuroPod-only commands or --runtime neuropod).
    // Mesh command uses docker::container_ip to resolve local pods, so it
    // needs the daemon, but we don't make that check blocking here — the
    // proxy will just return 502 if container_ip fails.
    let skip_docker = matches!(cli.command, Commands::Demo | Commands::Brain)
        || matches!(&cli.command, Commands::Watch { runtime, .. } if runtime == "neuropod")
        || std::env::var("ROYAK_NO_DOCKER").is_ok();
    if !skip_docker {
        if !docker::ping() {
            eprintln!("\n  ✗ Docker is not running.");
            eprintln!("    Use --runtime neuropod or set ROYAK_NO_DOCKER=1 to run without Docker.");
            std::process::exit(1);
        }
        println!("  ✓ Docker connected\n");
    } else if !matches!(cli.command, Commands::Demo | Commands::Brain) {
        println!("  ⚡ No Docker mode\n");
    }

    // State file for persisting desired state
    let state_path = std::env::var("ROYAK_STATE")
        .unwrap_or_else(|_| ".royak-state.json".to_string());
    STATE_PATH.set(state_path.clone()).ok();

    match cli.command {
        Commands::Apply { file } => {
            let resources = if file == "-" {
                // Read from stdin (supports: cat file.yaml | royak apply -f -)
                use std::io::Read;
                let mut input = String::new();
                std::io::stdin().read_to_string(&mut input).unwrap_or_else(|e| {
                    eprintln!("  Error reading stdin: {e}");
                    std::process::exit(1);
                });
                spec::parse_yaml(&input).unwrap_or_else(|e| {
                    eprintln!("  Error: {e}");
                    std::process::exit(1);
                })
            } else {
                spec::parse_file(&file).unwrap_or_else(|e| {
                    eprintln!("  Error: {e}");
                    std::process::exit(1);
                })
            };

            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);

            for resource in &resources {
                match world.apply(resource) {
                    Ok(msg) => println!("  ✓ {msg}"),
                    Err(e) => eprintln!("  ✗ {e}"),
                }
            }

            // Reconcile immediately
            println!("\n  Reconciling...");
            let log = cli_reconcile(&state_path, &mut world, &mut brain);
            for line in &log {
                println!("{line}");
            }

            // If rolling update in progress, keep reconciling until complete
            if !world.pending_rollouts.is_empty() {
                println!("\n  Rolling update in progress...");
                let max_ticks = 30; // max 30 ticks (60s with 2s sleep)
                for tick in 0..max_ticks {
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    let log = cli_reconcile(&state_path, &mut world, &mut brain);
                    let relevant: Vec<&String> = log.iter()
                        .filter(|l| l.contains("[rollout]") || l.contains("[ready]") || l.contains("[scale]") || l.contains("[error]"))
                        .collect();
                    if !relevant.is_empty() {
                        println!("  ── tick {} ──", tick + 1);
                        for line in &relevant { println!("{line}"); }
                    }

                    if world.pending_rollouts.is_empty() {
                        println!("\n  ✓ Rolling update complete!");
                        break;
                    }
                }
                if !world.pending_rollouts.is_empty() {
                    // Rollback — rolling update didn't complete
                    println!("\n  ⚠ Rolling update timed out — rolling back!");
                    for (name, rollout) in &world.pending_rollouts {
                        println!("  [rollback] {name}: reverting to {}", rollout.old_image);
                        if let Some(dep) = world.deployments.get_mut(name.as_str()) {
                            dep.image = rollout.old_image.clone();
                            if let Some(c) = dep.containers.first_mut() {
                                c.image = rollout.old_image.clone();
                            }
                        }
                    }
                    world.pending_rollouts.clear();
                    // Reconcile to fix state
                    let log = cli_reconcile(&state_path, &mut world, &mut brain);
                    for line in &log { println!("{line}"); }
                }
            }

            save_state(&state_path, &mut world);
        }

        Commands::Get { resource, output } => {
            // Single resource export: get deployment/web -o yaml
            if resource.contains('/') {
                // kind/name (namespace default) or kind/namespace/name
                let parts: Vec<&str> = resource.split('/').collect();
                let (kind, ns, name) = match parts.as_slice() {
                    [k, n] => (*k, store::DEFAULT_NS, *n),
                    [k, ns, n] => (*k, *ns, *n),
                    _ => { eprintln!("  usage: royak get <kind>/<name> | <kind>/<namespace>/<name>"); std::process::exit(2); }
                };
                let key = store::obj_key(ns, name);
                let world = load_state(&state_path);

                let yaml_val: Option<serde_json::Value> = match kind {
                    "deployment" | "deploy" => world.deployments.get(&key).map(|d| {
                        let ready = cli_local_pods(&world).iter()
                            .filter(|v| v.kind == "deployment" && v.namespace == ns && v.owner == name && v.ready).count();
                        serde_json::json!({
                            "apiVersion": "apps/v1", "kind": "Deployment",
                            "metadata": {"name": d.name, "namespace": d.namespace},
                            "spec": {
                                "replicas": d.replicas,
                                "strategy": d.strategy.as_ref().map(|s| match s {
                                    reconcile::DeployStrategy::RollingUpdate { max_surge, max_unavailable } => serde_json::json!({"type": "RollingUpdate", "maxSurge": max_surge, "maxUnavailable": max_unavailable}),
                                    reconcile::DeployStrategy::Canary { weight, .. } => serde_json::json!({"type": "Canary", "weight": weight}),
                                    reconcile::DeployStrategy::BlueGreen { active } => serde_json::json!({"type": "BlueGreen", "active": active}),
                                }),
                                "selector": {"matchLabels": {"app": d.name}},
                                "template": {"spec": {
                                    "containers": d.containers.iter().map(|c| {
                                        let mut cj = serde_json::json!({"name": c.name, "image": c.image});
                                        if !c.env.is_empty() { cj["env"] = serde_json::json!(c.env.iter().map(|e| {
                                            let parts: Vec<&str> = e.splitn(2, '=').collect();
                                            serde_json::json!({"name": parts[0], "value": parts.get(1).unwrap_or(&"")})
                                        }).collect::<Vec<_>>()); }
                                        if !c.env_from_configmaps.is_empty() || !c.env_from_secrets.is_empty() {
                                            let mut env_from = Vec::new();
                                            for cm in &c.env_from_configmaps { env_from.push(serde_json::json!({"configMapRef": {"name": cm}})); }
                                            for s in &c.env_from_secrets { env_from.push(serde_json::json!({"secretRef": {"name": s}})); }
                                            cj["envFrom"] = serde_json::json!(env_from);
                                        }
                                        if let Some(ref rl) = d.resource_limits {
                                            let mut limits = serde_json::Map::new();
                                            let mut requests = serde_json::Map::new();
                                            if let Some(cpu) = rl.cpu_limit { limits.insert("cpu".into(), serde_json::json!(format!("{}m", (cpu * 1000.0) as u32))); }
                                            if let Some(mem) = rl.mem_limit { limits.insert("memory".into(), serde_json::json!(format!("{}Mi", mem))); }
                                            if let Some(cpu) = rl.cpu_request { requests.insert("cpu".into(), serde_json::json!(format!("{}m", (cpu * 1000.0) as u32))); }
                                            if let Some(mem) = rl.mem_request { requests.insert("memory".into(), serde_json::json!(format!("{}Mi", mem))); }
                                            if !limits.is_empty() || !requests.is_empty() {
                                                cj["resources"] = serde_json::json!({"limits": limits, "requests": requests});
                                            }
                                        }
                                        cj
                                    }).collect::<Vec<_>>()
                                }}
                            },
                            "status": {"replicas": d.replicas, "readyReplicas": ready}
                        })
                    }),
                    "service" | "svc" => world.services.get(&key).map(|s| serde_json::json!({
                        "apiVersion": "v1", "kind": "Service",
                        "metadata": {"name": s.name, "namespace": s.namespace},
                        "spec": {
                            "type": s.service_type, "selector": s.selector,
                            "ports": s.ports.iter().map(|p| serde_json::json!({"port": p.port, "targetPort": p.target_port, "protocol": p.protocol})).collect::<Vec<_>>()
                        }
                    })),
                    "configmap" | "cm" => world.configmaps.get(&key).map(|cm| serde_json::json!({
                        "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"name": cm.name, "namespace": cm.namespace},
                        "data": cm.data
                    })),
                    "secret" => world.secrets.get(&key).map(|s| serde_json::json!({
                        "apiVersion": "v1", "kind": "Secret",
                        "metadata": {"name": s.name, "namespace": s.namespace},
                        "data": s.data
                    })),
                    "rbacrole" | "rbac" => world.rbac_roles.get(name).map(|r| serde_json::json!({
                        "apiVersion": "v1", "kind": "RbacRole",
                        "metadata": {"name": r.name},
                        "spec": {"rules": r.rules.iter().map(|rule| serde_json::json!({
                            "resources": rule.resources, "verbs": rule.verbs, "namespaces": rule.namespaces
                        })).collect::<Vec<_>>()}
                    })),
                    _ => { eprintln!("  Unknown resource type: {kind}"); None }
                };

                match yaml_val {
                    Some(val) => {
                        if output == "json" {
                            println!("{}", serde_json::to_string_pretty(&val).unwrap_or_default());
                        } else {
                            // YAML output (default for single resource)
                            println!("{}", serde_yaml::to_string(&val).unwrap_or_default());
                        }
                    }
                    None => {
                        eprintln!("  {kind}/{name} not found in namespace {ns}");
                        std::process::exit(1);
                    }
                }
            } else {
            match resource.as_str() {
                "pods" | "pod" | "po" => {
                    match docker::list_containers(true) {
                        Ok(containers) => {
                            let file_world = load_state(&state_path);
                            let managed: Vec<&docker::DockerContainer> = reconcile::our_containers(&file_world, &containers)
                                .into_iter()
                                .filter(|c| c.labels.contains_key(store::LABEL_POD))
                                .collect();

                            // Cluster-aware: also list pods running on peer nodes,
                            // so `get pods` on any node shows the WHOLE cluster
                            // (a peer's pods are invisible via local Docker alone).
                            let world = load_state(&state_path);
                            let me = reconcile::local_node_name();
                            let peer_pods = if world.nodes.len() > 1 {
                                reconcile::peer_pod_inventory(&world)
                            } else { Vec::new() };

                            if managed.is_empty() && peer_pods.is_empty() {
                                println!("  No managed pods found.");
                                println!("  Use 'royak apply <file>' to deploy.");
                            } else {
                                let clustered = !peer_pods.is_empty();
                                if clustered {
                                    println!("  {:<20} {:<14} {:<22} {:<11} {}", "NAME", "NODE", "IMAGE", "STATE", "STATUS");
                                    println!("  {}", "─".repeat(84));
                                } else {
                                    println!("  {:<20} {:<25} {:<12} {}", "NAME", "IMAGE", "STATE", "STATUS");
                                    println!("  {}", "─".repeat(70));
                                }
                                for c in &managed {
                                    let docker_name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                                    let ns = c.labels.get(store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(store::DEFAULT_NS);
                                    let name = if ns == store::DEFAULT_NS { docker_name.to_string() } else { format!("{ns}/{docker_name}") };
                                    let name = name.as_str();
                                    if clustered {
                                        println!("  {:<20} {:<14} {:<22} {:<11} {}", name, me, c.image, c.state, c.status);
                                    } else {
                                        println!("  {:<20} {:<25} {:<12} {}", name, c.image, c.state, c.status);
                                    }
                                }
                                // Peer pods — the /royak/v1/pods census returns names
                                // only, so image/status show as "—" (remote node).
                                for (node, pod) in &peer_pods {
                                    println!("  {:<20} {:<14} {:<22} {:<11} {}", pod, node, "—", "running", "(remote)");
                                }
                                println!("\n  {} pod(s) total", managed.len() + peer_pods.len());
                            }
                        }
                        Err(e) => eprintln!("  Error: {e}"),
                    }
                }
                "deployments" | "deployment" | "deploy" => {
                    let world = load_state(&state_path);
                    if world.deployments.is_empty() {
                        println!("  No deployments.");
                    } else {
                        println!("  {:<20} {:<25} {:<10} {:<10}", "NAME", "IMAGE", "READY", "REPLICAS");
                        println!("  {}", "─".repeat(70));
                        // Ready pods on this node, by namespace + owner label
                        let local = cli_local_pods(&world);
                        let mut deps: Vec<&reconcile::StoredDeployment> = world.deployments.values().collect();
                        deps.sort_by(|a, b| (&a.namespace, &a.name).cmp(&(&b.namespace, &b.name)));
                        for dep in deps {
                            let ready = local.iter()
                                .filter(|v| v.kind == "deployment" && v.namespace == dep.namespace && v.owner == dep.name && v.ready)
                                .count();
                            let name = if dep.namespace == store::DEFAULT_NS { dep.name.clone() } else { format!("{}/{}", dep.namespace, dep.name) };
                            println!("  {:<20} {:<25} {}/{:<7} {}", name, dep.image, ready, dep.replicas, dep.replicas);
                        }
                    }
                }
                "configmaps" | "configmap" | "cm" => {
                    let world = load_state(&state_path);
                    if world.configmaps.is_empty() {
                        println!("  No configmaps.");
                    } else {
                        println!("  {:<20} {:<15} {:<10}", "NAME", "NAMESPACE", "KEYS");
                        println!("  {}", "─".repeat(45));
                        for (name, cm) in &world.configmaps {
                            println!("  {:<20} {:<15} {}", name, cm.namespace, cm.data.len());
                        }
                    }
                }
                "secrets" | "secret" => {
                    let world = load_state(&state_path);
                    if world.secrets.is_empty() {
                        println!("  No secrets.");
                    } else {
                        println!("  {:<20} {:<15} {:<10}", "NAME", "NAMESPACE", "KEYS");
                        println!("  {}", "─".repeat(45));
                        for (name, s) in &world.secrets {
                            println!("  {:<20} {:<15} {}", name, s.namespace, s.data.len());
                        }
                    }
                }
                "namespaces" | "namespace" | "ns" => {
                    let world = load_state(&state_path);
                    println!("  {:<20} {}", "NAME", "STATUS");
                    println!("  {}", "─".repeat(30));
                    for ns in &world.namespaces {
                        println!("  {:<20} Active", ns);
                    }
                }
                "ingress" | "ing" => {
                    let world = load_state(&state_path);
                    if world.ingresses.is_empty() {
                        println!("  No ingresses.");
                    } else {
                        for (name, ing) in &world.ingresses {
                            println!("  ingress/{name}:");
                            for rule in &ing.rules {
                                for path in &rule.paths {
                                    println!("    {} {} → {}:{}", rule.host, path.path, path.service, path.port);
                                }
                            }
                        }
                    }
                }
                "networkpolicy" | "netpol" => {
                    let world = load_state(&state_path);
                    if world.network_policies.is_empty() {
                        println!("  No network policies.");
                    } else {
                        for (name, np) in &world.network_policies {
                            println!("  netpol/{name} (selector: {}):", np.pod_selector);
                            if !np.ingress_allow.is_empty() {
                                println!("    ingress allow: {}", np.ingress_allow.join(", "));
                            }
                            if !np.egress_allow.is_empty() {
                                println!("    egress allow: {}", np.egress_allow.join(", "));
                            }
                        }
                    }
                }
                "pv" | "persistentvolume" | "persistentvolumes" => {
                    let world = load_state(&state_path);
                    if world.pvs.is_empty() {
                        println!("  No persistent volumes.");
                    } else {
                        println!("  {:<15} {:<10} {:<10} {:<15} {:<10} {}", "NAME", "CAPACITY", "CLASS", "PATH", "STATUS", "BOUND TO");
                        println!("  {}", "─".repeat(75));
                        for (name, pv) in &world.pvs {
                            let status = match pv.status { reconcile::PVStatus::Available => "Available", reconcile::PVStatus::Bound => "Bound", reconcile::PVStatus::Released => "Released" };
                            println!("  {:<15} {:<10} {:<10} {:<15} {:<10} {}",
                                name, pv.capacity, pv.storage_class, &pv.host_path[..pv.host_path.len().min(14)],
                                status, pv.bound_to.as_deref().unwrap_or("-"));
                        }
                    }
                }
                "pvc" | "persistentvolumeclaim" | "persistentvolumeclaims" => {
                    let world = load_state(&state_path);
                    if world.pvcs.is_empty() {
                        println!("  No persistent volume claims.");
                    } else {
                        println!("  {:<15} {:<12} {:<10} {:<10} {}", "NAME", "NAMESPACE", "CLASS", "SIZE", "BOUND PV");
                        println!("  {}", "─".repeat(60));
                        for (name, pvc) in &world.pvcs {
                            println!("  {:<15} {:<12} {:<10} {:<10} {}",
                                name, pvc.namespace, pvc.storage_class, pvc.requested,
                                pvc.bound_pv.as_deref().unwrap_or("Pending"));
                        }
                    }
                }
                "config" | "cfg" => {
                    let world = load_state(&state_path);
                    println!("  ── Cluster Config ──");
                    println!("  LLM:     {} ({})", world.config.llm_model, world.config.llm_host);
                    println!("  Runtime: {}", world.config.runtime);
                    println!("  API:     port {}", world.config.api_port);
                    println!("  Alerts:  anomaly={}, restart={}, webhook={}",
                        world.config.alert_on_anomaly, world.config.alert_on_restart,
                        world.config.alert_webhook.as_deref().unwrap_or("none"));
                    println!("  Pause:   enabled={}, idle={}s", world.config.pause_enabled, world.config.pause_default_idle);
                }
                "nodes" | "node" => {
                    let world = load_state(&state_path);
                    if world.nodes.is_empty() {
                        println!("  No nodes registered. Use 'royak node list' to auto-register.");
                    } else {
                        println!("  {:<20} {:<22} {:<8} {:<10} {:<6} {}", "NAME", "ADDRESS", "CPU", "MEM", "PODS", "STATUS");
                        println!("  {}", "─".repeat(75));
                        for (name, n) in &world.nodes {
                            let status = match n.status {
                                reconcile::NodeStatus::Ready => "Ready",
                                reconcile::NodeStatus::NotReady => "NotReady",
                                reconcile::NodeStatus::Draining => "Draining",
                            };
                            println!("  {:<20} {:<22} {:<8.0} {:<.1}GB {:<6} {}",
                                name, n.address, n.cpu_capacity, n.mem_capacity / 1024.0, n.pod_count, status);
                        }
                    }
                }
                "all" => {
                    let world = load_state(&state_path);
                    println!("  Namespaces: {}", world.namespaces.join(", "));
                    println!("  Deployments: {}", world.deployments.len());
                    println!("  ConfigMaps: {}", world.configmaps.len());
                    println!("  Secrets: {}", world.secrets.len());
                    println!("  PVs: {}", world.pvs.len());
                    println!("  PVCs: {}", world.pvcs.len());
                    println!("  Pipelines: {}", world.pipelines.len());
                    println!("  Repositories: {}", world.repositories.len());
                    println!("  Nodes: {}", world.nodes.len());
                    let running = cli_local_pods(&world).iter().filter(|v| v.running).count();
                    println!("  Pods: {running} running on this node");
                }
                _ => {
                    println!("  Unknown resource: {resource}");
                    println!("  Available: pods, deployments, configmaps, secrets, namespaces, nodes, all");
                    println!("  Single resource: get deployment/web -o yaml");
                }
            }
            } // end else (list vs single resource)
        }

        Commands::Delete { resource } => {
            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);

            // Targets as (resource type, namespace, name).
            let mut targets: Vec<(String, String, String)> = Vec::new();
            if resource == "-f" || resource.ends_with(".yaml") || resource.ends_with(".yml") {
                let file = if resource == "-f" {
                    std::env::args().nth(3).unwrap_or_default()
                } else {
                    resource.clone()
                };
                match spec::parse_file(&file) {
                    Ok(resources) => {
                        for r in &resources {
                            targets.push((r.kind.to_lowercase(), store::ns_of(r), r.metadata.name.clone()));
                        }
                    }
                    Err(e) => { eprintln!("  Error: {e}"); std::process::exit(1); }
                }
            } else {
                // kind/name or kind/namespace/name
                let parts: Vec<&str> = resource.split('/').collect();
                match parts.as_slice() {
                    [kind, name] => targets.push((kind.to_string(), store::DEFAULT_NS.to_string(), name.to_string())),
                    [kind, ns, name] => targets.push((kind.to_string(), ns.to_string(), name.to_string())),
                    _ => {
                        eprintln!("  Usage:");
                        eprintln!("    royak delete <kind>/<name>              (namespace default)");
                        eprintln!("    royak delete <kind>/<namespace>/<name>");
                        eprintln!("    royak delete -f <file.yaml>");
                        std::process::exit(1);
                    }
                }
            }
            let mut failed = false;
            let mut cleanup: Vec<String> = Vec::new();
            for (kind, ns, name) in &targets {
                let kind = match kind.as_str() { "deploy" => "deployment", "ns" => "namespace", k => k };
                if kind == "namespace" && name == store::DEFAULT_NS {
                    eprintln!("  ✗ Cannot delete default namespace");
                    failed = true;
                    continue;
                }
                match world.delete_resource(kind, ns, name) {
                    Some(paths) => { cleanup.extend(paths); println!("  ✓ {kind}/{name} deleted (namespace {ns})"); }
                    None => { eprintln!("  ✗ {kind}/{name} not found in namespace {ns}"); failed = true; }
                }
            }
            save_state(&state_path, &mut world);
            reconcile::cleanup_paths(&cleanup);
            // Containers of deleted owners are garbage-collected by reconcile.
            let log = cli_reconcile(&state_path, &mut world, &mut brain);
            for line in &log { println!("{line}"); }
            if failed { std::process::exit(1); }
        }

        Commands::Brain => {
            let mut brain = OrinBrain::new(32, 4);
            // Load existing weights if available
            if brain.load_weights(".royak-brain.bin").is_ok() {
                println!("\n  ✓ Loaded trained brain: {} steps, loss={:.4}", brain.train_steps, brain.last_loss);
            } else {
                println!("\n  Brain: untrained (random weights)");
            }

            // Pre-train on augmented data
            println!("\n  ── Pre-training on augmented scenarios ──");
            let start = std::time::Instant::now();
            let losses = brain.pretrain(500);
            let elapsed = start.elapsed();
            for (epoch, loss) in &losses {
                let bar_len = ((1.0 - loss.min(1.0)) * 30.0) as usize;
                let bar = "█".repeat(bar_len) + &"░".repeat(30 - bar_len);
                println!("  epoch {epoch:>4}: loss={loss:.6} [{bar}]");
            }
            println!("  Trained {} epochs in {:.1}ms", 500, elapsed.as_secs_f64() * 1000.0);
            println!("  Final loss: {:.6}", brain.last_loss);
            println!("  Train steps: {}", brain.train_steps);

            // Save trained weights
            if brain.save_weights(".royak-brain.bin").is_ok() {
                println!("  ✓ Weights saved to .royak-brain.bin");
            }

            println!("\n  {}", brain.stats());
            println!("  Architecture: perceive(64) → decide(32) → act");
            println!("  KV store: embedded (replaces etcd)");
            println!("  Scheduler: neural placement");
            println!("  Controller: reconcile loop + neural decisions");
            println!("  ANOMALY: learned baseline monitoring (mean ± 2.5σ)");
            println!("  PREDICT: linear regression load forecasting");
            println!("  FP-TLS: Forward Pass TLS (neural auth + encryption)");
            println!();

            // Demo Forward Pass TLS
            let id_a = brain.neural_identity("node-alpha");
            let id_b = brain.neural_identity("node-beta");
            println!("  ── Forward Pass TLS Demo ──");
            println!("  node-alpha identity: [{:.4}, {:.4}, {:.4}, ...]", id_a[0], id_a[1], id_a[2]);
            println!("  node-beta  identity: [{:.4}, {:.4}, {:.4}, ...]", id_b[0], id_b[1], id_b[2]);
            println!("  verify(alpha, alpha_token): {}", brain.verify_identity("node-alpha", &id_a));
            println!("  verify(alpha, beta_token):  {}", brain.verify_identity("node-alpha", &id_b));
            let key = brain.derive_key("node-alpha", "node-beta");
            println!("  shared key (alpha↔beta): {:02x}{:02x}{:02x}{:02x}...{:02x}{:02x}{:02x}{:02x}",
                key[0], key[1], key[2], key[3], key[28], key[29], key[30], key[31]);

            // AES-256-GCM encrypt/decrypt demo
            let msg = b"hello from royak";
            let encrypted = brain.neural_encrypt(msg, "node-alpha", "node-beta");
            let decrypted = brain.neural_decrypt(&encrypted, "node-alpha", "node-beta");
            println!("  encrypt('hello from royak'): {} bytes (nonce + ciphertext + GCM tag)", encrypted.len());
            match decrypted {
                Ok(plain) => println!("  decrypt: {:?} ✓", std::str::from_utf8(&plain).unwrap_or("?")),
                Err(e) => println!("  decrypt FAILED: {}", e),
            }
            // Tamper detection demo
            let mut tampered = encrypted.clone();
            if tampered.len() > 15 { tampered[15] ^= 0xFF; }
            match brain.neural_decrypt(&tampered, "node-alpha", "node-beta") {
                Ok(_) => println!("  tamper check: NOT detected (unexpected)"),
                Err(_) => println!("  tamper check: DETECTED ✓ (1 bit flip → decrypt rejected)"),
            }
            // Base64 identity for HTTP headers
            let b64 = OrinBrain::identity_base64(&id_a);
            let verified = brain.verify_identity_base64("node-alpha", &b64);
            println!("  identity base64: {}...{} (verified: {})", &b64[..8], &b64[b64.len()-4..], verified);
            println!("  No CA. No PKI. No X.509. Just matmul + AES-256-GCM.");
        }

        Commands::Watch { interval, discover, tls, runtime, port, ingress_port, node_id, peers, bootstrap } => {
            // Peers serve their API with the same --tls setting; node RPC follows it.
            node_rpc::set_tls(tls);
            docker::set_background_pulls(true);
            let use_neuropod = runtime == "neuropod";
            if use_neuropod {
                println!("  ⚡ NeuroPod runtime [EXPERIMENTAL] — no Docker needed");
                println!("    ⚠ Mega-beta: basic deploy/scale only. For production use --runtime docker");
                if cfg!(target_os = "macos") && microvm::MicroVM::is_available() {
                    println!("    macOS: MicroVM (Apple Virtualization.framework, ~64MB RAM)");
                } else if cfg!(target_os = "linux") {
                    println!("    Linux: native (namespaces + OverlayFS + cgroups)");
                }
            }

            let mut brain = OrinBrain::new(32, 4);
            // Load pre-trained weights if available
            if let Ok(()) = brain.load_weights(".royak-brain.bin") {
                println!("  ✓ Brain loaded: {} train steps, loss={:.4}", brain.train_steps, brain.last_loss);
            }

            // ── Identity, credentials and durability are fixed BEFORE anything
            //    listens: no window where the API runs unauthenticated or a
            //    write is acknowledged without a durable commit path.
            let clustered = node_id.is_some();
            let data_dir = reconcile::royak_data_dir();
            let admin_token = match auth::init_user_auth(&data_dir) {
                Ok(t) => t,
                Err(e) => { eprintln!("  ✗ [auth] {e}"); std::process::exit(2); }
            };
            if clustered {
                if let Err(e) = auth::require_cluster_secret() {
                    eprintln!("  ✗ [cluster] {e}");
                    std::process::exit(2);
                }
            }

            // Single shared world for API + reconcile loop. A corrupt or
            // unsupported state file stops the process (load_state exits).
            let world_arc = Arc::new(RwLock::new(load_state(&state_path)));
            let api_port = port.unwrap_or_else(|| world_arc.read().unwrap().config.api_port);
            {
                let mut w = world_arc.write().unwrap();
                w.nodes.clear(); // the node census is runtime-only; peers re-announce
                reconcile::register_local_node(&mut w, &brain, api_port);
            }

            if clustered {
                // Cluster: a quorum-committed Raft entry is the commit point.
                // The local JSON file is only read once, as the bootstrap seed.
                store::set_durability(store::Durability::Raft);
                raft_node::CLUSTER_MODE.store(true, std::sync::atomic::Ordering::Release);
            } else {
                store::set_durability(store::Durability::File { path: state_path.clone() });
                match reconcile::try_take_ownership(&world_arc, &state_path) {
                    Ok(true) => println!("  ✓ state owner: {state_path}"),
                    Ok(false) => println!("  ⊘ {state_path} is owned by another Royak process — starting in standby (reads only; writes return 421, not applied)"),
                    Err(e) => { eprintln!("  ✗ cannot own {state_path}: {e}"); std::process::exit(2); }
                }
            }

            // kubeconfig for kubectl, carrying the admin bearer token.
            match &admin_token {
                Some(t) => generate_kubeconfig(api_port, t, tls),
                None => generate_kubeconfig(api_port, "insecure-dev", tls),
            }

            // Tokio runtime for async API server + ingress
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");

            // ── Raft consensus (--node-id + --peers) ──
            if let Some(nid) = node_id {
                rt.spawn(raft_node::leadership_poller());
                let peer_list: Vec<(u64, String)> = peers.split(',')
                    .filter(|s| !s.trim().is_empty())
                    .filter_map(|s| {
                        let (id, addr) = s.split_once('@')?;
                        Some((id.trim().parse::<u64>().ok()?, addr.trim().to_string()))
                    })
                    .collect();
                let peer_addrs: Vec<String> = peer_list.iter().map(|(_, addr)| addr.clone()).collect();
                let raft_dir = std::path::PathBuf::from(format!("{state_path}.raft"));
                // Only the bootstrap node offers its file state as the seed, and
                // only into a brand-new cluster (generation 0).
                // Every other node starts EMPTY and receives state only from
                // the Raft log/snapshot — a stale local file is never served.
                let seed = {
                    let mut w = world_arc.write().unwrap();
                    let file_state = w.to_state();
                    let mut empty = DesiredWorld::new().to_state();
                    empty.cluster_id = auth::derived_cluster_id().unwrap_or_else(|| file_state.cluster_id.clone());
                    w.install_state(empty);
                    if bootstrap { Some(file_state) } else { None }
                };
                let raft_world = Arc::clone(&world_arc);
                let do_bootstrap = bootstrap;
                let started = rt.block_on(raft_node::build_http_node(nid, raft_world, &peer_list, do_bootstrap, raft_dir.clone(), seed));
                match started {
                    Ok(()) => {
                        raft_node::RAFT_READY.store(true, std::sync::atomic::Ordering::Release);
                        println!("  [raft] node {nid} up (log: {}, peers: {}, bootstrap: {do_bootstrap})", raft_dir.display(), peer_list.len());
                    }
                    Err(e) => { eprintln!("  ✗ [raft] failed to start node {nid}: {e}"); std::process::exit(2); }
                }
                // Signed node census (heartbeats + pod inventory).
                reconcile::spawn_cluster_census(Arc::clone(&world_arc), peer_addrs);
            }

            // Start async API server (after auth + durability are in place)
            let api_world = Arc::clone(&world_arc);
            if tls {
                rt.spawn(api::serve_https(api_port, api_world));
            } else {
                rt.spawn(api::serve(api_port, api_world));
            }

            // Start autodiscovery if enabled
            if discover {
                let disc_world = Arc::clone(&world_arc);
                std::thread::spawn(move || {
                    reconcile::autodiscovery(disc_world, api_port);
                });
            }

            // Start async ingress controller. Port 80/443 needs root on Unix,
            // so --ingress-port lets you pick an unprivileged port (e.g. 8080)
            // for testing. --ingress-port 0 disables ingress entirely.
            let ingress_tls = tls;
            let resolved_ingress_port = ingress_port.unwrap_or_else(|| if ingress_tls { 443 } else { 80 });
            if resolved_ingress_port > 0 {
                let ingress_world = Arc::clone(&world_arc);
                rt.spawn(api::serve_ingress(resolved_ingress_port, ingress_world, ingress_tls));
            } else {
                println!("  ⊘ ingress disabled (--ingress-port 0)");
            }

            // Cross-node mesh proxy (:6550) — lets this node's ingress reach pods
            // running on a PEER (their pods sit on the peer's docker bridge, not
            // routable from here). node 1's ingress forwards to the peer's mesh
            // with an explicit X-Royak-Pod header; the peer hands off locally.
            // Only in cluster mode (--node-id): a single-node watch has no peers
            // to serve, and binding :6550 there collides with `royak mesh`.
            if node_id.is_some() {
                let mesh_world = Arc::clone(&world_arc);
                let mesh_node = reconcile::local_node_name();
                rt.spawn(cluster_mesh::run_proxy(cluster_mesh::DEFAULT_MESH_PORT, mesh_node, mesh_world, true));
            }

            // ServiceLB — NodePort listeners (userspace, klipper-lb-style)
            rt.spawn(servicelb::run(Arc::clone(&world_arc)));

            // Keep the container-stats cache warm off the reconcile thread, so a
            // tick only peeks (never blocks on Docker's ~1-2s/container sampling).
            docker::spawn_stats_sampler();

            // Server-side chaos monkey — when ROYAK_DEMO is on, reliably kill a
            // random pod of the chaos app (default demosite) every ~20s so the
            // self-heal is ALWAYS visible without a browser, clicks, or luck.
            if std::env::var("ROYAK_DEMO").map(|v| v == "1" || v == "true").unwrap_or(false) {
                let chaos_world = Arc::clone(&world_arc);
                std::thread::spawn(move || {
                    let app = std::env::var("ROYAK_CHAOS_APP").unwrap_or_else(|_| "demosite".to_string());
                    loop {
                        std::thread::sleep(std::time::Duration::from_secs(20));
                        // Only main containers of this cluster's own pods of the
                        // chaos deployment (default namespace) — never anything
                        // else on the host.
                        let all = docker::list_containers(false).unwrap_or_default();
                        let running: Vec<(String, String)> = {
                            let w = chaos_world.read().unwrap_or_else(|e| e.into_inner());
                            reconcile::our_containers(&w, &all).into_iter()
                                .filter(|c| c.state == "running"
                                    && c.labels.get(store::LABEL_DEPLOYMENT) == Some(&app)
                                    && c.labels.get(store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(store::DEFAULT_NS) == store::DEFAULT_NS
                                    && c.labels.get(store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true))
                                .filter_map(|c| c.names.first()
                                    .map(|n| (c.id.clone(), n.trim_start_matches('/').to_string())))
                                .collect()
                        };
                        if running.len() <= 1 { continue; } // always leave one serving
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
                        let (id, name) = &running[(now as usize) % running.len()];
                        if docker::remove_container(id, true).is_ok() {
                            crate::api::push_activity(&format!("[chaos] killed {name} — Royak reconciling…"));
                            println!("  🐒 [chaos] killed {name}");
                        }
                    }
                });
            }

            println!("  Watching cluster (Ctrl+C to stop)...");
            if discover { println!("  Autodiscovery: UDP broadcast on port 9443"); }
            if use_neuropod { println!("  Runtime: NeuroPod (no Docker)"); }
            println!();

            // Unified reconcile loop — auto-detects runtime
            reconcile::run_loop_shared_with_runtime(world_arc, &mut brain, interval, &state_path, use_neuropod);
        }

        Commands::Ask { question, ollama, model } => {
            let world = load_state(&state_path);
            let brain = OrinBrain::new(32, 4);
            let q = question.join(" ");

            // Use config values as defaults, CLI flags override
            let ollama = if ollama == "http://10.77.0.1:11434" { world.config.llm_host.clone() } else { ollama };
            let model = if model == "qwen2.5:32b" { world.config.llm_model.clone() } else { model };

            // Gather cluster state for context
            let pods = cli_local_pods(&world).iter()
                .map(|v| format!("  {}/{} ({}) [{}]", v.namespace, v.pod, v.image, if v.running { "running" } else { "not running" }))
                .collect::<Vec<_>>().join("\n");

            let deployments: Vec<String> = world.deployments.values()
                .map(|d| format!("  {} ({}x {}, ns={})", d.name, d.replicas, d.image, d.namespace))
                .collect();

            let functions: Vec<String> = world.functions.values()
                .map(|f| format!("  {} ({}, {} calls, state={})", f.name, f.image, f.invocations,
                    match f.state { reconcile::FunctionState::Cold => "cold", reconcile::FunctionState::Hot => "hot", _ => "other" }))
                .collect();

            let anomalies = brain.detect_anomalies();
            let anomaly_str = if anomalies.is_empty() {
                "  No anomalies detected".to_string()
            } else {
                anomalies.iter().map(|(p, t, v, th)| format!("  ⚠ {p}: {t} {v:.1} (threshold {th:.1})")).collect::<Vec<_>>().join("\n")
            };

            let context = format!(
                "You are the AI brain of Royak, an AI-first container orchestrator (like Kubernetes but 5000 lines of Rust instead of 2M lines of Go).\n\n\
                CLUSTER STATE:\n\
                Pods:\n{pods}\n\n\
                Deployments:\n{}\n\n\
                Functions (Lambda):\n{}\n\n\
                Nodes: {} registered\n\
                Pipelines: {} defined\n\
                Anomalies:\n{anomaly_str}\n\n\
                Brain stats: {}\n\n\
                USER QUESTION: {q}\n\n\
                Answer concisely. If the user asks to do something, provide the exact YAML or royak command. \
                If they ask about problems, check the anomalies and pod states. \
                You can suggest scaling, rolling updates, or function deployments.",
                deployments.join("\n"),
                if functions.is_empty() { "  None".to_string() } else { functions.join("\n") },
                world.nodes.len(),
                world.pipelines.len(),
                brain.stats(),
            );

            println!("  🧠 Asking {} ({})...\n", model, ollama);

            // Call Ollama API
            let payload = serde_json::json!({
                "model": model,
                "prompt": context,
                "stream": false,
                "options": {"temperature": 0.3, "num_predict": 500}
            });

            match std::process::Command::new("curl")
                .args(["-s", "-m", "30", &format!("{ollama}/api/generate"),
                    "-d", &payload.to_string()])
                .output()
            {
                Ok(output) => {
                    let resp = String::from_utf8_lossy(&output.stdout);
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
                        if let Some(response) = v["response"].as_str() {
                            println!("{response}");
                        } else if let Some(err) = v["error"].as_str() {
                            eprintln!("  Ollama error: {err}");
                        }
                    } else {
                        eprintln!("  Cannot reach Ollama at {ollama}");
                        eprintln!("  Make sure Ollama is running and the model is loaded.");
                        eprintln!("  Try: royak ask --ollama=http://localhost:11434 --model=llama3.2:3b \"{}\"", q);
                    }
                }
                Err(e) => eprintln!("  Error: {e}"),
            }
        }

        Commands::Invoke { name } => {
            let mut world = load_state(&state_path);
            match reconcile::invoke_function(&mut world, &name) {
                Ok(result) => {
                    println!("  {result}");
                    save_state(&state_path, &mut world);
                }
                Err(e) => eprintln!("  {e}"),
            }
        }

        Commands::Functions => {
            let world = load_state(&state_path);
            if world.functions.is_empty() {
                println!("  No functions deployed.");
                println!("  Use 'royak apply function.yaml' to deploy one.");
            } else {
                println!("  {:<18} {:<22} {:<8} {:<8} {:<12} {}", "NAME", "IMAGE", "STATE", "CALLS", "TRIGGERS", "TIMEOUT");
                println!("  {}", "─".repeat(80));
                for (name, f) in &world.functions {
                    let state = match f.state {
                        reconcile::FunctionState::Cold => "cold",
                        reconcile::FunctionState::Warming => "warming",
                        reconcile::FunctionState::Hot => "hot",
                        reconcile::FunctionState::Paused => "paused",
                    };
                    let triggers = f.http_triggers.len() + f.webhook_triggers.len() + f.schedule_triggers.len();
                    let img = if f.image.len() > 20 { &f.image[..20] } else { &f.image };
                    println!("  {:<18} {:<22} {:<8} {:<8} {:<12} {}s",
                        name, img, state, f.invocations, triggers, f.timeout_secs);
                }
            }
        }

        Commands::Node { action } => {
            let mut world = load_state(&state_path);
            let brain = OrinBrain::new(32, 4);

            match action {
                NodeAction::Join { peer, port } => {
                    // Membership is static and authenticated: start this node
                    // with `watch --node-id <id> --peers <id@addr,...>` and the
                    // shared ROYAK_CLUSTER_SECRET. State is never merged from a
                    // peer outside Raft.
                    let _ = (&mut world, &brain, port);
                    eprintln!("  ✗ `node join` is removed: start the node with `royak watch --node-id <id> --peers <id@{peer},...>` and ROYAK_CLUSTER_SECRET set");
                    std::process::exit(2);
                }
                NodeAction::List => {
                    if world.nodes.is_empty() {
                        // Auto-register local node
                        reconcile::register_local_node(&mut world, &brain, 6443);
                        save_state(&state_path, &mut world);
                    }
                    println!("  {:<20} {:<22} {:<8} {:<8} {:<6} {}", "NAME", "ADDRESS", "CPU", "MEM", "PODS", "STATUS");
                    println!("  {}", "─".repeat(75));
                    for (name, n) in &world.nodes {
                        let status = match n.status {
                            reconcile::NodeStatus::Ready => "Ready",
                            reconcile::NodeStatus::NotReady => "NotReady",
                            reconcile::NodeStatus::Draining => "Draining",
                        };
                        let mem_gb = n.mem_capacity / 1024.0;
                        println!("  {:<20} {:<22} {:<8.0} {:<.1}GB {:<6} {}",
                            name, n.address, n.cpu_capacity, mem_gb, n.pod_count, status);
                    }
                    println!("\n  {} node(s), FP-TLS secured", world.nodes.len());
                }
                NodeAction::Drain { name } => {
                    // Node status is runtime-only (rebuilt from signed
                    // heartbeats), so editing it in a state file never reached
                    // a running scheduler — refuse instead of pretending.
                    eprintln!("  ✗ `node drain {name}` is not supported: cordon/drain is not implemented for a running cluster. Stop the node's royak process; its pods are rescheduled once its census report expires.");
                    std::process::exit(2);
                }
            }
        }

        Commands::Api { port } => {
            // Single-node API server + reconcile loop: the same auth, ownership
            // and commit contract as `watch`, without ingress/cluster extras.
            docker::set_background_pulls(true);
            let admin_token = match auth::init_user_auth(&reconcile::royak_data_dir()) {
                Ok(t) => t,
                Err(e) => { eprintln!("  ✗ [auth] {e}"); std::process::exit(2); }
            };
            let world_arc = Arc::new(RwLock::new(load_state(&state_path)));
            store::set_durability(store::Durability::File { path: state_path.clone() });
            match reconcile::try_take_ownership(&world_arc, &state_path) {
                Ok(true) => {}
                Ok(false) => { eprintln!("  ✗ {state_path} is owned by another Royak process"); std::process::exit(3); }
                Err(e) => { eprintln!("  ✗ {e}"); std::process::exit(2); }
            }
            {
                let mut w = world_arc.write().unwrap();
                w.nodes.clear();
                reconcile::register_local_node(&mut w, &OrinBrain::new(32, 4), port);
            }
            match &admin_token {
                Some(t) => generate_kubeconfig(port, t, false),
                None => generate_kubeconfig(port, "insecure-dev", false),
            }
            println!("  Starting K8s-compatible API server on :{port} (kubeconfig: ~/.kube/royak.yaml)");

            let reconcile_world = world_arc.clone();
            let reconcile_state_path = state_path.clone();
            std::thread::spawn(move || {
                let mut brain = OrinBrain::new(32, 4);
                reconcile::run_loop_shared_with_runtime(reconcile_world, &mut brain, 5, &reconcile_state_path, false);
                // The loop returns only on SIGTERM/SIGINT (its handler replaced
                // the default "terminate"); the API server must stop with it.
                std::process::exit(0);
            });

            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");
            rt.spawn(servicelb::run(Arc::clone(&world_arc)));
            docker::spawn_stats_sampler();
            rt.block_on(api::serve(port, world_arc));
        }

        Commands::PortForward { pod, ports } => {
            let (local, remote) = match ports.split_once(':') {
                Some((l, r)) => (l.trim(), r.trim()),
                None => (ports.as_str(), ports.as_str()),
            };
            let local_port: u16 = match local.parse() {
                Ok(p) => p,
                Err(_) => { eprintln!("  ✗ bad local port: {local}"); return; }
            };
            let remote_port: u16 = match remote.parse() {
                Ok(p) => p,
                Err(_) => { eprintln!("  ✗ bad remote port: {remote}"); return; }
            };

            // Resolve the pod container and a reachable endpoint.
            let containers = match docker::list_containers(false) {
                Ok(c) => c,
                Err(e) => { eprintln!("  ✗ docker: {e}"); return; }
            };
            let (pf_ns, pf_pod) = cli_pod_ref(&pod);
            let pf_world = load_state(&state_path);
            let Some(c) = reconcile::our_containers(&pf_world, &containers).into_iter().find(|c|
                c.labels.get(store::LABEL_POD) == Some(&pf_pod)
                && c.labels.get(store::LABEL_NAMESPACE).map(|s| s.as_str()).unwrap_or(store::DEFAULT_NS) == pf_ns
                && c.labels.get(store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true)) else {
                eprintln!("  ✗ pod {pf_ns}/{pf_pod} not found on this node");
                return;
            };
            let cid = c.id[..12.min(c.id.len())].to_string();

            // Linux: container IP is host-routable. macOS: use the published
            // ephemeral host port (present when a NodePort/LoadBalancer service
            // exposes it), otherwise we can't reach the container from the host.
            let endpoint = if cfg!(target_os = "linux") {
                docker::container_ip(&cid).ok().map(|ip| format!("{ip}:{remote_port}"))
            } else {
                docker::container_host_port(&cid, remote_port).map(|hp| format!("127.0.0.1:{hp}"))
            };
            let Some(endpoint) = endpoint else {
                eprintln!("  ✗ port {remote_port} is not reachable from the host.");
                eprintln!("    On macOS, expose it via a NodePort/LoadBalancer service, or run royak on Linux.");
                return;
            };

            let listener = match std::net::TcpListener::bind(("127.0.0.1", local_port)) {
                Ok(l) => l,
                Err(e) => { eprintln!("  ✗ cannot bind 127.0.0.1:{local_port}: {e}"); return; }
            };
            println!("  Forwarding 127.0.0.1:{local_port} → {pod}:{remote_port}  (via {endpoint})");
            println!("  Press Ctrl+C to stop.");
            for stream in listener.incoming() {
                let Ok(mut inbound) = stream else { continue };
                let endpoint = endpoint.clone();
                std::thread::spawn(move || {
                    let Ok(mut outbound) = std::net::TcpStream::connect(&endpoint) else { return };
                    let mut in2 = inbound.try_clone().unwrap();
                    let mut out2 = outbound.try_clone().unwrap();
                    let t = std::thread::spawn(move || { std::io::copy(&mut in2, &mut out2).ok(); });
                    std::io::copy(&mut outbound, &mut inbound).ok();
                    let _ = t.join();
                });
            }
        }

        Commands::Flows { server, top } => {
            // Simple blocking GET against the running api server.
            let url = format!("{}/royak/v1/flows", server.trim_end_matches('/'));
            let addr = url.trim_start_matches("http://");
            let (host_port, path) = match addr.split_once('/') {
                Some((hp, p)) => (hp.to_string(), format!("/{p}")),
                None => (addr.to_string(), "/".to_string()),
            };
            let body = (|| -> Result<String, String> {
                use std::io::{Read, Write};
                let mut s = std::net::TcpStream::connect(&host_port).map_err(|e| format!("connect {host_port}: {e}"))?;
                let auth = cli_bearer().map(|t| format!("Authorization: Bearer {t}\r\n")).unwrap_or_default();
                write!(s, "GET {path} HTTP/1.1\r\nHost: {host_port}\r\n{auth}Connection: close\r\n\r\n").map_err(|e| e.to_string())?;
                let mut raw = String::new(); s.read_to_string(&mut raw).map_err(|e| e.to_string())?;
                Ok(raw.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
            })();
            let json: serde_json::Value = match body.and_then(|b| serde_json::from_str(&b).map_err(|e| e.to_string())) {
                Ok(v) => v,
                Err(e) => { eprintln!("  ✗ could not reach {server}: {e}\n    Is `royak api` running?"); return; }
            };
            if top {
                println!("  {:<28} {:>6} {:>12} {:>12}", "DEST", "CONNS", "BYTES ↑", "BYTES ↓");
                println!("  {}", "─".repeat(64));
                for t in json["topTalkers"].as_array().cloned().unwrap_or_default() {
                    println!("  {:<28} {:>6} {:>12} {:>12}",
                        t["dest"].as_str().unwrap_or("?"),
                        t["connections"].as_u64().unwrap_or(0),
                        t["bytesUp"].as_u64().unwrap_or(0),
                        t["bytesDown"].as_u64().unwrap_or(0));
                }
            } else {
                let flows = json["flows"].as_array().cloned().unwrap_or_default();
                if flows.is_empty() { println!("  No flows observed yet (traffic through ServiceLB/ingress/mesh is tapped)."); }
                println!("  {:<10} {:<24} {:<20} {:>6} {:>10} {:>10} {:>8}", "VIA", "SOURCE", "DEST", "PORT", "↑ BYTES", "↓ BYTES", "ms");
                println!("  {}", "─".repeat(96));
                for f in flows {
                    println!("  {:<10} {:<24} {:<20} {:>6} {:>10} {:>10} {:>8}",
                        f["via"].as_str().unwrap_or("?"),
                        f["source"].as_str().unwrap_or("?"),
                        f["dest"].as_str().unwrap_or("?"),
                        f["port"].as_u64().unwrap_or(0),
                        f["bytes_up"].as_u64().unwrap_or(0),
                        f["bytes_down"].as_u64().unwrap_or(0),
                        f["duration_ms"].as_u64().unwrap_or(0));
                }
            }
        }

        Commands::Logs { pod, tail, stderr } => {
            // No pod given — list what's available instead of erroring out.
            let pod = match pod {
                Some(p) => p,
                None => {
                    println!("  Usage: royak logs <pod|deployment|all> [--tail N] [--stderr]");
                    let names: Vec<String> = cli_local_pods(&load_state(&state_path)).iter()
                        .map(|v| if v.namespace == store::DEFAULT_NS { v.pod.clone() } else { format!("{}/{}", v.namespace, v.pod) })
                        .collect();
                    if names.is_empty() {
                        println!("  No pods on this node. Try 'royak get pods'.");
                    } else {
                        println!("\n  Pods on this node:");
                        for n in &names { println!("    {n}"); }
                        println!("\n  ('royak get pods' shows pods on peer nodes too.)");
                    }
                    return;
                }
            };
            let fetch_logs = |id: &str, tail: u32| -> Result<String, String> {
                if stderr {
                    docker::get_stderr_logs(id, tail)
                } else {
                    docker::get_logs(id, tail)
                }
            };
            let stream_label = if stderr { " (stderr)" } else { "" };

            let world = load_state(&state_path);
            let all_containers = match docker::list_containers(true) {
                Ok(c) => c,
                Err(e) => { eprintln!("  Error: {e}"); return; }
            };
            let ours = reconcile::our_containers(&world, &all_containers);
            let mains = |pred: &dyn Fn(&docker::DockerContainer) -> bool| -> Vec<&docker::DockerContainer> {
                ours.iter().copied()
                    .filter(|c| c.labels.contains_key(store::LABEL_POD)
                        && c.labels.get(store::LABEL_ROLE).map(|r| r == "main").unwrap_or(true)
                        && pred(c))
                    .collect()
            };
            let ns_of = |c: &docker::DockerContainer| c.labels.get(store::LABEL_NAMESPACE).cloned().unwrap_or_else(|| store::DEFAULT_NS.to_string());
            let print = |c: &docker::DockerContainer| {
                let name = c.labels.get(store::LABEL_POD).cloned().unwrap_or_default();
                if let Ok(logs) = fetch_logs(&c.id[..12.min(c.id.len())], tail) {
                    let clean: String = logs.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).collect();
                    if !clean.trim().is_empty() {
                        println!("  ── {}/{name}{stream_label} ──", ns_of(c));
                        println!("{clean}");
                    }
                }
            };
            if pod == "all" {
                for c in mains(&|_| true) { print(c); }
            } else {
                // `ns/pod`, a pod name, or a deployment name (→ all its pods here).
                let (ns, name) = cli_pod_ref(&pod);
                let full_name = if name.starts_with("rk-") { name.clone() } else { format!("{}", store::pod_stem(&ns, &name)) };
                let exact = mains(&|c| ns_of(c) == ns && c.labels.get(store::LABEL_POD) == Some(&full_name));
                let by_owner = mains(&|c| ns_of(c) == ns && c.labels.get(store::LABEL_DEPLOYMENT) == Some(&name));
                if !exact.is_empty() {
                    for c in exact { print(c); }
                } else if !by_owner.is_empty() {
                    for c in by_owner { print(c); }
                } else {
                    // Not on this node — in a cluster the pod may live on a
                    // peer. Find its owner and fetch the logs from there.
                    match reconcile::find_pod_node(&world, &full_name).filter(|(_, _, pns)| *pns == ns) {
                        Some((node, addr, pns)) => match reconcile::fetch_remote_logs(&addr, &pns, &full_name) {
                            Ok(logs) => {
                                let clean: String = logs.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).collect();
                                println!("  ── {pns}/{full_name} (on {node}){stream_label} ──");
                                println!("{clean}");
                            }
                            Err(e) => eprintln!("  Pod '{ns}/{full_name}' is on {node} but log fetch failed: {e}"),
                        },
                        None => eprintln!("  Pod '{ns}/{full_name}' not found"),
                    }
                }
            }
        }

        Commands::Wake { deployment } => {
            let (ns, name) = cli_deployment_ref(&deployment);
            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);

            if let Some(dep) = world.deployments.get_mut(&store::obj_key(&ns, &name)) {
                if dep.paused {
                    dep.paused = false;
                    dep.idle_since = None;
                    println!("  ☀ Waking {name} ({} replicas)...", dep.replicas);
                    let log = cli_reconcile(&state_path, &mut world, &mut brain);
                    for line in &log { println!("{line}"); }
                    save_state(&state_path, &mut world);
                } else {
                    println!("  {name} is not paused");
                }
            } else {
                eprintln!("  ✗ deployment '{name}' not found in namespace {ns}");
                std::process::exit(1);
            }
        }

        Commands::Scale { deployment, replicas } => {
            let (ns, name) = cli_deployment_ref(&deployment);
            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);

            if let Some(dep) = world.deployments.get_mut(&store::obj_key(&ns, &name)) {
                let old = dep.replicas;
                dep.replicas = replicas;
                println!("  Scaling {name}: {old} → {replicas}");
                let log = cli_reconcile(&state_path, &mut world, &mut brain);
                for line in &log { println!("{line}"); }
                save_state(&state_path, &mut world);
            } else {
                eprintln!("  Deployment '{name}' not found in namespace {ns}");
                std::process::exit(1);
            }
        }

        Commands::Repo { action } => {
            let mut world = load_state(&state_path);

            match action {
                RepoAction::Add { name, source, branch, pipeline } => {
                    let (url, path) = if source.starts_with("http") || source.starts_with("git@") {
                        (Some(source.clone()), None)
                    } else {
                        (None, Some(source.clone()))
                    };

                    let has_pipeline = pipeline.is_some();
                    world.repositories.insert(name.clone(), reconcile::StoredRepository {
                        name: name.clone(),
                        url,
                        path,
                        branch: branch.clone(),
                        secret_ref: None,
                        pipeline,
                        last_commit: None,
                    });

                    let trigger = if has_pipeline { " (auto-trigger enabled)" } else { "" };
                    println!("  ✓ repository/{name} registered ({source}:{branch}){trigger}");
                    save_state(&state_path, &mut world);
                }
                RepoAction::List => {
                    if world.repositories.is_empty() {
                        println!("  No repositories registered.");
                        println!("  Use 'royak repo add <name> <path/url>' to register one.");
                    } else {
                        println!("  {:<15} {:<35} {:<10} {:<15} {}", "NAME", "SOURCE", "BRANCH", "PIPELINE", "LAST COMMIT");
                        println!("  {}", "─".repeat(85));
                        for (name, r) in &world.repositories {
                            let source = r.url.as_deref().or(r.path.as_deref()).unwrap_or("?");
                            let short_src = if source.len() > 33 { &source[source.len()-33..] } else { source };
                            let pipe = r.pipeline.as_deref().unwrap_or("-");
                            let commit = r.last_commit.as_ref()
                                .map(|c| c[..8.min(c.len())].to_string())
                                .unwrap_or_else(|| "-".to_string());
                            println!("  {:<15} {:<35} {:<10} {:<15} {}", name, short_src, r.branch, pipe, commit);
                        }
                    }
                }
                RepoAction::Remove { name } => {
                    if world.repositories.remove(&name).is_some() {
                        println!("  ✓ repository/{name} removed");
                        save_state(&state_path, &mut world);
                    } else {
                        eprintln!("  ✗ repository/{name} not found");
                    }
                }
            }
        }

        Commands::Pipeline { action } => {
            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);

            match action {
                PipelineAction::Run { name } => {
                    match reconcile::start_pipeline(&mut world, &name) {
                        Ok(run_id) => {
                            println!("  ✓ pipeline/{name} started (run #{run_id})\n");
                            // Execute stages immediately in a reconcile loop
                            let max_ticks = 60; // max 60 ticks (5 min with 5s interval)
                            for tick in 0..max_ticks {
                                let log = cli_reconcile(&state_path, &mut world, &mut brain);
                                let pipeline_lines: Vec<&String> = log.iter()
                                    .filter(|l| l.contains("[pipeline]") || l.contains("[start]") || l.contains("✓") || l.contains("✗"))
                                    .collect();
                                if !pipeline_lines.is_empty() {
                                    println!("  ── tick {} ──", tick + 1);
                                    for line in &pipeline_lines {
                                        println!("{line}");
                                    }
                                }
                                // Check if pipeline is done
                                if world.pipeline_runs.is_empty() {
                                    println!("\n  ✓ pipeline/{name} completed!");
                                    break;
                                }
                                std::thread::sleep(std::time::Duration::from_secs(2));
                            }
                            save_state(&state_path, &mut world);
                        }
                        Err(e) => eprintln!("  ✗ {e}"),
                    }
                }
                PipelineAction::Status => {
                    if world.pipeline_runs.is_empty() {
                        println!("  No active pipeline runs.");
                    } else {
                        for run in &world.pipeline_runs {
                            println!("  pipeline/{} (run #{}):", run.pipeline, run.run_id);
                            for (name, status) in &run.stage_status {
                                let symbol = match status {
                                    reconcile::StageStatus::Pending => "○",
                                    reconcile::StageStatus::Running => "◉",
                                    reconcile::StageStatus::Succeeded => "✓",
                                    reconcile::StageStatus::Failed => "✗",
                                    reconcile::StageStatus::Skipped => "⊘",
                                };
                                println!("    {symbol} {name}");
                            }
                        }
                    }
                }
                PipelineAction::List => {
                    if world.pipelines.is_empty() {
                        println!("  No pipelines defined.");
                        println!("  Use 'royak apply pipeline.yaml' to define one.");
                    } else {
                        println!("  {:<20} {:<10} {}", "NAME", "STAGES", "TRIGGERS");
                        println!("  {}", "─".repeat(50));
                        for (name, p) in &world.pipelines {
                            let triggers: Vec<&str> = p.triggers.iter()
                                .map(|t| t.trigger_type.as_str()).collect();
                            println!("  {:<20} {:<10} {}",
                                name, p.stages.len(), triggers.join(", "));
                        }
                    }
                }
            }
        }

        Commands::Rollback { deployment } => {
            let (ns, name) = cli_deployment_ref(&deployment);
            let key = store::obj_key(&ns, &name);
            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);
            let Some(dep) = world.deployments.get_mut(&key) else {
                eprintln!("  ✗ deployment {ns}/{name} not found");
                std::process::exit(1);
            };
            let Some(old_image) = dep.previous_image.clone() else {
                eprintln!("  ✗ no rollback available for {ns}/{name} (no previous image)");
                std::process::exit(1);
            };
            // Changing the image changes the pod template hash, so the normal
            // rolling update replaces the pods.
            println!("  Rolling back {ns}/{name} to {old_image}...");
            dep.previous_image = Some(dep.image.clone());
            dep.image = old_image.clone();
            if let Some(c) = dep.containers.first_mut() { c.image = old_image.clone(); }
            world.record_event("Deployment", &key, "RolledBack", &format!("Rolled back to {old_image}"), "Normal");
            // Drive the rollout to completion, like `apply` does.
            for tick in 0..30 {
                let log = cli_reconcile(&state_path, &mut world, &mut brain);
                for line in &log { println!("{line}"); }
                if world.pending_rollouts.is_empty() { break; }
                if tick < 29 { std::thread::sleep(std::time::Duration::from_secs(2)); }
            }
            if !world.pending_rollouts.is_empty() {
                eprintln!("  ✗ rollback of {ns}/{name} did not complete within 60s; the rollout continues on the next reconcile");
                std::process::exit(1);
            }
        }

        Commands::Backup { file } => {
            // A backup is the complete state in the same v2 format the server
            // loads (secrets sealed with this node's secret key).
            let world = load_state(&state_path);
            match persist::encode(&world.to_state(), &[]).and_then(|b| persist::atomic_write(&file, &b)) {
                Ok(()) => println!("  ✓ cluster state backed up to {file}"),
                Err(e) => { eprintln!("  ✗ backup failed: {e}"); std::process::exit(3); }
            }
        }

        Commands::Restore { file } => {
            // Restore REPLACES desired state with the backup (no merge), through
            // the offline owner-locked save: refused while a server owns it.
            let content = match std::fs::read_to_string(&file) {
                Ok(c) => c,
                Err(e) => { eprintln!("  ✗ read error: {e}"); std::process::exit(3); }
            };
            let (state, _, _) = match persist::decode(&content) {
                Ok(d) => d,
                Err(e) => { eprintln!("  ✗ {file}: {e}"); std::process::exit(3); }
            };
            let mut world = load_state(&state_path);
            let gen = world.generation;
            world.install_state(state);
            world.generation = gen;
            save_state(&state_path, &mut world);
            println!("  ✓ restored from {file} ({} deployments, {} namespaces)", world.deployments.len(), world.namespaces.len());
        }

        Commands::Demo => {
            run_demo();
        }

        Commands::Pull { image, runtime: rt } => {
            let r = runtime::get_runtime(&rt);
            println!("  Pulling {image} via {} runtime...", r.name());
            match r.pull(&image) {
                Ok(()) => println!("  ✓ {image} pulled successfully"),
                Err(e) => eprintln!("  ✗ pull failed: {e}"),
            }
        }

        Commands::Mesh { port } => {
            let world = load_state(&state_path);
            let world_arc = Arc::new(RwLock::new(world));
            let local_node = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("HOST"))
                .unwrap_or_else(|_| "localhost".to_string());
            println!("  ⚡ Mesh proxy mode — cross-node service routing [v0.3 MVP]");
            println!("     Host header → Router::resolve → forward to pod or remote mesh");
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");
            rt.block_on(cluster_mesh::run_proxy(port, local_node, world_arc, false));
        }
    }
}

// ─── Cascade delete ───


// ─── Kubeconfig generation ───

fn generate_kubeconfig(port: u16, token: &str, tls: bool) {
    let proto = if tls { "https" } else { "http" };
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let tls_extra = if tls {
        format!("\n    certificate-authority: {home}/.kube/royak-ca.pem")
    } else {
        String::new()
    };
    let kubeconfig = format!(r#"apiVersion: v1
kind: Config
clusters:
- cluster:
    server: {proto}://127.0.0.1:{port}{tls_extra}
  name: royak
contexts:
- context:
    cluster: royak
    user: royak-admin
    namespace: default
  name: royak
current-context: royak
users:
- name: royak-admin
  user:
    token: {token}
"#);

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let kube_dir = format!("{home}/.kube");
    std::fs::create_dir_all(&kube_dir).ok();
    let path = format!("{kube_dir}/royak.yaml");
    // The kubeconfig carries the admin bearer token: owner-only permissions.
    if persist::atomic_write(&path, kubeconfig.as_bytes()).is_ok() {
        println!("  ✓ kubeconfig written to {path}");
        println!("    export KUBECONFIG={path}");
        println!("    kubectl get nodes");
    }
}

// ─── State persistence (replaces etcd) ───

/// Get or generate the master encryption key for secrets.
/// Priority: 1) ROYAK_SECRET_KEY env var  2) ~/.royak/secret.key file  3) auto-generate
fn get_secret_key() -> [u8; 32] {
    // 1. Environment variable (explicit, for production/CI)
    if let Ok(key_hex) = std::env::var("ROYAK_SECRET_KEY") {
        let mut key = [0u8; 32];
        let bytes: Vec<u8> = (0..key_hex.len()).step_by(2)
            .filter_map(|i| u8::from_str_radix(&key_hex[i..i.min(key_hex.len()-1)+2], 16).ok())
            .collect();
        for (i, &b) in bytes.iter().enumerate() {
            if i < 32 { key[i] = b; }
        }
        return key;
    }

    // 2. Key file (auto-generated on first run, mode 0600)
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let key_dir = format!("{home}/.royak");
    let key_path = format!("{key_dir}/secret.key");

    if let Ok(key_hex) = std::fs::read_to_string(&key_path) {
        let mut key = [0u8; 32];
        let bytes: Vec<u8> = (0..key_hex.trim().len()).step_by(2)
            .filter_map(|i| u8::from_str_radix(&key_hex.trim()[i..i+2], 16).ok())
            .collect();
        for (i, &b) in bytes.iter().enumerate() {
            if i < 32 { key[i] = b; }
        }
        return key;
    }

    // 3. Generate new random key and save it
    let mut key = [0u8; 32];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut key);
    let key_hex: String = key.iter().map(|b| format!("{b:02x}")).collect();

    std::fs::create_dir_all(&key_dir).ok();
    if std::fs::write(&key_path, &key_hex).is_ok() {
        // Restrict permissions to owner-only (0600)
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).ok();
        }
        eprintln!("  [security] master key generated: {key_path} (mode 0600)");
    }
    key
}

/// Encrypt a secret value for at-rest storage (AES-256-GCM, random nonce).
pub fn encrypt_secret_value(plaintext: &str) -> Result<String, String> {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    let key = get_secret_key();
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher.encrypt(nonce, plaintext.as_bytes()).map_err(|_| "secret encryption failed".to_string())?;
    let mut out = String::from("enc:");
    for b in &nonce_bytes { out.push_str(&format!("{b:02x}")); }
    for b in &ct { out.push_str(&format!("{b:02x}")); }
    Ok(out)
}

/// Decrypt an at-rest secret value. Unlike the old reader this never hands
/// the ciphertext back as if it were the value: a wrong key or tampered data
/// is an error.
pub fn decrypt_secret_value_strict(stored: &str) -> Result<String, String> {
    let Some(hex) = stored.strip_prefix("enc:") else { return Ok(stored.to_string()) };
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    if hex.len() < 24 + 32 || hex.len() % 2 != 0 { return Err("sealed value too short".into()); }
    let bytes: Vec<u8> = (0..hex.len()).step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "sealed value is not hex".to_string()))
        .collect::<Result<_, _>>()?;
    let key = get_secret_key();
    let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
    let pt = cipher.decrypt(Nonce::from_slice(&bytes[..12]), &bytes[12..])
        .map_err(|_| "cannot decrypt (wrong secret key or tampered data)".to_string())?;
    String::from_utf8(pt).map_err(|_| "decrypted value is not UTF-8".to_string())
}

/// Resolved state path for this process — set once at startup so the API
/// layer can persist mutations write-through without threading the path
/// through every handler signature.
pub static STATE_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The state path the process was started with (default if unset, e.g. tests).
pub fn state_path() -> &'static str {
    STATE_PATH.get().map(|s| s.as_str()).unwrap_or(".royak-state.json")
}

/// Read a v0/v1 state document (the pre-namespacing format) into a world
/// whose maps are still keyed by bare name. Only used for migration
/// (`persist::decode`), which re-keys everything to `namespace/name`.
pub fn load_v1_world(state: &serde_json::Value) -> Result<DesiredWorld, String> {
    let mut world = DesiredWorld::new();
    let mut secret_err: Option<String> = None;
    {
        {
            // Stored manifests (client-side apply source of truth)
            if let Some(mans) = state["manifests"].as_object() {
                for (k, v) in mans {
                    world.manifests.insert(k.clone(), v.clone());
                }
            }

            // Deployments
            if let Some(deps) = state["deployments"].as_array() {
                for item in deps {
                    let parse_container = |c: &serde_json::Value| -> reconcile::StoredContainer {
                        let volumes: Vec<(String, String)> = c["volumes"].as_array()
                            .map(|arr| arr.iter().filter_map(|v| {
                                let h = v["host"].as_str()?;
                                let p = v["container"].as_str()?;
                                Some((h.to_string(), p.to_string()))
                            }).collect())
                            .unwrap_or_default();
                        reconcile::StoredContainer {
                            name: c["name"].as_str().unwrap_or("").to_string(),
                            image: c["image"].as_str().unwrap_or("").to_string(),
                            command: c["command"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                            env: c["env"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                            env_from_configmaps: c["envFromConfigmaps"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                            env_from_secrets: c["envFromSecrets"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(), env_refs: vec![],
                            volumes,
                            liveness_probe: c.get("livenessProbe").and_then(|p| {
                                if p.is_null() { return None; }
                                Some(reconcile::StoredProbe {
                                    http_get: p["httpGet"].as_array().and_then(|a| Some((a[0].as_str()?.to_string(), a[1].as_u64()? as u16))),
                                    exec: p["exec"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                                    initial_delay_seconds: p["initialDelay"].as_u64().unwrap_or(5),
                                    period_seconds: p["period"].as_u64().unwrap_or(10),
                                    failure_threshold: p["failureThreshold"].as_u64().unwrap_or(3) as u32,
                                })
                            }),
                            readiness_probe: c.get("readinessProbe").and_then(|p| {
                                if p.is_null() { return None; }
                                Some(reconcile::StoredProbe {
                                    http_get: p["httpGet"].as_array().and_then(|a| Some((a[0].as_str()?.to_string(), a[1].as_u64()? as u16))),
                                    exec: p["exec"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                                    initial_delay_seconds: p["initialDelay"].as_u64().unwrap_or(5),
                                    period_seconds: p["period"].as_u64().unwrap_or(10),
                                    failure_threshold: p["failureThreshold"].as_u64().unwrap_or(3) as u32,
                                })
                            }),
                            startup_probe: c.get("startupProbe").and_then(|p| {
                                if p.is_null() { return None; }
                                Some(reconcile::StoredProbe {
                                    http_get: p["httpGet"].as_array().and_then(|a| Some((a[0].as_str()?.to_string(), a[1].as_u64()? as u16))),
                                    exec: p["exec"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                                    initial_delay_seconds: p["initialDelay"].as_u64().unwrap_or(5),
                                    period_seconds: p["period"].as_u64().unwrap_or(10),
                                    failure_threshold: p["failureThreshold"].as_u64().unwrap_or(3) as u32,
                                })
                            }),
                        }
                    };
                    let resource_limits = item.get("resourceLimits").and_then(|r| {
                        if r.is_null() { return None; }
                        Some(reconcile::ResourceLimits {
                            cpu_request: r["cpuRequest"].as_f64().map(|v| v as f32),
                            cpu_limit: r["cpuLimit"].as_f64().map(|v| v as f32),
                            mem_request: r["memRequest"].as_u64(),
                            mem_limit: r["memLimit"].as_u64(),
                        })
                    });
                    let init_containers: Vec<reconcile::StoredContainer> = item["initContainers"].as_array()
                        .map(|arr| arr.iter().map(|c| parse_container(c)).collect())
                        .unwrap_or_default();
                    let dep = reconcile::StoredDeployment {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        replicas: item["replicas"].as_u64().unwrap_or(1) as u32,
                        image: item["image"].as_str().unwrap_or("").to_string(),
                        previous_image: item["previousImage"].as_str().map(|s| s.to_string()),
                        command: item["command"].as_array().map(|a| {
                            a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()
                        }),
                        env: item["env"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                        init_containers,
                        resource_limits,
                        restart_nonce: 0,
                        strategy: item.get("strategy").and_then(|s| {
                            if s.is_null() { return None; }
                            Some(match s["type"].as_str().unwrap_or("") {
                                "Canary" => reconcile::DeployStrategy::Canary {
                                    weight: s["weight"].as_u64().unwrap_or(10) as u32,
                                    steps: vec![],
                                },
                                "BlueGreen" => reconcile::DeployStrategy::BlueGreen {
                                    active: s["active"].as_str().unwrap_or("green").to_string(),
                                },
                                "RollingUpdate" => reconcile::DeployStrategy::RollingUpdate {
                                    max_surge: s["maxSurge"].as_u64().unwrap_or(1) as u32,
                                    max_unavailable: s["maxUnavailable"].as_u64().unwrap_or(0) as u32,
                                },
                                _ => return None,
                            })
                        }),
                        pause_after_idle: item["pauseAfterIdle"].as_u64(),
                        paused: item["paused"].as_bool().unwrap_or(false),
                        idle_since: None,
                        stateful: item["stateful"].as_bool().unwrap_or(false),
                        owner_ref: item["ownerRef"].as_str().map(|s| s.to_string()),
                        containers: item["containers"].as_array()
                            .map(|arr| arr.iter().map(|c| parse_container(c)).collect())
                            .unwrap_or_else(|| vec![parse_container(&serde_json::json!({
                                "name": "main",
                                "image": item["image"].as_str().unwrap_or(""),
                                "command": item["command"], "env": item["env"],
                            }))]),
                    };
                    world.deployments.insert(dep.name.clone(), dep);
                }
            }
            // ConfigMaps
            if let Some(cms) = state["configmaps"].as_array() {
                for item in cms {
                    let mut data = std::collections::HashMap::new();
                    if let Some(d) = item["data"].as_object() {
                        for (k, v) in d {
                            if let Some(val) = v.as_str() {
                                data.insert(k.clone(), val.to_string());
                            }
                        }
                    }
                    let cm = reconcile::StoredConfigMap {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        data,
                    };
                    world.configmaps.insert(cm.name.clone(), cm);
                }
            }
            // Secrets (decrypt if encrypted at rest)
            if let Some(secs) = state["secrets"].as_array() {
                for item in secs {
                    let is_encrypted = item["encrypted"].as_bool().unwrap_or(false);
                    let mut data = std::collections::HashMap::new();
                    if let Some(d) = item["data"].as_object() {
                        for (k, v) in d {
                            if let Some(val) = v.as_str() {
                                let decrypted = if is_encrypted || val.starts_with("enc:") {
                                    match decrypt_secret_value_strict(val) {
                                        Ok(v) => v,
                                        Err(e) => { secret_err = Some(format!("secret {}: {e}", item["name"].as_str().unwrap_or("?"))); val.to_string() }
                                    }
                                } else { val.to_string() };
                                data.insert(k.clone(), decrypted);
                            }
                        }
                    }
                    let s = reconcile::StoredSecret {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        data,
                    };
                    world.secrets.insert(s.name.clone(), s);
                }
            }
            // Namespaces
            if let Some(nss) = state["namespaces"].as_array() {
                world.namespaces = nss.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect();
            }
            // DaemonSets
            if let Some(dss) = state["daemonsets"].as_array() {
                for item in dss {
                    let ds = reconcile::StoredDaemonSet {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        container: reconcile::StoredContainer {
                            name: item["container"]["name"].as_str().unwrap_or("main").to_string(),
                            image: item["container"]["image"].as_str().unwrap_or("").to_string(),
                            command: item["container"]["command"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                            env: item["container"]["env"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                            volumes: vec![], env_from_configmaps: vec![], env_from_secrets: vec![], env_refs: vec![],
                            liveness_probe: None, readiness_probe: None, startup_probe: None,
                        },
                    };
                    world.daemonsets.insert(ds.name.clone(), ds);
                }
            }
            // Jobs
            if let Some(jobs) = state["jobs"].as_array() {
                for item in jobs {
                    let j = reconcile::StoredJob {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        completions: item["completions"].as_u64().unwrap_or(1) as u32,
                        status: reconcile::JobStatus::Pending,
                        container: reconcile::StoredContainer {
                            name: item["container"]["name"].as_str().unwrap_or("main").to_string(),
                            image: item["container"]["image"].as_str().unwrap_or("").to_string(),
                            command: item["container"]["command"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                            env: item["container"]["env"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                            volumes: vec![], env_from_configmaps: vec![], env_from_secrets: vec![], env_refs: vec![],
                            liveness_probe: None, readiness_probe: None, startup_probe: None,
                        },
                    };
                    world.jobs.insert(j.name.clone(), j);
                }
            }
            // CronJobs
            if let Some(cjs) = state["cronjobs"].as_array() {
                for item in cjs {
                    let cj = reconcile::StoredCronJob {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        schedule: item["schedule"].as_str().unwrap_or("").to_string(),
                        last_run: item["lastRun"].as_u64(),
                        container: reconcile::StoredContainer {
                            name: item["container"]["name"].as_str().unwrap_or("main").to_string(),
                            image: item["container"]["image"].as_str().unwrap_or("").to_string(),
                            command: item["container"]["command"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                            env: item["container"]["env"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                            volumes: vec![], env_from_configmaps: vec![], env_from_secrets: vec![], env_refs: vec![],
                            liveness_probe: None, readiness_probe: None, startup_probe: None,
                        },
                    };
                    world.cronjobs.insert(cj.name.clone(), cj);
                }
            }
            // HPAs
            if let Some(hpas) = state["hpas"].as_array() {
                for item in hpas {
                    let h = reconcile::StoredHPA {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        deployment: item["deployment"].as_str().unwrap_or("").to_string(),
                        min_replicas: item["min"].as_u64().unwrap_or(1) as u32,
                        max_replicas: item["max"].as_u64().unwrap_or(10) as u32,
                        target_cpu: item["cpu"].as_f64().unwrap_or(70.0) as f32,
                        history: Vec::new(),
                        last_scaled: None,
                    };
                    world.hpas.insert(h.name.clone(), h);
                }
            }
            // Services
            if let Some(svcs) = state["services"].as_array() {
                for item in svcs {
                    let ports: Vec<reconcile::ServicePort> = item["ports"].as_array()
                        .map(|arr| arr.iter().map(|p| reconcile::ServicePort {
                            port: p["port"].as_u64().unwrap_or(80) as u16,
                            target_port: p["targetPort"].as_u64().unwrap_or(80) as u16,
                            protocol: p["protocol"].as_str().unwrap_or("TCP").to_string(),
                            node_port: p["nodePort"].as_u64().map(|v| v as u16),
                        }).collect())
                        .unwrap_or_default();
                    let selector: std::collections::HashMap<String, String> = item["selector"].as_object()
                        .map(|m| m.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
                        .unwrap_or_default();
                    let svc = reconcile::StoredService {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        service_type: item["type"].as_str().unwrap_or("ClusterIP").to_string(),
                        selector, ports,
                    };
                    world.services.insert(svc.name.clone(), svc);
                }
            }
            // Ingresses
            if let Some(ings) = state["ingresses"].as_array() {
                for item in ings {
                    let rules = item["rules"].as_array().map(|rules| rules.iter().map(|r| {
                        let paths = r["paths"].as_array().map(|ps| ps.iter().map(|p| {
                            reconcile::IngressPath {
                                path: p["path"].as_str().unwrap_or("/").to_string(),
                                service: p["service"].as_str().unwrap_or("").to_string(),
                                port: p["port"].as_u64().unwrap_or(80) as u16,
                            }
                        }).collect()).unwrap_or_default();
                        reconcile::IngressRule { host: r["host"].as_str().unwrap_or("*").to_string(), paths }
                    }).collect()).unwrap_or_default();
                    let i = reconcile::StoredIngress {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        rules,
                        ingress_class: item["ingressClassName"].as_str().map(|s| s.to_string()),
                    };
                    world.ingresses.insert(i.name.clone(), i);
                }
            }
            // Network Policies
            if let Some(nps) = state["network_policies"].as_array() {
                for item in nps {
                    let np = reconcile::StoredNetworkPolicy {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        pod_selector: item["selector"].as_str().unwrap_or("*").to_string(),
                        ingress_allow: item["ingress_allow"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                        egress_allow: item["egress_allow"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                            .unwrap_or_default(),
                        ingress_ports: item["ingress_ports"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_u64().map(|p| p as u16)).collect())
                            .unwrap_or_default(),
                        egress_ports: item["egress_ports"].as_array()
                            .map(|a| a.iter().filter_map(|v| v.as_u64().map(|p| p as u16)).collect())
                            .unwrap_or_default(),
                        internal: item["internal"].as_bool().unwrap_or(false),
                        mtls_required: item["mtls"].as_bool().unwrap_or(false),
                        deny_all: item["denyAll"].as_bool().unwrap_or(false),
                    };
                    world.network_policies.insert(np.name.clone(), np);
                }
            }
            // Resource Quotas
            if let Some(quotas) = state["resource_quotas"].as_array() {
                for item in quotas {
                    let q = reconcile::StoredResourceQuota {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        hard_cpu: item["cpu"].as_f64().map(|v| v as f32),
                        hard_memory: item["memory"].as_u64(),
                        hard_pods: item["pods"].as_u64().map(|v| v as u32),
                        hard_services: item["services"].as_u64().map(|v| v as u32),
                        hard_configmaps: item["configmaps"].as_u64().map(|v| v as u32),
                        hard_secrets: item["secrets"].as_u64().map(|v| v as u32),
                    };
                    world.resource_quotas.insert(format!("{}/{}", q.namespace, q.name), q);
                }
            }
            // PVs
            if let Some(pvs) = state["pvs"].as_array() {
                for item in pvs {
                    let pv = reconcile::StoredPV {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        capacity: item["capacity"].as_str().unwrap_or("1Gi").to_string(),
                        storage_class: item["class"].as_str().unwrap_or("local").to_string(),
                        host_path: item["path"].as_str().unwrap_or("/data").to_string(),
                        access_mode: item["access"].as_str().unwrap_or("ReadWriteOnce").to_string(),
                        status: match item["status"].as_str().unwrap_or("Available") {
                            "Bound" => reconcile::PVStatus::Bound,
                            "Released" => reconcile::PVStatus::Released,
                            _ => reconcile::PVStatus::Available,
                        },
                        bound_to: item["boundTo"].as_str().map(|s| s.to_string()),
                    };
                    world.pvs.insert(pv.name.clone(), pv);
                }
            }
            // PVCs
            if let Some(pvcs) = state["pvcs"].as_array() {
                for item in pvcs {
                    let pvc = reconcile::StoredPVC {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        storage_class: item["class"].as_str().unwrap_or("local").to_string(),
                        requested: item["requested"].as_str().unwrap_or("1Gi").to_string(),
                        access_mode: item["access"].as_str().unwrap_or("ReadWriteOnce").to_string(),
                        bound_pv: item["bound"].as_str().map(|s| s.to_string()),
                    };
                    world.pvcs.insert(pvc.name.clone(), pvc);
                }
            }
            // Pipelines
            if let Some(pipes) = state["pipelines"].as_array() {
                for item in pipes {
                    let triggers: Vec<reconcile::StoredTrigger> = item["triggers"].as_array()
                        .map(|arr| arr.iter().map(|t| reconcile::StoredTrigger {
                            trigger_type: t["type"].as_str().unwrap_or("manual").to_string(),
                            path: t["path"].as_str().map(|s| s.to_string()),
                        }).collect())
                        .unwrap_or_default();
                    let stages: Vec<reconcile::StoredStage> = item["stages"].as_array()
                        .map(|arr| arr.iter().map(|s| reconcile::StoredStage {
                            name: s["name"].as_str().unwrap_or("").to_string(),
                            image: s["image"].as_str().map(|s| s.to_string()),
                            command: s["command"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                            action: s["action"].as_str().map(|s| s.to_string()),
                            file: s["file"].as_str().map(|s| s.to_string()),
                            context: s["context"].as_str().map(|s| s.to_string()),
                            dockerfile: s["dockerfile"].as_str().map(|s| s.to_string()),
                            tag: s["tag"].as_str().map(|s| s.to_string()),
                            build_args: s["args"].as_array()
                                .map(|a| a.iter().filter_map(|v| {
                                    Some((v["name"].as_str()?.to_string(), v["value"].as_str().unwrap_or("").to_string()))
                                }).collect())
                                .unwrap_or_default(),
                            artifacts: s["artifacts"].as_array()
                                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default(),
                            depends_on: s["dependsOn"].as_str().map(|s| s.to_string()),
                            env: s["env"].as_array()
                                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default(),
                            if_condition: s["if"].as_str().map(|s| s.to_string()),
                            matrix_images: s["matrix"]["image"].as_array()
                                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default(),
                            matrix_envs: s["matrix"]["env"].as_array()
                                .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                                .unwrap_or_default(),
                        }).collect())
                        .unwrap_or_default();
                    let p = reconcile::StoredPipeline {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        stages,
                        triggers,
                    };
                    world.pipelines.insert(p.name.clone(), p);
                }
            }
            // Config
            if let Some(cfg) = state.get("config") {
                if let Some(llm) = cfg.get("llm") {
                    if let Some(h) = llm["host"].as_str() { world.config.llm_host = h.to_string(); }
                    if let Some(m) = llm["model"].as_str() { world.config.llm_model = m.to_string(); }
                    if let Some(t) = llm["temperature"].as_f64() { world.config.llm_temperature = t as f32; }
                }
                if let Some(alerts) = cfg.get("alerts") {
                    world.config.alert_webhook = alerts["webhook"].as_str().map(|s| s.to_string());
                    if let Some(a) = alerts["onAnomaly"].as_bool() { world.config.alert_on_anomaly = a; }
                    if let Some(r) = alerts["onRestart"].as_bool() { world.config.alert_on_restart = r; }
                }
                if let Some(r) = cfg["runtime"].as_str() { world.config.runtime = r.to_string(); }
                if let Some(pause) = cfg.get("pause") {
                    if let Some(d) = pause["defaultIdle"].as_u64() { world.config.pause_default_idle = d; }
                    if let Some(e) = pause["enabled"].as_bool() { world.config.pause_enabled = e; }
                }
                if let Some(api) = cfg.get("api") {
                    if let Some(p) = api["port"].as_u64() { world.config.api_port = p as u16; }
                }
            }
            // Functions
            if let Some(fns) = state["functions"].as_array() {
                for item in fns {
                    let f = reconcile::StoredFunction {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        image: item["image"].as_str().unwrap_or("alpine:latest").to_string(),
                        command: item["command"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()),
                        env: item["env"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                        http_triggers: item["httpTriggers"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                        webhook_triggers: item["webhookTriggers"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                        schedule_triggers: item["scheduleTriggers"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                        timeout_secs: item["timeout"].as_u64().unwrap_or(30),
                        memory_mb: item["memory"].as_u64().unwrap_or(128) as u32,
                        code: item["code"].as_str().map(|s| s.to_string()),
                        container_id: None,
                        invocations: item["invocations"].as_u64().unwrap_or(0),
                        last_invoked: None,
                        state: reconcile::FunctionState::Cold,
                    };
                    world.functions.insert(f.name.clone(), f);
                }
            }
            // Repositories
            if let Some(repos) = state["repositories"].as_array() {
                for item in repos {
                    let r = reconcile::StoredRepository {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        url: item["url"].as_str().map(|s| s.to_string()),
                        path: item["path"].as_str().map(|s| s.to_string()),
                        branch: item["branch"].as_str().unwrap_or("main").to_string(),
                        secret_ref: item["secretRef"].as_str().map(|s| s.to_string()),
                        pipeline: item["pipeline"].as_str().map(|s| s.to_string()),
                        last_commit: item["lastCommit"].as_str().map(|s| s.to_string()),
                    };
                    world.repositories.insert(r.name.clone(), r);
                }
            }
            // RBAC Roles
            if let Some(roles) = state["rbac_roles"].as_array() {
                for item in roles {
                    let rules: Vec<reconcile::RbacRule> = item["rules"].as_array()
                        .map(|arr| arr.iter().map(|r| {
                            let get_strs = |key: &str| -> Vec<String> {
                                r[key].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_else(|| vec!["*".to_string()])
                            };
                            reconcile::RbacRule { resources: get_strs("resources"), verbs: get_strs("verbs"), namespaces: get_strs("namespaces"), resource_names: vec![] }
                        }).collect())
                        .unwrap_or_default();
                    let name = item["name"].as_str().unwrap_or("").to_string();
                    world.rbac_roles.insert(name.clone(), reconcile::RbacRole { name, rules, namespace: None, kind: "RbacRole".to_string() });
                }
            }
            // Guards
            if let Some(guards) = state["guards"].as_array() {
                for item in guards {
                    let rules: Vec<reconcile::GuardRule> = item["rules"].as_array()
                        .map(|arr| arr.iter().map(|r| reconcile::GuardRule {
                            when: r["when"].as_str().unwrap_or("").to_string(),
                            action: r["action"].as_str().unwrap_or("").to_string(),
                            params: r["params"].as_object().map(|m| m.iter().filter_map(|(k,v)| Some((k.clone(), v.as_str()?.to_string()))).collect()).unwrap_or_default(),
                        }).collect())
                        .unwrap_or_default();
                    let hooks: std::collections::HashMap<String, String> = item["hooks"].as_object()
                        .map(|m| m.iter().filter_map(|(k,v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
                        .unwrap_or_default();
                    let name = item["name"].as_str().unwrap_or("").to_string();
                    world.guards.insert(name.clone(), reconcile::Guard { name, rules, hooks });
                }
            }
            // Operators
            if let Some(ops) = state["operators"].as_array() {
                for item in ops {
                    let provision: Vec<reconcile::OperatorComponent> = item["provision"].as_array()
                        .map(|arr| arr.iter().map(|c| reconcile::OperatorComponent {
                            role: c["role"].as_str().unwrap_or("").to_string(),
                            image: c["image"].as_str().unwrap_or("").to_string(),
                            replicas: c["replicas"].as_u64().unwrap_or(1) as u32,
                            env: c["env"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                            volumes: vec![], ports: vec![],
                        }).collect())
                        .unwrap_or_default();
                    let hooks: std::collections::HashMap<String, String> = item["hooks"].as_object()
                        .map(|m| m.iter().filter_map(|(k,v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
                        .unwrap_or_default();
                    let name = item["name"].as_str().unwrap_or("").to_string();
                    let custom_kind = item["customKind"].as_str().unwrap_or("").to_string();
                    world.operators.insert(name.clone(), reconcile::Operator { name, custom_kind, provision, hooks, rules: vec![] });
                }
            }
            // Custom Resources
            if let Some(crs) = state["custom_resources"].as_array() {
                for item in crs {
                    let name = item["name"].as_str().unwrap_or("").to_string();
                    let status = match item["status"].as_str().unwrap_or("Pending") {
                        "Provisioning" => reconcile::CRStatus::Provisioning,
                        "Running" => reconcile::CRStatus::Running,
                        "Failed" => reconcile::CRStatus::Failed,
                        _ => reconcile::CRStatus::Pending,
                    };
                    world.custom_resources.insert(name.clone(), reconcile::CustomResource {
                        name, kind: item["kind"].as_str().unwrap_or("").to_string(),
                        namespace: item["namespace"].as_str().unwrap_or("default").to_string(),
                        spec: serde_json::from_value(item["spec"].clone()).unwrap_or(serde_json::json!({})),
                        status,
                    });
                }
            }
            // Admission webhooks
            if let Some(hooks) = state["admission_webhooks"].as_array() {
                for item in hooks {
                    let name = item["name"].as_str().unwrap_or("").to_string();
                    world.admission_webhooks.insert(name.clone(), reconcile::AdmissionWebhook {
                        name,
                        url: item["url"].as_str().unwrap_or("").to_string(),
                        kinds: item["kinds"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
                        failure_policy: item["failurePolicy"].as_str().unwrap_or("Fail").to_string(),
                    });
                }
            }
            // Nodes
            if let Some(nodes) = state["nodes"].as_array() {
                for item in nodes {
                    let n = reconcile::ClusterNode {
                        name: item["name"].as_str().unwrap_or("").to_string(),
                        address: item["address"].as_str().unwrap_or("").to_string(),
                        cpu_capacity: item["cpuCapacity"].as_f64().unwrap_or(100.0) as f32,
                        mem_capacity: item["memCapacity"].as_f64().unwrap_or(8192.0) as f32,
                        cpu_used: item["cpuUsed"].as_f64().unwrap_or(0.0) as f32,
                        mem_used: item["memUsed"].as_f64().unwrap_or(0.0) as f32,
                        pod_count: item["podCount"].as_u64().unwrap_or(0) as u32,
                        status: match item["status"].as_str().unwrap_or("Ready") {
                            "NotReady" => reconcile::NodeStatus::NotReady,
                            "Draining" => reconcile::NodeStatus::Draining,
                            _ => reconcile::NodeStatus::Ready,
                        },
                        last_heartbeat: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default().as_secs(),
                        neural_token: vec![],
                        joined_at: item["joinedAt"].as_u64().unwrap_or(0),
                    };
                    world.nodes.insert(n.name.clone(), n);
                }
            }
        }
    }
    if let Some(e) = secret_err { return Err(e); }
    Ok(world)
}

/// Load desired state for this process, or exit: an unreadable or corrupt
/// state file must never turn into an empty cluster that reconcile would act on.
/// Token for CLI commands that call a running server's API: ROYAK_TOKEN, else
/// the admin token a local server generated in the data dir.
fn cli_bearer() -> Option<String> {
    std::env::var("ROYAK_TOKEN").ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty())
        .or_else(|| std::fs::read_to_string(format!("{}/admin.token", reconcile::royak_data_dir()))
            .ok().map(|t| t.trim().to_string()).filter(|t| !t.is_empty()))
}

fn load_state(path: &str) -> DesiredWorld {
    match persist::load(path) {
        Ok(l) => {
            if let Some(v) = l.migrated_from {
                eprintln!("  [migrate] {path}: state schema v{v} → v{} (in memory; written on first save, original kept as {path}.v1.bak)", persist::SCHEMA_VERSION);
            }
            let mut w = DesiredWorld::new();
            w.install_state(l.state);
            for n in l.nodes { w.nodes.insert(n.name.clone(), n); }
            w
        }
        Err(e) => {
            eprintln!("  ✗ cannot load state: {e}");
            std::process::exit(2);
        }
    }
}

/// The CLI's owner lock, taken by the first offline write and held until the
/// command exits, so no server can start acting on the state in between.
static CLI_OWNER: std::sync::Mutex<Option<persist::OwnerLock>> = std::sync::Mutex::new(None);

/// Offline (no server) state write used by CLI commands. Refuses while a
/// server owns the state file — the server's API is the only writer then.
/// Exits non-zero on any failure: a CLI change is reported only once durable.
pub fn save_state(path: &str, world: &mut DesiredWorld) {
    let mut held = CLI_OWNER.lock().unwrap_or_else(|e| e.into_inner());
    if held.is_none() {
        match persist::try_own(path) {
            Ok(Some(l)) => *held = Some(l),
            Ok(None) => {
                eprintln!("  ✗ a running Royak server owns {path}; send the change through its API (kubectl) instead");
                std::process::exit(3);
            }
            Err(e) => { eprintln!("  ✗ {e}"); std::process::exit(3); }
        }
    }
    let on_disk = persist::load(path).map(|l| (l.state, l.migrated_from));
    let mut next = world.to_state();
    match on_disk {
        Ok((cur, migrated)) => {
            if cur.generation > world.generation {
                eprintln!("  ✗ {path} changed since it was read (generation {} > {}); not overwriting", cur.generation, world.generation);
                std::process::exit(3);
            }
            if migrated.is_some() {
                if let Err(e) = persist::backup_before_migration(path) { eprintln!("  ✗ {e}"); std::process::exit(3); }
            }
            if next.same_content(&cur) && migrated.is_none() { world.generation = cur.generation; return; }
            next.generation = cur.generation + 1;
        }
        Err(e) => { eprintln!("  ✗ {e}"); std::process::exit(3); }
    }
    if let Err(e) = persist::save(path, &next, &world.nodes_for_save()) {
        eprintln!("  ✗ state NOT saved: {e}");
        std::process::exit(3);
    }
    // Later saves in the same command build on what was just written.
    world.generation = next.generation;
}

/// This node's pods (this cluster's own containers, by label) as census
/// entries — what file-mode CLI commands show and count.
fn cli_local_pods(world: &DesiredWorld) -> Vec<placement::PodView> {
    let all = docker::list_containers(true).unwrap_or_default();
    let ours = reconcile::our_containers(world, &all);
    reconcile::local_views(world, &ours)
}

/// `pod` or `namespace/pod` → (namespace, pod).
fn cli_pod_ref(arg: &str) -> (String, String) {
    match arg.split_once('/') {
        Some((ns, pod)) => (ns.to_string(), pod.to_string()),
        None => (store::DEFAULT_NS.to_string(), arg.to_string()),
    }
}

/// `name`, `deployment/name`, `namespace/name` or `deployment/namespace/name`
/// → (namespace, name).
fn cli_deployment_ref(arg: &str) -> (String, String) {
    let rest = arg.strip_prefix("deployment/").or_else(|| arg.strip_prefix("deploy/")).unwrap_or(arg);
    cli_pod_ref(rest)
}

/// Offline CLI reconcile: the desired change is made durable FIRST, then one
/// reconcile pass acts on it, then any bookkeeping that pass produced is saved.
fn cli_reconcile(path: &str, world: &mut DesiredWorld, brain: &mut OrinBrain) -> Vec<String> {
    save_state(path, world);
    let log = reconcile::reconcile_once(world, brain);
    save_state(path, world);
    log
}

fn run_demo() {
    use brain::*;
    println!("\n  ═══ DEMO: Neural Orchestration (simulated) ═══\n");

    let mut brain = OrinBrain::new(32, 4);
    println!("  [brain] {}\n", brain.stats());

    let nodes = vec![
        NodeState { id: "node-1".into(), cpu_avail: 80.0, mem_avail: 8192.0, pod_count: 3, healthy: true },
        NodeState { id: "node-2".into(), cpu_avail: 60.0, mem_avail: 4096.0, pod_count: 5, healthy: true },
        NodeState { id: "node-3".into(), cpu_avail: 90.0, mem_avail: 16384.0, pod_count: 1, healthy: true },
    ];

    let desired = vec![
        DesiredState { name: "web".into(), replicas: 3, image: "nginx".into(), cpu_limit: 50.0, mem_limit: 512.0 },
    ];

    println!("  ─── Tick 1: Schedule pending pods ───");
    let state = ClusterState {
        pods: vec![
            PodState { id: "web-1".into(), name: "web".into(), node: "".into(), status: PodStatus::Pending, cpu_pct: 0.0, mem_mb: 0.0, restarts: 0, age_secs: 0, image: "nginx".into() },
            PodState { id: "web-2".into(), name: "web".into(), node: "".into(), status: PodStatus::Pending, cpu_pct: 0.0, mem_mb: 0.0, restarts: 0, age_secs: 0, image: "nginx".into() },
        ],
        nodes: nodes.clone(),
        desired: desired.clone(),
    };
    let d = brain.tick(&state);
    for a in &d.actions { print_action(a); }

    println!("\n  ─── Tick 2: Pod failure → auto-heal ───");
    let state2 = ClusterState {
        pods: vec![
            PodState { id: "web-1".into(), name: "web".into(), node: "node-3".into(), status: PodStatus::Running, cpu_pct: 30.0, mem_mb: 128.0, restarts: 0, age_secs: 60, image: "nginx".into() },
            PodState { id: "web-2".into(), name: "web".into(), node: "node-1".into(), status: PodStatus::Failed, cpu_pct: 0.0, mem_mb: 0.0, restarts: 2, age_secs: 60, image: "nginx".into() },
        ],
        nodes: nodes.clone(),
        desired: desired.clone(),
    };
    let d2 = brain.tick(&state2);
    for a in &d2.actions { print_action(a); }

    println!("\n  {}", brain.stats());
}

fn print_action(a: &brain::Action) {
    match a {
        brain::Action::Schedule { pod, node } => println!("  ✓ SCHEDULE {pod} → {node}"),
        brain::Action::Scale { name, from, to } => println!("  ⚡ SCALE {name} {from} → {to}"),
        brain::Action::Restart { pod, reason } => println!("  ↻ RESTART {pod} ({reason})"),
        brain::Action::Migrate { pod, from_node, to_node } => println!("  → MIGRATE {pod}: {from_node} → {to_node}"),
        brain::Action::Alert { severity, message } => println!("  ⚠ [{severity}] {message}"),
        brain::Action::Noop => println!("  · ok"),
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    fn tmp_path(tag: &str) -> String {
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        format!("{}/rk-state-{pid}-{nanos}-{tag}.json", std::env::temp_dir().display())
    }

    fn cleanup(path: &str) {
        for suffix in ["", ".nrns", ".lock", ".v1.bak"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
    }

    #[test]
    fn secret_encrypt_decrypt_roundtrip() {
        let plain = "plaintext-sentinel-42";
        let encrypted = encrypt_secret_value(plain).unwrap();
        assert_ne!(encrypted, plain, "encrypted form must differ from plaintext");
        assert!(encrypted.starts_with("enc:"));
        assert_eq!(decrypt_secret_value_strict(&encrypted).unwrap(), plain);
        let mut tampered = encrypted.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == '0' { '1' } else { '0' });
        assert!(decrypt_secret_value_strict(&tampered).is_err(), "tampered ciphertext must not decrypt to itself");
    }

    #[test]
    fn save_load_roundtrip_writes_schema_version() {
        let path = tmp_path("roundtrip");
        cleanup(&path);
        let mut world = DesiredWorld::new();
        save_state(&path, &mut world);
        let content = std::fs::read_to_string(&path).expect("state file written");
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["schemaVersion"].as_u64(), Some(persist::SCHEMA_VERSION as u64));
        cleanup(&path);
    }

    #[test]
    fn owner_ref_survives_save_load_roundtrip() {
        let path = tmp_path("ownerref");
        cleanup(&path);

        let mk = |name: &str, owner: Option<&str>| reconcile::StoredDeployment {
            name: name.to_string(),
            namespace: "default".to_string(),
            replicas: 1,
            init_containers: Vec::new(),
            containers: Vec::new(),
            image: "postgres:16".to_string(),
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
        };

        let mut world = DesiredWorld::new();
        world.deployments.insert("default/db-primary".to_string(), mk("db-primary", Some("db")));
        world.deployments.insert("default/web".to_string(), mk("web", None));

        save_state(&path, &mut world);
        let loaded = load_state(&path);

        assert_eq!(loaded.deployments["default/db-primary"].owner_ref.as_deref(), Some("db"),
            "owner ref must survive the save/load JSON round-trip");
        assert_eq!(loaded.deployments["default/web"].owner_ref, None,
            "absent owner ref must load back as None");
        cleanup(&path);
    }

    #[test]
    fn legacy_state_without_schema_version_migrates() {
        let path = tmp_path("legacy");
        cleanup(&path);
        std::fs::write(&path, r#"{"deployments":[{"name":"web","namespace":"default","replicas":2,"image":"nginx"}],"services":[]}"#).unwrap();
        let l = persist::load(&path).unwrap();
        assert_eq!(l.migrated_from, Some(0));
        assert_eq!(l.state.deployments["default/web"].replicas, 2);
        cleanup(&path);
    }

    #[test]
    fn future_schema_refuses_to_load() {
        let path = tmp_path("future");
        cleanup(&path);
        std::fs::write(&path, r#"{"schemaVersion": 99, "deployments": []}"#).unwrap();
        assert!(persist::load(&path).is_err(), "a newer schema must not load as an empty cluster");
        cleanup(&path);
    }

    /// A crash mid-save leaves a stray temp file; the committed file is intact.
    #[test]
    fn stray_tmp_file_is_ignored() {
        let path = tmp_path("partial");
        cleanup(&path);
        let mut world = DesiredWorld::new();
        world.namespaces.push("kept".into());
        save_state(&path, &mut world);
        std::fs::write(format!("{path}.tmp.12345"), b"partial garbage, not valid json").unwrap();
        let l = persist::load(&path).unwrap();
        assert!(l.state.namespaces.iter().any(|n| n == "kept"));
        let _ = std::fs::remove_file(format!("{path}.tmp.12345"));
        cleanup(&path);
    }

    #[test]
    fn corrupted_state_refuses_instead_of_emptying() {
        let path = tmp_path("corrupt");
        cleanup(&path);
        std::fs::write(&path, b"{{ not valid json at all").unwrap();
        assert!(persist::load(&path).is_err());
        cleanup(&path);
    }

    #[test]
    fn offline_save_is_refused_while_a_server_owns_the_state() {
        let path = tmp_path("owned");
        cleanup(&path);
        let _owner = persist::try_own(&path).unwrap().expect("first owner");
        assert!(persist::try_own(&path).unwrap().is_none());
        cleanup(&path);
    }
}
