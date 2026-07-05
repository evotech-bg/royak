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
        /// Pod name, "all", or deployment name
        pod: String,
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
            let log = reconcile::reconcile_once(&mut world, &mut brain);
            for line in &log {
                println!("{line}");
            }

            // If rolling update in progress, keep reconciling until complete
            if !world.pending_rollouts.is_empty() {
                println!("\n  Rolling update in progress...");
                let max_ticks = 30; // max 30 ticks (60s with 2s sleep)
                for tick in 0..max_ticks {
                    std::thread::sleep(std::time::Duration::from_secs(2));

                    let log = reconcile::reconcile_once(&mut world, &mut brain);
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
                    let log = reconcile::reconcile_once(&mut world, &mut brain);
                    for line in &log { println!("{line}"); }
                }
            }

            save_state(&state_path, &world);
        }

        Commands::Get { resource, output } => {
            // Single resource export: get deployment/web -o yaml
            if resource.contains('/') {
                let parts: Vec<&str> = resource.split('/').collect();
                let (kind, name) = (parts[0], parts[1]);
                let world = load_state(&state_path);

                let yaml_val: Option<serde_json::Value> = match kind {
                    "deployment" | "deploy" => world.deployments.get(name).map(|d| {
                        let containers = docker::list_containers(true).unwrap_or_default();
                        let prefix = format!("rk-{name}-");
                        let ready = containers.iter().filter(|c| c.names.iter().any(|n| n.contains(&prefix)) && c.state == "running").count();
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
                    "service" | "svc" => world.services.get(name).map(|s| serde_json::json!({
                        "apiVersion": "v1", "kind": "Service",
                        "metadata": {"name": s.name, "namespace": s.namespace},
                        "spec": {
                            "type": s.service_type, "selector": s.selector,
                            "ports": s.ports.iter().map(|p| serde_json::json!({"port": p.port, "targetPort": p.target_port, "protocol": p.protocol})).collect::<Vec<_>>()
                        }
                    })),
                    "configmap" | "cm" => world.configmaps.get(name).map(|cm| serde_json::json!({
                        "apiVersion": "v1", "kind": "ConfigMap",
                        "metadata": {"name": cm.name, "namespace": cm.namespace},
                        "data": cm.data
                    })),
                    "secret" => world.secrets.get(name).map(|s| serde_json::json!({
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
                        eprintln!("  {kind}/{name} not found");
                        std::process::exit(1);
                    }
                }
            } else {
            match resource.as_str() {
                "pods" | "pod" | "po" => {
                    match docker::list_containers(true) {
                        Ok(containers) => {
                            let managed: Vec<&docker::DockerContainer> = containers.iter()
                                .filter(|c| c.names.iter().any(|n| n.contains("rk-")))
                                .collect();

                            if managed.is_empty() {
                                println!("  No managed pods found.");
                                println!("  Use 'royak apply <file>' to deploy.");
                            } else {
                                println!("  {:<20} {:<25} {:<12} {}", "NAME", "IMAGE", "STATE", "STATUS");
                                println!("  {}", "─".repeat(70));
                                for c in &managed {
                                    let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                                    println!("  {:<20} {:<25} {:<12} {}",
                                        name, c.image, c.state, c.status);
                                }
                                println!("\n  {} pod(s) total", managed.len());
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
                        // Query Docker for real running counts
                        let containers = docker::list_containers(true).unwrap_or_default();
                        for (name, dep) in &world.deployments {
                            let prefix = format!("rk-{name}-");
                            let ready = containers.iter()
                                .filter(|c| c.names.iter().any(|n| n.contains(&prefix)) && c.state == "running")
                                .count();
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
                    if let Ok(containers) = docker::list_containers(false) {
                        let managed = containers.iter().filter(|c| c.names.iter().any(|n| n.contains("rk-"))).count();
                        println!("  Pods: {managed} running");
                    }
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

            // Delete by YAML file: royak delete -f file.yaml
            if resource == "-f" || resource.ends_with(".yaml") || resource.ends_with(".yml") {
                let file = if resource == "-f" {
                    std::env::args().nth(3).unwrap_or_default()
                } else {
                    resource.clone()
                };
                match spec::parse_file(&file) {
                    Ok(resources) => {
                        for r in &resources {
                            let name = &r.metadata.name;
                            match r.kind.as_str() {
                                "Deployment" => {
                                    if let Some(dep) = world.deployments.get_mut(name.as_str()) {
                                        dep.replicas = 0;
                                    }
                                    let log = reconcile::reconcile_once(&mut world, &mut brain);
                                    for line in &log { println!("{line}"); }
                                    world.delete(name);
                                    println!("  ✓ deployment/{name} deleted");
                                }
                                "ConfigMap" => {
                                    world.configmaps.remove(name.as_str());
                                    println!("  ✓ configmap/{name} deleted");
                                }
                                "Secret" => {
                                    world.secrets.remove(name.as_str());
                                    println!("  ✓ secret/{name} deleted");
                                }
                                "Namespace" => {
                                    delete_namespace(&mut world, name, &mut brain);
                                }
                                k => println!("  skip {k}/{name}"),
                            }
                        }
                        save_state(&state_path, &world);
                    }
                    Err(e) => eprintln!("  Error: {e}"),
                }
                return;
            }

            // Delete by resource path: deployment/web, namespace/prod, etc.
            let parts: Vec<&str> = resource.split('/').collect();
            if parts.len() != 2 {
                eprintln!("  Usage:");
                eprintln!("    royak delete deployment/<name>");
                eprintln!("    royak delete namespace/<name>");
                eprintln!("    royak delete configmap/<name>");
                eprintln!("    royak delete secret/<name>");
                eprintln!("    royak delete <file.yaml>");
                std::process::exit(1);
            }

            let (kind, name) = (parts[0], parts[1]);

            match kind {
                "deployment" | "deploy" => {
                    if let Some(dep) = world.deployments.get_mut(name) {
                        dep.replicas = 0;
                    }
                    println!("  Scaling down {name}...");
                    let log = reconcile::reconcile_once(&mut world, &mut brain);
                    for line in &log { println!("{line}"); }
                    let removed_from_state = world.delete(name);
                    // Also clean up any orphan Docker containers with this name
                    let prefix = format!("rk-{name}-");
                    let mut docker_cleaned = 0u32;
                    if let Ok(containers) = docker::list_containers(true) {
                        for c in containers.iter().filter(|c| c.names.iter().any(|n| n.contains(&prefix))) {
                            docker::stop_container(&c.id).ok();
                            docker::remove_container(&c.id, true).ok();
                            docker_cleaned += 1;
                        }
                    }
                    if removed_from_state || docker_cleaned > 0 {
                        println!("  ✓ deployment/{name} deleted ({docker_cleaned} containers removed)");
                    } else {
                        println!("  ✗ deployment/{name} not found");
                    }
                }
                "configmap" | "cm" => {
                    if world.configmaps.remove(name).is_some() {
                        println!("  ✓ configmap/{name} deleted");
                    } else {
                        println!("  ✗ configmap/{name} not found");
                    }
                }
                "secret" => {
                    if world.secrets.remove(name).is_some() {
                        println!("  ✓ secret/{name} deleted");
                    } else {
                        println!("  ✗ secret/{name} not found");
                    }
                }
                "namespace" | "ns" => {
                    if name == "default" {
                        eprintln!("  ✗ Cannot delete default namespace");
                    } else {
                        delete_namespace(&mut world, name, &mut brain);
                    }
                }
                _ => eprintln!("  Unknown: {kind}. Use: deployment, configmap, secret, namespace"),
            }
            save_state(&state_path, &world);
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

            // Single shared world for API + reconcile loop
            let world_arc = Arc::new(RwLock::new(load_state(&state_path)));

            // Register local node (CLI --port overrides cluster config)
            {
                let mut w = world_arc.write().unwrap();
                if let Some(p) = port {
                    w.config.api_port = p;
                }
                let api_port = w.config.api_port;
                reconcile::register_local_node(&mut w, &brain, api_port);
            }

            let api_port = {
                let w = world_arc.read().unwrap();
                w.config.api_port
            };

            // Generate kubeconfig for kubectl
            let hostname = std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("HOST"))
                .unwrap_or_else(|_| "localhost".to_string());
            let token_b64 = OrinBrain::identity_base64(&brain.neural_identity(&hostname));
            generate_kubeconfig(api_port, &token_b64, tls);

            // Tokio runtime for async API server + ingress
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");

            // Start async API server
            let api_world = Arc::clone(&world_arc);
            if tls {
                rt.spawn(api::serve_https(api_port, api_world));
            } else {
                rt.spawn(api::serve(api_port, api_world));
            }

            // ── Raft consensus mode (opt-in) ──
            // With --node-id + --peers, this node joins an openraft cluster.
            // The live write path proposes commands through the leader; the
            // file lease remains the single-node fallback when Raft is off.
            if let Some(nid) = node_id {
                let peer_list: Vec<(u64, String)> = peers.split(',')
                    .filter(|s| !s.trim().is_empty())
                    .filter_map(|s| {
                        let (id, addr) = s.split_once('@')?;
                        Some((id.trim().parse::<u64>().ok()?, addr.trim().to_string()))
                    })
                    .collect();
                let raft_world = Arc::clone(&world_arc);
                let do_bootstrap = bootstrap;
                rt.spawn(async move {
                    match raft_node::build_http_node(nid, raft_world, &peer_list, do_bootstrap).await {
                        Ok(()) => println!("  [raft] node {nid} joined (peers: {}, bootstrap: {do_bootstrap})", peer_list.len()),
                        Err(e) => eprintln!("  [raft] failed to start node {nid}: {e}"),
                    }
                });
            }

            // Start autodiscovery if enabled
            if discover {
                let disc_world = Arc::clone(&world_arc);
                let disc_brain = OrinBrain::new(32, 4);
                std::thread::spawn(move || {
                    reconcile::autodiscovery(disc_world, &disc_brain, api_port);
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

            // ServiceLB — NodePort listeners (userspace, klipper-lb-style)
            rt.spawn(servicelb::run(Arc::clone(&world_arc)));

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
            let pods = docker::list_containers(false)
                .map(|cs| cs.iter()
                    .filter(|c| c.names.iter().any(|n| n.contains("rk-")))
                    .map(|c| {
                        let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                        format!("  {} ({}) [{}]", name, c.image, c.state)
                    })
                    .collect::<Vec<_>>().join("\n"))
                .unwrap_or_default();

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
                    save_state(&state_path, &world);
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
                    match reconcile::join_cluster(&mut world, &brain, &peer, port) {
                        Ok(msg) => {
                            println!("  ✓ {msg}");
                            println!("  FP-TLS identity generated ✓");
                            println!("  Brain weights synced ✓");
                            save_state(&state_path, &world);
                        }
                        Err(e) => eprintln!("  ✗ {e}"),
                    }
                }
                NodeAction::List => {
                    if world.nodes.is_empty() {
                        // Auto-register local node
                        reconcile::register_local_node(&mut world, &brain, 6443);
                        save_state(&state_path, &world);
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
                    if let Some(node) = world.nodes.get_mut(&name) {
                        node.status = reconcile::NodeStatus::Draining;
                        println!("  ✓ node/{name} draining (pods will be rescheduled)");
                        save_state(&state_path, &world);
                    } else {
                        eprintln!("  ✗ node/{name} not found");
                    }
                }
            }
        }

        Commands::Api { port } => {
            let world = load_state(&state_path);
            let world_arc = Arc::new(RwLock::new(world));
            println!("  Starting K8s-compatible API server (async)...");
            println!("  Try: kubectl --server=http://localhost:{port} get pods");
            println!("  Try: kubectl --server=http://localhost:{port} get deployments");
            println!("  Try: kubectl --server=http://localhost:{port} get namespaces\n");

            // Background reconcile loop — applies changes made via API
            let reconcile_world = world_arc.clone();
            let reconcile_state_path = state_path.clone();
            std::thread::spawn(move || {
                let mut brain = OrinBrain::new(32, 4);
                loop {
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    let mut w = reconcile_world.write().unwrap();
                    let log = reconcile::reconcile_once(&mut w, &mut brain);
                    for line in &log {
                        if !line.contains("[ok]") { eprintln!("{line}"); }
                    }
                    save_state(&reconcile_state_path, &w);
                }
            });

            // Async API server — blocks main thread
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to create tokio runtime");
            // ServiceLB — NodePort listeners (userspace, klipper-lb-style)
            rt.spawn(servicelb::run(Arc::clone(&world_arc)));
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
            let Some(c) = containers.iter().find(|c| c.names.iter().any(|n| n.trim_start_matches('/') == pod)) else {
                eprintln!("  ✗ pod {pod} not found");
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
                write!(s, "GET {path} HTTP/1.1\r\nHost: {host_port}\r\nConnection: close\r\n\r\n").map_err(|e| e.to_string())?;
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
            let fetch_logs = |id: &str, tail: u32| -> Result<String, String> {
                if stderr {
                    docker::get_stderr_logs(id, tail)
                } else {
                    docker::get_logs(id, tail)
                }
            };
            let stream_label = if stderr { " (stderr)" } else { "" };

            if pod == "all" {
                // Aggregate logs from ALL managed pods — no sidecar needed!
                match docker::list_containers(false) {
                    Ok(containers) => {
                        let managed: Vec<&docker::DockerContainer> = containers.iter()
                            .filter(|c| c.names.iter().any(|n| n.contains("rk-")))
                            .collect();
                        for c in &managed {
                            let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                            if let Ok(logs) = fetch_logs(&c.id[..12], tail) {
                                let clean: String = logs.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).collect();
                                if !clean.trim().is_empty() {
                                    println!("  ── {name}{stream_label} ──");
                                    println!("{clean}");
                                }
                            }
                        }
                    }
                    Err(e) => eprintln!("  Error: {e}"),
                }
            } else {
                // Single pod logs
                let full_name = if pod.starts_with("rk-") { pod.clone() } else { format!("rk-{pod}") };
                // Check if it's a deployment name — show all pods
                match docker::list_containers(true) {
                    Ok(containers) => {
                        let matching: Vec<&docker::DockerContainer> = containers.iter()
                            .filter(|c| c.names.iter().any(|n| {
                                let n = n.trim_start_matches('/');
                                n == full_name || n.starts_with(&format!("{full_name}-"))
                            }))
                            .collect();
                        if matching.len() > 1 {
                            // Multiple pods — aggregate
                            for c in &matching {
                                let name = c.names.first().map(|s| s.trim_start_matches('/')).unwrap_or("?");
                                if let Ok(logs) = fetch_logs(&c.id[..12], tail) {
                                    let clean: String = logs.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).collect();
                                    if !clean.trim().is_empty() {
                                        println!("  ── {name}{stream_label} ──");
                                        println!("{clean}");
                                    }
                                }
                            }
                        } else if let Ok(logs) = fetch_logs(&full_name, tail) {
                            let clean: String = logs.chars().filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace()).collect();
                            println!("{clean}");
                        } else {
                            eprintln!("  Pod '{full_name}' not found");
                        }
                    }
                    Err(e) => eprintln!("  Error: {e}"),
                }
            }
        }

        Commands::Wake { deployment } => {
            let name = deployment.trim_start_matches("deployment/").trim_start_matches("deploy/");
            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);

            if let Some(dep) = world.deployments.get_mut(name) {
                if dep.paused {
                    dep.paused = false;
                    dep.idle_since = None;
                    println!("  ☀ Waking {name} ({} replicas)...", dep.replicas);
                    let log = reconcile::reconcile_once(&mut world, &mut brain);
                    for line in &log { println!("{line}"); }
                    save_state(&state_path, &world);
                } else {
                    println!("  {name} is not paused");
                }
            } else {
                eprintln!("  ✗ deployment '{name}' not found");
            }
        }

        Commands::Scale { deployment, replicas } => {
            let name = deployment.trim_start_matches("deployment/").trim_start_matches("deploy/");
            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);

            if let Some(dep) = world.deployments.get_mut(name) {
                let old = dep.replicas;
                dep.replicas = replicas;
                println!("  Scaling {name}: {old} → {replicas}");
                let log = reconcile::reconcile_once(&mut world, &mut brain);
                for line in &log { println!("{line}"); }
                save_state(&state_path, &world);
            } else {
                eprintln!("  Deployment '{name}' not found");
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
                    save_state(&state_path, &world);
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
                        save_state(&state_path, &world);
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
                                let log = reconcile::reconcile_once(&mut world, &mut brain);
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
                            save_state(&state_path, &world);
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
            let name = deployment.trim_start_matches("deployment/").trim_start_matches("deploy/");
            let mut world = load_state(&state_path);
            let mut brain = OrinBrain::new(32, 4);

            // Try pending rollout first, then previous_image history
            let rollback_image = if let Some(rollout) = world.pending_rollouts.get(name) {
                Some(rollout.old_image.clone())
            } else if let Some(dep) = world.deployments.get(name) {
                dep.previous_image.clone()
            } else {
                None
            };

            if let Some(old_image) = rollback_image {
                println!("  Rolling back {name} to {old_image}...");
                let current_image;
                let replicas;
                if let Some(dep) = world.deployments.get_mut(name) {
                    current_image = dep.image.clone();
                    replicas = dep.replicas;
                    dep.previous_image = Some(dep.image.clone());
                    dep.image = old_image.clone();
                    for c in &mut dep.containers { c.image = old_image.clone(); }
                } else {
                    eprintln!("  ✗ deployment {name} not found");
                    std::process::exit(1);
                }
                // Create a rolling update to actually replace running containers
                world.pending_rollouts.remove(name); // clear any existing
                world.pending_rollouts.insert(name.to_string(), reconcile::RolloutState {
                    old_image: current_image.clone(),
                    new_image: old_image.clone(),
                    total_replicas: replicas,
                    old_pods: std::collections::VecDeque::new(),
                    new_pods_created: 0,
                });
                // Drive the rollout to completion
                for tick in 0..30 {
                    let log = reconcile::reconcile_once(&mut world, &mut brain);
                    for line in &log { println!("{line}"); }
                    if world.pending_rollouts.is_empty() { break; }
                    if tick < 29 { std::thread::sleep(std::time::Duration::from_secs(2)); }
                }
                world.record_event("Deployment", name, "RolledBack", &format!("Rolled back to {old_image}"), "Normal");
                save_state(&state_path, &world);
            } else {
                eprintln!("  ✗ no rollback available for {name} (no previous image)");
            }
        }

        Commands::Backup { file } => {
            let world = load_state(&state_path);
            let state = reconcile::export_state(&world);
            match std::fs::write(&file, serde_json::to_string_pretty(&state).unwrap_or_default()) {
                Ok(_) => println!("  ✓ cluster state backed up to {file}"),
                Err(e) => eprintln!("  ✗ backup failed: {e}"),
            }
        }

        Commands::Restore { file } => {
            match std::fs::read_to_string(&file) {
                Ok(content) => {
                    match serde_json::from_str::<serde_json::Value>(&content) {
                        Ok(remote) => {
                            let mut world = load_state(&state_path);
                            let log = reconcile::merge_state(&mut world, &remote);
                            save_state(&state_path, &world);
                            println!("  ✓ restored from {file}:");
                            for line in &log { println!("    {line}"); }
                        }
                        Err(e) => eprintln!("  ✗ parse error: {e}"),
                    }
                }
                Err(e) => eprintln!("  ✗ read error: {e}"),
            }
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
            rt.block_on(cluster_mesh::run_proxy(port, local_node, world_arc));
        }
    }
}

// ─── Cascade delete ───

fn delete_namespace(world: &mut DesiredWorld, ns: &str, brain: &mut OrinBrain) {
    println!("  Deleting namespace/{ns} (cascade)...");

    // Scale down all deployments in this namespace
    let dep_names: Vec<String> = world.deployments.iter()
        .filter(|(_, d)| d.namespace == ns)
        .map(|(name, _)| name.clone())
        .collect();

    for name in &dep_names {
        if let Some(dep) = world.deployments.get_mut(name.as_str()) {
            dep.replicas = 0;
        }
    }

    // Reconcile to actually remove containers
    if !dep_names.is_empty() {
        let log = reconcile::reconcile_once(world, brain);
        for line in &log { println!("{line}"); }
    }

    // Remove all resources in this namespace
    let mut removed = 0;
    for name in &dep_names {
        world.deployments.remove(name.as_str());
        removed += 1;
        println!("    ✓ deployment/{name}");
    }

    let cm_names: Vec<String> = world.configmaps.iter()
        .filter(|(_, c)| c.namespace == ns)
        .map(|(name, _)| name.clone())
        .collect();
    for name in &cm_names {
        world.configmaps.remove(name.as_str());
        removed += 1;
        println!("    ✓ configmap/{name}");
    }

    let secret_names: Vec<String> = world.secrets.iter()
        .filter(|(_, s)| s.namespace == ns)
        .map(|(name, _)| name.clone())
        .collect();
    for name in &secret_names {
        world.secrets.remove(name.as_str());
        removed += 1;
        println!("    ✓ secret/{name}");
    }

    world.namespaces.retain(|n| n != ns);
    println!("  ✓ namespace/{ns} deleted ({removed} resources removed)");
}

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
    if std::fs::write(&path, &kubeconfig).is_ok() {
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

/// Encrypt a secret value for at-rest storage (AES-256-GCM, random nonce)
fn encrypt_secret_value(plaintext: &str) -> String {
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    let key = get_secret_key();
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    // Random nonce for each encryption (cryptographically secure)
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    match cipher.encrypt(nonce, plaintext.as_bytes()) {
        Ok(ct) => {
            let mut out = String::from("enc:");
            for b in &nonce_bytes { out.push_str(&format!("{b:02x}")); }
            for b in &ct { out.push_str(&format!("{b:02x}")); }
            out
        }
        Err(_) => plaintext.to_string(),
    }
}

/// Decrypt a secret value from at-rest storage
fn decrypt_secret_value(stored: &str) -> String {
    if !stored.starts_with("enc:") { return stored.to_string(); }
    use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
    use aes_gcm::aead::Aead;
    let hex = &stored[4..];
    if hex.len() < 24 { return stored.to_string(); }
    let key = get_secret_key();
    let bytes: Vec<u8> = (0..hex.len()).step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i+2], 16).ok())
        .collect();
    if bytes.len() < 12 { return stored.to_string(); }
    let nonce = Nonce::from_slice(&bytes[..12]);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    match cipher.decrypt(nonce, &bytes[12..]) {
        Ok(pt) => String::from_utf8(pt).unwrap_or_else(|_| stored.to_string()),
        Err(_) => stored.to_string(),
    }
}

/// Current on-disk state schema version. Increment when the JSON shape changes
/// in a way older readers cannot handle. load_state warns on older versions
/// (migration path) and aborts on newer (refuses downgrade).
pub const STATE_SCHEMA_VERSION: u32 = 1;

/// Resolved state path for this process — set once at startup so the API
/// layer can persist mutations write-through without threading the path
/// through every handler signature.
pub static STATE_PATH: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// The state path the process was started with (default if unset, e.g. tests).
pub fn state_path() -> &'static str {
    STATE_PATH.get().map(|s| s.as_str()).unwrap_or(".royak-state.json")
}

pub fn save_state(path: &str, world: &DesiredWorld) {
    let state = serde_json::json!({
        "schemaVersion": STATE_SCHEMA_VERSION,
        "manifests": world.manifests,
        "namespaces": world.namespaces,
        "deployments": world.deployments.values().map(|d| serde_json::json!({
            "name": d.name, "namespace": d.namespace, "replicas": d.replicas,
            "image": d.image, "previousImage": d.previous_image, "command": d.command, "env": d.env,
            "paused": d.paused, "pauseAfterIdle": d.pause_after_idle, "stateful": d.stateful,
            "containers": d.containers.iter().map(|c| {
                let mut cj = serde_json::json!({
                    "name": c.name, "image": c.image, "command": c.command, "env": c.env,
                    "volumes": c.volumes.iter().map(|(h, p)| serde_json::json!({"host": h, "container": p})).collect::<Vec<_>>(),
                });
                if let Some(ref lp) = c.liveness_probe {
                    cj["livenessProbe"] = serde_json::json!({"httpGet": lp.http_get, "exec": lp.exec, "initialDelay": lp.initial_delay_seconds, "period": lp.period_seconds, "failureThreshold": lp.failure_threshold});
                }
                if let Some(ref rp) = c.readiness_probe {
                    cj["readinessProbe"] = serde_json::json!({"httpGet": rp.http_get, "exec": rp.exec, "initialDelay": rp.initial_delay_seconds, "period": rp.period_seconds, "failureThreshold": rp.failure_threshold});
                }
                if let Some(ref sp) = c.startup_probe {
                    cj["startupProbe"] = serde_json::json!({"httpGet": sp.http_get, "exec": sp.exec, "initialDelay": sp.initial_delay_seconds, "period": sp.period_seconds, "failureThreshold": sp.failure_threshold});
                }
                cj
            }).collect::<Vec<_>>(),
            "initContainers": d.init_containers.iter().map(|c| serde_json::json!({
                "name": c.name, "image": c.image, "command": c.command, "env": c.env,
            })).collect::<Vec<_>>(),
            "resourceLimits": d.resource_limits.as_ref().map(|r| serde_json::json!({
                "cpuRequest": r.cpu_request, "cpuLimit": r.cpu_limit,
                "memRequest": r.mem_request, "memLimit": r.mem_limit,
            })),
            "strategy": d.strategy.as_ref().map(|s| match s {
                reconcile::DeployStrategy::RollingUpdate { max_surge, max_unavailable } =>
                    serde_json::json!({"type": "RollingUpdate", "maxSurge": max_surge, "maxUnavailable": max_unavailable}),
                reconcile::DeployStrategy::Canary { weight, .. } =>
                    serde_json::json!({"type": "Canary", "weight": weight}),
                reconcile::DeployStrategy::BlueGreen { active } =>
                    serde_json::json!({"type": "BlueGreen", "active": active}),
            }),
        })).collect::<Vec<_>>(),
        "daemonsets": world.daemonsets.values().map(|d| serde_json::json!({
            "name": d.name, "namespace": d.namespace,
            "container": {"name": d.container.name, "image": d.container.image, "command": d.container.command, "env": d.container.env},
        })).collect::<Vec<_>>(),
        "jobs": world.jobs.values().map(|j| serde_json::json!({
            "name": j.name, "namespace": j.namespace, "completions": j.completions,
            "container": {"name": j.container.name, "image": j.container.image, "command": j.container.command, "env": j.container.env},
        })).collect::<Vec<_>>(),
        "cronjobs": world.cronjobs.values().map(|c| serde_json::json!({
            "name": c.name, "namespace": c.namespace, "schedule": c.schedule,
            "lastRun": c.last_run,
            "container": {"name": c.container.name, "image": c.container.image, "command": c.container.command, "env": c.container.env},
        })).collect::<Vec<_>>(),
        "hpas": world.hpas.values().map(|h| serde_json::json!({
            "name": h.name, "deployment": h.deployment, "min": h.min_replicas, "max": h.max_replicas, "cpu": h.target_cpu,
        })).collect::<Vec<_>>(),
        "services": world.services.values().map(|s| serde_json::json!({
            "name": s.name, "namespace": s.namespace, "type": s.service_type,
            "selector": s.selector,
            "ports": s.ports.iter().map(|p| serde_json::json!({"port": p.port, "targetPort": p.target_port, "protocol": p.protocol, "nodePort": p.node_port})).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "ingresses": world.ingresses.values().map(|i| serde_json::json!({
            "name": i.name, "namespace": i.namespace, "ingressClassName": i.ingress_class,
            "rules": i.rules.iter().map(|r| serde_json::json!({
                "host": r.host, "paths": r.paths.iter().map(|p| serde_json::json!({"path": p.path, "service": p.service, "port": p.port})).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "network_policies": world.network_policies.values().map(|n| serde_json::json!({
            "name": n.name, "namespace": n.namespace, "selector": n.pod_selector,
            "ingress_allow": n.ingress_allow, "egress_allow": n.egress_allow,
            "ingress_ports": n.ingress_ports, "egress_ports": n.egress_ports,
            "internal": n.internal, "mtls": n.mtls_required, "denyAll": n.deny_all,
        })).collect::<Vec<_>>(),
        "resource_quotas": world.resource_quotas.values().map(|q| serde_json::json!({
            "name": q.name, "namespace": q.namespace,
            "cpu": q.hard_cpu, "memory": q.hard_memory,
            "pods": q.hard_pods, "services": q.hard_services,
            "configmaps": q.hard_configmaps, "secrets": q.hard_secrets,
        })).collect::<Vec<_>>(),
        "configmaps": world.configmaps.values().map(|c| serde_json::json!({
            "name": c.name, "namespace": c.namespace, "data": c.data,
        })).collect::<Vec<_>>(),
        "secrets": world.secrets.values().map(|s| {
            // Encrypt secret values at rest with AES-256-GCM
            let encrypted_data: std::collections::HashMap<String, String> = s.data.iter()
                .map(|(k, v)| (k.clone(), encrypt_secret_value(v)))
                .collect();
            serde_json::json!({
                "name": s.name, "namespace": s.namespace,
                "data": encrypted_data, "encrypted": true,
            })
        }).collect::<Vec<_>>(),
        "pvs": world.pvs.values().map(|p| {
            let status = match p.status { reconcile::PVStatus::Available => "Available", reconcile::PVStatus::Bound => "Bound", reconcile::PVStatus::Released => "Released" };
            serde_json::json!({
                "name": p.name, "capacity": p.capacity, "class": p.storage_class,
                "path": p.host_path, "access": p.access_mode,
                "status": status, "boundTo": p.bound_to,
            })
        }).collect::<Vec<_>>(),
        "pvcs": world.pvcs.values().map(|p| serde_json::json!({
            "name": p.name, "namespace": p.namespace, "class": p.storage_class,
            "requested": p.requested, "access": p.access_mode, "bound": p.bound_pv,
        })).collect::<Vec<_>>(),
        "pipelines": world.pipelines.values().map(|p| serde_json::json!({
            "name": p.name,
            "triggers": p.triggers.iter().map(|t| serde_json::json!({"type": t.trigger_type, "path": t.path})).collect::<Vec<_>>(),
            "stages": p.stages.iter().map(|s| serde_json::json!({
                "name": s.name, "image": s.image, "command": s.command,
                "action": s.action, "file": s.file, "artifacts": s.artifacts,
                "context": s.context, "dockerfile": s.dockerfile, "tag": s.tag,
                "dependsOn": s.depends_on, "env": s.env,
                "if": s.if_condition, "matrixImages": s.matrix_images,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "config": serde_json::json!({
            "llm": {"host": world.config.llm_host, "model": world.config.llm_model, "temperature": world.config.llm_temperature},
            "alerts": {"webhook": world.config.alert_webhook, "onAnomaly": world.config.alert_on_anomaly, "onRestart": world.config.alert_on_restart},
            "runtime": world.config.runtime,
            "pause": {"defaultIdle": world.config.pause_default_idle, "enabled": world.config.pause_enabled},
            "api": {"port": world.config.api_port},
        }),
        "functions": world.functions.values().map(|f| serde_json::json!({
            "name": f.name, "image": f.image, "command": f.command,
            "httpTriggers": f.http_triggers, "webhookTriggers": f.webhook_triggers,
            "scheduleTriggers": f.schedule_triggers,
            "timeout": f.timeout_secs, "memory": f.memory_mb,
            "invocations": f.invocations, "code": f.code,
        })).collect::<Vec<_>>(),
        "repositories": world.repositories.values().map(|r| serde_json::json!({
            "name": r.name, "url": r.url, "path": r.path, "branch": r.branch,
            "secretRef": r.secret_ref, "pipeline": r.pipeline, "lastCommit": r.last_commit,
        })).collect::<Vec<_>>(),
        "nodes": world.nodes.values().map(|n| {
            let status = match n.status { reconcile::NodeStatus::Ready => "Ready", reconcile::NodeStatus::NotReady => "NotReady", reconcile::NodeStatus::Draining => "Draining" };
            serde_json::json!({
                "name": n.name, "address": n.address, "status": status,
                "cpuCapacity": n.cpu_capacity, "memCapacity": n.mem_capacity,
                "cpuUsed": n.cpu_used, "memUsed": n.mem_used,
                "podCount": n.pod_count, "joinedAt": n.joined_at,
            })
        }).collect::<Vec<_>>(),
        "rbac_roles": world.rbac_roles.values().map(|r| serde_json::json!({
            "name": r.name,
            "rules": r.rules.iter().map(|rule| serde_json::json!({
                "resources": rule.resources, "verbs": rule.verbs, "namespaces": rule.namespaces,
            })).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
        "guards": world.guards.values().map(|g| serde_json::json!({
            "name": g.name,
            "rules": g.rules.iter().map(|r| serde_json::json!({
                "when": r.when, "action": r.action, "params": r.params,
            })).collect::<Vec<_>>(),
            "hooks": g.hooks,
        })).collect::<Vec<_>>(),
        "operators": world.operators.values().map(|o| serde_json::json!({
            "name": o.name, "customKind": o.custom_kind,
            "provision": o.provision.iter().map(|c| serde_json::json!({
                "role": c.role, "image": c.image, "replicas": c.replicas, "env": c.env,
            })).collect::<Vec<_>>(),
            "hooks": o.hooks,
        })).collect::<Vec<_>>(),
        "custom_resources": world.custom_resources.values().map(|cr| serde_json::json!({
            "name": cr.name, "kind": cr.kind, "namespace": cr.namespace,
            "spec": cr.spec,
            "status": match cr.status { reconcile::CRStatus::Pending => "Pending", reconcile::CRStatus::Provisioning => "Provisioning", reconcile::CRStatus::Running => "Running", reconcile::CRStatus::Failed => "Failed" },
        })).collect::<Vec<_>>(),
        "admission_webhooks": world.admission_webhooks.values().map(|h| serde_json::json!({
            "name": h.name, "url": h.url, "kinds": h.kinds, "failurePolicy": h.failure_policy,
        })).collect::<Vec<_>>(),
    });
    let json = serde_json::to_string_pretty(&state).unwrap_or_default();

    // ── Neural state: save as binary weight matrix ──
    let neural_path = format!("{path}.nrns");
    let mut ns = neural_state::NeuralState::new();
    // Full state for fast reconstruction
    ns.set("_full".to_string(), json.as_bytes().to_vec());
    // Individual resources for neural search (brain can query via matmul)
    if let Some(obj) = state.as_object() {
        for (section, val) in obj {
            if let Some(arr) = val.as_array() {
                for item in arr {
                    if let Some(name) = item["name"].as_str() {
                        let ns_str = item["namespace"].as_str().unwrap_or("default");
                        let key = format!("{section}/{ns_str}/{name}");
                        ns.set(key, serde_json::to_vec(item).unwrap_or_default());
                    }
                }
            }
        }
    }
    if ns.save(&neural_path).is_ok() {
        eprintln!("  [neural] state saved: {}", ns.stats());
    }

    // ── JSON backup (human-readable) ──
    let lock_path = format!("{path}.lock");
    let lock_file = std::fs::OpenOptions::new().create(true).write(true).open(&lock_path);
    if let Ok(ref lock) = lock_file {
        #[cfg(unix)]
        unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(lock), libc::LOCK_EX); }
    }
    // State may reference secrets/tokens — keep it owner-only (0600).
    let tmp_path = format!("{path}.tmp");
    let tmp_written = {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true).create(true).truncate(true).mode(0o600)
                .open(&tmp_path)
                .and_then(|mut f| f.write_all(json.as_bytes()))
                .is_ok()
        }
        #[cfg(not(unix))]
        { std::fs::write(&tmp_path, &json).is_ok() }
    };
    if tmp_written {
        if std::fs::rename(&tmp_path, path).is_err() {
            std::fs::write(path, &json).ok();
        }
    } else {
        std::fs::write(path, &json).ok();
    }
    if let Ok(ref lock) = lock_file {
        #[cfg(unix)]
        unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(lock), libc::LOCK_UN); }
    }
}

fn load_state(path: &str) -> DesiredWorld {
    let mut world = DesiredWorld::new();

    // ── Try neural state first (binary, fast) ──
    let neural_path = format!("{path}.nrns");
    let content = if let Ok(ns) = neural_state::NeuralState::load(&neural_path) {
        eprintln!("  [neural] loaded state: {}", ns.stats());
        ns.get("_full").and_then(|d| String::from_utf8(d.to_vec()).ok())
    } else {
        None
    };

    // ── Fall back to JSON file ──
    let content = content.or_else(|| {
        let lock_path = format!("{path}.lock");
        let lock_file = std::fs::OpenOptions::new().create(true).write(true).open(&lock_path);
        if let Ok(ref lock) = lock_file {
            #[cfg(unix)]
            unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(lock), libc::LOCK_SH); }
        }
        let result = std::fs::read_to_string(path).ok();
        if let Ok(ref lock) = lock_file {
            #[cfg(unix)]
            unsafe { libc::flock(std::os::unix::io::AsRawFd::as_raw_fd(lock), libc::LOCK_UN); }
        }
        result
    });

    if let Some(content) = content {
        if let Ok(state) = serde_json::from_str::<serde_json::Value>(&content) {
            // ── Schema version check ──
            let found_version = state["schemaVersion"].as_u64().map(|v| v as u32);
            match found_version {
                None => {
                    eprintln!("  [migrate] state file has no schemaVersion — treating as v0, upgrading on next save.");
                }
                Some(v) if v == STATE_SCHEMA_VERSION => {}
                Some(v) if v < STATE_SCHEMA_VERSION => {
                    eprintln!("  [migrate] state schema v{v} → v{STATE_SCHEMA_VERSION} (upgrading on next save)");
                }
                Some(v) => {
                    eprintln!("  [error] state schema v{v} newer than supported v{STATE_SCHEMA_VERSION}. Refusing to downgrade. Upgrade the binary or delete the state files.");
                    return world;
                }
            }

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
                            env_from_secrets: c["envFromSecrets"].as_array().map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect()).unwrap_or_default(),
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
                                let decrypted = if is_encrypted { decrypt_secret_value(val) } else { val.to_string() };
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
                            volumes: vec![], env_from_configmaps: vec![], env_from_secrets: vec![],
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
                            volumes: vec![], env_from_configmaps: vec![], env_from_secrets: vec![],
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
                            volumes: vec![], env_from_configmaps: vec![], env_from_secrets: vec![],
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
                        deployment: item["deployment"].as_str().unwrap_or("").to_string(),
                        min_replicas: item["min"].as_u64().unwrap_or(1) as u32,
                        max_replicas: item["max"].as_u64().unwrap_or(10) as u32,
                        target_cpu: item["cpu"].as_f64().unwrap_or(70.0) as f32,
                        history: Vec::new(),
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
                            reconcile::RbacRule { resources: get_strs("resources"), verbs: get_strs("verbs"), namespaces: get_strs("namespaces") }
                        }).collect())
                        .unwrap_or_default();
                    let name = item["name"].as_str().unwrap_or("").to_string();
                    world.rbac_roles.insert(name.clone(), reconcile::RbacRole { name, rules });
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
    world
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
        // Use a path whose `.nrns` companion does not exist → load_state falls through to JSON.
        format!("/tmp/rk-state-{pid}-{nanos}-{tag}.json")
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.nrns"));
        let _ = std::fs::remove_file(format!("{path}.lock"));
        let _ = std::fs::remove_file(format!("{path}.nrns.tmp"));
    }

    #[test]
    fn secret_encrypt_decrypt_roundtrip() {
        let plain = "plaintext-sentinel-42";
        let encrypted = encrypt_secret_value(plain);
        assert_ne!(encrypted, plain, "encrypted form must differ from plaintext");
        assert!(encrypted.starts_with("enc:"));
        let decrypted = decrypt_secret_value(&encrypted);
        assert_eq!(decrypted, plain);
    }

    #[test]
    fn save_load_roundtrip_writes_schema_version() {
        let path = tmp_path("roundtrip");
        cleanup(&path);

        let world = DesiredWorld::new();
        save_state(&path, &world);

        let content = std::fs::read_to_string(&path).expect("state file written");
        let v: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(v["schemaVersion"].as_u64(), Some(STATE_SCHEMA_VERSION as u64));

        cleanup(&path);
    }

    #[test]
    fn load_state_without_schema_version_proceeds() {
        // Simulates loading a pre-schema-version state file (v0).
        let path = tmp_path("legacy");
        cleanup(&path);
        std::fs::write(&path, r#"{"deployments":[],"services":[]}"#).unwrap();

        let world = load_state(&path);
        assert_eq!(world.deployments.len(), 0);
        cleanup(&path);
    }

    #[test]
    fn load_state_with_future_version_refuses() {
        // Newer schema than we support → we must not silently ignore it.
        let path = tmp_path("future");
        cleanup(&path);
        let body = format!(r#"{{"schemaVersion": {}, "deployments": []}}"#, STATE_SCHEMA_VERSION + 99);
        std::fs::write(&path, body).unwrap();

        let world = load_state(&path);
        // Refused load → empty world.
        assert_eq!(world.deployments.len(), 0);
        assert!(world.services.is_empty());
        cleanup(&path);
    }

    #[test]
    fn load_state_with_current_version_ok() {
        let path = tmp_path("current");
        cleanup(&path);
        let body = format!(r#"{{"schemaVersion": {}, "deployments": []}}"#, STATE_SCHEMA_VERSION);
        std::fs::write(&path, body).unwrap();

        let world = load_state(&path);
        assert_eq!(world.deployments.len(), 0);
        cleanup(&path);
    }

    /// If the orchestrator crashes mid-save, a stray `.tmp` file may linger
    /// next to the completed state. load_state must still load the last-good
    /// state and ignore the partial tmp.
    #[test]
    fn load_state_ignores_partial_tmp_file() {
        let path = tmp_path("partial");
        cleanup(&path);

        // Write a complete, valid state.
        let good = format!(r#"{{"schemaVersion": {}, "deployments": []}}"#, STATE_SCHEMA_VERSION);
        std::fs::write(&path, &good).unwrap();
        // Simulate a crash mid-save: garbage in the .tmp companion.
        std::fs::write(format!("{path}.tmp"), b"partial garbage, not valid json").unwrap();

        let world = load_state(&path);
        // The main file is still intact, so load must succeed.
        assert_eq!(world.deployments.len(), 0);

        // Also: the stray tmp file should not prevent a subsequent save.
        save_state(&path, &world);
        let after = std::fs::read_to_string(&path).unwrap();
        let v: serde_json::Value = serde_json::from_str(&after).unwrap();
        assert_eq!(v["schemaVersion"].as_u64(), Some(STATE_SCHEMA_VERSION as u64));

        cleanup(&path);
    }

    /// A corrupted (malformed JSON) main state file should degrade safely
    /// to an empty world, not panic or crash the orchestrator.
    #[test]
    fn load_state_corrupted_json_degrades_safely() {
        let path = tmp_path("corrupt");
        cleanup(&path);
        std::fs::write(&path, b"{{ not valid json at all").unwrap();

        let world = load_state(&path);
        assert_eq!(world.deployments.len(), 0);
        assert!(world.services.is_empty());

        cleanup(&path);
    }
}
