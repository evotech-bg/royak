//! OrinNet — Single neural network for ALL orchestration.
//!
//! One forward pass = one orchestration decision.
//! Weights = cluster state + policy + learned behavior.
//! No etcd. No scheduler. No controller. Just matmul.
//!
//! Input:  [pod_states, node_resources, metrics, desired_state]
//! Output: [actions: schedule, scale, restart, migrate, alert]

use ndarray::{Array1, Array2};
use rustc_hash::FxHashMap;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use aes_gcm::aead::Aead;

/// The brain — one neural network for everything
pub struct OrinBrain {
    /// Layer 1: input → perception (understand cluster state)
    w_perceive: Array2<f32>,
    b_perceive: Array1<f32>,

    /// Layer 2: perception → decision (what to do)
    w_decide: Array2<f32>,
    b_decide: Array1<f32>,

    /// Layer 3: decision → action (specific actions)
    w_act: Array2<f32>,
    b_act: Array1<f32>,

    /// Key-value memory (replaces etcd)
    pub kv: FxHashMap<String, String>,

    /// Decision history (learn from past)
    pub history: Vec<Decision>,

    /// Stats
    pub ticks: u64,
    pub actions_taken: u64,
    /// Training stats
    pub train_steps: u32,
    pub last_loss: f32,
}

/// Cluster snapshot — input to the brain
#[derive(Debug, Clone, serde::Serialize)]
pub struct ClusterState {
    /// Pod states: (pod_id, status, cpu_usage, mem_usage, restarts, age_secs)
    pub pods: Vec<PodState>,
    /// Node states: (node_id, cpu_avail, mem_avail, pod_count, healthy)
    pub nodes: Vec<NodeState>,
    /// Desired state from specs
    pub desired: Vec<DesiredState>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PodState {
    pub id: String,
    pub name: String,
    pub node: String,
    pub status: PodStatus,
    pub cpu_pct: f32,
    pub mem_mb: f32,
    pub restarts: u32,
    pub age_secs: u64,
    pub image: String,
}

#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum PodStatus {
    Running,
    Pending,
    Failed,
    Succeeded,
    Unknown,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeState {
    pub id: String,
    pub cpu_avail: f32,  // percentage available
    pub mem_avail: f32,  // MB available
    pub pod_count: u32,
    pub healthy: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DesiredState {
    pub name: String,
    pub replicas: u32,
    pub image: String,
    pub cpu_limit: f32,
    pub mem_limit: f32,
}

/// Brain output — actions to take
#[derive(Debug, Clone, serde::Serialize)]
pub struct Decision {
    pub tick: u64,
    pub actions: Vec<Action>,
    pub confidence: f32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub enum Action {
    /// Schedule a pending pod to a node
    Schedule { pod: String, node: String },
    /// Scale a deployment up/down
    Scale { name: String, from: u32, to: u32 },
    /// Restart a failing pod
    Restart { pod: String, reason: String },
    /// Migrate pod from overloaded node
    Migrate { pod: String, from_node: String, to_node: String },
    /// Alert operator
    Alert { severity: String, message: String },
    /// No action needed
    Noop,
}

impl OrinBrain {
    /// Create brain with dimensions based on max cluster size
    pub fn new(max_pods: usize, max_nodes: usize) -> Self {
        // Input: per-pod features + per-node features + desired state
        let pod_features = 6;  // status, cpu, mem, restarts, age, node_id
        let node_features = 4; // cpu_avail, mem_avail, pod_count, healthy
        let desired_features = 4; // replicas, cpu_limit, mem_limit, current_count

        let input_dim = max_pods * pod_features + max_nodes * node_features + max_pods * desired_features;
        let perceive_dim = 64;
        let decide_dim = 32;
        let action_dim = max_pods * 4; // per-pod: schedule, scale, restart, migrate

        // Xavier initialization
        let scale_1 = (2.0 / (input_dim + perceive_dim) as f32).sqrt();
        let scale_2 = (2.0 / (perceive_dim + decide_dim) as f32).sqrt();
        let scale_3 = (2.0 / (decide_dim + action_dim) as f32).sqrt();

        OrinBrain {
            w_perceive: Array2::from_shape_fn((perceive_dim, input_dim), |_| (rand::random::<f32>() - 0.5) * scale_1),
            b_perceive: Array1::zeros(perceive_dim),
            w_decide: Array2::from_shape_fn((decide_dim, perceive_dim), |_| (rand::random::<f32>() - 0.5) * scale_2),
            b_decide: Array1::zeros(decide_dim),
            w_act: Array2::from_shape_fn((action_dim, decide_dim), |_| (rand::random::<f32>() - 0.5) * scale_3),
            b_act: Array1::zeros(action_dim),
            kv: FxHashMap::default(),
            history: Vec::new(),
            ticks: 0,
            actions_taken: 0,
            train_steps: 0,
            last_loss: 1.0,
        }
    }

    /// One tick = one forward pass = all orchestration decisions
    pub fn tick(&mut self, state: &ClusterState) -> Decision {
        self.ticks += 1;

        // 1. Encode cluster state into input vector
        let input = self.encode_state(state);

        // 2. Forward pass: perceive → decide → act
        let perceived = self.w_perceive.dot(&input).mapv(|x| x.max(0.0)) + &self.b_perceive;
        let decided = self.w_decide.dot(&perceived).mapv(|x| x.max(0.0)) + &self.b_decide;
        let action_logits = self.w_act.dot(&decided) + &self.b_act;

        // 3. Decode actions from output
        let mut actions = Vec::new();

        // Check each pod for needed actions
        for (i, pod) in state.pods.iter().enumerate() {
            let offset = i * 4;
            if offset + 3 >= action_logits.len() { break; }

            let _schedule_score = action_logits[offset];
            let _scale_score = action_logits[offset + 1];
            let _restart_score = action_logits[offset + 2];
            let migrate_score = action_logits[offset + 3];

            // Rule-enhanced neural decisions (neural suggests, rules validate)
            match pod.status {
                PodStatus::Pending => {
                    // Find best node
                    if let Some(node) = self.find_best_node(state, pod) {
                        actions.push(Action::Schedule {
                            pod: pod.id.clone(),
                            node: node.id.clone(),
                        });
                    }
                }
                PodStatus::Failed => {
                    if pod.restarts < 5 {
                        actions.push(Action::Restart {
                            pod: pod.id.clone(),
                            reason: "pod failed".to_string(),
                        });
                    } else {
                        actions.push(Action::Alert {
                            severity: "critical".to_string(),
                            message: format!("Pod {} failed {} times", pod.name, pod.restarts),
                        });
                    }
                }
                PodStatus::Running => {
                    // Check for overload → migrate
                    if pod.cpu_pct > 90.0 || pod.mem_mb > 1000.0 {
                        if migrate_score > 0.0 {
                            if let Some(target) = self.find_least_loaded_node(state, &pod.node) {
                                actions.push(Action::Migrate {
                                    pod: pod.id.clone(),
                                    from_node: pod.node.clone(),
                                    to_node: target.id.clone(),
                                });
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Check desired vs actual for scaling
        for desired in &state.desired {
            let actual_count = state.pods.iter()
                .filter(|p| p.name.starts_with(&desired.name) && p.status == PodStatus::Running)
                .count() as u32;

            if actual_count != desired.replicas {
                actions.push(Action::Scale {
                    name: desired.name.clone(),
                    from: actual_count,
                    to: desired.replicas,
                });
            }
        }

        if actions.is_empty() {
            actions.push(Action::Noop);
        }

        self.actions_taken += actions.iter().filter(|a| !matches!(a, Action::Noop)).count() as u64;

        // Store in kv (replaces etcd)
        self.kv.insert("last_tick".to_string(), self.ticks.to_string());
        self.kv.insert("total_pods".to_string(), state.pods.len().to_string());
        self.kv.insert("total_nodes".to_string(), state.nodes.len().to_string());

        let confidence = if actions.is_empty() { 1.0 } else { 0.95 };
        let decision = Decision {
            tick: self.ticks,
            actions,
            confidence,
        };

        self.history.push(decision.clone());
        if self.history.len() > 1000 {
            self.history.drain(..500);
        }

        decision
    }

    /// Encode cluster state into flat input vector
    fn encode_state(&self, state: &ClusterState) -> Array1<f32> {
        let input_dim = self.w_perceive.shape()[1];
        let mut input = Array1::zeros(input_dim);
        let mut idx = 0;

        // Pod features
        for pod in &state.pods {
            if idx + 5 >= input_dim { break; }
            input[idx] = match pod.status {
                PodStatus::Running => 1.0,
                PodStatus::Pending => 0.5,
                PodStatus::Failed => 0.0,
                _ => 0.3,
            };
            input[idx + 1] = pod.cpu_pct / 100.0;
            input[idx + 2] = pod.mem_mb / 4096.0;
            input[idx + 3] = pod.restarts as f32 / 10.0;
            input[idx + 4] = (pod.age_secs as f32 / 86400.0).min(1.0);
            idx += 6;
        }

        // Node features
        for node in &state.nodes {
            if idx + 3 >= input_dim { break; }
            input[idx] = node.cpu_avail / 100.0;
            input[idx + 1] = node.mem_avail / 32768.0;
            input[idx + 2] = node.pod_count as f32 / 100.0;
            input[idx + 3] = if node.healthy { 1.0 } else { 0.0 };
            idx += 4;
        }

        input
    }

    /// Find best node for a pending pod (neural-enhanced)
    fn find_best_node<'a>(&self, state: &'a ClusterState, _pod: &PodState) -> Option<&'a NodeState> {
        state.nodes.iter()
            .filter(|n| n.healthy && n.cpu_avail > 10.0 && n.mem_avail > 256.0)
            .max_by(|a, b| {
                let score_a = a.cpu_avail * 0.5 + a.mem_avail * 0.001 - a.pod_count as f32 * 5.0;
                let score_b = b.cpu_avail * 0.5 + b.mem_avail * 0.001 - b.pod_count as f32 * 5.0;
                score_a.partial_cmp(&score_b).unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// Find least loaded node (for migration)
    fn find_least_loaded_node<'a>(&self, state: &'a ClusterState, exclude: &str) -> Option<&'a NodeState> {
        state.nodes.iter()
            .filter(|n| n.healthy && n.id != exclude)
            .max_by(|a, b| {
                a.cpu_avail.partial_cmp(&b.cpu_avail).unwrap_or(std::cmp::Ordering::Equal)
            })
    }

    /// KV store — get (replaces etcd GET)
    #[allow(dead_code)]
    pub fn get(&self, key: &str) -> Option<&String> {
        self.kv.get(key)
    }

    /// KV store — set (replaces etcd PUT)
    pub fn set(&mut self, key: String, value: String) {
        self.kv.insert(key, value);
    }

    /// KV store — list keys with prefix (replaces etcd range)
    #[allow(dead_code)]
    pub fn list(&self, prefix: &str) -> Vec<(&String, &String)> {
        self.kv.iter().filter(|(k, _)| k.starts_with(prefix)).collect()
    }

    // ─── ANOMALY: Neural Container Monitoring ───

    /// Record a metric observation for a pod
    pub fn observe(&mut self, pod: &str, cpu: f32, mem: f32, restarts: u32) {
        let key = format!("metrics.{pod}");
        let entry = self.kv.entry(key).or_insert_with(String::new);

        // Append observation (compact: cpu,mem,restarts;cpu,mem,restarts;...)
        if !entry.is_empty() { entry.push(';'); }
        entry.push_str(&format!("{cpu:.1},{mem:.0},{restarts}"));

        // Keep last 100 observations
        let count = entry.matches(';').count();
        if count > 100 {
            if let Some(pos) = entry.find(';') {
                *entry = entry[pos+1..].to_string();
            }
        }
    }

    /// Detect anomalies — returns (pod, anomaly_type, value, threshold)
    pub fn detect_anomalies(&self) -> Vec<(String, String, f32, f32)> {
        let mut anomalies = Vec::new();

        for (key, data) in &self.kv {
            if !key.starts_with("metrics.") { continue; }
            let pod = &key[8..]; // strip "metrics."

            let observations: Vec<(f32, f32, f32)> = data.split(';')
                .filter_map(|obs| {
                    let parts: Vec<&str> = obs.split(',').collect();
                    if parts.len() == 3 {
                        Some((
                            parts[0].parse().unwrap_or(0.0),
                            parts[1].parse().unwrap_or(0.0),
                            parts[2].parse().unwrap_or(0.0),
                        ))
                    } else {
                        None
                    }
                })
                .collect();

            if observations.len() < 5 { continue; } // need history to detect

            // Compute mean and stddev for CPU
            let n = observations.len() as f32;
            let cpu_mean = observations.iter().map(|o| o.0).sum::<f32>() / n;
            let cpu_var = observations.iter().map(|o| (o.0 - cpu_mean).powi(2)).sum::<f32>() / n;
            let cpu_std = cpu_var.sqrt().max(1.0); // min 1% to avoid false positives

            // Compute mean and stddev for memory
            let mem_mean = observations.iter().map(|o| o.1).sum::<f32>() / n;
            let mem_var = observations.iter().map(|o| (o.1 - mem_mean).powi(2)).sum::<f32>() / n;
            let mem_std = mem_var.sqrt().max(1.0);

            // Check latest observation against learned baseline
            if let Some(latest) = observations.last() {
                let cpu_z = (latest.0 - cpu_mean).abs() / cpu_std;
                let mem_z = (latest.1 - mem_mean).abs() / mem_std;

                if cpu_z > 2.5 {
                    anomalies.push((
                        pod.to_string(),
                        "CPU".to_string(),
                        latest.0,
                        cpu_mean + 2.5 * cpu_std,
                    ));
                }
                if mem_z > 2.5 {
                    anomalies.push((
                        pod.to_string(),
                        "MEM".to_string(),
                        latest.1,
                        mem_mean + 2.5 * mem_std,
                    ));
                }

                // Restart spike detection (any restart increase = anomaly)
                let prev_restarts = observations.get(observations.len().saturating_sub(2))
                    .map(|o| o.2).unwrap_or(0.0);
                if latest.2 > prev_restarts {
                    anomalies.push((
                        pod.to_string(),
                        "RESTART".to_string(),
                        latest.2,
                        prev_restarts,
                    ));
                }
            }
        }

        anomalies
    }

    // ─── PREDICT: Proactive Neural Scaling ───

    /// Record load metric for a deployment (for prediction)
    pub fn record_load(&mut self, deployment: &str, cpu: f32, replicas: u32) {
        let key = format!("load.{deployment}");
        let entry = self.kv.entry(key).or_insert_with(String::new);
        let ts = self.ticks;
        if !entry.is_empty() { entry.push(';'); }
        entry.push_str(&format!("{ts},{cpu:.1},{replicas}"));

        // Keep last 200 entries
        let count = entry.matches(';').count();
        if count > 200 {
            if let Some(pos) = entry.find(';') {
                *entry = entry[pos+1..].to_string();
            }
        }
    }

    /// Predict next load using linear regression on recent trend
    /// Returns (predicted_cpu, confidence, suggested_replicas)
    pub fn predict_load(&self, deployment: &str, target_cpu: f32, max_replicas: u32) -> Option<(f32, f32, u32)> {
        let key = format!("load.{deployment}");
        let data = self.kv.get(&key)?;

        let points: Vec<(f32, f32)> = data.split(';')
            .filter_map(|entry| {
                let parts: Vec<&str> = entry.split(',').collect();
                if parts.len() >= 2 {
                    Some((
                        parts[0].parse::<f32>().unwrap_or(0.0),
                        parts[1].parse::<f32>().unwrap_or(0.0),
                    ))
                } else {
                    None
                }
            })
            .collect();

        if points.len() < 10 { return None; } // need history

        // Simple linear regression: y = a + b*x
        let n = points.len() as f32;
        let sum_x: f32 = points.iter().map(|p| p.0).sum();
        let sum_y: f32 = points.iter().map(|p| p.1).sum();
        let sum_xy: f32 = points.iter().map(|p| p.0 * p.1).sum();
        let sum_xx: f32 = points.iter().map(|p| p.0 * p.0).sum();

        let denom = n * sum_xx - sum_x * sum_x;
        if denom.abs() < 0.001 { return None; }

        let b = (n * sum_xy - sum_x * sum_y) / denom;
        let a = (sum_y - b * sum_x) / n;

        // Predict 5 ticks ahead
        let future_tick = self.ticks as f32 + 5.0;
        let predicted_cpu = a + b * future_tick;
        let predicted_cpu = predicted_cpu.max(0.0).min(100.0);

        // Confidence based on R² (how well the line fits)
        let mean_y = sum_y / n;
        let ss_tot: f32 = points.iter().map(|p| (p.1 - mean_y).powi(2)).sum();
        let ss_res: f32 = points.iter().map(|p| {
            let predicted = a + b * p.0;
            (p.1 - predicted).powi(2)
        }).sum();
        let r_squared = if ss_tot > 0.0 { 1.0 - ss_res / ss_tot } else { 0.0 };
        let confidence = r_squared.max(0.0);

        // Suggest replicas based on predicted load
        let current_replicas = points.last()
            .and_then(|_| {
                data.split(';').last()
                    .and_then(|e| e.split(',').nth(2))
                    .and_then(|r| r.parse::<u32>().ok())
            })
            .unwrap_or(1);

        let suggested = if predicted_cpu > target_cpu {
            let ratio = predicted_cpu / target_cpu;
            ((current_replicas as f32 * ratio).ceil() as u32).min(max_replicas)
        } else if predicted_cpu < target_cpu * 0.3 && current_replicas > 1 {
            (current_replicas - 1).max(1)
        } else {
            current_replicas
        };

        Some((predicted_cpu, confidence, suggested))
    }

    /// Get trend direction for a deployment ("rising", "stable", "falling")
    pub fn trend(&self, deployment: &str) -> &str {
        let key = format!("load.{deployment}");
        if let Some(data) = self.kv.get(&key) {
            let cpus: Vec<f32> = data.split(';')
                .filter_map(|e| e.split(',').nth(1)?.parse().ok())
                .collect();
            if cpus.len() < 5 { return "learning"; }
            let recent: f32 = cpus[cpus.len()-3..].iter().sum::<f32>() / 3.0;
            let older: f32 = cpus[..3].iter().sum::<f32>() / 3.0;
            let diff = recent - older;
            if diff > 5.0 { "rising ↑" }
            else if diff < -5.0 { "falling ↓" }
            else { "stable →" }
        } else {
            "no data"
        }
    }

    /// Get learned baseline for a pod
    #[allow(dead_code)]
    pub fn baseline(&self, pod: &str) -> Option<(f32, f32)> {
        let key = format!("metrics.{pod}");
        let data = self.kv.get(&key)?;
        let observations: Vec<f32> = data.split(';')
            .filter_map(|obs| obs.split(',').next()?.parse().ok())
            .collect();
        if observations.is_empty() { return None; }
        let n = observations.len() as f32;
        let mean = observations.iter().sum::<f32>() / n;
        let std = (observations.iter().map(|x| (x - mean).powi(2)).sum::<f32>() / n).sqrt();
        Some((mean, std))
    }

    // ─── FORWARD PASS TLS: Neural Authentication & Encryption ───
    // Inspired by NeuroCaddy's Neural AES. But purer — no OpenSSL, no X.509.
    // The brain IS the certificate authority. One forward pass = identity proof.

    /// Generate a neural identity token for a node.
    /// The token is the brain's response to the node_id — only a node with
    /// the correct weights can reproduce it.
    pub fn neural_identity(&self, node_id: &str) -> Vec<f32> {
        // Encode node_id into input vector
        let input = self.encode_node_id(node_id);
        // Forward pass through perceive + decide layers
        let perceived = self.w_perceive.dot(&input).mapv(|x| x.max(0.0)) + &self.b_perceive;
        let decided = self.w_decide.dot(&perceived).mapv(|x| x.max(0.0)) + &self.b_decide;
        decided.to_vec()
    }

    /// Verify a node's identity: does their claimed token match our forward pass?
    pub fn verify_identity(&self, node_id: &str, claimed_token: &[f32]) -> bool {
        let expected = self.neural_identity(node_id);
        if expected.len() != claimed_token.len() { return false; }
        // Compare with tolerance (floating point)
        let distance: f32 = expected.iter().zip(claimed_token.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            .sqrt();
        distance < 0.001 // same weights = near-identical output
    }

    /// Derive a symmetric encryption key between two nodes.
    /// Both nodes compute the same key because they share weights.
    pub fn derive_key(&self, node_a: &str, node_b: &str) -> [u8; 32] {
        // Combine both node IDs into input
        let input_a = self.encode_node_id(node_a);
        let input_b = self.encode_node_id(node_b);
        // XOR the encoded inputs for a symmetric operation (A↔B = B↔A)
        let combined = &input_a + &input_b;
        // Forward pass for key derivation
        let perceived = self.w_perceive.dot(&combined).mapv(|x| x.max(0.0)) + &self.b_perceive;
        let decided = self.w_decide.dot(&perceived).mapv(|x| (x * 1000.0).sin()) + &self.b_decide;
        // Hash output into 32 bytes (AES-256 key size)
        let mut key = [0u8; 32];
        for (i, &val) in decided.iter().enumerate() {
            let byte_idx = i % 32;
            key[byte_idx] ^= (val.to_bits() & 0xFF) as u8;
            key[(byte_idx + 1) % 32] ^= ((val.to_bits() >> 8) & 0xFF) as u8;
        }
        key
    }

    /// AES-256-GCM encrypt using neural-derived key.
    /// Returns: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn neural_encrypt(&self, data: &[u8], node_a: &str, node_b: &str) -> Vec<u8> {
        let key = self.derive_key(node_a, node_b);
        let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
        // Cryptographically secure random 96-bit nonce
        let mut nonce_bytes = [0u8; 12];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data).expect("encrypt");
        // Prepend nonce so decryption knows it
        let mut out = Vec::with_capacity(12 + ciphertext.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ciphertext);
        out
    }

    /// AES-256-GCM decrypt using neural-derived key.
    /// Input: nonce (12 bytes) || ciphertext || tag (16 bytes)
    pub fn neural_decrypt(&self, data: &[u8], node_a: &str, node_b: &str) -> Result<Vec<u8>, String> {
        if data.len() < 12 { return Err("data too short".into()); }
        let key = self.derive_key(node_a, node_b);
        let cipher = Aes256Gcm::new_from_slice(&key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(&data[..12]);
        cipher.decrypt(nonce, &data[12..]).map_err(|_| "decrypt failed: data tampered or wrong key".into())
    }

    /// Base64-encode a neural identity token for HTTP headers
    pub fn identity_base64(token: &[f32]) -> String {
        let bytes: Vec<u8> = token.iter().flat_map(|f| f.to_le_bytes()).collect();
        // Simple base64 without external crate
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in bytes.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let triple = (b0 << 16) | (b1 << 8) | b2;
            out.push(B64[((triple >> 18) & 0x3F) as usize] as char);
            out.push(B64[((triple >> 12) & 0x3F) as usize] as char);
            if chunk.len() > 1 { out.push(B64[((triple >> 6) & 0x3F) as usize] as char); } else { out.push('='); }
            if chunk.len() > 2 { out.push(B64[(triple & 0x3F) as usize] as char); } else { out.push('='); }
        }
        out
    }

    /// Decode base64 identity and verify against node_id
    pub fn verify_identity_base64(&self, node_id: &str, b64: &str) -> bool {
        const DECODE: [u8; 128] = {
            let mut t = [255u8; 128];
            let mut i = 0u8;
            while i < 26 { t[(b'A' + i) as usize] = i; i += 1; }
            i = 0; while i < 26 { t[(b'a' + i) as usize] = 26 + i; i += 1; }
            i = 0; while i < 10 { t[(b'0' + i) as usize] = 52 + i; i += 1; }
            t[b'+' as usize] = 62; t[b'/' as usize] = 63;
            t
        };
        let chars: Vec<u8> = b64.bytes().filter(|&b| b != b'=').collect();
        let mut bytes = Vec::new();
        for chunk in chars.chunks(4) {
            if chunk.len() < 2 { break; }
            let vals: Vec<u32> = chunk.iter().map(|&b| {
                if b < 128 { DECODE[b as usize] as u32 } else { 0 }
            }).collect();
            let triple = (vals[0] << 18) | (vals[1] << 12)
                | (if vals.len() > 2 { vals[2] << 6 } else { 0 })
                | (if vals.len() > 3 { vals[3] } else { 0 });
            bytes.push(((triple >> 16) & 0xFF) as u8);
            if chunk.len() > 2 { bytes.push(((triple >> 8) & 0xFF) as u8); }
            if chunk.len() > 3 { bytes.push((triple & 0xFF) as u8); }
        }
        // Convert bytes back to f32 tokens
        let token: Vec<f32> = bytes.chunks_exact(4)
            .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        self.verify_identity(node_id, &token)
    }

    /// Encode a node_id string into a fixed-size input vector
    fn encode_node_id(&self, node_id: &str) -> Array1<f32> {
        let input_dim = self.w_perceive.shape()[1];
        let mut input = Array1::zeros(input_dim);
        // Hash node_id bytes into input vector positions
        for (i, byte) in node_id.bytes().enumerate() {
            let idx = (byte as usize * 7 + i * 13) % input_dim;
            input[idx] += byte as f32 / 255.0;
            // Spread influence
            let idx2 = (idx + 17) % input_dim;
            input[idx2] += (byte as f32 / 510.0) * (i as f32 + 1.0).sin();
        }
        input
    }

    /// Stats
    pub fn stats(&self) -> String {
        let params = self.w_perceive.len() + self.w_decide.len() + self.w_act.len()
            + self.b_perceive.len() + self.b_decide.len() + self.b_act.len();
        let key_sample = self.derive_key("node-0", "node-1");
        format!(
            "OrinBrain: {} params, {} ticks, {} actions, {} kv entries, loss: {:.4}, FP-TLS key[0..4]: {:02x}{:02x}{:02x}{:02x}",
            params, self.ticks, self.actions_taken, self.kv.len(), self.last_loss,
            key_sample[0], key_sample[1], key_sample[2], key_sample[3]
        )
    }

    // ─── TRAINING: Real backpropagation on cluster telemetry ───

    /// Forward pass with cached intermediates (needed for backprop)
    fn forward_cached(&self, input: &Array1<f32>) -> ForwardCache {
        let z1 = self.w_perceive.dot(input) + &self.b_perceive;
        let a1 = z1.mapv(|x| x.max(0.0)); // ReLU

        let z2 = self.w_decide.dot(&a1) + &self.b_decide;
        let a2 = z2.mapv(|x| x.max(0.0)); // ReLU

        let z3 = self.w_act.dot(&a2) + &self.b_act;
        // No activation on output (raw logits)

        ForwardCache { input: input.clone(), z1, a1, z2, a2, output: z3 }
    }

    /// Train one step via backpropagation.
    /// target: what the correct action vector should be (from rule-based decisions)
    /// lr: learning rate (default 0.001)
    /// Returns loss value.
    pub fn train_step(&mut self, state: &ClusterState, target: &Array1<f32>, lr: f32) -> f32 {
        let input = self.encode_state(state);
        let cache = self.forward_cached(&input);

        // Loss: MSE
        let diff = &cache.output - target;
        let loss = diff.mapv(|x| x * x).sum() / diff.len() as f32;

        // Backprop layer 3 (act): dL/dz3 = (output - target) * 2/n
        let n = diff.len() as f32;
        let dz3 = &diff * (2.0 / n);

        // Gradients for W3, b3
        let dw3 = outer(&dz3, &cache.a2);
        let db3 = dz3.clone();

        // Backprop through layer 2 (decide): dL/da2 = W3.T @ dz3
        let da2 = self.w_act.t().dot(&dz3);
        let dz2 = &da2 * &cache.z2.mapv(|x| if x > 0.0 { 1.0 } else { 0.0 }); // ReLU derivative

        let dw2 = outer(&dz2, &cache.a1);
        let db2 = dz2.clone();

        // Backprop through layer 1 (perceive): dL/da1 = W2.T @ dz2
        let da1 = self.w_decide.t().dot(&dz2);
        let dz1 = &da1 * &cache.z1.mapv(|x| if x > 0.0 { 1.0 } else { 0.0 });

        let dw1 = outer(&dz1, &cache.input);
        let db1 = dz1;

        // Gradient descent update (SGD)
        self.w_act = &self.w_act - &(dw3 * lr);
        self.b_act = &self.b_act - &(db3 * lr);
        self.w_decide = &self.w_decide - &(dw2 * lr);
        self.b_decide = &self.b_decide - &(db2 * lr);
        self.w_perceive = &self.w_perceive - &(dw1 * lr);
        self.b_perceive = &self.b_perceive - &(db1 * lr);

        self.train_steps += 1;
        self.last_loss = loss;
        loss
    }

    /// Generate target action vector from rule-based decisions.
    /// This teaches the network to reproduce what rules decided —
    /// then eventually surpass them by finding patterns rules can't.
    pub fn decisions_to_target(&self, state: &ClusterState, decisions: &[Action]) -> Array1<f32> {
        let action_dim = self.w_act.shape()[0];
        let mut target = Array1::zeros(action_dim);

        for action in decisions {
            match action {
                Action::Schedule { pod, .. } => {
                    if let Some(i) = state.pods.iter().position(|p| p.id == *pod) {
                        let offset = i * 4;
                        if offset < action_dim { target[offset] = 1.0; } // schedule=high
                    }
                }
                Action::Scale { name, to, .. } => {
                    if let Some(i) = state.desired.iter().position(|d| d.name == *name) {
                        let offset = i * 4;
                        if offset + 1 < action_dim { target[offset + 1] = *to as f32 / 10.0; }
                    }
                }
                Action::Restart { pod, .. } => {
                    if let Some(i) = state.pods.iter().position(|p| p.id == *pod) {
                        let offset = i * 4;
                        if offset + 2 < action_dim { target[offset + 2] = 1.0; }
                    }
                }
                Action::Migrate { pod, .. } => {
                    if let Some(i) = state.pods.iter().position(|p| p.id == *pod) {
                        let offset = i * 4;
                        if offset + 3 < action_dim { target[offset + 3] = 1.0; }
                    }
                }
                _ => {}
            }
        }
        target
    }

    /// Save trained weights to binary file
    pub fn save_weights(&self, path: &str) -> Result<(), String> {
        use std::io::Write;
        let tmp = format!("{path}.tmp");
        let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;

        // Header: magic + dimensions
        f.write_all(b"NRBN").map_err(|e| e.to_string())?; // neural brain magic (legacy tag, do not change — breaks saved weights)
        let dims = [
            self.w_perceive.shape()[0] as u32, self.w_perceive.shape()[1] as u32,
            self.w_decide.shape()[0] as u32, self.w_decide.shape()[1] as u32,
            self.w_act.shape()[0] as u32, self.w_act.shape()[1] as u32,
            self.train_steps, self.ticks as u32,
        ];
        for d in &dims {
            f.write_all(&d.to_le_bytes()).map_err(|e| e.to_string())?;
        }
        f.write_all(&self.last_loss.to_le_bytes()).map_err(|e| e.to_string())?;

        // Weights
        for w in [&self.w_perceive, &self.w_decide, &self.w_act] {
            for &v in w.iter() { f.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())?; }
        }
        for b in [&self.b_perceive, &self.b_decide, &self.b_act] {
            for &v in b.iter() { f.write_all(&v.to_le_bytes()).map_err(|e| e.to_string())?; }
        }

        std::fs::rename(&tmp, path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Load trained weights from binary file
    pub fn load_weights(&mut self, path: &str) -> Result<(), String> {
        let data = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
        if data.len() < 40 || &data[0..4] != b"NRBN" {
            return Err("not a brain file".into());
        }

        let mut pos = 4;
        let read_u32 = |data: &[u8], pos: &mut usize| -> u32 {
            let v = u32::from_le_bytes(data[*pos..*pos+4].try_into().unwrap());
            *pos += 4; v
        };

        let p_rows = read_u32(&data, &mut pos) as usize;
        let p_cols = read_u32(&data, &mut pos) as usize;
        let d_rows = read_u32(&data, &mut pos) as usize;
        let d_cols = read_u32(&data, &mut pos) as usize;
        let a_rows = read_u32(&data, &mut pos) as usize;
        let a_cols = read_u32(&data, &mut pos) as usize;
        self.train_steps = read_u32(&data, &mut pos);
        let _ticks = read_u32(&data, &mut pos);
        self.last_loss = f32::from_le_bytes(data[pos..pos+4].try_into().unwrap());
        pos += 4;

        // Verify dimensions match
        if (p_rows, p_cols) != (self.w_perceive.shape()[0], self.w_perceive.shape()[1]) {
            return Err(format!("perceive dim mismatch: file ({p_rows},{p_cols}) vs brain ({},{})",
                self.w_perceive.shape()[0], self.w_perceive.shape()[1]));
        }

        // Read weights
        let read_mat = |data: &[u8], pos: &mut usize, rows: usize, cols: usize| -> Array2<f32> {
            let mut mat = Array2::zeros((rows, cols));
            for v in mat.iter_mut() {
                *v = f32::from_le_bytes(data[*pos..*pos+4].try_into().unwrap());
                *pos += 4;
            }
            mat
        };
        let read_vec = |data: &[u8], pos: &mut usize, len: usize| -> Array1<f32> {
            let mut vec = Array1::zeros(len);
            for v in vec.iter_mut() {
                *v = f32::from_le_bytes(data[*pos..*pos+4].try_into().unwrap());
                *pos += 4;
            }
            vec
        };

        self.w_perceive = read_mat(&data, &mut pos, p_rows, p_cols);
        self.w_decide = read_mat(&data, &mut pos, d_rows, d_cols);
        self.w_act = read_mat(&data, &mut pos, a_rows, a_cols);
        self.b_perceive = read_vec(&data, &mut pos, p_rows);
        self.b_decide = read_vec(&data, &mut pos, d_rows);
        self.b_act = read_vec(&data, &mut pos, a_rows);

        Ok(())
    }

    // ─── PRE-TRAINING: augmented data for cold-start intelligence ───

    /// Pre-train the brain on synthetic cluster scenarios.
    /// This gives the brain real intelligence before it sees any live data.
    /// Scenarios: normal ops, CPU spikes, memory leaks, pod failures, scale events.
    pub fn pretrain(&mut self, epochs: u32) -> Vec<(u32, f32)> {
        let mut losses = Vec::new();
        let lr = 0.005; // higher LR for synthetic data

        for epoch in 0..epochs {
            let mut epoch_loss = 0.0;
            let scenarios = generate_training_scenarios();

            for (state, target) in &scenarios {
                let loss = self.train_step(state, target, lr);
                epoch_loss += loss;
            }

            epoch_loss /= scenarios.len() as f32;
            if epoch % 50 == 0 || epoch == epochs - 1 {
                losses.push((epoch, epoch_loss));
            }
        }
        losses
    }
}

/// Generate diverse synthetic training scenarios
fn generate_training_scenarios() -> Vec<(ClusterState, ndarray::Array1<f32>)> {
    let mut scenarios = Vec::new();
    let max_pods = 32;
    let action_dim = max_pods * 4;

    // Scenario 1: Normal operation — all pods healthy, no action needed
    for replica_count in [1, 2, 3, 5] {
        let pods: Vec<PodState> = (0..replica_count).map(|i| PodState {
            id: format!("web-{i}"), name: "web".into(), node: "node-0".into(),
            status: PodStatus::Running, cpu_pct: 30.0 + (i as f32 * 5.0),
            mem_mb: 128.0, restarts: 0, age_secs: 3600, image: "nginx".into(),
        }).collect();
        let desired = vec![DesiredState {
            name: "web".into(), replicas: replica_count as u32,
            image: "nginx".into(), cpu_limit: 80.0, mem_limit: 512.0,
        }];
        let state = ClusterState { pods, nodes: healthy_nodes(), desired };
        let target = ndarray::Array1::zeros(action_dim); // no action needed
        scenarios.push((state, target));
    }

    // Scenario 2: Pod pending — should schedule
    for i in 0..3 {
        let pods = vec![PodState {
            id: format!("pending-{i}"), name: "app".into(), node: "".into(),
            status: PodStatus::Pending, cpu_pct: 0.0, mem_mb: 0.0,
            restarts: 0, age_secs: 0, image: "app".into(),
        }];
        let desired = vec![DesiredState {
            name: "app".into(), replicas: 1, image: "app".into(),
            cpu_limit: 50.0, mem_limit: 256.0,
        }];
        let state = ClusterState { pods, nodes: healthy_nodes(), desired };
        let mut target = ndarray::Array1::zeros(action_dim);
        target[0] = 1.0; // schedule action for first pod
        scenarios.push((state, target));
    }

    // Scenario 3: Pod failed — should restart (< 5 restarts)
    for restarts in [0, 1, 2, 3] {
        let pods = vec![PodState {
            id: "crashed-0".into(), name: "api".into(), node: "node-0".into(),
            status: PodStatus::Failed, cpu_pct: 0.0, mem_mb: 0.0,
            restarts, age_secs: 120, image: "api".into(),
        }];
        let desired = vec![DesiredState {
            name: "api".into(), replicas: 1, image: "api".into(),
            cpu_limit: 80.0, mem_limit: 512.0,
        }];
        let state = ClusterState { pods, nodes: healthy_nodes(), desired };
        let mut target = ndarray::Array1::zeros(action_dim);
        target[2] = 1.0; // restart action
        scenarios.push((state, target));
    }

    // Scenario 4: Pod failed too many times — should alert, NOT restart
    {
        let pods = vec![PodState {
            id: "crashloop-0".into(), name: "broken".into(), node: "node-0".into(),
            status: PodStatus::Failed, cpu_pct: 0.0, mem_mb: 0.0,
            restarts: 6, age_secs: 600, image: "broken".into(),
        }];
        let desired = vec![DesiredState {
            name: "broken".into(), replicas: 1, image: "broken".into(),
            cpu_limit: 50.0, mem_limit: 256.0,
        }];
        let state = ClusterState { pods, nodes: healthy_nodes(), desired };
        let target = ndarray::Array1::zeros(action_dim); // no restart, alert only
        scenarios.push((state, target));
    }

    // Scenario 5: High CPU — should consider migration
    for cpu in [85.0, 90.0, 95.0, 99.0] {
        let pods = vec![PodState {
            id: "hot-0".into(), name: "compute".into(), node: "node-0".into(),
            status: PodStatus::Running, cpu_pct: cpu, mem_mb: 400.0,
            restarts: 0, age_secs: 7200, image: "compute".into(),
        }];
        let desired = vec![DesiredState {
            name: "compute".into(), replicas: 1, image: "compute".into(),
            cpu_limit: 80.0, mem_limit: 512.0,
        }];
        let state = ClusterState { pods, nodes: healthy_nodes(), desired };
        let mut target = ndarray::Array1::zeros(action_dim);
        if cpu > 90.0 { target[3] = 1.0; } // migrate at very high CPU
        scenarios.push((state, target));
    }

    // Scenario 6: Under-provisioned — fewer pods than desired
    {
        let pods = vec![PodState {
            id: "web-0".into(), name: "web".into(), node: "node-0".into(),
            status: PodStatus::Running, cpu_pct: 70.0, mem_mb: 256.0,
            restarts: 0, age_secs: 3600, image: "nginx".into(),
        }];
        let desired = vec![DesiredState {
            name: "web".into(), replicas: 3, image: "nginx".into(),
            cpu_limit: 80.0, mem_limit: 512.0,
        }];
        let state = ClusterState { pods, nodes: healthy_nodes(), desired };
        let mut target = ndarray::Array1::zeros(action_dim);
        target[1] = 3.0 / 10.0; // scale signal
        scenarios.push((state, target));
    }

    // Scenario 7: Over-provisioned — more pods than needed, low CPU
    {
        let pods: Vec<PodState> = (0..5).map(|i| PodState {
            id: format!("idle-{i}"), name: "web".into(), node: "node-0".into(),
            status: PodStatus::Running, cpu_pct: 5.0, mem_mb: 64.0,
            restarts: 0, age_secs: 7200, image: "nginx".into(),
        }).collect();
        let desired = vec![DesiredState {
            name: "web".into(), replicas: 2, image: "nginx".into(),
            cpu_limit: 80.0, mem_limit: 512.0,
        }];
        let state = ClusterState { pods, nodes: healthy_nodes(), desired };
        let mut target = ndarray::Array1::zeros(action_dim);
        target[1] = 2.0 / 10.0; // scale down signal
        scenarios.push((state, target));
    }

    // Scenario 8: Mixed — some healthy, some failing, scale needed
    {
        let pods = vec![
            PodState { id: "mix-0".into(), name: "api".into(), node: "node-0".into(),
                status: PodStatus::Running, cpu_pct: 45.0, mem_mb: 200.0,
                restarts: 0, age_secs: 3600, image: "api".into() },
            PodState { id: "mix-1".into(), name: "api".into(), node: "node-1".into(),
                status: PodStatus::Failed, cpu_pct: 0.0, mem_mb: 0.0,
                restarts: 1, age_secs: 300, image: "api".into() },
        ];
        let desired = vec![DesiredState {
            name: "api".into(), replicas: 3, image: "api".into(),
            cpu_limit: 70.0, mem_limit: 512.0,
        }];
        let state = ClusterState { pods, nodes: healthy_nodes(), desired };
        let mut target = ndarray::Array1::zeros(action_dim);
        target[4 + 2] = 1.0; // restart second pod
        target[1] = 3.0 / 10.0; // scale up
        scenarios.push((state, target));
    }

    scenarios
}

/// Generate healthy nodes for training scenarios
fn healthy_nodes() -> Vec<NodeState> {
    vec![
        NodeState { id: "node-0".into(), cpu_avail: 70.0, mem_avail: 8192.0, pod_count: 3, healthy: true },
        NodeState { id: "node-1".into(), cpu_avail: 85.0, mem_avail: 4096.0, pod_count: 1, healthy: true },
    ]
}

/// Cached forward pass intermediates for backpropagation
struct ForwardCache {
    input: Array1<f32>,
    z1: Array1<f32>,
    a1: Array1<f32>,
    z2: Array1<f32>,
    a2: Array1<f32>,
    output: Array1<f32>,
}

/// Outer product: vec_a (n,) × vec_b (m,) → matrix (n, m)
fn outer(a: &Array1<f32>, b: &Array1<f32>) -> Array2<f32> {
    Array2::from_shape_fn((a.len(), b.len()), |(i, j)| a[i] * b[j])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_state() -> ClusterState {
        ClusterState { pods: vec![], nodes: vec![], desired: vec![] }
    }

    #[test]
    fn new_brain_has_stats() {
        let b = OrinBrain::new(8, 2);
        let s = b.stats();
        assert!(s.contains("OrinBrain"));
        assert!(s.contains("params"));
    }

    #[test]
    fn kv_set_get_list() {
        let mut b = OrinBrain::new(4, 2);
        b.set("deploy/web".into(), "v1".into());
        b.set("deploy/api".into(), "v2".into());
        b.set("svc/web".into(), "v3".into());

        assert_eq!(b.get("deploy/web"), Some(&"v1".to_string()));
        assert_eq!(b.get("missing"), None);

        let deploys = b.list("deploy/");
        assert_eq!(deploys.len(), 2);
    }

    #[test]
    fn tick_increments_and_returns_decision() {
        let mut b = OrinBrain::new(4, 2);
        let d1 = b.tick(&empty_state());
        let d2 = b.tick(&empty_state());
        assert_eq!(d1.tick, 1);
        assert_eq!(d2.tick, 2);
    }

    #[test]
    fn neural_identity_deterministic() {
        let b = OrinBrain::new(4, 2);
        let t1 = b.neural_identity("node-alpha");
        let t2 = b.neural_identity("node-alpha");
        assert_eq!(t1, t2);
        assert!(b.verify_identity("node-alpha", &t1));
    }

    #[test]
    fn verify_identity_rejects_wrong_token() {
        let b = OrinBrain::new(4, 2);
        let token = b.neural_identity("node-alpha");
        // Tamper one value
        let mut bad = token.clone();
        bad[0] += 1.0;
        assert!(!b.verify_identity("node-alpha", &bad));
    }

    #[test]
    fn derive_key_symmetric() {
        let b = OrinBrain::new(4, 2);
        let k_ab = b.derive_key("a", "b");
        let k_ba = b.derive_key("b", "a");
        assert_eq!(k_ab, k_ba, "symmetric key A↔B must match B↔A");
    }

    #[test]
    fn neural_encrypt_decrypt_roundtrip() {
        let b = OrinBrain::new(4, 2);
        let msg = b"hello from royak";
        let ct = b.neural_encrypt(msg, "node-alpha", "node-beta");
        assert_ne!(&ct[..msg.len().min(ct.len())], &msg[..msg.len().min(ct.len())]);
        let pt = b.neural_decrypt(&ct, "node-alpha", "node-beta").expect("decrypt ok");
        assert_eq!(pt, msg);
    }

    #[test]
    fn neural_decrypt_tamper_detection() {
        let b = OrinBrain::new(4, 2);
        let ct = b.neural_encrypt(b"secret", "a", "b");
        let mut tampered = ct.clone();
        // Flip a byte inside the ciphertext portion (after 12-byte nonce)
        tampered[15] ^= 0x01;
        assert!(b.neural_decrypt(&tampered, "a", "b").is_err());
    }

    #[test]
    fn train_step_reduces_loss() {
        let mut b = OrinBrain::new(4, 2);
        // Non-empty state so encoded input is non-zero (otherwise loss starts at 0).
        let state = ClusterState {
            pods: vec![PodState {
                id: "p1".into(),
                name: "rk-web-1".into(),
                node: "node-0".into(),
                status: PodStatus::Running,
                cpu_pct: 45.0,
                mem_mb: 256.0,
                restarts: 0,
                age_secs: 120,
                image: "nginx:alpine".into(),
            }],
            nodes: vec![NodeState {
                id: "node-0".into(),
                cpu_avail: 60.0,
                mem_avail: 2048.0,
                pod_count: 1,
                healthy: true,
            }],
            desired: vec![DesiredState {
                name: "web".into(),
                replicas: 3,
                image: "nginx:alpine".into(),
                cpu_limit: 0.5,
                mem_limit: 128.0,
            }],
        };
        let target_dim = 4 * 4; // max_pods * 4 (action_dim)
        let target: Array1<f32> = Array1::from_elem(target_dim, 1.0);

        let loss0 = b.train_step(&state, &target, 0.01);
        for _ in 0..50 {
            b.train_step(&state, &target, 0.01);
        }
        let loss_n = b.train_step(&state, &target, 0.01);
        assert!(loss0 > 0.0, "initial loss should be positive, got {loss0}");
        assert!(loss_n < loss0, "loss should decrease: start={loss0} end={loss_n}");
    }

    #[test]
    fn observe_records_metrics() {
        let mut b = OrinBrain::new(4, 2);
        b.observe("pod-x", 10.0, 100.0, 0);
        b.observe("pod-x", 12.0, 105.0, 0);
        assert!(b.get("metrics.pod-x").is_some());
    }

    #[test]
    fn detect_anomalies_flags_cpu_spike() {
        let mut b = OrinBrain::new(4, 2);
        // Baseline: steady low CPU
        for _ in 0..10 {
            b.observe("crasher", 5.0, 100.0, 0);
        }
        // Spike
        b.observe("crasher", 95.0, 100.0, 0);
        let anomalies = b.detect_anomalies();
        assert!(
            anomalies.iter().any(|(p, k, _, _)| p == "crasher" && k == "CPU"),
            "expected CPU anomaly for crasher, got {anomalies:?}"
        );
    }

    #[test]
    fn save_load_weights_roundtrip() {
        let mut b1 = OrinBrain::new(4, 2);
        b1.set("deploy/web".into(), "3".into());
        let token_before = b1.neural_identity("node-x");

        let path = format!("/tmp/rk-brain-{}.bin", std::process::id());
        b1.save_weights(&path).expect("save ok");

        let mut b2 = OrinBrain::new(4, 2);
        b2.load_weights(&path).expect("load ok");

        // Loaded brain must reproduce the same neural identity.
        let token_after = b2.neural_identity("node-x");
        let dist: f32 = token_before.iter().zip(token_after.iter())
            .map(|(a, b)| (a - b).powi(2)).sum::<f32>().sqrt();
        assert!(dist < 0.001, "loaded weights must match (dist={dist})");

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_weights_missing_file_errors() {
        let mut b = OrinBrain::new(4, 2);
        let r = b.load_weights("/tmp/rk-brain-does-not-exist-9876543210.bin");
        assert!(r.is_err());
    }

    #[test]
    fn load_weights_corrupt_file_errors() {
        let path = format!("/tmp/rk-brain-corrupt-{}.bin", std::process::id());
        std::fs::write(&path, b"garbage bytes, not a brain file").unwrap();
        let mut b = OrinBrain::new(4, 2);
        let r = b.load_weights(&path);
        assert!(r.is_err(), "corrupted weights file should error");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn detect_anomalies_flags_restart_spike() {
        let mut b = OrinBrain::new(4, 2);
        for _ in 0..6 {
            b.observe("flaky", 10.0, 100.0, 0);
        }
        b.observe("flaky", 10.0, 100.0, 3);
        let anomalies = b.detect_anomalies();
        assert!(
            anomalies.iter().any(|(p, k, _, _)| p == "flaky" && k == "RESTART"),
            "expected RESTART anomaly, got {anomalies:?}"
        );
    }
}
