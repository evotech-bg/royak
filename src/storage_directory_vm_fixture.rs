//! QUALIFICATION COMPANION ONLY. Never included in the normal server input.
//! One private inherited socket, one fixed thread, finite typed controls.
//! The actual Watch world is captured by the narrow main hook, not received
//! over this channel. No storage HTTP route, remote grant, writer or init.
use crate::reconcile::DesiredWorld;
use crate::storage_boot::BootId;
use crate::storage_controller::{self, ProvisionIntent, ReplicaTarget};
use crate::storage_driver::NativeAgent;
use crate::storage_driver::dispatcher::{self, ColdPreparedHeld, Dispatcher, Outcome, Ticket};
use crate::storage_identity::Uid;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const FD: i32 = 198;
const FRAME_LIMIT: usize = 16 * 1024;
const MESSAGE_LIMIT: u32 = 64;
const FD_ENV: &str = "ROYAK_STORAGE_QUALIFICATION_FD";
const SOCKET_IDLE: Duration = Duration::from_secs(30);
const WAIT_SLICE: Duration = Duration::from_secs(5);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frame {
    sequence: u32,
    control: Control,
}
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Control {
    Begin {
        version: u32,
        run_token: String,
        binary_sha256: String,
        pool_sha256: String,
        plan_sha256: String,
        // Explicit operator resource admission, not inferred from a test pass.
        budget: crate::storage_driver::ResourceBudget,
    },
    Inspect { volume_uid: Option<Uid> },
    Reserve { volume_uid: Uid, operation_uid: Uid, targets: [Target; 3] },
    Submit { world: WorldChoice },
    Wait,
    Cancel,
    ReleaseHeld,
    TryEraseDirectory,
    PeerControlRootProbe { raft_id: u64, mode: PeerProbe },
    Finish,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target { node_uid: Uid, boot_id: BootId }
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WorldChoice { Actual, FrozenClone }
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum PeerProbe { HonestHostLocal, FalseHostLocal, AliasFalseHostLocal }

fn digest(bytes: &[u8]) -> String { format!("{:x}", Sha256::digest(bytes)) }
fn hex(value: &str, size: usize) -> bool {
    value.len() == size && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn private_file(path: &Path, maximum: u64) -> Result<Vec<u8>, String> {
    // All control inputs are under the permanently reserved storage root.
    // Every parent and leaf is checked; aliases/links are not fixture shortcuts.
    if !path.starts_with("/var/lib/royak/storage") || path.components().any(|c|
        !matches!(c, std::path::Component::RootDir | std::path::Component::Normal(_))) {
        return Err("fixture input is outside the fixed reserved root".into());
    }
    let parent = path.parent().ok_or("fixture input parent missing")?;
    if std::fs::canonicalize(parent).map_err(|e| e.to_string())? != parent {
        return Err("fixture input parent alias refused".into());
    }
    for ancestor in parent.ancestors() {
        let m = std::fs::symlink_metadata(ancestor).map_err(|e| e.to_string())?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err("root-trusted canonical fixture ancestors required".into());
        }
    }
    let file = std::fs::OpenOptions::new().read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path).map_err(|e| e.to_string())?;
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o077 != 0 || m.nlink() != 1 || m.len() > maximum {
        return Err("bounded singly linked root-private fixture file required".into());
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
    if bytes.len() as u64 != m.len() { return Err("fixture input changed while reading".into()); }
    Ok(bytes)
}
fn self_hash() -> Result<(PathBuf, String), String> {
    let path = std::env::current_exe().map_err(|e| e.to_string())?;
    let mut file = std::fs::File::open(&path).map_err(|e| e.to_string())?;
    let m = file.metadata().map_err(|e| e.to_string())?;
    if !m.is_file() || m.uid() != 0 || m.mode() & 0o022 != 0 || m.len() > 64 * 1024 * 1024 {
        return Err("bounded root-owned immutable companion image required".into());
    }
    let mut hash = Sha256::new();
    let mut bytes = [0u8; 65536];
    loop {
        let size = file.read(&mut bytes).map_err(|e| e.to_string())?;
        if size == 0 { break; }
        hash.update(&bytes[..size]);
    }
    Ok((path, format!("{:x}", hash.finalize())))
}
fn read_frame(socket: &mut UnixStream) -> Result<Frame, String> {
    let mut size = [0; 4];
    socket.read_exact(&mut size).map_err(|e| e.to_string())?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > FRAME_LIMIT { return Err("fixture frame exceeds fixed limit".into()); }
    let mut bytes = vec![0; size];
    socket.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid finite fixture control: {e}"))
}
fn write_frame(socket: &mut UnixStream, sequence: u32, result: Result<Value, String>) -> Result<(), String> {
    let value = match result {
        Ok(value) => json!({"sequence": sequence, "ok": true, "observation": value}),
        Err(error) => json!({"sequence": sequence, "ok": false, "error": error}),
    };
    let bytes = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
    if bytes.len() > FRAME_LIMIT { return Err("fixture response exceeds fixed limit".into()); }
    socket.write_all(&(bytes.len() as u32).to_be_bytes()).map_err(|e| e.to_string())?;
    socket.write_all(&bytes).map_err(|e| e.to_string())
}

struct State {
    world: Arc<RwLock<DesiredWorld>>,
    raft_dir: PathBuf,
    root: Option<PathBuf>,
    dispatcher: Option<Dispatcher>,
    agent: Option<NativeAgent>,
    intent: Option<ProvisionIntent>,
    ticket: Option<Ticket>,
    held: Option<ColdPreparedHeld>,
    submissions: u32,
    peer_probes: u32,
}
impl Drop for State {
    fn drop(&mut self) {
        if let Some(ticket) = &self.ticket { ticket.cancel(); }
        // Release is not rollback and does not claim descendants are gone.
        self.held.take();
    }
}
impl State {
    fn actual(&self) -> Result<(), String> {
        if !crate::raft_node::storage_remote_core::is_actual_world(&self.world) {
            return Err("hook lost the actual Raft world".into());
        }
        Ok(())
    }
    fn inspect(&self, uid: Option<Uid>) -> Result<Value, String> {
        self.actual()?;
        let (cluster, generation, registry, volumes) = {
            let w = self.world.read().map_err(|_| "actual world poisoned")?;
            (w.cluster_id.clone(), w.generation, w.storage_node_directory.clone(),
                w.storage_identities.volumes.clone())
        };
        let guard = crate::storage_driver::node_identity::load_guard(&self.raft_dir)?;
        registry.require_guard(guard.as_ref())?;
        let node = crate::raft_node::RAFT.get().ok_or("actual Raft missing")?;
        let metrics = node.raft.metrics().borrow().clone();
        let local = uid.as_ref().map(|uid| crate::raft_node::storage_remote_core::observe_local(uid))
            .transpose()?;
        let registry_bytes = serde_json::to_vec(&registry).map_err(|e| e.to_string())?;
        let boot = BootId::current()?;
        Ok(json!({"kind":"actual_core_local_observation_only", "actual_world":true,
            "cluster_id":cluster, "generation":generation, "raft_id":node.node_id,
            "current_leader_hint":metrics.current_leader, "term_hint":metrics.current_term,
            "kernel_boot_id":boot, "registry":registry, "registry_sha256":digest(&registry_bytes),
            "guard_matches":true,"volumes":volumes,
            "local_node_uid":local.as_ref().and_then(|o|o.local_node_uid()),
            "directory_commitment":local.as_ref().and_then(|o|o.directory_commitment()),
            "scope_sha256":local.as_ref().map(|o|o.scope_sha256()),
            "fresh_quorum_authority":false, "held":self.held.is_some(), "ticket":self.ticket.is_some()}))
    }
    fn handle(&mut self, control: Control) -> Result<Value, String> {
        self.actual()?;
        match control {
            Control::Begin { version, run_token, binary_sha256, pool_sha256, plan_sha256, budget } => {
                if self.root.is_some() || version != 1 || !hex(&run_token, 32)
                    || ![&binary_sha256, &pool_sha256, &plan_sha256].iter().all(|s|hex(s,64)) {
                    return Err("one exact bounded fixture Begin required".into());
                }
                let root = PathBuf::from(format!("/var/lib/royak/storage/qualification-{run_token}"));
                let pool = root.join("pool.json"); let plan = root.join("plan.json");
                if digest(&private_file(&pool, 65536)?) != pool_sha256
                    || digest(&private_file(&plan, 65536)?) != plan_sha256 {
                    return Err("pinned root-private pool/plan changed".into());
                }
                let (helper_image, actual_hash) = self_hash()?;
                if actual_hash != binary_sha256 { return Err("companion image hash changed".into()); }
                let registry = self.world.read().map_err(|_| "actual world poisoned")?.storage_node_directory.clone();
                let directory = registry.directory().ok_or("actual directory not enrolled")?;
                let handle = crate::raft_node::RAFT.get().ok_or("actual Raft missing")?;
                let local = directory.nodes.iter().find(|p|p.raft_id == handle.node_id)
                    .ok_or("actual voter has no committed node UID")?;
                let agent = NativeAgent::load(&pool, &plan)?;
                let dispatcher = Dispatcher::start(dispatcher::Config {
                    journal_root:root.join("dispatcher"),
                    delegated_cgroup_root:PathBuf::from(format!("/sys/fs/cgroup/royak-storage-qualification-{run_token}")),
                    node_uid:local.node_uid.clone(), helper_image, helper_sha256:binary_sha256,
                    deadline:Duration::from_secs(180), budget,
                })?;
                self.root=Some(root); self.agent=Some(agent); self.dispatcher=Some(dispatcher);
                Ok(json!({"kind":"fixed_fixture_ready","native_dispatch_deadline_seconds":180,
                    "maximum_messages":MESSAGE_LIMIT,"maximum_frame_bytes":FRAME_LIMIT,
                    "physical_action_started":false}))
            }
            Control::Inspect { volume_uid } => self.inspect(volume_uid),
            Control::Reserve { volume_uid, operation_uid, targets } => {
                if self.root.is_none() || self.intent.is_some() { return Err("one real reservation after Begin only".into()); }
                let (directory, capacity) = {
                    let w=self.world.read().map_err(|_| "actual world poisoned")?;
                    let d=w.storage_node_directory.directory().ok_or("directory not enrolled")?.clone();
                    let volume=w.storage_identities.lifecycle.get(&volume_uid).ok_or("actual managed volume absent")?;
                    (d,volume.capacity_bytes())
                };
                if directory.nodes.len()!=3 || capacity>128*1024*1024
                    || targets.iter().map(|t|&t.node_uid).ne(directory.nodes.iter().map(|p|&p.node_uid)) {
                    return Err("exact three directory nodes and NEW fixture volume <=128MiB required".into());
                }
                // Typed UIDs/boots are lookup/binding inputs, NOT attestation.
                // The returned capability comes only from actual durable commit.
                let targets=targets.map(|t|ReplicaTarget{node_uid:t.node_uid,boot_id:t.boot_id});
                let intent=storage_controller::reserve_provision(&self.world,&volume_uid,targets,operation_uid)
                    .map_err(|e|format!("actual reserve not acknowledged: {e:?}"))?;
                self.intent=Some(intent);
                Ok(json!({"kind":"actual_reservation_acknowledged","volume_uid":volume_uid,
                    "capability_exported":false,"writer_granted":false}))
            }
            Control::Submit { world } => {
                if self.ticket.is_some() || self.held.is_some() || self.submissions>=3 {
                    return Err("one outstanding cold ticket, at most three exact submissions".into());
                }
                let dispatcher=self.dispatcher.as_ref().ok_or("Begin missing")?;
                let intent=self.intent.as_ref().ok_or("real reservation missing")?.clone();
                let agent=self.agent.as_ref().ok_or("private agent missing")?.clone();
                let target=match world {
                    WorldChoice::Actual=>self.world.clone(),
                    WorldChoice::FrozenClone=>{
                        let state=self.world.read().map_err(|_| "actual world poisoned")?.to_state();
                        let mut clone=DesiredWorld::new();clone.install_state(state);
                        Arc::new(RwLock::new(clone))
                    }
                };
                self.submissions+=1;
                let ticket=dispatcher.submit_virgin_offline(target,intent,agent,dispatcher::Replay::NewOnly)?;
                self.ticket=Some(ticket);
                Ok(json!({"kind":"actual_cold_ticket_submitted","outcome":"PENDING","writer_granted":false}))
            }
            Control::Wait => {
                let until=Instant::now()+WAIT_SLICE;
                loop {
                    let outcome=self.ticket.as_ref().ok_or("no outstanding cold ticket")?.try_result()?;
                    if let Some(outcome)=outcome {
                        self.ticket.take();
                        return match outcome {
                            Outcome::Unknown{reason}=>Ok(json!({"kind":"cold_unknown","reason":reason,
                                "rollback_claimed":false,"held_minted":false})),
                            Outcome::ColdPreparedHeld{held}=>{
                                let raw=held.diagnostics()?;
                                let hash=digest(raw);let size=raw.len();
                                self.held=Some(held);
                                Ok(json!({"kind":"actual_cold_held","diagnostics_sha256":hash,"diagnostics_bytes":size,
                                    "writer_granted":false,"core_receipt_exported":false}))
                            }
                            Outcome::CompletedDiagnostics{..}=>Err("wrong online diagnostic result; no cold success".into()),
                        };
                    }
                    if Instant::now()>=until { return Ok(json!({"kind":"cold_pending"})); }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            Control::Cancel => {
                self.ticket.as_ref().ok_or("no outstanding ticket")?.cancel();
                Ok(json!({"kind":"exact_ticket_cancel_requested","rollback_claimed":false,"drain_claimed":false}))
            }
            Control::ReleaseHeld => {
                if self.held.take().is_none() { return Err("no held cold reservation".into()); }
                Ok(json!({"kind":"held_dropped","external_kernel_lock_probe_required":true,"rollback_claimed":false}))
            }
            Control::TryEraseDirectory => {
                let before=self.world.read().map_err(|_| "actual world poisoned")?.storage_node_directory.clone();
                let result=crate::store::commit(&self.world,|w|{
                    w.storage_node_directory=crate::storage_node_directory::Registry::fresh();Ok(())
                });
                let after=self.world.read().map_err(|_| "actual world poisoned")?.storage_node_directory.clone();
                Ok(json!({"kind":"ordinary_commit_directory_erasure_attempt","result":format!("{result:?}"),
                    "acknowledged":result.is_ok(),"registry_unchanged":before==after}))
            }
            Control::PeerControlRootProbe { raft_id, mode } => {
                if self.peer_probes>=6 {return Err("six fixed peer negative probes maximum".into());}
                let intent=self.intent.as_ref().ok_or("real namespace reservation required")?;
                intent.check_current(&self.world)?;
                let (peer,generation)={
                    let w=self.world.read().map_err(|_| "actual world poisoned")?;
                    let directory=w.storage_node_directory.directory().ok_or("directory not enrolled")?;
                    let peer=directory.nodes.iter().find(|p|p.raft_id==raft_id).ok_or("unknown peer voter")?.clone();
                    (peer,w.generation)
                };
                if crate::raft_node::RAFT.get().map(|h|h.node_id)==Some(raft_id) {return Err("peer probe is not a local loopback shortcut".into());}
                let root=self.root.as_ref().ok_or("Begin missing")?;
                let honest=matches!(&mode,PeerProbe::HonestHostLocal);
                let alias=matches!(&mode,PeerProbe::AliasFalseHostLocal);
                let run=root.file_name().and_then(|s|s.to_str()).ok_or("invalid fixture root")?;
                let path=if alias {format!("/srv/royak-storage-qual-alias-{run}/node-identity.json")}
                    else {root.join("node-identity.json").to_string_lossy().into_owned()};
                self.peer_probes+=1;
                let pod=format!("rk-qual-control-{}",self.peer_probes);
                let mut plan=crate::workload::PodLaunch {
                    namespace_uid:Some(intent.owner().namespace_uid.clone()),cluster_id:intent.owner().cluster_id.clone(),
                    node:peer.signer_name,namespace:intent.owner().namespace.clone(),kind:"deployment".into(),
                    owner:"qual-control".into(),pod:pod.clone(),ordinal:None,template:"qualification-only-negative".into(),
                    generation,init_containers:vec![],containers:vec![crate::workload::ContainerLaunch {
                        host_access:None,security_context:None,health:None,name:"main".into(),docker_name:pod,
                        image:"busybox:1.36".into(),command:Some(vec!["true".into()]),env:vec![],
                        mounts:vec![crate::workload::MountLaunch{source:crate::workload::MountSource::HostPath{path},container_path:"/qual-control".into()}],
                        cpu_limit:None,mem_limit_mb:Some(16),publish:vec![],role:"main".into(),
                    }],aliases:vec![],host_local:honest,
                };
                // Fixed negative fixture only: valid current server contract,
                // deliberately hostile mount/host_local metadata. No generic
                // plan input, secret output or Permit constructor is added.
                // Receiver must recheck BEFORE Docker creates anything.
                crate::host_access::issue_launch(&mut plan)?;
                let sealed=crate::workload::seal_launch(&plan)?;
                let endpoint=crate::workload::create_path(&plan);
                let body=serde_json::to_vec(&json!({"sealed":sealed})).map_err(|e|e.to_string())?;
                let result=crate::node_rpc::call("POST",&format!("{}:6443",peer.wireguard_ip),endpoint,&body,Duration::from_secs(5));
                Ok(match result {
                    Ok(bytes)=>json!({"kind":"peer_control_root_probe","accepted":true,"response_sha256":digest(&bytes),"backend_side_effects_verified":false}),
                    Err(error)=>json!({"kind":"peer_control_root_probe","accepted":false,"error":error,
                        "expected_layer":if honest{"host_local_early_refusal"}else{"receiver_reserved_resolved_path"},
                        "backend_side_effects_verified":false}),
                })
            }
            Control::Finish => {
                if self.ticket.is_some() || self.held.is_some() { return Err("Finish requires explicit ticket result and Held release".into()); }
                Ok(json!({"kind":"fixture_finished","resource_cleanup_verified":false}))
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn socket() -> Result<Option<UnixStream>, String> {
    let Some(value)=std::env::var_os(FD_ENV) else {return Ok(None)};
    if value.to_str()!=Some("198") || unsafe{libc::geteuid()}!=0 {return Err("fixed inherited root fixture descriptor required".into());}
    // No socket from a path, forwarded header or caller-selected descriptor.
    let mut cred:libc::ucred=unsafe{std::mem::zeroed()};
    let mut length=std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe{libc::getsockopt(FD,libc::SOL_SOCKET,libc::SO_PEERCRED,
        (&mut cred as *mut libc::ucred).cast(),&mut length)}!=0
        || cred.uid!=0 || cred.pid!=unsafe{libc::getppid()} {
        return Err("fixture socket peer is not the actual root parent".into());
    }
    let mut kind=0i32;let mut kind_len=std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe{libc::getsockopt(FD,libc::SOL_SOCKET,libc::SO_TYPE,
        (&mut kind as *mut i32).cast(),&mut kind_len)}!=0 || kind!=libc::SOCK_STREAM {
        return Err("fixture descriptor is not a stream socket".into());
    }
    let mut domain=0i32;let mut domain_len=std::mem::size_of::<i32>() as libc::socklen_t;
    if unsafe{libc::getsockopt(FD,libc::SOL_SOCKET,libc::SO_DOMAIN,
        (&mut domain as *mut i32).cast(),&mut domain_len)}!=0 || domain!=libc::AF_UNIX {
        return Err("fixture descriptor is not a private Unix socket".into());
    }
    if unsafe{libc::fcntl(FD,libc::F_SETFD,libc::FD_CLOEXEC)}!=0 {return Err("cannot confine fixture FD to daemon".into());}
    let socket=unsafe{UnixStream::from_raw_fd(FD)};
    socket.set_read_timeout(Some(SOCKET_IDLE)).map_err(|e|e.to_string())?;
    socket.set_write_timeout(Some(SOCKET_IDLE)).map_err(|e|e.to_string())?;
    Ok(Some(socket))
}
#[cfg(not(target_os = "linux"))]
fn socket()->Result<Option<UnixStream>,String>{
    if std::env::var_os(FD_ENV).is_some(){Err("fixture is Linux-only".into())}else{Ok(None)}
}

pub(crate) fn start(world:Arc<RwLock<DesiredWorld>>,state_path:&str)->Result<(),String>{
    let Some(mut socket)=socket()? else{return Ok(())};
    if !crate::raft_node::storage_remote_core::is_actual_world(&world) {return Err("same-process actual Raft world required".into());}
    // Startup owns this one fixed thread. No thread/task is created per message.
    let raft_dir=PathBuf::from(format!("{state_path}.raft"));
    std::thread::Builder::new().name("royak-qual-storage-cold".into()).spawn(move||{
        let mut state=State{world,raft_dir,root:None,dispatcher:None,agent:None,intent:None,ticket:None,held:None,submissions:0,peer_probes:0};
        let result=(||->Result<(),String>{
            write_frame(&mut socket,0,Ok(json!({"kind":"same_process_fixture_ready","limits":{"frames":MESSAGE_LIMIT,"bytes":FRAME_LIMIT}})))?;
            for expected in 1..=MESSAGE_LIMIT {
                let frame=read_frame(&mut socket)?;
                if frame.sequence!=expected {return Err("fixture sequence replay/gap refused".into());}
                let finish=matches!(&frame.control,Control::Finish);
                let result=state.handle(frame.control);let finished=finish&&result.is_ok();
                write_frame(&mut socket,expected,result)?;
                if finished{return Ok(());}
            }
            Err("finite fixture message allowance exhausted".into())
        })();
        if let Err(error)=result {eprintln!("[qualification-cold] closed/UNKNOWN: {error}; no rollback/cleanup claim");}
        // State Drop cancels a pending ticket and releases Held. Dispatcher and
        // worker still enforce real drain; this is not a follower grant path.
    }).map_err(|e|e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finite_controls_cannot_import_world_command_or_authority_json() {
        for control in [
            json!({"kind":"inspect","volume_uid":null,"world":{}}),
            json!({"kind":"submit","world":"actual","owns_state":true}),
            json!({"kind":"submit","world":"leader_clone"}),
            json!({"kind":"execute","argv":["true"]}),
            json!({"kind":"receipt","passed":true}),
            json!({"kind":"peer_control_root_probe","raft_id":2,"mode":"arbitrary"}),
        ] {
            assert!(serde_json::from_value::<Frame>(json!({"sequence":1,"control":control})).is_err());
        }
        for control in [json!({"kind":"inspect","volume_uid":null}),
            json!({"kind":"submit","world":"frozen_clone"}),json!({"kind":"finish"})] {
            assert!(serde_json::from_value::<Frame>(json!({"sequence":1,"control":control})).is_ok());
        }
        assert!(serde_json::from_value::<Frame>(json!({"sequence":1,"control":{"kind":"finish"},"extra":true})).is_err());
    }
    #[test]
    fn finite_frame_reader_refuses_oversize_before_body_allocation_or_read() {
        let (mut sender,mut receiver)=UnixStream::pair().unwrap();
        sender.write_all(&((FRAME_LIMIT+1) as u32).to_be_bytes()).unwrap();
        assert!(matches!(read_frame(&mut receiver),Err(error) if error.contains("fixed limit")));
    }
}
