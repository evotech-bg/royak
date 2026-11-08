//! AUTHOR-ONLY DATA/source cases. No actual parent/book/native/drain/FD
//! capability is constructed. No physical topology is claimed to pass.
use super::*;
use crate::storage_remote_protocol as protocol;
use crate::storage_lifecycle::pod_attachment::{InitialReplicaLineage,AttachReplicaTarget,AttachPhase,MountObservation};
use crate::storage_lifecycle::generation::physical::{PrimaryFlushObservation,OfflineReplicaObservation};
pub(crate) fn data_scope()->ExpectedAttachScope{maximal_scope().0}
fn table_data(mounted:usize)->(ExpectedAttachScope,InventoryRoleTable){
    use super::super::super::super::replica::initialize::managed_mount::inventory::{InventoryMountOrigin,InventoryFdObservation};
    let(mut scope,volume,world)=maximal_scope();
    // Max mounted-role envelope is writer-local, not a fabricated mounted
    // Secondary. Full metadata World remains the existing validated model.
    scope.phase_node_uid=scope.mount_ref.node_uid().clone();scope.phase_boot=scope.mount_ref.node_boot().clone();
    scope.validate().unwrap();scope.check_volume(&volume).unwrap();
    let facts=world.storage_identities.volumes.values().map(|id|world.storage_identities.lifecycle.get(id).unwrap()
        .data_generation().unwrap().virgin_replicas.iter().find(|f|f.node_uid==scope.phase_node_uid).unwrap().clone()).collect::<Vec<_>>();
    assert_eq!(facts.len(),8);let namespace=(u64::MAX,u64::MAX);
    let watch:WatchProcessObservation=serde_json::from_value(serde_json::json!({"pid":u32::MAX,"boot":scope.phase_boot,"start":u64::MAX,
        "captured_tid":u32::MAX,"pidfd_identity":[u64::MAX,u64::MAX,u32::MAX],"proc_identity":[u64::MAX,u64::MAX,u32::MAX],"namespace":namespace})).unwrap();
    let members=facts.iter().take(mounted).enumerate().map(|(i,fact)|{
        let major=147u32;let minor=i as u32;let device=libc::makedev(major.try_into().expect("fixture major fits target makedev"),minor.try_into().expect("fixture minor fits target makedev"))as u64;let mount_id=u64::MAX-i as u64;
        MemberRoleData{observation:InventoryMemberObservation{kind:InventoryMountOrigin::Provisional,
            fact:fact.clone(),mounted:MountObservation{mount_id,namespace_device:namespace.0,namespace_inode:namespace.1,device_major:major,device_minor:minor,
                filesystem_uuid:scope.generation.filesystem_uuid.clone(),target:format!("/var/lib/royak/storage/mounts/{}/1/{}",fact.volume_uid.as_str(),scope.mount_ref.writer_uid().as_uid().as_str()),
                private_propagation:true},source_scope_sha256:"f".repeat(64),origin_native:live::JobIdentity{node_uid:scope.phase_node_uid.clone(),
                boot_id:scope.phase_boot.as_str().into(),volume_uid:fact.volume_uid.clone(),operation_uid:Uid::new(),attempt_uid:Uid::new(),binding_sha256:"f".repeat(64)},
            origin_completion_sha256:"f".repeat(64),original_mounted:InventoryFdObservation{number:1000+2*i as i32,device,inode:u64::MAX,rdev:0,
                mode:libc::S_IFDIR as u32|0o700,mount_id:Some(mount_id)},original_block:InventoryFdObservation{number:1001+2*i as i32,device:1,
                inode:u64::MAX,rdev:device,mode:libc::S_IFBLK as u32|0o600,mount_id:None}},mounted_fd:100+2*i as i32,block_fd:101+2*i as i32}
    }).collect();
    let table=InventoryRoleTable{domain:DOMAIN.into(),version:1,context_uid:Uid::new(),group_sha256:"f".repeat(64),source_scope_sha256:scope_digest(&scope).unwrap(),
        round_uid:scope.round_uid.clone(),namespace,namespace_fd:80,watch,watch_pidfd:81,watch_proc:82,members,cgroup_fd:83,
        cgroup_identity:(u64::MAX,u64::MAX),delegated_root:format!("/{}",(0..16).map(|i|"d".repeat(if i==15{254}else{255})).collect::<Vec<_>>().join("/")).into(),live_members:facts};
    (scope,table)
}
#[test]fn v7_total_roles_include_baseline_cgroup_inventory_and_watch_proof(){
    assert_eq!(total_roles(0).unwrap(),7);assert_eq!(total_roles(8).unwrap(),23);
    assert_eq!(capture_peak(0).unwrap(),20);assert_eq!(capture_peak(8).unwrap(),36);assert!(total_roles(9).is_err());
}
#[test]fn v7_eight_live_unmounted_members_have_no_fabricated_mount_roles(){
    let(scope,table)=table_data(0);table.validate(&scope,Some([3,4,5])).unwrap();
    assert_eq!(table.live_members.len(),8);assert!(table.members.is_empty());assert_eq!(table.role_numbers().len()+3,7);
}
#[test]fn v7_maximal_valid_eight_member_capsule_fits_original_envelopes(){
    let(scope,table)=table_data(8);table.validate(&scope,Some([3,4,5])).unwrap();
    let pool=super::super::super::super::Config{version:1,cluster_id:scope.owner.cluster_id.clone(),node_uid:scope.phase_node_uid.clone(),
        pool_uid:scope.target().unwrap().pool_uid.clone(),vg_name:"v".repeat(64),vg_uuid:"123456-1234-1234-1234-1234-1234-123456".into(),
        pv_uuid:"654321-4321-4321-4321-4321-4321-654321".into(),disk_serial:"S".repeat(64),max_volume_bytes:1024u64.pow(4),max_managed_bytes:u64::MAX};
    pool.validate().unwrap();scope.validate().unwrap();
    let identity=live::JobIdentity{node_uid:scope.phase_node_uid.clone(),boot_id:scope.phase_boot.as_str().into(),volume_uid:scope.owner.volume_uid.clone(),
        operation_uid:scope.mount_ref.operation_uid().clone(),attempt_uid:scope.phase_job_uid.clone(),binding_sha256:"f".repeat(64)};
    let plan=super::super::super::super::replica::initialized_activation::maximal_inventory_plan_data(&pool,&scope);
    let payload=Payload{config:serde_json::to_value(OwnedAttachPayload{attachment:AttachPayload{pool,scope:scope.clone(),step:AttachNativeStep::Single,
        publication:None,existing_anchor:None},roles:table.clone()}).unwrap(),plan,projection:Vec::new(),
        extended:Some(ExtendedJob::AttachWithOwnedInventory),dataset_uid:Some(scope.generation.uid.clone()),remote_binding:Some(scope_digest(&scope).unwrap()),
        initialization:None,worker_remaining_ms:Some(180000)};
    let capsule=Capsule{version:7,identity,payload,budget:super::super::super::super::ResourceBudget{pids_max:4096,memory_max_bytes:16*1024u64.pow(3),
        cpu_quota_us:8_000_000,cpu_period_us:1_000_000}};
    assert!(valid_capsule(&capsule));let raw=serde_json::to_vec(&capsule).unwrap();
    assert!(raw.len()as u64<=CAPSULE_LIMIT,"max DATA envelope {} exceeds original64KiB",raw.len());assert_eq!(table.role_numbers().len()+3,23);
    // Original2pages/512 full256-bit hashes. Tag419 consumes an ORIGINAL
    // admission, not a new read-window or per-helper allowance.
    assert!(23552+2*128+512*80<=2*32768);assert_eq!(CAPSULE_LIMIT,64*1024);
}
#[test]fn v7_role_alias_wrong_source_namespace_member_and_root_refuse(){
    let(scope,table)=table_data(8);
    for case in 0..8{let mut bad=table.clone();match case{0=>bad.watch_pidfd=bad.namespace_fd,1=>bad.cgroup_fd=3,
        2=>bad.source_scope_sha256="e".repeat(64),3=>bad.round_uid=Uid::new(),4=>bad.members[0].observation.mounted.namespace_inode=1,
        5=>bad.members[1].observation.fact=bad.members[0].observation.fact.clone(),6=>bad.live_members.clear(),_=>bad.members[0].observation.mounted.target="/".into()}
        assert!(bad.validate(&scope,Some([3,4,5])).is_err(),"negative DATA case {case}");}
}
#[test]fn v7_inventory_operation_binds_full_context_and_fixed_vector(){
    let(_,table)=table_data(8);let mut changed=table.clone();changed.context_uid=Uid::new();
    assert_ne!(InventoryOperation::Pvs.detail(&table).unwrap(),InventoryOperation::Pvs.detail(&changed).unwrap());
    for op in [InventoryOperation::Pvs,InventoryOperation::Vgs,InventoryOperation::Lvs,InventoryOperation::Lsblk,InventoryOperation::KernelCensus]{
        assert_eq!(InventoryOperation::from_boundary(op.boundary()),Some(op));}
    for old in ["fixed-program","attachment-read","terminal-reference-census","initialization-read","mount"]{assert!(InventoryOperation::from_boundary(old).is_none());}
    assert!(InventoryOperation::Lsblk.args().contains(&"--tree"));
}
#[test]fn v7_source_preserves_original_cgroup_and_releases_guards_before_authorization(){
    let source=include_str!("dispatcher_attach_inventory.rs");
    let launch=source.split("pub(super) fn launch_owned").nth(1).unwrap().split("pub(in crate::storage_driver) const PROFILE").next().unwrap();
    assert!(!launch.contains("JobCgroup::open("));assert!(launch.contains("duplicate_for_owned_inventory"));
    assert!(launch.contains("terminal_cgroup=Some(value.clone())"));
    let parent=include_str!("native_runtime_attach_parent.rs");
    let grant=parent.split("fn approve_owned_inventory(").nth(1).unwrap().split("async fn fresh_owned_inventory").next().unwrap();
    assert!(!grant.contains(".probe.lock("));assert!(!grant.contains(".state.lock("));assert!(grant.contains("rt.block_on("));
}
fn maximal_scope()->(ExpectedAttachScope,crate::storage_lifecycle::Volume,crate::reconcile::DesiredWorld){
    let(mut world,uid,node,_)=crate::storage_lifecycle::model_pod_writer_world();
    let mut raw=serde_json::to_value(world.storage_identities.lifecycle.get(&uid).unwrap()).unwrap();
    raw["owner"]["cluster_id"]=serde_json::json!("f".repeat(12));
    let longest=["z".repeat(63),"z".repeat(63),"z".repeat(63),"z".repeat(61)].join(".");
    assert_eq!(longest.len(),253);assert!(crate::store::is_dns_subdomain(&longest));
    raw["owner"]["namespace"]=serde_json::json!("z".repeat(63));
    for key in ["claim_name","pv_name"]{raw["owner"][key]=serde_json::json!(longest);}
    let maximum=u64::MAX-4095;
    raw["capacity_bytes"]=serde_json::json!(maximum);
    for fact in raw["data_generation"]["virgin_replicas"].as_array_mut().unwrap(){
        fact["requested_bytes"]=serde_json::json!(maximum);fact["exposed_bytes"]=serde_json::json!(maximum);
    }
    let mut volume:crate::storage_lifecycle::Volume=serde_json::from_value(raw).unwrap();
    let generation=volume.data_generation().unwrap().clone();
    for fact in &generation.virgin_replicas{fact.validate().unwrap();}
    let primary=PrimaryFlushObservation{version:1,owner:volume.owner().clone(),data_generation_uid:generation.uid.clone(),
        initialize_operation_uid:generation.initialize_operation_uid.clone(),filesystem_uuid:generation.filesystem_uuid.clone(),
        replica:generation.virgin_replicas[0].clone(),backing_major:u32::MAX as u64,backing_minor:u32::MAX as u64,
        backing_bytes:u64::MAX,data_sha256:"a".repeat(64),flush_sha256:"b".repeat(64),evidence_sha256:"c".repeat(64)};
    let offline=std::array::from_fn(|i|OfflineReplicaObservation{version:1,owner:volume.owner().clone(),
        data_generation_uid:generation.uid.clone(),initialize_operation_uid:generation.initialize_operation_uid.clone(),
        filesystem_uuid:generation.filesystem_uuid.clone(),replica:generation.virgin_replicas[i].clone(),
        backing_major:u32::MAX as u64,backing_minor:u32::MAX as u64,backing_bytes:u64::MAX,data_sha256:"a".repeat(64),
        offline_metadata_sha256:"d".repeat(64),drbd_current_uuid:"ffffffffffffffff".into(),evidence_sha256:"e".repeat(64)});
    let evidence=Uid::new();
    let prior=protocol::hash(&serde_json::to_vec(&("royak-physical-three-node-generation-v1",volume.owner(),&generation,&primary,&offline)).unwrap());
    let mut raw=serde_json::to_value(&volume).unwrap();raw["evidence"]=serde_json::json!({"uid":evidence,"sha256":prior});
    volume=serde_json::from_value(raw).unwrap();
    let writer_boot=generation.virgin_replicas.iter().find(|r|r.node_uid==node).unwrap().node_boot_id.clone();
    volume.begin_attach(0,node.clone(),writer_boot,Uid::new(),Uid::new()).unwrap();
    let mut raw=serde_json::to_value(&volume).unwrap();
    let namespace=volume.owner().namespace.clone();let workload="w".repeat(63);
    raw["pod_writer"]["namespace"]=serde_json::json!(namespace);
    raw["pod_writer"]["workload"]=serde_json::json!(workload);
    raw["pod_writer"]["pod"]=serde_json::json!(format!("{}-{}",crate::store::pod_stem(&namespace,&workload),u32::MAX));
    raw["pod_writer"]["stateful"]=serde_json::json!(true);raw["pod_writer"]["ordinal"]=serde_json::json!(u32::MAX);
    // Build and validate the WHOLE canonical eight-volume metadata World,
    // not merely an owner-unchecked wire scope. Still DATA/model only: no
    // actual Raft pointer, receipt factory, parent, FD or effect authority.
    let mut rows=Vec::new();let mut bindings=serde_json::Map::new();let mut mounts=Vec::new();
    let pv_template=world.pvs.values().next().unwrap().clone();
    let pvc_template=world.pvcs.values().next().unwrap().clone();
    let mut deployment=world.deployments["a/db"].clone();
    world.pvs.clear();world.pvcs.clear();world.deployments.clear();
    world.cluster_id=volume.owner().cluster_id.clone();
    world.namespaces=vec![crate::store::DEFAULT_NS.into(),namespace.clone()];
    world.storage_identities.namespaces.retain(|name,_|name==crate::store::DEFAULT_NS);
    world.storage_identities.namespaces.insert(namespace.clone(),volume.owner().namespace_uid.clone());
    world.storage_identities.claims.clear();world.storage_identities.volumes.clear();
    for index in 0..8{
        let mut row=raw.clone();let id=if index==0{uid.clone()}else{Uid::new()};
        let claim=if index==0{volume.owner().claim_uid.clone()}else{Uid::new()};
        let name=if index==0{longest.clone()}else{format!("{}{}",&longest[..252],index)};
        assert_eq!(name.len(),253);assert!(crate::store::is_dns_subdomain(&name));
        row["owner"]["volume_uid"]=serde_json::json!(id);row["owner"]["claim_uid"]=serde_json::json!(claim);
        row["owner"]["pv_name"]=serde_json::json!(name);row["owner"]["claim_name"]=serde_json::json!(name);
        if index!=0{
            let data=Uid::new();let prepare=Uid::new();let initialize=Uid::new();
            row["data_generation"]["uid"]=serde_json::json!(data);
            row["data_generation"]["prepare_operation_uid"]=serde_json::json!(prepare);
            row["data_generation"]["initialize_operation_uid"]=serde_json::json!(initialize);
            row["assignment"]["data_generation_uid"]=serde_json::json!(data);
            for fact in row["data_generation"]["virgin_replicas"].as_array_mut().unwrap(){
                fact["volume_uid"]=serde_json::json!(id);fact["prepare_operation_uid"]=serde_json::json!(prepare);
                fact["allocation_nonce"]=serde_json::json!(Uid::new());
            }
        }
        bindings.insert(id.as_str().into(),serde_json::json!({"claim_uid":claim,"generation_uid":row["data_generation"]["uid"],
            "filesystem_uuid":row["data_generation"]["filesystem_uuid"]}));
        let key=crate::store::obj_key(&namespace,&name);
        let mut pv=pv_template.clone();pv.name=name.clone();pv.bound_to=Some(key.clone());pv.capacity=maximum.to_string();
        let mut pvc=pvc_template.clone();pvc.name=name.clone();pvc.namespace=namespace.clone();pvc.bound_pv=Some(name.clone());pvc.requested=maximum.to_string();
        world.pvs.insert(name.clone(),pv);world.pvcs.insert(key.clone(),pvc);
        world.storage_identities.volumes.insert(name.clone(),id.clone());
        world.storage_identities.claims.insert(key,crate::storage_identity::ClaimIdentity{uid:claim,namespace_uid:volume.owner().namespace_uid.clone()});
        mounts.push((format!("pvc:{name}"),format!("/data/{index}")));rows.push((id,row));
    }
    deployment.namespace=namespace.clone();deployment.name=workload.clone();deployment.stateful=true;deployment.replicas=u32::MAX;
    deployment.containers[0].volumes=mounts;
    let source_bytes=serde_json::to_vec(&(&deployment.namespace,&deployment.name,deployment.stateful,
        &deployment.init_containers,&deployment.containers,&deployment.resource_limits,deployment.restart_nonce)).unwrap();
    assert!(source_bytes.len()<=32768);let source=protocol::hash(&source_bytes);
    world.deployments.insert(crate::store::obj_key(&namespace,&workload),deployment);
    let mut registry=serde_json::to_value(&world.storage_identities.lifecycle).unwrap();
    registry["volumes"]=serde_json::json!({});
    for(id,mut row)in rows{
        row["pod_writer"]["volumes"]=serde_json::Value::Object(bindings.clone());
        row["pod_writer"]["source_sha256"]=serde_json::json!(source);
        registry["volumes"][id.as_str()]=row;
    }
    world.storage_identities.lifecycle=serde_json::from_value(registry).unwrap();
    let state=world.to_state();state.storage_identities.validate(&state).unwrap();
    volume=world.storage_identities.lifecycle.get(&uid).unwrap().clone();
    volume.pod_writer().unwrap().check_source_current(&world).unwrap();
    let replicas=std::array::from_fn(|i|AttachReplicaTarget{node_uid:generation.virgin_replicas[i].node_uid.clone(),
        current_boot:generation.virgin_replicas[i].node_boot_id.clone(),pool_uid:generation.virgin_replicas[i].pool_uid.clone(),
        plan_sha256:generation.virgin_replicas[i].plan_sha256.clone()});
    let revision=protocol::Revision{term:u64::MAX,leader_raft_id:u64::MAX,applied_term:u64::MAX,applied_leader_raft_id:u64::MAX,
        applied_index:u64::MAX,desired_generation:u64::MAX,membership_sha256:"f".repeat(64)};
    let scope=ExpectedAttachScope{version:1,owner:volume.owner().clone(),
        mount_ref:crate::storage_pod_writer::ManagedMountRef::from_metadata(&volume).unwrap(),
        pod_writer:volume.pod_writer().unwrap().clone(),generation:generation.clone(),
        initial_lineage:InitialReplicaLineage{committed_evidence_uid:evidence,primary,offline},replicas:replicas.clone(),
        round_uid:Uid::new(),phase:AttachPhase::ObserveSynchronized,phase_job_uid:Uid::new(),
        phase_node_uid:replicas[1].node_uid.clone(),phase_boot:replicas[1].current_boot.clone(),
        issuer_node_uid:replicas[0].node_uid.clone(),issuer_boot:replicas[0].current_boot.clone(),issuer_revision:revision,
        scope_sha256:"e".repeat(64),directory_sha256:"f".repeat(64),remaining_budget_ms:180000};
    scope.validate().unwrap();scope.check_volume(&volume).unwrap();
    (scope,volume,world)
}
