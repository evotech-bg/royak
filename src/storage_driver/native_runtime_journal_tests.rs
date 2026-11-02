//! Authored unit DATA and owned temporary evidence-FD tests, NOT Core/worker proof.
use super::*;
use crate::storage_lifecycle::pod_attachment::{ExpectedAttachScope,InitialReplicaLineage,AttachReplicaTarget,AttachPhase};
use crate::storage_lifecycle::generation::physical::{PrimaryFlushObservation,OfflineReplicaObservation,ExpectedInitScope,InitPhase};

fn maximal_scope()->(ExpectedAttachScope,crate::storage_lifecycle::Volume){
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
    (scope,volume)
}

#[test]
fn maximal_valid_eight_volume_attach_dto_and_full_identity_header_fit_two_bounded_pages(){
    let(scope,volume)=maximal_scope();
    assert_eq!(serde_json::to_value(&scope.pod_writer).unwrap()["volumes"].as_object().unwrap().len(),8);
    assert_eq!(volume.owner().namespace.len(),63);assert_eq!(volume.owner().claim_name.len(),253);assert_eq!(volume.owner().pv_name.len(),253);
    assert_eq!(scope.initial_lineage.offline.len(),3);assert_eq!(scope.generation.virgin_replicas.len(),3);
    let source=serde_json::json!({"version":1,"scope":scope,"session_uid":Uid::new(),"disposition":"UNKNOWN_BEFORE_PERMISSION","restart_authority":false});
    let raw=protocol::encode_node(&source).unwrap();assert!(raw.len()<=32768);
    let header=Journal::header(JobClass::AttachIssuer,&source).unwrap();
    assert!(header.len()<=pages::ATTACH_HEADER_BYTES,"actual maximal closed header {} exceeds23552; change packing, NOT DTO input",header.len());
    // Existing wire DATA limit is unchanged, even for a32KiB opaque value.
    assert_eq!(protocol::encode_node(&"x".repeat(32766)).unwrap().len(),32768);
    assert!(protocol::encode_node(&"x".repeat(32767)).is_err());
}

#[test]
fn maximal_valid_init_scope_and_round_preserve_full_facts_in_one_32k_page(){
    let(scope,_)=maximal_scope();let generation=scope.generation.clone();let fact=&generation.virgin_replicas[0];
    let init=ExpectedInitScope{version:1,owner:scope.owner.clone(),generation:generation.clone(),
        issuer_node_uid:scope.issuer_node_uid.clone(),issuer_boot:scope.issuer_boot.clone(),issuer_revision:scope.issuer_revision.clone(),
        directory_sha256:scope.directory_sha256.clone(),scope_sha256:scope.scope_sha256.clone(),
        target_node_uid:fact.node_uid.clone(),target_boot:fact.node_boot_id.clone(),prepare_job_uid:Uid::new(),
        phase_job_uid:Uid::new(),phase:InitPhase::ObserveOffline,remaining_budget_ms:180000};
    init.validate().unwrap();
    let spec=JobSpec{version:2,owner:scope.owner.clone(),operation_uid:generation.initialize_operation_uid.clone(),dataset_uid:Some(generation.uid.clone()),
        kind:protocol::JobKind::InitializeVirginGeneration,issuer_node_uid:init.issuer_node_uid.clone(),issuer_boot:init.issuer_boot.clone(),
        target_node_uid:init.target_node_uid.clone(),target_boot:init.target_boot.clone(),job_uid:init.phase_job_uid.clone(),
        plan_sha256:fact.plan_sha256.clone(),scope_sha256:init.scope_sha256.clone(),directory_sha256:init.directory_sha256.clone(),
        issuer_revision:init.issuer_revision.clone(),maximum_duration_ms:180000,initialization:Some(init.clone())};
    for source in [serde_json::json!({"version":2,"scope":init,"reference":fact,"disposition":"UNKNOWN_BEFORE_LAUNCH","restart_authority":false}),
        serde_json::json!({"version":2,"spec":spec,"spec_sha256":"f".repeat(64),"acknowledged_core":true,"restart_authority":false})]{
        let full=Journal::header(JobClass::InitIssuer,&source).unwrap();assert!(full.len()+pages::PREFIX_BYTES+2*pages::FRAME_BYTES<=32768);
    }
    let round=Journal::header(JobClass::InitRound,&serde_json::json!({"version":2,"prepare_owner":scope.owner,"prepare_operation_uid":generation.prepare_operation_uid,
        "reference":fact,"generation":generation,"restart_authority":false})).unwrap();
    assert!(round.len()+pages::PREFIX_BYTES+3*pages::FRAME_BYTES<=32768);
}

#[test]
fn whole_eight_volume_file_charge_is397_without_optimistic_second_page_reuse(){
    assert_eq!(group_files(1),Some(52));assert_eq!(2+group_files(1).unwrap(),54);
    assert_eq!(group_files(8),Some(395));assert_eq!(2+group_files(8).unwrap(),397);
    assert_eq!(397+4,401);assert!(group_files(0).is_none());assert!(group_files(9).is_none());
    let ids=(0..8).map(|_|Uid::new()).collect::<Vec<_>>();
    let mut group=Group{run:Uid::new(),volumes:ids.iter().cloned().collect(),used:BTreeMap::new()};
    group.claim(Bucket::Budget,None,1).unwrap();group.claim(Bucket::Reservation,None,1).unwrap();group.claim(Bucket::Outcome,None,1).unwrap();
    for id in &ids{for(bucket,count)in[(Bucket::ColdRun,1),(Bucket::ColdExpected,2),(Bucket::ColdHeld,1),(Bucket::InitRound,1),(Bucket::InitJob,26),(Bucket::AttachPage,18)]{
        group.claim(bucket,Some(id),count).unwrap();assert!(group.claim(bucket,Some(id),1).is_err());
    }}
    assert_eq!(group.used.values().sum::<usize>(),395);
    assert!(group.claim(Bucket::AttachPage,Some(&Uid::new()),2).is_err());
    assert_eq!(group.used.values().sum::<usize>(),395);
}

#[test]
fn all_new_partial_and_complete_page_histories_freeze_restart_not_replay(){
    for name in ["budget-x.json","cold-job-x-p0.jrn","init-round-x-p0.jrn","init-job-x-p0.jrn","attach-job-x-p1.jrn","consumer-x-admission.json"]{
        assert!(has_history(&["lock".into(),"runtime-owner.json".into(),name.into()]));
    }
}

struct OwnedJournalData {journal:Journal,path:std::path::PathBuf}
impl OwnedJournalData {
    /// Unit operational-files fixture ONLY, no Runtime Shared/Core/worker,
    /// authority, cgroup or physical storage capability is constructed.
    fn new()->Self{
        let path=std::fs::canonicalize(std::env::temp_dir()).unwrap().join(format!("royak-journal-budget-{}",Uid::new().as_str()));
        let dir=Arc::new(Dir::open(&path,true).unwrap());let lease=dir.lock().unwrap();
        let owner=Owner{version:1,cluster:"a".repeat(12),node:Uid::new(),
            boot:serde_json::from_value(serde_json::json!("12345678-1234-4234-a234-123456789abc")).unwrap(),configuration_sha256:"b".repeat(64)};
        let journal=Journal{dir,_lease:lease,owner,state:Mutex::new(State{frozen:false,entries:2,failed:false,group:None,
            jobs:BTreeMap::new(),exact:BTreeMap::new(),cold_jobs:BTreeMap::new(),cold_runs:BTreeMap::new(),consumer:None})};
        Self{journal,path}
    }
}
impl Drop for OwnedJournalData{fn drop(&mut self){std::fs::remove_dir_all(&self.path).unwrap();}}

#[test]
fn actual_precharge_is_once_and_dynamic_overflow_keeps_prior_charge_unknown(){
    let data=OwnedJournalData::new();let run=Uid::new();let volume=Uid::new();
    data.journal.precharge_group(&run,&[volume.clone()]).unwrap();
    assert_eq!(data.journal.state.lock().unwrap().entries,54);
    assert!(data.journal.precharge_group(&Uid::new(),&[volume.clone()]).is_err());
    // This is deliberately NOT a valid closed job DTO. It proves an unexpected
    // later overflow is retained UNKNOWN, not whole-pipeline zero effect.
    assert!(data.journal.start(JobClass::AttachIssuer,&volume,"oversized".into(),&"x".repeat(32766)).is_err());
    let state=data.journal.state.lock().unwrap();assert_eq!(state.entries,54);assert!(state.failed);
    assert_eq!(state.exact.len(),1);assert!(data.path.join(format!("budget-{}.json",run.as_str())).exists());
}

#[test]
fn actual_consumer_exact_plan_reserves_before_first_effect_and_no_refund_on_unknown(){
    let data=OwnedJournalData::new();let run=Uid::new();data.journal.precharge_group(&run,&[Uid::new()]).unwrap();
    let budget=data.journal.reserve_consumer_plan(&"c".repeat(64),1,0).unwrap();
    assert_eq!(data.journal.state.lock().unwrap().entries,58);
    assert!(data.journal.reserve_consumer_plan(&"d".repeat(64),1,0).is_err());
    let operation=Uid::new();let action=Uid::new();
    data.journal.consumer_admission_record(&budget,&operation,&action,&serde_json::json!({"actual_data":"admission"})).unwrap();
    data.journal.consumer_outcome_record(&budget,&operation,&action,&serde_json::json!({"actual_data":"known outcome"})).unwrap();
    assert!(data.journal.consumer_outcome_record(&budget,&operation,&action,&serde_json::json!({"replay":true})).is_err());
    let state=data.journal.state.lock().unwrap();assert!(state.failed);assert_eq!(state.entries,58);
    assert!(Arc::ptr_eq(state.consumer.as_ref().unwrap(),&budget.root));
    let retained=budget.root.state.lock().unwrap();assert!(retained.failed);assert_eq!(retained.remaining,2);
}

#[test]
fn consumer_128_is_data_ceiling_not_a_false_512_file_capacity_claim(){
    let data=OwnedJournalData::new();let volumes=(0..8).map(|_|Uid::new()).collect::<Vec<_>>();
    data.journal.precharge_group(&Uid::new(),&volumes).unwrap();
    assert_eq!(data.journal.state.lock().unwrap().entries,397);
    assert!(data.journal.reserve_consumer_plan(&"c".repeat(64),128,128).is_err());
    {let state=data.journal.state.lock().unwrap();assert_eq!(state.entries,397);assert!(state.consumer.is_none());assert!(!state.failed);}
    let accepted=data.journal.reserve_consumer_plan(&"c".repeat(64),28,0).unwrap();
    assert_eq!(accepted.root.slots,112);assert_eq!(data.journal.state.lock().unwrap().entries,509);
}

#[test]
fn healthy_existing_attach_evidence_refuses_global_unknown_before_bytes_or_sequence_change(){
    // Real owned temporary operational files, NOT an ExpectedAttachJob,
    // actual Core, helper, FD capability, session or physical receipt fixture.
    let data=OwnedJournalData::new();let volume=Uid::new();
    data.journal.precharge_group(&Uid::new(),&[volume.clone()]).unwrap();
    let key="healthy-current-attach";
    let source=serde_json::json!({"unit_operational_data_only":true});
    data.journal.start(JobClass::AttachIssuer,&volume,key.into(),&source).unwrap();
    let header=Journal::header(JobClass::AttachIssuer,&source).unwrap();
    data.journal.append_existing(key,Some(&header),411,[1;32]).unwrap();
    let path=data.path.join(format!("{key}-p0.jrn"));
    let before=std::fs::read(&path).unwrap();let offset=pages::PREFIX_BYTES+header.len();
    let sequence=u64::from_be_bytes(before[offset..offset+8].try_into().unwrap());
    assert_eq!(sequence,1);
    let original=data.journal.state.lock().unwrap().jobs.get(key).unwrap().clone();
    assert!(data.journal.latch::<()>(Err("unit-injected OTHER durable-record failure".into())).is_err());
    assert!(data.journal.append_existing(key,Some(&header),411,[2;32]).is_err());
    let after=std::fs::read(&path).unwrap();assert_eq!(after,before);
    assert_eq!(u64::from_be_bytes(after[offset..offset+8].try_into().unwrap()),sequence);
    let state=data.journal.state.lock().unwrap();assert!(state.failed);assert_eq!(state.entries,54);
    assert!(Arc::ptr_eq(state.jobs.get(key).unwrap(),&original));
}
