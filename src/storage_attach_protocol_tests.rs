//! Tests actual pure validators USED by the real session. No registered
//! parent/owner/prepared mount or physical permission factory is supplied.
use super::*;
fn uid(n:u8)->Uid{serde_json::from_value(serde_json::json!(format!("{n:032x}"))).unwrap()}
fn revision()->Revision{Revision {term:7,leader_raft_id:1,applied_term:7,applied_leader_raft_id:1,
    applied_index:41,desired_generation:35,membership_sha256:"a".repeat(64)}}
fn expectation()->ReplyExpectation{ReplyExpectation {purpose:Purpose::MountedCommit,sequence:11,nonce:uid(2),
    request_sha256:"b".repeat(64),scope_sha256:"c".repeat(64),session:Some(uid(3)),minimum:revision(),maximum_ms:500}}
fn reply()->Reply{Reply {domain:WIRE.into(),version:1,scope_sha256:"c".repeat(64),purpose:Purpose::MountedCommit,
    sequence:11,nonce:uid(2),request_sha256:"b".repeat(64),session:uid(3),confirmed_revision:revision(),remaining_ms:500}}
#[test]
fn exact_mounted_commit_reply_data_matches_validator_not_a_mount_capability(){
    check_reply_fields(&expectation(),&reply()).unwrap();
}
#[test]
fn mounted_commit_and_confirm_are_not_interchangeable(){
    let mut data=reply();data.purpose=Purpose::MountedCommitConfirm;
    assert!(check_reply_fields(&expectation(),&data).is_err());
}
#[test]
fn reply_nonce_sequence_scope_request_and_session_are_exact(){
    for case in 0..5 {let mut data=reply();match case {0=>data.nonce=uid(9),1=>data.sequence+=1,
        2=>data.scope_sha256="d".repeat(64),3=>data.request_sha256="e".repeat(64),_=>data.session=uid(9)}
        assert!(check_reply_fields(&expectation(),&data).is_err(),"case {case}");
    }
}
#[test]
fn reply_changed_term_leader_membership_or_lagged_applied_state_is_denied(){
    for case in 0..4 {let mut data=reply();match case {0=>data.confirmed_revision.term+=1,
        1=>data.confirmed_revision.leader_raft_id=2,2=>data.confirmed_revision.membership_sha256="f".repeat(64),
        _=>data.confirmed_revision.applied_index-=1}
        assert!(check_reply_fields(&expectation(),&data).is_err(),"case {case}");
    }
}
#[test]
fn reply_zero_extended_budget_or_wrong_domain_is_denied(){
    for case in 0..4 {let mut data=reply();match case {0=>data.remaining_ms=0,1=>data.remaining_ms=501,
        2=>data.domain="royak-storage-issuer-v1".into(),_=>data.version=2}
        assert!(check_reply_fields(&expectation(),&data).is_err());
    }
}
#[test]
fn delayed_reply_anchors_to_original_request_not_receipt(){
    let start=Instant::now();let original=start+Duration::from_millis(800);
    let now=start+Duration::from_millis(200);
    let (accepted,_)=reply_deadlines(original,start,500,now).unwrap();
    assert_eq!(accepted,start+Duration::from_millis(500));
    assert_ne!(accepted,now+Duration::from_millis(500));
}
#[test]
fn later_request_cannot_extend_already_shortened_original_round(){
    let start=Instant::now();let original=start+Duration::from_millis(450);
    let later=start+Duration::from_millis(200);
    let (accepted,_)=reply_deadlines(original,later,500,later+Duration::from_millis(20)).unwrap();
    assert_eq!(accepted,original);
}
#[test]
fn applied_wait_hint_is_clipped_to_original_request_freshness(){
    let start=Instant::now();let original=start+Duration::from_secs(180);
    let (accepted,fresh)=reply_deadlines(original,start,180_000,start).unwrap();
    assert_eq!(accepted,original);
    assert_eq!(fresh,start+Duration::from_millis(MAX_BOUNDARY_MS));
}
#[test]
fn reply_after_original_or_request_freshness_expiry_is_denied(){
    let start=Instant::now();
    assert!(reply_deadlines(start+Duration::from_millis(250),start,500,start+Duration::from_millis(250)).is_err());
    assert!(reply_deadlines(start+Duration::from_secs(180),start,180_000,start+Duration::from_millis(MAX_BOUNDARY_MS)).is_err());
}
#[test]
fn attach_boundary_matrix_never_grants_read_anchor_or_mount_in_another_phase(){
    for phase in [AttachPhase::ActivateReplica,AttachPhase::ObserveSynchronized,AttachPhase::PromoteTarget,
        AttachPhase::Mount,AttachPhase::ObserveMounted] {
        assert_eq!(AttachBoundary::Read.allowed(phase),phase==AttachPhase::ObserveSynchronized);
        for kind in [AttachBoundary::AnchorBind,AttachBoundary::AnchorPrivate,AttachBoundary::MountExt4,AttachBoundary::MakePrivate] {
            assert_eq!(kind.allowed(phase),phase==AttachPhase::Mount);
        }
    }
}
#[test]
fn commit_route_is_distinct_and_closed_purposes_select_only_expected_route(){
    assert_eq!(Purpose::MountedCommit.path(),MOUNTED_PATH);
    assert_eq!(Purpose::MountedCommitConfirm.path(),MOUNTED_PATH);
    for kind in [AttachBoundary::Start,AttachBoundary::Identity,AttachBoundary::Program,AttachBoundary::Read,
        AttachBoundary::AnchorBind,AttachBoundary::AnchorPrivate,AttachBoundary::MountExt4,AttachBoundary::MakePrivate,AttachBoundary::Complete] {
        assert_eq!(Purpose::PhaseBoundary(kind).path(),PATH);
    }
    assert_ne!(PATH,GRANT_PATH);assert_ne!(PATH,BOUNDARY_PATH);assert_ne!(MOUNTED_PATH,NODE_JOB_PATH);
}
#[test]
fn malformed_or_foreign_wire_data_does_not_construct_registered_parent(){
    for raw in [b"{}".as_slice(),b"null".as_slice(),b"{\"domain\":\"royak-storage-issuer-v1\"}".as_slice()] {
        assert!(Request::decode(raw).is_err());
    }
}

struct ModelSessionData {scope:ExpectedAttachScope,view:CoreObservation,directory:VerifiedDirectory}
fn model_session_data()->ModelSessionData {
    // DATA-only lifecycle/protocol fixture. It never creates a registered
    // parent, actual World, native attempt, mount witness or prepared commit.
    use crate::storage_lifecycle::pod_attachment::{InitialReplicaLineage,AttachReplicaTarget};
    use crate::storage_lifecycle::generation::physical::{PrimaryFlushObservation,OfflineReplicaObservation};
    let (world,uid,node,model_boot)=crate::storage_lifecycle::model_pod_writer_world();
    let mut volume=world.storage_identities.lifecycle.get(&uid).unwrap().clone();
    // This local protocol DATA fixture needs an enrolled-format cluster ID;
    // the shared generic lifecycle model deliberately uses legacy instead.
    let mut volume_data=serde_json::to_value(&volume).unwrap();
    volume_data["owner"]["cluster_id"]=serde_json::json!("a".repeat(12));
    volume=serde_json::from_value(volume_data).unwrap();
    let generation=volume.data_generation().unwrap().clone();
    let primary=PrimaryFlushObservation {version:1,owner:volume.owner().clone(),data_generation_uid:generation.uid.clone(),
        initialize_operation_uid:generation.initialize_operation_uid.clone(),filesystem_uuid:generation.filesystem_uuid.clone(),
        replica:generation.virgin_replicas[0].clone(),backing_major:253,backing_minor:0,
        backing_bytes:generation.virgin_replicas[0].exposed_bytes,data_sha256:"a".repeat(64),
        flush_sha256:"b".repeat(64),evidence_sha256:"c".repeat(64)};
    let offline=std::array::from_fn(|i|OfflineReplicaObservation {version:1,owner:volume.owner().clone(),
        data_generation_uid:generation.uid.clone(),initialize_operation_uid:generation.initialize_operation_uid.clone(),
        filesystem_uuid:generation.filesystem_uuid.clone(),replica:generation.virgin_replicas[i].clone(),
        backing_major:253,backing_minor:i as u64,backing_bytes:generation.virgin_replicas[i].exposed_bytes,
        data_sha256:primary.data_sha256.clone(),offline_metadata_sha256:"d".repeat(64),
        drbd_current_uuid:"1234567890abcdef".into(),evidence_sha256:"e".repeat(64)});
    let evidence=uid_for_model(40);
    let prior=hash(&serde_json::to_vec(&("royak-physical-three-node-generation-v1",volume.owner(),&generation,&primary,&offline)).unwrap());
    let mut raw=serde_json::to_value(&volume).unwrap();
    raw["evidence"]=serde_json::json!({"uid":evidence,"sha256":prior});
    volume=serde_json::from_value(raw).unwrap();
    let lineage=InitialReplicaLineage {committed_evidence_uid:evidence,primary,offline};
    // The shared model boot is arbitrary DATA, not this generation's current target boot.
    let writer_boot=generation.virgin_replicas.iter().find(|r|r.node_uid==node).unwrap().node_boot_id.clone();
    volume.begin_attach(0,node.clone(),writer_boot,uid_for_model(41),uid_for_model(42)).unwrap();
    let replicas=std::array::from_fn(|i|AttachReplicaTarget {node_uid:generation.virgin_replicas[i].node_uid.clone(),
        current_boot:generation.virgin_replicas[i].node_boot_id.clone(),pool_uid:generation.virgin_replicas[i].pool_uid.clone(),
        plan_sha256:generation.virgin_replicas[i].plan_sha256.clone()});
    let dto=DirectoryDto {version:1,cluster_id:volume.owner().cluster_id.clone(),nodes:(0..3).map(|i|NodePin {
        node_uid:replicas[i].node_uid.clone(),raft_id:i as u64+1,signer_name:format!("model-node{}",i+1),
        wireguard_key:format!("{}{}=","A".repeat(42),["E","I","M"][i]),
        wireguard_ip:format!("10.77.0.{}",i+1).parse().unwrap(),
    }).collect()};
    dto.validate().expect("local protocol DATA directory must independently validate");
    let mut legacy_directory=dto.clone();
    legacy_directory.cluster_id=crate::store::LEGACY_CLUSTER_ID.into();
    assert!(legacy_directory.validate().is_err());
    let directory_hash=hash(&encode(&dto).unwrap());
    let scope=ExpectedAttachScope {version:1,owner:volume.owner().clone(),
        mount_ref:crate::storage_pod_writer::ManagedMountRef::from_metadata(&volume).unwrap(),
        pod_writer:volume.pod_writer().unwrap().clone(),generation:generation.clone(),initial_lineage:lineage,
        replicas:replicas.clone(),round_uid:uid_for_model(43),phase:AttachPhase::ActivateReplica,
        phase_job_uid:uid_for_model(44),phase_node_uid:replicas[1].node_uid.clone(),phase_boot:replicas[1].current_boot.clone(),
        issuer_node_uid:replicas[0].node_uid.clone(),issuer_boot:replicas[0].current_boot.clone(),issuer_revision:revision(),
        scope_sha256:"b".repeat(64),directory_sha256:directory_hash.clone(),remaining_budget_ms:180_000};
    scope.validate().expect("local protocol DATA scope must independently validate");
    let mut wrong_writer_boot=scope.clone();
    wrong_writer_boot.replicas.iter_mut().find(|r|&r.node_uid==scope.mount_ref.node_uid()).unwrap().current_boot=model_boot;
    assert!(wrong_writer_boot.validate().is_err());
    let view=crate::raft_node::storage_remote_core::model_for_protocol_tests(volume,revision(),scope.phase_node_uid.clone(),
        scope.phase_boot.clone(),scope.scope_sha256.clone(),Some(directory_hash),Instant::now(),false);
    let directory=VerifiedDirectory::from_core(&view,dto).unwrap();
    scope.check_receiver(&view,&directory).unwrap();
    ModelSessionData {scope,view,directory}
}
fn uid_for_model(n:u8)->Uid{uid(n)}
fn model_reply(request:&Request,remaining:u64)->VerifiedPeerFrame{
    let reply=Reply {domain:WIRE.into(),version:1,scope_sha256:hash(&encode(&request.scope).unwrap()),
        purpose:request.purpose,sequence:request.sequence,nonce:request.nonce.clone(),request_sha256:request.hash().unwrap(),
        session:uid_for_model(55),confirmed_revision:revision(),remaining_ms:remaining};
    VerifiedPeerFrame {sender:request.scope.issuer_node_uid.clone(),receiver:request.scope.phase_node_uid.clone(),body:encode(&reply).unwrap()}
}
#[test]
fn actual_receiver_state_machine_accepts_exact_model_reply_once_without_physical_parent(){
    let model=model_session_data();let (mut session,raw)=Receiver::challenge(model.scope,&model.view,&model.directory).unwrap();
    let request=Request::decode(&raw).unwrap();
    let permission=session.accept(model_reply(&request,500),&model.view,&model.directory).unwrap();
    permission.consume(Purpose::PhaseGrant,&hash(b"attach-grant")).unwrap();
    assert!(permission.consume(Purpose::PhaseGrant,&hash(b"attach-grant")).is_err());
    assert!(session.request(Purpose::PhaseBoundary(AttachBoundary::Identity),&hash(b"identity")).is_err());
}
#[test]
fn actual_receiver_rejects_wrong_nonce_and_stays_revoked(){
    let model=model_session_data();let (mut session,raw)=Receiver::challenge(model.scope,&model.view,&model.directory).unwrap();
    let request=Request::decode(&raw).unwrap();let mut peer=model_reply(&request,500);
    let mut reply:Reply=decode(peer.body()).unwrap();reply.nonce=uid_for_model(99);peer.body=encode(&reply).unwrap();
    assert!(session.accept(peer,&model.view,&model.directory).is_err());
    assert!(session.request(Purpose::PhaseBoundary(AttachBoundary::Identity),&hash(b"identity")).is_err());
}
#[test]
fn actual_receiver_never_reopens_expired_original_session(){
    let model=model_session_data();let (mut session,raw)=Receiver::challenge(model.scope,&model.view,&model.directory).unwrap();
    let request=Request::decode(&raw).unwrap();session.deadline=Instant::now();
    assert!(session.accept(model_reply(&request,500),&model.view,&model.directory).is_err());
    assert!(session.request(Purpose::PhaseGrant,&hash(b"attach-grant")).is_err());
}


