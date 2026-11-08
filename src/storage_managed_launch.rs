//! Native launch DATA only. None of these values is a live mount or effect
//! permission; the actual Watch actor rebuilds launch contents from Core.
use super::{PodLaunch,MountSource};
use crate::storage_identity::Uid;
use crate::storage_pod_writer::{ManagedMountRef,PodWriterUid};
use std::collections::{BTreeMap,BTreeSet};

pub(crate) const CREATE_PATH:&str="/royak/v5/create-pod";
pub(crate) const SEAL_PURPOSE:&[u8]=b"royak-pod-launch-v3-managed-source-data";
pub(crate) const LABEL_WRITER:&str="royak.native-writer";
pub(crate) const LABEL_OPERATION:&str="royak.native-consumer-operation";
pub(crate) const LABEL_NONCE:&str="royak.native-consumer-nonce";
pub(crate) const MAX_DATA_CONTAINERS:usize=128;

#[derive(Clone,Debug,PartialEq,Eq,serde::Serialize)]
pub(crate) struct LaunchKey {
    pub(crate) cluster:String,
    pub(crate) namespace:String,
    pub(crate) namespace_uid:Uid,
    pub(crate) workload:String,
    pub(crate) pod:String,
    pub(crate) ordinal:Option<u32>,
    pub(crate) template:String,
    pub(crate) writer:PodWriterUid,
    pub(crate) references:BTreeMap<Uid,ManagedMountRef>,
    pub(crate) destinations:BTreeMap<String,BTreeMap<String,Uid>>,
}
pub(crate) fn has_managed(plan:&PodLaunch)->bool {
    plan.init_containers.iter().chain(&plan.containers)
        .any(|c|c.mounts.iter().any(|m|matches!(&m.source,MountSource::Managed{..})))
}
/// Existing Royak name/`app` matching DATA, NOT Kubernetes label-selector
/// conformance. The real consumer supplies the complete actual Docker names.
pub(crate) fn policy_selects_names<'a>(selector:&str,workload:&str,names:impl Iterator<Item=&'a str>)->bool{
    selector=="*"||selector==workload||names.into_iter().any(|name|name.contains(selector))
}
/// Conservative bounded generated-name language for a pending workload:
/// stem + canonical positive u32 ordinal + exact init/sidecar suffix. This
/// does not enumerate replicas, assume ordinal 1, or invent a chosen Pod.
fn generated_name_may_match(selector:&str,prefix:&str,suffix:&str)->bool{
    if selector.is_empty(){return true;}
    for digits in 1usize..=10 {
        let length=prefix.len()+digits+suffix.len();
        if selector.len()>length{continue;}
        for start in 0..=length-selector.len(){
            let mut number=vec![b'0';digits];number[0]=b'1';let mut possible=true;
            for (offset,&byte) in selector.as_bytes().iter().enumerate(){
                let position=start+offset;
                if position<prefix.len(){possible&=prefix.as_bytes()[position]==byte;}
                else if position<prefix.len()+digits{
                    let index=position-prefix.len();
                    if !byte.is_ascii_digit()||(index==0&&byte==b'0'){possible=false;break;}
                    number[index]=byte;
                }else{possible&=suffix.as_bytes()[position-prefix.len()-digits]==byte;}
                if !possible{break;}
            }
            if possible&&std::str::from_utf8(&number).ok().and_then(|s|s.parse::<u32>().ok()).is_some(){return true;}
        }
    }
    false
}
pub(crate) fn policy_may_select_workload(selector:&str,namespace:&str,workload:&str,
    init:&[crate::reconcile::StoredContainer],containers:&[crate::reconcile::StoredContainer])->bool{
    if selector=="*"||selector==workload{return true;}
    let prefix=format!("{}-",crate::store::pod_stem(namespace,workload));
    generated_name_may_match(selector,&prefix,"")
        ||init.iter().any(|c|generated_name_may_match(selector,&prefix,&format!("-init-{}",c.name)))
        ||containers.iter().skip(1).any(|c|generated_name_may_match(selector,&prefix,&format!("-{}",c.name)))
}
/// Atomic scratch/Core mutation denial, not a network or volume grant. A
/// retained writer with missing source is ambiguous and cannot be downgraded.
pub(crate) fn require_supported_policy_admission(world:&crate::reconcile::DesiredWorld,
    namespace:&str,selector:&str)->Result<(),String>{
    if world.storage_identities.lifecycle.retained_writer_policy_conflict(world,namespace,selector){
        return Err("NetworkPolicy selects retained native writer history; native policy is unsupported".into());
    }
    for deployment in world.deployments.values().filter(|d|d.namespace==namespace){
        if policy_may_select_workload(selector,namespace,&deployment.name,&deployment.init_containers,&deployment.containers)
            &&crate::storage::observe_unsupported_runtime_storage(world,namespace,&deployment.init_containers,&deployment.containers)
                !=crate::storage::UnsupportedRuntimeStorage::ProvenLegacy{
            return Err("NetworkPolicy may select current/pending native or unresolved PVC workload; native policy is unsupported".into());
        }
    }
    Ok(())
}
/// Readonly identity DATA, never resolution of a kernel source or launch
/// permission. Native pending/unassigned/inconsistent history never falls
/// through to legacy host-path planning.
pub(crate) fn native_reference_data(world:&crate::reconcile::DesiredWorld,namespace:&str,claim_name:&str)
    ->Result<Option<ManagedMountRef>,String>{
    let key=crate::store::obj_key(namespace,claim_name);
    let claim=world.pvcs.get(&key).ok_or("current managed/legacy claim absent")?;
    let pv=claim.bound_pv.as_ref().and_then(|name|world.pvs.get(name));
    let lifecycle=claim.bound_pv.as_ref().and_then(|name|world.storage_identities.volumes.get(name))
        .and_then(|uid|world.storage_identities.lifecycle.get(uid));
    let native=world.storage_classes.get(&claim.storage_class)
        .is_some_and(|class|class.provisioner==crate::storage_lifecycle::PROVISIONER)
        || pv.is_some_and(|pv|world.storage_classes.get(&pv.storage_class)
            .is_some_and(|class|class.provisioner==crate::storage_lifecycle::PROVISIONER))
        || lifecycle.is_some();
    if !native{return Ok(None);}
    world.storage_identities.validate(&world.to_state())?;
    let pv=pv.ok_or("native claim not bound; no legacy path substitute")?;
    let volume=lifecycle.ok_or("native bound volume identity absent")?;
    let identity=world.storage_identities.claims.get(&key).ok_or("native claim UID absent")?;
    let namespace_uid=world.storage_identities.namespaces.get(namespace).ok_or("native namespace UID absent")?;
    if claim.namespace!=namespace || claim.name!=claim_name || pv.storage_class!=claim.storage_class
        || pv.status!=crate::reconcile::PVStatus::Bound || pv.bound_to.as_deref()!=Some(key.as_str())
        || pv.access_mode!="ReadWriteOnce" || claim.access_mode!="ReadWriteOnce" || !pv.host_path.is_empty()
        || !world.storage_classes.get(&pv.storage_class).is_some_and(|class|class.provisioner==crate::storage_lifecycle::PROVISIONER)
        || volume.owner().namespace!=namespace || volume.owner().claim_name!=claim_name
        || &volume.owner().namespace_uid!=namespace_uid || volume.owner().claim_uid!=identity.uid {
        return Err("native claim/PV/namespace/lifecycle identity is inconsistent".into());
    }
    Ok(Some(ManagedMountRef::from_metadata(volume)?))
}
fn canonical_name(value:&str)->bool {
    !value.is_empty() && value.len()<=512 && value!="." && value!=".."
        && value.bytes().all(|b|b.is_ascii_alphanumeric()||b"_.-".contains(&b))
}
fn overlaps(a:&str,b:&str)->bool {
    let a=std::path::Path::new(a);let b=std::path::Path::new(b);
    a.starts_with(b)||b.starts_with(a)
}
impl LaunchKey {
    pub(crate) fn from_plan_data(plan:&PodLaunch)->Result<Self,String>{
        if !has_managed(plan) || plan.kind!="deployment" || plan.containers.is_empty()
            || !crate::store::is_dns_label(&plan.namespace) || !crate::store::is_dns_subdomain(&plan.owner)
            || !canonical_name(&plan.pod) || plan.template.len()!=12
            || !plan.template.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
            return Err("managed launch DATA has unsupported/malformed Pod identity".into());
        }
        let namespace_uid=plan.namespace_uid.as_ref().ok_or("managed DATA has no namespace UID")?.clone();
        let mut references=BTreeMap::new();let mut destinations=BTreeMap::new();let mut writer=None;
        let mut names=BTreeSet::new();let mut containers=0usize;
        for container in plan.init_containers.iter().chain(&plan.containers){
            containers+=1;
            if containers>MAX_DATA_CONTAINERS || !canonical_name(&container.docker_name)
                || !crate::store::is_dns_label(&container.name)
                || !matches!(container.role.as_str(),"init"|"main"|"sidecar")
                || !names.insert(container.docker_name.clone()) {
                return Err("managed launch container identity/history bound differs".into());
            }
            if container.host_access.is_some(){return Err("native managed consumer does not accept host-access launch authority".into());}
            if let Some(security)=&container.security_context {
                security.validate()?;
                if security.capabilities.as_ref().is_some_and(|caps|!caps.add.is_empty()){
                    return Err("native first consumer does not accept additional capabilities".into());
                }
            }
            let mut per_container=BTreeMap::new();
            let mut paths=Vec::<String>::new();
            for mount in &container.mounts{
                crate::host_access::validate_container_path(&mount.container_path)?;
                if paths.iter().any(|p|overlaps(p,&mount.container_path)){
                    return Err("managed consumer has overlapping/duplicate container mounts".into());
                }
                paths.push(mount.container_path.clone());
                match &mount.source {
                    MountSource::Managed{reference}=>{
                        if reference.epoch()!=1 {return Err("first managed consumer requires exact epoch1 DATA".into());}
                        if writer.as_ref().is_some_and(|id|id!=reference.writer_uid()){
                            return Err("managed DATA mixes PodWriter identities".into());
                        }
                        writer=Some(reference.writer_uid().clone());
                        if let Some(prior)=references.insert(reference.volume_uid().clone(),reference.clone()){
                            if prior!=*reference {return Err("managed DATA disagrees about the same volume".into());}
                        }
                        per_container.insert(mount.container_path.clone(),reference.volume_uid().clone());
                    }
                    MountSource::EmptyDir{..}|MountSource::Projected{..}=>(),
                    MountSource::HostPath{..}|MountSource::ClaimPath{..}|MountSource::StatefulPath{..}=>
                        return Err("native first consumer cannot mix public/legacy host storage".into()),
                }
            }
            destinations.insert(container.docker_name.clone(),per_container);
        }
        if references.is_empty()||references.len()>8 {return Err("managed DATA group exceeds exact existing1..8 bound".into());}
        let first=references.values().next().unwrap();
        if references.values().any(|reference|reference.node_uid()!=first.node_uid()||reference.node_boot()!=first.node_boot()){
            return Err("managed DATA group names different writer nodes/boots".into());
        }
        Ok(Self {cluster:plan.cluster_id.clone(),namespace:plan.namespace.clone(),namespace_uid,
            workload:plan.owner.clone(),pod:plan.pod.clone(),ordinal:plan.ordinal,template:plan.template.clone(),
            writer:writer.ok_or("managed DATA writer absent")?,references,destinations})
    }
}

/// Queue receipt/status DATA. Accepted/Unknown never means Started or Ready.
#[derive(Clone,Copy,Debug,PartialEq,Eq,serde::Serialize)]
pub(crate) enum SubmissionStatus {Accepted,InProgress,Running,Unknown}
#[derive(Clone,Debug,serde::Serialize)]
pub(crate) struct Submission {
    pub(crate) operation:Uid,
    pub(crate) status:SubmissionStatus,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference(volume:u8,writer:u8)->ManagedMountRef{
        // Literal serialized identity DATA, never a physical test constructor.
        serde_json::from_value(serde_json::json!({
            "cluster_id":"123456abcdef","namespace_uid":format!("{:032x}",1),
            "claim_uid":format!("{volume:032x}"),"volume_uid":format!("{volume:032x}"),
            "generation_uid":format!("{:032x}",volume+16),"filesystem_uuid":"71cb439a-d59b-4d47-9058-2134d97ebd7f",
            "writer_uid":format!("{writer:032x}"),"epoch":1,"attach_operation":format!("{:032x}",40),
            "node_uid":format!("{:032x}",50),"node_boot_id":"81cb439a-d59b-4d47-9058-2134d97ebd7f"
        })).unwrap()
    }
    fn plan()->PodLaunch{
        let c=super::super::ContainerLaunch {host_access:None,security_context:None,health:None,name:"db".into(),
            docker_name:"a-db-1".into(),image:"not-executed".into(),command:None,env:vec![],mounts:vec![
                super::super::MountLaunch {source:MountSource::Managed{reference:reference(2,3)},container_path:"/data".into()}],
            cpu_limit:None,mem_limit_mb:None,publish:vec![],role:"main".into()};
        PodLaunch {namespace_uid:Some(serde_json::from_value(serde_json::json!(format!("{:032x}",1))).unwrap()),
            cluster_id:"123456abcdef".into(),node:"n1".into(),namespace:"a".into(),kind:"deployment".into(),
            owner:"db".into(),pod:"a-db-1".into(),ordinal:None,template:"a".repeat(12),generation:10,
            init_containers:vec![],containers:vec![c],aliases:vec![],host_local:false}
    }
    #[test]
    fn native_launch_key_is_data_and_has_no_host_path_or_action_permission(){
        let key=LaunchKey::from_plan_data(&plan()).unwrap();
        assert_eq!(key.references.len(),1);
        assert_eq!(key.destinations["a-db-1"]["/data"],*key.references.keys().next().unwrap());
        let raw=serde_json::to_string(&key).unwrap();
        assert!(!raw.contains("source_path"));assert!(!raw.contains("/var/lib/royak/storage"));
        // This constructs only DATA, never READY/FD/lease/Core/effect authority.
    }
    #[test]
    fn native_launch_data_rejects_cross_writer_and_overlapping_mounts(){
        let mut p=plan();
        p.containers[0].mounts.push(super::super::MountLaunch{
            source:MountSource::Managed{reference:reference(4,5)},container_path:"/other".into()});
        assert!(LaunchKey::from_plan_data(&p).is_err());
        p=plan();p.containers[0].mounts.push(super::super::MountLaunch{
            source:MountSource::EmptyDir{name:"shadow".into()},container_path:"/data/shadow".into()});
        assert!(LaunchKey::from_plan_data(&p).is_err());
        p.containers[0].mounts[1].container_path="/data".into();
        assert!(LaunchKey::from_plan_data(&p).is_err());
    }
    #[test]
    fn native_launch_data_refuses_legacy_host_sources_and_unsupported_workload(){
        let mut p=plan();p.containers[0].mounts.push(super::super::MountLaunch{
            source:MountSource::HostPath{path:"/not-opened".into()},container_path:"/other".into()});
        assert!(LaunchKey::from_plan_data(&p).is_err());
        p=plan();p.kind="job".into();assert!(LaunchKey::from_plan_data(&p).is_err());
        p=plan();p.namespace_uid=None;assert!(LaunchKey::from_plan_data(&p).is_err());
    }
    #[test]
    fn pending_policy_name_language_is_bounded_without_replica_enumeration(){
        assert!(generated_name_may_match("a-db-4294967295","a-db-",""));
        assert!(!generated_name_may_match("a-db-4294967296","a-db-",""));
        assert!(!generated_name_may_match("a-db-0","a-db-",""));
        assert!(!generated_name_may_match("a-db-01","a-db-",""));
        assert!(generated_name_may_match("db-712-init-check","a-db-","-init-check"));
        assert!(!generated_name_may_match("different","a-db-","-init-check"));
        assert!(generated_name_may_match("11","a-db-",""));
        // DATA selector language only, never chosen ordinal/Pod authority.
    }
    fn apply(world:&mut crate::reconcile::DesiredWorld,kind:&str,namespace:&str,name:&str,spec:serde_json::Value)
        ->Result<String,String>{
        world.apply(&serde_json::from_value(serde_json::json!({"kind":kind,
            "metadata":{"name":name,"namespace":namespace},"spec":spec})).unwrap())
    }
    fn pending_native_world()->crate::reconcile::DesiredWorld{
        let mut world=crate::reconcile::DesiredWorld::new();
        apply(&mut world,"StorageClass","","native",serde_json::json!({
            "provisioner":crate::storage_lifecycle::PROVISIONER,"reclaimPolicy":"Retain"})).unwrap();
        apply(&mut world,"PersistentVolumeClaim","a","data",serde_json::json!({"storageClassName":"native",
            "resources":{"requests":{"storage":"64Mi"}}})).unwrap();
        apply(&mut world,"Deployment","a","db",serde_json::json!({"replicas":1,"template":{"spec":{
            "initContainers":[{"name":"check","image":"not-executed","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
            "containers":[{"name":"db","image":"not-executed","volumeMounts":[{"name":"data","mountPath":"/data"}]}],
            "volumes":[{"name":"data","persistentVolumeClaim":{"claimName":"data"}}]}}})).unwrap();
        world
    }
    fn policy(selector:&str)->serde_json::Value{serde_json::json!({"podSelector":{"matchLabels":{"app":selector}},"denyAll":true})}
    #[test]
    fn policy_admission_rejects_pending_native_init_and_main_without_mutation(){
        let mut world=pending_native_world();
        let init_name=format!("{}-731-init-check",crate::store::pod_stem("a","db"));
        for selector in ["*","db",init_name.as_str()]{
            let before=serde_json::to_value(world.to_state()).unwrap();
            assert!(apply(&mut world,"NetworkPolicy","a","blocked",policy(selector)).is_err());
            assert_eq!(serde_json::to_value(world.to_state()).unwrap(),before);
            assert!(!world.network_policies.contains_key("a/blocked"));
        }
        // Rejection also precedes the implicit namespace write when a damaged
        // external/model graph omitted its name. It cannot be called legacy.
        world.namespaces.retain(|namespace|namespace!="a");
        let before=serde_json::to_value(world.to_state()).unwrap();
        assert!(apply(&mut world,"NetworkPolicy","a","blocked",policy("db")).is_err());
        assert_eq!(serde_json::to_value(world.to_state()).unwrap(),before);
    }
    #[test]
    fn policy_admission_preserves_other_namespace_unmatched_and_legacy(){
        let mut world=pending_native_world();
        apply(&mut world,"NetworkPolicy","b","other",policy("db")).unwrap();
        apply(&mut world,"NetworkPolicy","a","different",policy("unrelated-app")).unwrap();
        let mut legacy=crate::reconcile::DesiredWorld::new();
        apply(&mut legacy,"Deployment","a","web",serde_json::json!({"replicas":1,"template":{"spec":{
            "containers":[{"name":"web","image":"not-executed"}]}}})).unwrap();
        apply(&mut legacy,"NetworkPolicy","a","ordinary",policy("web")).unwrap();
        assert!(legacy.network_policies.contains_key("a/ordinary"));
    }
    #[test]
    fn retained_writer_policy_denial_does_not_depend_on_current_claim_or_workload(){
        let (mut world,uid,node,boot)=crate::storage_lifecycle::model_pod_writer_world();
        world.storage_identities.lifecycle.get_mut(&uid).unwrap()
            .begin_attach(0,node,boot,Uid::new(),Uid::new()).unwrap();
        world.deployments.clear();world.pvcs.clear();
        let before=serde_json::to_value(world.to_state()).unwrap();
        assert!(apply(&mut world,"NetworkPolicy","a","retained",policy("db")).is_err());
        assert!(require_supported_policy_admission(&world,"a","unknown-sidecar").is_err());
        assert_eq!(serde_json::to_value(world.to_state()).unwrap(),before);
        assert!(require_supported_policy_admission(&world,"b","db").is_ok());
        // Existing model-only metadata fixture; no FD/READY/effect producer.
    }
    #[test]
    fn retained_changed_source_cannot_admit_policy_for_an_old_native_sidecar(){
        let (mut world,uid,node,boot)=crate::storage_lifecycle::model_pod_writer_world();
        crate::storage_pod_writer::model_reserve_current_db_writer(&mut world,&uid,&node,&boot).unwrap();
        let writer=world.storage_identities.lifecycle.get(&uid).unwrap().pod_writer().unwrap().clone();
        assert_eq!((writer.namespace(),writer.workload()),("a","db"));
        assert!(writer.check_source_current(&world).is_ok());
        assert!(require_supported_policy_admission(&world,"a","old-sidecar").is_ok());
        // SAME deployment remains present but its process source no longer
        // matches canonical retained writer history. Absence of an old suffix
        // in the new template is not proof that the old incarnation drained.
        world.deployments.get_mut("a/db").unwrap().containers[0].command=Some(vec!["changed-command-DATA".into()]);
        assert!(writer.check_source_current(&world).is_err());
        let before=serde_json::to_value(world.to_state()).unwrap();
        assert!(apply(&mut world,"NetworkPolicy","a","old-sidecar-policy",policy("old-sidecar")).is_err());
        assert_eq!(serde_json::to_value(world.to_state()).unwrap(),before);
        assert!(require_supported_policy_admission(&world,"b","old-sidecar").is_ok());
        // Existing lifecycle MODEL only, never FD/READY/effect authority.
    }
    #[test]
    fn actual_name_policy_check_covers_init_and_sidecar_selectors(){
        let names=["a-db-1","a-db-1-init-check","a-db-1-agent"];
        assert!(policy_selects_names("init-check","db",names.into_iter()));
        assert!(policy_selects_names("agent","db",names.into_iter()));
        assert!(!policy_selects_names("other","db",names.into_iter()));
        assert!(policy_selects_names("db","db",std::iter::empty()));
    }
}
