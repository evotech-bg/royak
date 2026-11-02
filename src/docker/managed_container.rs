//! Closed bounded managed-container adapter. Data parsers never mint mount,
//! Core, READY or effect capabilities. Legacy targets get a separate denial
//! preflight; they cannot enter these positive native Create/Start methods.
use super::*;
use crate::storage_driver::native_runtime::mount::consumer::{OwnedManagedContainer,VerifiedConsumerAction};
use crate::storage_driver::dispatcher::attachment::consumer_lifetime::VerifiedManagedSource;
use crate::storage_identity::Uid;
use crate::workload::{PodLaunch,ContainerLaunch,MountSource,managed as contract};
use std::collections::{BTreeMap,BTreeSet};
use std::sync::atomic::{AtomicBool,Ordering};
use std::time::Instant;
static NATIVE_HISTORY:AtomicBool=AtomicBool::new(false);
// Readonly actual main-owned source pointer for NEGATIVE legacy admission.
// This is not a writer registry, World clone, effect or mount capability.
static ACTUAL_STORE:std::sync::OnceLock<std::sync::Weak<std::sync::RwLock<crate::reconcile::DesiredWorld>>>=std::sync::OnceLock::new();
static ACTUAL_RAFT_REGISTERED:AtomicBool=AtomicBool::new(false);
pub(crate) fn requested_native_runtime(){NATIVE_HISTORY.store(true,Ordering::Release);}
pub(crate) fn observe_restored_history(world:&crate::reconcile::DesiredWorld){
    // Includes retained/quarantined history after claim removal, not just
    // currently Attached records. This is a negative-only startup selection.
    if !world.storage_identities.lifecycle.is_empty(){NATIVE_HISTORY.store(true,Ordering::Release);}
}
pub(crate) fn strict_scope()->bool{NATIVE_HISTORY.load(Ordering::Acquire)}
pub(crate) fn register_actual_store(world:&Arc<std::sync::RwLock<crate::reconcile::DesiredWorld>>)->Result<(),String>{
    if crate::raft_node::RAFT.get().is_some(){
        if !crate::raft_node::storage_remote_core::is_actual_world(world){return Err("native history source differs from actual registered Raft store".into());}
        ACTUAL_RAFT_REGISTERED.store(true,Ordering::Release);
    }
    if let Some(original)=ACTUAL_STORE.get(){
        require_registered_pointer(original,world)?;
    }else{ACTUAL_STORE.set(Arc::downgrade(world)).map_err(|_|"actual legacy-denial source registration raced")?;}
    let current=world.try_read().map_err(|_|"actual startup history source busy")?;
    observe_restored_history(&current);Ok(())
}
fn require_registered_pointer(source:&std::sync::Weak<std::sync::RwLock<crate::reconcile::DesiredWorld>>,
    world:&Arc<std::sync::RwLock<crate::reconcile::DesiredWorld>>)->Result<(),String>{
    if !std::sync::Weak::ptr_eq(source,&Arc::downgrade(world)){
        return Err("actual legacy-denial source cannot be replaced by equal JSON/another Arc".into());
    }
    Ok(())
}
fn unregistered_scope(strict:bool,raft_registered:bool)->Result<bool,String>{
    if raft_registered{return Err("actual store exists without registered history source; no fallback".into());}
    Ok(strict)
}
fn read_registered_history(source:&std::sync::Weak<std::sync::RwLock<crate::reconcile::DesiredWorld>>)->Result<bool,String>{
    let world=source.upgrade().ok_or("registered actual store disappeared; no legacy fallback")?;
    let current=world.try_read().map_err(|_|"registered actual store busy/poisoned; no legacy fallback")?;
    Ok(!current.storage_identities.lifecycle.is_empty())
}
/// Only the REAL transport entrypoint calls this, before socket selection.
/// Raft snapshots/current commits arriving after startup cannot erase scope.
pub(super) fn native_history_before_legacy()->Result<bool,String>{
    if let Some(source)=ACTUAL_STORE.get(){
        let world=source.upgrade().ok_or("registered actual store missing; legacy mutation refused")?;
        match crate::raft_node::RAFT.get(){
            Some(_handle)=>{
                ACTUAL_RAFT_REGISTERED.store(true,Ordering::Release);
                if !crate::raft_node::storage_remote_core::is_actual_world(&world){return Err("actual native history store changed; no fallback".into());}
            },
            None if ACTUAL_RAFT_REGISTERED.load(Ordering::Acquire)=>return Err("registered actual Raft unexpectedly missing".into()),
            None=>(), // registered standalone file-backed API source
        }
        if read_registered_history(source)?{NATIVE_HISTORY.store(true,Ordering::Release);}
    }else{
        return unregistered_scope(strict_scope(),crate::raft_node::RAFT.get().is_some()
            ||ACTUAL_RAFT_REGISTERED.load(Ordering::Acquire));
    }
    // No registered source +no actual Raft +no requested/historical native
    // scope is the distinct ordinary legacy-only CLI/macOS/proxy boundary.
    Ok(strict_scope())
}
pub(crate) fn registered_target(selector:&str)->bool{
    crate::storage_driver::native_runtime::mount::consumer::registered_target(selector)
}
pub(crate) fn reject_legacy_create(name:&str,labels:&[(&str,&str)],volumes:&[(String,String)])->Result<(),String>{
    if registered_target(name)||labels.iter().any(|(key,_)|[contract::LABEL_WRITER,contract::LABEL_OPERATION,contract::LABEL_NONCE].contains(key)){
        return Err("native owned name/metadata requires the actual typed Create; legacy refused".into());
    }
    for (source,_) in volumes{crate::host_access::reject_native_publication_source(source)?;}
    Ok(())
}
pub(crate) fn native_labels(value:&serde_json::Value)->Result<bool,String>{
    match value {
        serde_json::Value::Null=>Ok(false),
        serde_json::Value::Object(labels)=>{
            if labels.values().any(|v|!v.is_string()){return Err("Docker labels malformed; not proven legacy".into());}
            Ok([contract::LABEL_WRITER,contract::LABEL_OPERATION,contract::LABEL_NONCE].iter()
                .any(|key|labels.contains_key(*key)))
        }
        _=>Err("Docker labels missing/wrong type; not proven legacy".into())
    }
}
pub(crate) fn legacy_inspected_id(raw:&[u8],selector:&str)->Result<String,String>{
    let value=strict_json(raw)?;let id=string(&value,"Id")?;
    if !full_id(id){return Err("legacy inspect did not return a full canonical CID".into());}
    let name=string(&value,"Name")?.trim_start_matches('/');
    let matches=selector==id||selector==name||selector.len()>=12&&selector.len()<64
        &&selector.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))&&id.starts_with(selector);
    if !matches{return Err("legacy selector is not the returned actual CID/name".into());}
    let config=value.get("Config").ok_or("legacy inspect Config missing")?;
    let labels=config.get("Labels").ok_or("legacy inspect labels missing")?;
    let mounts=value.get("Mounts").and_then(|v|v.as_array()).ok_or("legacy inspect mount census missing")?;
    let mut native=native_labels(labels)?;
    for mount in mounts{
        let kind=string(mount,"Type")?;
        if kind=="bind"{
            let source=string(mount,"Source")?;
            native|=source=="/var/lib/royak/storage/mounts"||source.starts_with("/var/lib/royak/storage/mounts/");
        }
    }
    if native{return Err("native retained metadata/source is denial evidence, never legacy permission".into());}
    if registered_target(id){return Err("actual owned managed CID cannot be downgraded by labels".into());}
    Ok(id.to_string())
}
pub(crate) fn inspected_native_history(raw:&[u8])->Result<bool,String>{
    let value=strict_json(raw)?;
    let config=value.get("Config").ok_or("actual Docker Config absent")?;
    let mut native=native_labels(config.get("Labels").ok_or("actual Docker labels absent")?)?;
    for mount in value.get("Mounts").and_then(|v|v.as_array()).ok_or("actual mount census absent")?{
        if string(mount,"Type")?=="bind"{
            let source=string(mount,"Source")?;
            native|=source=="/var/lib/royak/storage/mounts"||source.starts_with("/var/lib/royak/storage/mounts/");
        }
    }Ok(native)
}
pub(crate) fn legacy_helper_created_id(raw:&[u8])->Result<String,String>{
    let value=strict_json(raw)?;let id=string(&value,"Id")?;
    if !full_id(id)||registered_target(id){return Err("legacy helper Create has no unique unmanaged full CID".into());}
    Ok(id.to_owned())
}
pub(crate) fn require_legacy_netns_helper(raw:&[u8],helper:&str,target:&str,script:&str)->Result<(),String>{
    if !full_id(helper)||!full_id(target)||registered_target(helper)||registered_target(target){
        return Err("native/malformed netns association denied before helper Start".into());
    }
    let value=strict_json(raw)?;
    if inspected_native_history(raw)?||value.get("Id").and_then(|v|v.as_str())!=Some(helper)
        || value.pointer("/Config/Image").and_then(|v|v.as_str())!=Some("alpine:3.21")
        || value.pointer("/Config/Cmd")!=Some(&serde_json::json!(["sh","-c",script]))
        || value.pointer("/HostConfig/NetworkMode").and_then(|v|v.as_str())!=Some(format!("container:{target}").as_str())
        || value.pointer("/HostConfig/CapAdd")!=Some(&serde_json::json!(["NET_ADMIN"]))
        || value.pointer("/HostConfig/AutoRemove").and_then(|v|v.as_bool())!=Some(true)
        || value.pointer("/State/Running").and_then(|v|v.as_bool())!=Some(false){
        return Err("actual legacy netns helper differs from exact Create/full-CID association".into());
    }
    Ok(())
}
fn full_id(value:&str)->bool{value.len()==64&&value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))}
#[cfg(test)]
mod conservative_legacy_regressions{
    use super::*;
    fn inspected(name:&str)->serde_json::Value{serde_json::json!({
        "Id":"a".repeat(64),"Name":format!("/{name}"),"Config":{"Labels":null},"Mounts":[]})}
    fn raw(value:&serde_json::Value)->Vec<u8>{serde_json::to_vec(value).unwrap()}
    #[test]
    fn actual_legacy_selector_observation_binds_full_cid_not_rebound_name(){
        let original=inspected("ordinary");
        assert_eq!(legacy_inspected_id(&raw(&original),"ordinary").unwrap(),"a".repeat(64));
        assert_eq!(legacy_inspected_id(&raw(&original),&"a".repeat(12)).unwrap(),"a".repeat(64));
        assert!(legacy_inspected_id(&raw(&original),"renamed").is_err());
        assert!(legacy_inspected_id(&raw(&original),&"a".repeat(11)).is_err());
        let mut replacement=original.clone();replacement["Id"]=serde_json::json!("b".repeat(64));
        assert!(legacy_inspected_id(&raw(&replacement),&"a".repeat(64)).is_err());
        // Returned full ID DATA is only used by SAME-connection actual
        // LegacyContainerConnection, never a native capability/owner.
    }
    #[test]
    fn lost_book_native_metadata_and_published_source_still_deny_legacy(){
        for key in [contract::LABEL_WRITER,contract::LABEL_OPERATION,contract::LABEL_NONCE]{
            let mut value=inspected("ordinary");value["Config"]["Labels"]=serde_json::Value::Object(
                [(key.to_owned(),serde_json::json!("retained"))].into_iter().collect());
            assert!(legacy_inspected_id(&raw(&value),"ordinary").is_err());
            assert!(inspected_native_history(&raw(&value)).unwrap());
        }
        let mut value=inspected("ordinary");value["Mounts"]=serde_json::json!([
            {"Type":"bind","Source":"/var/lib/royak/storage/mounts/retained","Destination":"/data"}]);
        assert!(legacy_inspected_id(&raw(&value),"ordinary").is_err());
        value["Config"]["Labels"]=serde_json::json!({"broken":3});
        assert!(legacy_inspected_id(&raw(&value),"ordinary").is_err());
    }
    #[test]
    fn malformed_missing_duplicate_and_404_observations_never_prove_legacy(){
        for raw in [b"null".as_slice(),b"{}",b"{\"message\":\"No such container\"}",
            b"{\"Id\":\"x\",\"Id\":\"y\"}"]{
            assert!(legacy_inspected_id(raw,"ordinary").is_err());
        }
        let mut value=inspected("ordinary");value.as_object_mut().unwrap().remove("Mounts");
        assert!(legacy_inspected_id(&raw(&value),"ordinary").is_err());
        assert!(strict_json(b"{\"Config\":{\"Labels\":null,\"Labels\":{}}}").is_err());
        assert!(strict_json(b"{} false").is_err());
    }
    fn helper(target:&str,script:&str)->serde_json::Value{serde_json::json!({
        "Id":"b".repeat(64),"Config":{"Image":"alpine:3.21","Cmd":["sh","-c",script],"Labels":null},
        "HostConfig":{"NetworkMode":format!("container:{target}"),"CapAdd":["NET_ADMIN"],"AutoRemove":true},
        "Mounts":[],"State":{"Running":false}})}
    #[test]
    fn netns_helper_parser_requires_exact_full_target_script_and_never_started_state(){
        let target="a".repeat(64);let helper_id="b".repeat(64);let script="iptables -F OUTPUT";
        let original=helper(&target,script);
        require_legacy_netns_helper(&raw(&original),&helper_id,&target,script).unwrap();
        assert!(require_legacy_netns_helper(&raw(&original),&helper_id,"ordinary",script).is_err());
        assert!(require_legacy_netns_helper(&raw(&original),&helper_id,&"c".repeat(64),script).is_err());
        for pointer in ["/Config/Cmd","/HostConfig/NetworkMode","/HostConfig/CapAdd","/HostConfig/AutoRemove","/State/Running"]{
            let mut changed=original.clone();*changed.pointer_mut(pointer).unwrap()=serde_json::Value::Null;
            assert!(require_legacy_netns_helper(&raw(&changed),&helper_id,&target,script).is_err(),"{pointer}");
        }
        // Parser DATA fixtures do not construct LegacyContainerConnection or
        // execute Create/Start/NET_ADMIN, much less native mount authority.
    }
    #[test]
    fn native_create_receipt_parser_preserves_full_id_and_duplicate_refusal(){
        assert_eq!(created_id(&raw(&serde_json::json!({"Id":"a".repeat(64),"Warnings":null}))).unwrap(),"a".repeat(64));
        for value in [serde_json::json!({"Id":"a".repeat(12),"Warnings":null}),
            serde_json::json!({"Id":"a".repeat(64)}),serde_json::json!({"Id":"a".repeat(64),"Warnings":false})]{
            assert!(created_id(&raw(&value)).is_err());
        }
        assert!(created_id(b"{\"Id\":\"x\",\"Id\":\"y\",\"Warnings\":null}").is_err());
    }
    #[test]
    fn actual_source_reader_observes_native_history_arriving_after_its_initial_read(){
        let world=Arc::new(std::sync::RwLock::new(crate::reconcile::DesiredWorld::new()));
        let source=Arc::downgrade(&world);assert!(!read_registered_history(&source).unwrap());
        let (mut history,uid,node,boot)=crate::storage_lifecycle::model_pod_writer_world();
        history.storage_identities.lifecycle.get_mut(&uid).unwrap()
            .begin_attach(0,node,boot,Uid::new(),Uid::new()).unwrap();
        world.write().unwrap().storage_identities.lifecycle=history.storage_identities.lifecycle;
        assert!(read_registered_history(&source).unwrap());
        let mut retained=serde_json::to_value(&world.read().unwrap().storage_identities.lifecycle).unwrap();
        retained["volumes"][uid.as_str()]["phase"]=serde_json::json!("Attached");
        {let mut current=world.write().unwrap();
            current.storage_identities.lifecycle=serde_json::from_value(retained).unwrap();
            current.pvcs.clear();current.deployments.clear();}
        assert!(read_registered_history(&source).unwrap());
        // Exact SAME readonly code/Weak, but isolated metadata DATA fixture:
        // raw Attached history (not a valid positive receipt) remains denial
        // even after indexes/source disappear. No static registration/latch,
        // actual Raft snapshot, Core or effect factory is constructed here.
    }
    #[test]
    fn registered_store_is_same_arc_only_and_unregistered_native_never_downgrades(){
        let world=Arc::new(std::sync::RwLock::new(crate::reconcile::DesiredWorld::new()));
        let source=Arc::downgrade(&world);require_registered_pointer(&source,&world).unwrap();
        let equal_json=Arc::new(std::sync::RwLock::new(world.read().unwrap().clone()));
        assert!(require_registered_pointer(&source,&equal_json).is_err());
        assert_eq!(unregistered_scope(false,false),Ok(false));
        assert_eq!(unregistered_scope(true,false),Ok(true));
        assert!(unregistered_scope(false,true).is_err());assert!(unregistered_scope(true,true).is_err());
        // These are negative transport-selection DATA cases. Real RAFT identity
        // still comes only from core::is_actual_world in production, not here.
    }
    #[test]
    fn registered_source_busy_and_lost_are_errors_not_legacy_or_zero(){
        let world=Arc::new(std::sync::RwLock::new(crate::reconcile::DesiredWorld::new()));
        let source=Arc::downgrade(&world);
        {let _writer=world.write().unwrap();assert!(read_registered_history(&source).is_err());}
        assert!(!read_registered_history(&source).unwrap());
        drop(world);assert!(read_registered_history(&source).is_err());
    }
}
fn encode_segment(value:&str)->String{
    value.bytes().map(|b|if b.is_ascii_alphanumeric()||b"_.-".contains(&b){(b as char).to_string()}
        else{format!("%{b:02X}")}).collect()
}

/// Strict JSON authority-field observation, including duplicate nested fields.
struct StrictValue(serde_json::Value);
impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D:serde::Deserializer<'de>>(d:D)->Result<Self,D::Error>{
        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor{
            type Value=StrictValue;
            fn expecting(&self,f:&mut std::fmt::Formatter)->std::fmt::Result{f.write_str("bounded unique-key Docker JSON")}
            fn visit_bool<E:serde::de::Error>(self,v:bool)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_i64<E:serde::de::Error>(self,v:i64)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_u64<E:serde::de::Error>(self,v:u64)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_f64<E:serde::de::Error>(self,v:f64)->Result<Self::Value,E>{
                serde_json::Number::from_f64(v).map(|n|StrictValue(n.into())).ok_or_else(||E::custom("nonfinite Docker number"))}
            fn visit_str<E:serde::de::Error>(self,v:&str)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_string<E:serde::de::Error>(self,v:String)->Result<Self::Value,E>{Ok(StrictValue(v.into()))}
            fn visit_unit<E:serde::de::Error>(self)->Result<Self::Value,E>{Ok(StrictValue(serde_json::Value::Null))}
            fn visit_none<E:serde::de::Error>(self)->Result<Self::Value,E>{self.visit_unit()}
            fn visit_seq<A:serde::de::SeqAccess<'de>>(self,mut seq:A)->Result<Self::Value,A::Error>{
                let mut values=Vec::new();while let Some(StrictValue(value))=seq.next_element()?{values.push(value);}
                Ok(StrictValue(values.into()))}
            fn visit_map<A:serde::de::MapAccess<'de>>(self,mut map:A)->Result<Self::Value,A::Error>{
                let mut fields=serde_json::Map::new();
                while let Some((key,StrictValue(value)))=map.next_entry::<String,StrictValue>()?{
                    if fields.insert(key,value).is_some(){return Err(serde::de::Error::custom("duplicate Docker JSON field"));}
                }Ok(StrictValue(fields.into()))}
        }
        d.deserialize_any(Visitor)
    }
}
pub(crate) fn strict_json(raw:&[u8])->Result<serde_json::Value,String>{
    if raw.len()>1024*1024{return Err("Docker JSON exceeds existing1MiB frame".into());}
    let mut decoder=serde_json::Deserializer::from_slice(raw);
    let value=<StrictValue as serde::Deserialize>::deserialize(&mut decoder)
        .map_err(|_|"malformed/duplicate Docker JSON")?.0;
    decoder.end().map_err(|_|"trailing Docker JSON")?;Ok(value)
}
fn string<'a>(value:&'a serde_json::Value,key:&str)->Result<&'a str,String>{
    value.get(key).and_then(|v|v.as_str()).ok_or_else(||format!("Docker field {key} missing/wrong type"))
}
fn strings(value:&serde_json::Value)->Result<Vec<String>,String>{
    match value {serde_json::Value::Null=>Ok(vec![]),serde_json::Value::Array(v)=>v.iter()
        .map(|v|v.as_str().map(str::to_string).ok_or("Docker string-array field malformed".into())).collect(),
        _=>Err("Docker string-array field missing/wrong type".into())}
}
fn env_map(values:&[String])->Result<BTreeMap<String,String>,String>{
    let mut env=BTreeMap::new();
    for value in values{
        let (key,value)=value.split_once('=').ok_or("native env must have an explicit value")?;
        if key.is_empty()||!key.bytes().enumerate().all(|(i,b)|b==b'_'||b.is_ascii_alphabetic()||i>0&&b.is_ascii_digit())
            || env.insert(key.into(),value.into()).is_some(){return Err("native env key malformed/duplicated".into());}
    }Ok(env)
}
pub(crate) struct PinnedImage {id:String,user:String,env:BTreeMap<String,String>,cmd:Vec<String>,entrypoint:Vec<String>,volumes:BTreeSet<String>}
pub(crate) fn inspect_image(connection:&mut ManagedConsumerConnection,image:&str,deadline:Instant)->Result<PinnedImage,String>{
    let (status,raw)=connection.get(&format!("/images/{}/json",encode_segment(image)),1024*1024,deadline)?;
    if status!=200{return Err("actual required image is not available; no Create attempted".into());}
    let v=strict_json(&raw)?;let id=string(&v,"Id")?.to_string();
    if !id.strip_prefix("sha256:").is_some_and(full_id){return Err("actual immutable image ID malformed".into());}
    let cfg=v.get("Config").and_then(|v|v.as_object()).ok_or("actual image Config absent")?;
    let get=|key:&str|cfg.get(key).ok_or_else(||format!("actual image field {key} absent"));
    let user=get("User")?.as_str().ok_or("actual image User malformed")?.into();
    let env=env_map(&strings(get("Env")?)?)?;
    let cmd=strings(get("Cmd")?)?;let entrypoint=strings(get("Entrypoint")?)?;
    let volumes=match get("Volumes")?{serde_json::Value::Null=>BTreeSet::new(),
        serde_json::Value::Object(map)=>map.keys().cloned().collect(),_=>return Err("actual image Volumes malformed".into())};
    Ok(PinnedImage{id,user,env,cmd,entrypoint,volumes})
}
#[derive(Clone)]
struct ExpectedBind {source:String,target:String,readonly:bool}
pub(crate) struct PinnedNetwork {name:String,id:String}
pub(crate) fn inspect_network(connection:&mut ManagedConsumerConnection,namespace:&str,deadline:Instant)->Result<PinnedNetwork,String>{
    let name=format!("rk-{namespace}");
    let (status,raw)=connection.get(&format!("/networks/{}",encode_segment(&name)),1024*1024,deadline)?;
    if status!=200{return Err("actual namespace network is not present; no implicit network creation".into());}
    let value=strict_json(&raw)?;
    let id=string(&value,"Id")?.to_string();
    if !full_id(&id)||string(&value,"Name")?!=name||string(&value,"Driver")?!="bridge"
        || value.get("Labels").and_then(|v|v.get("royak.managed")).and_then(|v|v.as_str())!=Some("true"){
        return Err("actual owned namespace network identity differs".into());
    }
    Ok(PinnedNetwork{name,id})
}
pub(crate) struct PreparedCreate {
    path:String,body:Vec<u8>,name:String,nonce:Uid,image:String,user:String,
    env:BTreeMap<String,String>,cmd:Vec<String>,entrypoint:Vec<String>,binds:Vec<ExpectedBind>,network:PinnedNetwork,
    explicit_host:serde_json::Value,aliases:BTreeSet<String>,
    role:String,
}
impl PreparedCreate {
    pub(crate) fn name(&self)->&str{&self.name}
    pub(crate) fn role(&self)->&str{&self.role}
    pub(crate) fn path(&self)->&str{&self.path}
    pub(crate) fn body(&self)->&[u8]{&self.body}
    pub(crate) fn image_id(&self)->&str{&self.image}
    pub(crate) fn nonce(&self)->&Uid{&self.nonce}
}
pub(crate) fn prepare_create(plan:&PodLaunch,container:&ContainerLaunch,operation:&Uid,nonce:Uid,image:PinnedImage,
    network:PinnedNetwork,sources:&BTreeMap<Uid,VerifiedManagedSource>,internal:&[(String,String)])
    ->Result<PreparedCreate,String>{
    contract::LaunchKey::from_plan_data(plan)?;
    let mut binds=Vec::new();
    for mount in &container.mounts{
        let source=match &mount.source{
            MountSource::Managed{reference}=>{
                let held=sources.get(reference.volume_uid()).ok_or("actual mounted source capability absent")?;
                if held.reference()!=reference{return Err("actual mounted source differs from current reference".into());}
                held.published_path().to_string()
            }
            MountSource::EmptyDir{name}=>{
                let expected=format!("{}/empty-{name}",crate::workload::pod_dir(&plan.namespace,&plan.pod));
                if !internal.iter().any(|(source,target)|source==&expected&&target==&mount.container_path){
                    return Err("actual current EmptyDir materialization absent".into());}expected
            }
            MountSource::Projected{name,secret,..}=>{
                let expected=format!("{}/{}-{name}",crate::workload::pod_dir(&plan.namespace,&plan.pod),if *secret{"secret"}else{"configmap"});
                if !internal.iter().any(|(source,target)|source==&expected&&target==&mount.container_path){
                    return Err("actual current projected materialization absent".into());}expected
            }
            _=>return Err("legacy/public storage cannot enter native typed Create".into()),
        };
        binds.push(ExpectedBind{source,target:mount.container_path.clone(),readonly:matches!(mount.source,MountSource::Projected{..})});
    }
    if image.volumes.iter().any(|target|!binds.iter().any(|binding|&binding.target==target)){
        return Err("image declares an unplanned anonymous data volume; no silent extra storage".into());
    }
    let mut env=image.env.clone();for (key,value) in env_map(&container.env)?{env.insert(key,value);}
    let mut labels=crate::workload::labels_for(plan,&container.role)?;
    let key=contract::LaunchKey::from_plan_data(plan)?;
    labels.extend([(contract::LABEL_WRITER.into(),key.writer.as_uid().as_str().into()),
        (contract::LABEL_OPERATION.into(),operation.as_str().into()),(contract::LABEL_NONCE.into(),nonce.as_str().into())]);
    let labels=labels.into_iter().collect::<BTreeMap<_,_>>();
    let mut body=serde_json::json!({"Image":image.id,"Env":container.env,"Labels":labels});
    let cmd=container.command.as_ref().filter(|c|!c.is_empty()).cloned().unwrap_or(image.cmd);
    if container.command.as_ref().is_some_and(|c|!c.is_empty()){body["Cmd"]=serde_json::json!(cmd);}
    let mut host=serde_json::Map::new();
    let mut user=image.user.clone();
    if let Some(security)=&container.security_context{
        security.validate()?;
        if security.capabilities.as_ref().is_some_and(|caps|!caps.add.is_empty()){return Err("native extra capabilities unsupported".into());}
        let (requested,options)=security.docker_options(&image.user)?;host.extend(options);
        if let Some(value)=requested{user=value;body["User"]=serde_json::json!(user);}
    }
    host.insert("Privileged".into(),serde_json::json!(false));
    host.insert("RestartPolicy".into(),serde_json::json!({"Name":"no","MaximumRetryCount":0}));
    host.insert("Init".into(),serde_json::json!(container.health.as_ref().is_some_and(crate::probes::ContainerHealth::configured)));
    host.insert("Mounts".into(),serde_json::json!(binds.iter().map(|b|serde_json::json!({
        "Type":"bind","Source":b.source,"Target":b.target,"ReadOnly":b.readonly,
        "BindOptions":{"Propagation":"rprivate"}})).collect::<Vec<_>>()));
    if network.name!=format!("rk-{}",plan.namespace){return Err("actual network belongs to another namespace".into());}
    host.insert("NetworkMode".into(),serde_json::json!(network.name));
    if let Some(cpu)=container.cpu_limit{host.insert("NanoCpus".into(),serde_json::json!((cpu*1_000_000_000.0)as u64));}
    if let Some(mb)=container.mem_limit_mb{host.insert("Memory".into(),serde_json::json!(mb*1024*1024));}
    if !container.publish.is_empty(){
        let mut exposed=serde_json::Map::new();let mut ports=serde_json::Map::new();
        for port in &container.publish{let key=format!("{port}/tcp");exposed.insert(key.clone(),serde_json::json!({}));
            ports.insert(key,serde_json::json!([{"HostPort":"0"}]));}
        body["ExposedPorts"]=exposed.into();host.insert("PortBindings".into(),ports.into());
    }
    let explicit_host=serde_json::Value::Object(host);
    body["HostConfig"]=explicit_host.clone();
    let aliases=if container.role=="main"{plan.aliases.clone()}else{vec![container.docker_name.clone()]};
    let aliases=aliases.into_iter().collect::<BTreeSet<_>>();
    let mut endpoints=serde_json::Map::new();
    endpoints.insert(network.name.clone(),serde_json::json!({"Aliases":aliases}));
    body["NetworkingConfig"]=serde_json::json!({"EndpointsConfig":endpoints});
    let body=serde_json::to_vec(&body).map_err(|_|"native exact Create encoding failed")?;
    if body.len()>1024*1024{return Err("native Create exceeds existing1MiB frame".into());}
    Ok(PreparedCreate{path:format!("/containers/create?name={}",encode_segment(&container.docker_name)),body,
        name:container.docker_name.clone(),nonce,image:image.id,user,env,cmd,entrypoint:image.entrypoint,binds,network,explicit_host,aliases,role:container.role.clone()})
}
/// Only the actual permission-bearing 201 path constructs this effect result.
pub(crate) struct DockerCreated {id:String}
impl DockerCreated {pub(crate) fn id(&self)->&str{&self.id}}
fn created_id(raw:&[u8])->Result<String,String>{
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Receipt {#[serde(rename="Id")]id:String,#[serde(rename="Warnings")]warnings:serde_json::Value}
    let value:Receipt=serde_json::from_slice(raw).map_err(|_|"Create receipt malformed/duplicated")?;
    if !full_id(&value.id)||!matches!(&value.warnings,serde_json::Value::Null)
        && !value.warnings.as_array().is_some_and(|a|a.iter().all(|v|v.is_string())){
        return Err("Create full-ID/warnings receipt malformed".into());
    }
    Ok(value.id)
}
pub(crate) fn create(connection:&mut ManagedConsumerConnection,permission:VerifiedConsumerAction,
    prepared:&PreparedCreate,deadline:Instant)->Result<DockerCreated,String>{
    let (status,raw)=connection.effect(permission,"POST",prepared.path(),Some(prepared.body()),32*1024,deadline)?;
    if status!=201{return Err("native Create not definitively acknowledged201; UNKNOWN".into());}
    Ok(DockerCreated{id:created_id(&raw)?})
}
pub(crate) fn start(connection:&mut ManagedConsumerConnection,permission:VerifiedConsumerAction,
    container:&OwnedManagedContainer,deadline:Instant)->Result<(),String>{
    let (status,raw)=connection.effect(permission,"POST",&format!("/containers/{}/start",container.id()),None,4096,deadline)?;
    if status!=204||!raw.is_empty(){return Err("native Start not definitively acknowledged204; UNKNOWN".into());}
    Ok(())
}

#[derive(Clone)]
pub(crate) struct ContainerObservation {pub(crate) running:bool,pub(crate) exit_code:i64,pub(crate) started_at:String}
fn inspect_matches(value:&serde_json::Value,expected:&PreparedCreate,container:&OwnedManagedContainer)
    ->Result<ContainerObservation,String>{
    if string(value,"Id")?!=container.id() || string(value,"Name")?!=format!("/{}",expected.name)
        || string(value,"Image")?!=expected.image{return Err("actual full container/image/name association differs".into());}
    let config=value.get("Config").ok_or("actual Config missing")?;
    let labels=config.get("Labels").and_then(|v|v.as_object()).ok_or("actual immutable labels absent")?;
    for (key,expected_value) in [(contract::LABEL_WRITER,container.writer().as_uid().as_str()),
        (contract::LABEL_OPERATION,container.operation_uid().as_str()),(contract::LABEL_NONCE,container.nonce().as_str())]{
        if labels.get(key).and_then(|v|v.as_str())!=Some(expected_value){return Err("actual immutable consumer lineage label differs".into());}
    }
    if string(config,"User")?!=expected.user
        || env_map(&strings(config.get("Env").ok_or("actual Config Env absent")?)?)?!=expected.env
        || strings(config.get("Cmd").ok_or("actual Config Cmd absent")?)?!=expected.cmd
        || strings(config.get("Entrypoint").ok_or("actual Config Entrypoint absent")?)?!=expected.entrypoint{
        return Err("actual process user/env/command differs from rebuilt current source".into());
    }
    let host=value.get("HostConfig").and_then(|v|v.as_object()).ok_or("actual HostConfig absent")?;
    if host.get("Privileged").and_then(|v|v.as_bool())!=Some(false)
        || host.get("RestartPolicy").and_then(|v|v.get("Name")).and_then(|v|v.as_str())!=Some("no")
        || host.get("RestartPolicy").and_then(|v|v.get("MaximumRetryCount")).and_then(|v|v.as_u64())!=Some(0)
        || host.get("NetworkMode").and_then(|v|v.as_str())!=Some(expected.network.name.as_str()){
        return Err("actual privileged/restart/network configuration differs".into());
    }
    for field in ["Binds","VolumesFrom","Devices","DeviceRequests","CapAdd"]{
        let value=host.get(field).ok_or("actual extra-mount/capability field missing")?;
        if !value.is_null() && !value.as_array().is_some_and(|a|a.is_empty()){
            return Err("actual native container has an extra mount/device/capability source".into());
        }
    }
    for field in ["PidMode","IpcMode","UTSMode"]{
        let value=host.get(field).and_then(|v|v.as_str()).ok_or("actual namespace mode absent")?;
        if value=="host"||value.starts_with("container:"){return Err("actual native container shares an unsupported namespace".into());}
    }
    for (key,explicit) in expected.explicit_host.as_object().unwrap(){
        if matches!(key.as_str(),"Mounts"|"PortBindings"){continue;}
        if host.get(key)!=Some(explicit){return Err("actual explicit native HostConfig field differs".into());}
    }
    let mounts=value.get("Mounts").and_then(|v|v.as_array()).ok_or("actual mounted-source census absent")?;
    if mounts.len()!=expected.binds.len(){return Err("actual native container has missing/extra mount sources".into());}
    let mut seen=BTreeSet::new();
    for mount in mounts{
        let target=string(mount,"Destination")?;
        if !seen.insert(target){return Err("actual container duplicates a mount destination".into());}
        let binding=expected.binds.iter().find(|b|b.target==target).ok_or("actual mount destination not planned")?;
        if string(mount,"Type")?!="bind"||string(mount,"Source")?!=binding.source
            || mount.get("RW").and_then(|v|v.as_bool())!=Some(!binding.readonly)||string(mount,"Propagation")?!="rprivate"{
            return Err("actual source/private propagation differs from real installed source".into());
        }
    }
    let networks=value.get("NetworkSettings").and_then(|v|v.get("Networks")).and_then(|v|v.as_object())
        .ok_or("actual network census absent")?;
    if networks.len()!=1{return Err("actual native container has an extra/missing network".into());}
    let network=networks.get(&expected.network.name).ok_or("actual native namespace network absent")?;
    if string(network,"NetworkID")?!=expected.network.id{return Err("actual namespace network was replaced".into());}
    let aliases=strings(network.get("Aliases").ok_or("actual network aliases absent")?)?.into_iter().collect::<BTreeSet<_>>();
    let mut allowed=expected.aliases.clone();allowed.extend([expected.name.clone(),container.id().into(),container.id()[..12].into()]);
    if !expected.aliases.is_subset(&aliases)||!aliases.is_subset(&allowed){return Err("actual native DNS aliases differ".into());}
    let state=value.get("State").ok_or("actual container state absent")?;
    Ok(ContainerObservation{running:state.get("Running").and_then(|v|v.as_bool()).ok_or("actual running state malformed")?,
        exit_code:state.get("ExitCode").and_then(|v|v.as_i64()).ok_or("actual exit state malformed")?,
        started_at:string(state,"StartedAt")?.into()})
}
pub(crate) fn inspect_owned(connection:&mut ManagedConsumerConnection,expected:&PreparedCreate,
    container:&OwnedManagedContainer,deadline:Instant)->Result<ContainerObservation,String>{
    let (status,raw)=connection.get(&format!("/containers/{}/json",container.id()),1024*1024,deadline)?;
    if status!=200{return Err("actual owned container inspect is absent/unknown; not terminal proof".into());}
    inspect_matches(&strict_json(&raw)?,expected,container)
}

/// DATA from the exact attested Docker connection + complete expected Create
/// join. No serde/default/raw constructor and no process/mount authority.
pub(crate) struct ActualProcessCandidate {
    cid:String,pid:u32,running:bool,paused:bool,restarting:bool,started_at:String,
}
impl ActualProcessCandidate {
    pub(crate) fn cid(&self)->&str{&self.cid}
    pub(crate) fn pid(&self)->u32{self.pid}
    pub(crate) fn running(&self)->bool{self.running}
    pub(crate) fn paused(&self)->bool{self.paused}
    pub(crate) fn restarting(&self)->bool{self.restarting}
    pub(crate) fn started_at(&self)->&str{&self.started_at}
}
pub(crate) fn inspect_process(connection:&mut ManagedConsumerConnection,expected:&PreparedCreate,
    container:&OwnedManagedContainer,deadline:Instant)->Result<ActualProcessCandidate,String>{
    let (status,raw)=connection.get(&format!("/containers/{}/json",container.id()),1024*1024,deadline)?;
    if status!=200{return Err("original process inspect absent; not an exited-task proof".into());}
    let value=strict_json(&raw)?;let observed=inspect_matches(&value,expected,container)?;
    require_native_exec_absence(&value)?;
    if value.get("HostConfig").and_then(|v|v.get("AutoRemove")).and_then(|v|v.as_bool())!=Some(false){
        return Err("original terminal container requires actual AutoRemove=false; missing/changed is UNKNOWN".into());}
    let state=value.get("State").ok_or("actual original process State absent")?;
    let pid=u32::try_from(state.get("Pid").and_then(|v|v.as_u64()).ok_or("actual original process Pid malformed")?)
        .map_err(|_|"actual original process Pid out of range")?;
    let paused=state.get("Paused").and_then(|v|v.as_bool()).ok_or("actual original pause state missing")?;
    let restarting=state.get("Restarting").and_then(|v|v.as_bool()).ok_or("actual original restart state missing")?;
    if observed.running && (pid<=1||zero_started_at(&observed.started_at)){
        return Err("running original task lacks exact actual PID/start".into());
    }
    Ok(ActualProcessCandidate{cid:container.id().into(),pid,running:observed.running,paused,restarting,started_at:observed.started_at})
}
fn require_native_exec_absence(value:&serde_json::Value)->Result<(),String>{
    // Denial/contradiction only. Native birth labels already exclude all four
    // legacy ExecCreate paths, including before the Create201 book insert.
    // A contradictory actual daemon census cannot be "drained" by census0 or
    // adopted as a previously admitted native diagnostic capability.
    match value.get("ExecIDs"){
        Some(serde_json::Value::Null)=>Ok(()),
        Some(serde_json::Value::Array(ids)) if ids.is_empty()=>Ok(()),
        _=>Err("actual native CID has missing/malformed/nonempty ExecIDs; terminal UNKNOWN".into()),
    }
}
fn zero_started_at(value:&str)->bool{value=="0001-01-01T00:00:00Z"||value=="0001-01-01T00:00:00.000000000Z"}
/// Current guest version on SAME attested connection. The old n1 receipt and
/// local host daemon are neither freshness nor this three-node evidence.
pub(crate) fn terminal_daemon_version(connection:&mut ManagedConsumerConnection,deadline:Instant)->Result<String,String>{
    let (status,raw)=connection.get("/version",65536,deadline)?;
    if status!=200{return Err("terminal daemon version unavailable; no signal".into());}
    let value=strict_json(&raw)?;
    let version=string(&value,"Version")?;
    if version!="29.1.3" || string(&value,"ApiVersion")?!="1.52" || string(&value,"Os")?!="linux"
        || !matches!(string(&value,"Arch")?,"arm64"|"aarch64"){
        return Err("terminal signal wire unsupported for actual guest daemon; no fallback".into());
    }
    Ok(digest_bytes(&raw))
}
fn digest_bytes(bytes:&[u8])->String{use sha2::{Digest,Sha256};format!("{:x}",Sha256::digest(bytes))}
pub(crate) fn signal_term(connection:&mut ManagedConsumerConnection,
    permission:crate::storage_driver::native_runtime::mount::consumer::terminal::VerifiedSignalTerm,
    container:&OwnedManagedContainer,deadline:Instant)->Result<(),String>{
    let path=format!("/containers/{}/kill?signal=SIGTERM",container.id());
    let (status,body)=connection.terminal_signal(permission,&path,deadline)?;
    if status!=204||!body.is_empty(){return Err("once-only SIGTERM response ambiguous/refused; no retry/escalation".into());}
    Ok(())
}

#[cfg(test)]
mod terminal_data_regressions{
    use super::*;
    #[test] fn native_process_exec_census_contradiction_is_not_adopted_as_a_terminal_permission(){
        assert!(require_native_exec_absence(&serde_json::json!({"ExecIDs":null})).is_ok());
        assert!(require_native_exec_absence(&serde_json::json!({"ExecIDs":[]})).is_ok());
        for value in [serde_json::json!({}),serde_json::json!({"ExecIDs":true}),serde_json::json!({"ExecIDs":["a".repeat(64)]}),serde_json::json!({"ExecIDs":[null]})]{
            assert!(require_native_exec_absence(&value).is_err());
        }
        // Empty DATA alone creates neither OriginalProcessPin nor a grant.
    }
    #[test] fn each_immutable_native_birth_marker_is_independent_legacy_exec_denial_data(){
        for marker in [contract::LABEL_WRITER,contract::LABEL_OPERATION,contract::LABEL_NONCE]{
            let mut labels=serde_json::Map::new();labels.insert(marker.into(),serde_json::Value::String("data-only".into()));
            assert!(native_labels(&serde_json::Value::Object(labels)).unwrap());
        }
        assert!(!native_labels(&serde_json::json!({"ordinary":"legacy"})).unwrap());
        assert!(native_labels(&serde_json::json!({"ordinary":true})).is_err());
    }
}
