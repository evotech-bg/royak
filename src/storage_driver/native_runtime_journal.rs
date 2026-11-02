//! Operational DATA only. No grant, owner or replay authority is decoded.
use super::private_fs::Dir;
use crate::storage_identity::Uid;
use crate::storage_remote_protocol::{self as protocol,ExpectedColdJob,JobSpec};
use serde::{Deserialize,Serialize};
use std::collections::{BTreeMap,BTreeSet};
use std::fs::File;
use std::path::Path;
use std::sync::{Arc,Mutex};
#[path="native_runtime_journal_pages.rs"]
mod pages;
#[path="native_runtime_terminal_journal.rs"]
mod terminal_evidence;
pub(super) use terminal_evidence::{TerminalEvidenceBudget,TerminalRecordKind};
const FILES:usize=512;

#[derive(Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
struct Owner {version:u32,cluster:String,node:Uid,boot:crate::storage_boot::BootId,configuration_sha256:String}
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
enum Bucket {Budget,ColdRun,ColdExpected,ColdHeld,InitRound,InitJob,AttachPage,Reservation,Outcome}
#[derive(Clone,Copy,Serialize)]
enum JobClass {ColdIssuer,ColdReceiver,InitIssuer,InitReceiver,InitLocal,InitRound,AttachIssuer}
impl JobClass {
    fn layout(self)->(Bucket,usize,usize,u16){match self{
        Self::ColdIssuer|Self::ColdReceiver=>(Bucket::ColdExpected,2,1,101),
        Self::InitIssuer|Self::InitReceiver|Self::InitLocal=>(Bucket::InitJob,2,1,201),
        Self::InitRound=>(Bucket::InitRound,3,1,301),Self::AttachIssuer=>(Bucket::AttachPage,512,2,0)}}
}
impl Bucket {
    fn bound(self)->usize{match self{Self::ColdExpected=>2,Self::InitJob=>26,Self::AttachPage=>18,_=>1}}
    fn per_volume(self)->bool{!matches!(self,Self::Budget|Self::Reservation|Self::Outcome)}
}
fn group_files(n:usize)->Option<usize>{if !(1..=8).contains(&n){None}else{n.checked_mul(49)?.checked_add(3)}}
struct Group {run:Uid,volumes:BTreeSet<Uid>,used:BTreeMap<(Bucket,Option<Uid>),usize>}
impl Group {
    fn claim(&mut self,bucket:Bucket,volume:Option<&Uid>,count:usize)->Result<(),String>{
        if count==0||bucket.per_volume()!=volume.is_some()||volume.is_some_and(|v|!self.volumes.contains(v)){
            return Err("evidence outside exact precharged group".into());
        }
        let key=(bucket,volume.cloned());let old=self.used.get(&key).copied().unwrap_or(0);
        let next=old.checked_add(count).ok_or("evidence count overflow")?;
        if next>bucket.bound(){return Err("closed evidence category exhausted; UNKNOWN".into());}
        self.used.insert(key,next);Ok(())
    }
}
struct ConsumerState {operation:Option<Uid>,remaining:usize,actions:BTreeMap<Uid,bool>,failed:bool}
struct ConsumerRoot {source:String,containers:usize,materializations:usize,slots:usize,state:Mutex<ConsumerState>,
    terminal:Option<Arc<terminal_evidence::TerminalRoot>>}
/// Resource reservation ONLY. Journal roots the SAME inner object independently
/// of ticket/caller Drop. No serde/default/raw/public constructor.
pub(super) struct ConsumerEvidenceBudget {root:Arc<ConsumerRoot>}
impl ConsumerEvidenceBudget {pub(super) fn source_sha256(&self)->&str{&self.root.source}}
struct State {
    frozen:bool,entries:usize,failed:bool,group:Option<Group>,
    jobs:BTreeMap<String,Arc<pages::JobWriter>>,exact:BTreeMap<String,Arc<pages::ExactRecord>>,
    cold_jobs:BTreeMap<Uid,Uid>,cold_runs:BTreeMap<Uid,Uid>,consumer:Option<Arc<ConsumerRoot>>,
}
fn has_history(entries:&[String])->bool{entries.iter().any(|n|n!="lock"&&n!="runtime-owner.json")}
pub(super) struct Journal {dir:Arc<Dir>,_lease:File,owner:Owner,state:Mutex<State>}
impl Journal {
    pub(super) fn consumer_admission(&self,budget:&ConsumerEvidenceBudget,operation:&Uid,action:&Uid,
        purpose:super::mount::consumer::ConsumerPurpose,key:&crate::workload::managed::LaunchKey,
        method:&str,path:&str,body_sha256:&str,daemon_sha256:&str)->Result<(),String>{
        if ![body_sha256,daemon_sha256].iter().all(|hash|hash.len()==64
            && hash.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))){
            return Err("consumer immutable action binding malformed".into());
        }
        self.consumer_admission_record(budget,operation,action,
            &serde_json::json!({"version":1,"operation":operation,"action":action,"purpose":purpose,
                "source_data":key,"method":method,"path":path,"body_sha256":body_sha256,
                "actual_daemon_sha256":daemon_sha256,"disposition":"UNKNOWN_BEFORE_ONCE_ONLY_EFFECT",
                "restart_authority":false,"mount_authority":false}))
    }
    pub(super) fn consumer_outcome(&self,budget:&ConsumerEvidenceBudget,operation:&Uid,action:&Uid,status:u16,full_cid:Option<&str>,known:&str)->Result<(),String>{
        self.consumer_outcome_record(budget,operation,action,
            &serde_json::json!({"version":1,"operation":operation,"action":action,"status":status,
                "full_cid":full_cid,"observed":known,"restart_authority":false,"mount_authority":false}))
    }
    pub(super) fn open(path:&Path,cluster:String,node:Uid,boot:crate::storage_boot::BootId,configuration_sha256:String)->Result<Self,String>{
        super::reserved_path(path)?;let dir=Dir::open(path,true)?;let lease=dir.lock()?;
        let entries=dir.bounded_entries(FILES)?;let owner=Owner{version:1,cluster,node,boot,configuration_sha256};
        match dir.read("runtime-owner.json")?{
            Some(raw)=>{let old:Owner=serde_json::from_slice(&raw).map_err(|_|"invalid runtime owner history")?;
                if old!=owner{return Err("runtime owner/boot/config changed; explicit recovery required".into());}},
            None=>{if entries.iter().any(|n|n!="lock"){return Err("runtime never adopts existing unowned directory".into());}
                dir.write_new("runtime-owner.json",&protocol::encode_node(&owner)?)?;}
        }
        let frozen=has_history(&entries);
        Ok(Self{dir:Arc::new(dir),_lease:lease,owner,state:Mutex::new(State{frozen,entries:entries.len().max(2),failed:false,
            group:None,jobs:BTreeMap::new(),exact:BTreeMap::new(),cold_jobs:BTreeMap::new(),cold_runs:BTreeMap::new(),consumer:None})})
    }
    pub(super) fn fresh(&self)->Result<bool,String>{let s=self.state.lock().map_err(|_|"runtime journal poisoned")?;Ok(!s.frozen&&!s.failed)}
    fn latch<T>(&self,result:Result<T,String>)->Result<T,String>{
        if result.is_err(){self.state.lock().unwrap_or_else(|p|p.into_inner()).failed=true;}result
    }
    /// Whole count/byte envelope before FIRST product LV/helper effect. External
    /// operator PV/VG creation is a separate historical prerequisite, not this.
    pub(super) fn precharge_group(&self,run:&Uid,volumes:&[Uid])->Result<(),String>{
        let charge=group_files(volumes.len()).ok_or("invalid bounded actual group")?;
        let exact:BTreeSet<_>=volumes.iter().cloned().collect();
        if exact.len()!=volumes.len(){return Err("duplicate reserved volume".into());}
        {
            let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
            if s.frozen||s.failed||s.group.is_some(){return Err("group already attempted/history/UNKNOWN; no retry".into());}
            if s.entries.checked_add(charge).is_none_or(|n|n>FILES){return Err("complete group exceeds512 BEFORE native effects".into());}
            s.entries+=charge;s.group=Some(Group{run:run.clone(),volumes:exact,used:BTreeMap::new()});
        }
        self.exact(Bucket::Budget,None,format!("budget-{}.json",run.as_str()),&serde_json::json!({
            "layout":2,"kind":"royak-runtime-group-evidence-budget-v2","owner":self.owner,"group":run,
            "volumes":volumes,"files_reserved":charge,"bytes_each_maximum":32768,"cold_each":4,
            "init_each":27,"attach_each":18,"global_files_maximum":512,"restart_authority":false}))
    }
    fn claim(&self,bucket:Bucket,volume:Option<&Uid>,count:usize)->Result<(),String>{
        let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
        if s.failed{return Err("runtime evidence UNKNOWN; no retry".into());}
        s.group.as_mut().ok_or("no complete precharged group")?.claim(bucket,volume,count)
    }
    fn exact<T:Serialize>(&self,bucket:Bucket,volume:Option<&Uid>,name:String,value:&T)->Result<(),String>{
        let result=(||{
            let raw=protocol::encode_node(value)?;self.claim(bucket,volume,1)?;
            let record=Arc::new(pages::ExactRecord::new(self.dir.clone(),name.clone(),raw)?);
            {let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
                if s.exact.contains_key(&name){return Err("exact evidence already attempted".into());}
                s.exact.insert(name,record.clone());}
            record.write_once()
        })();self.latch(result)
    }
    fn header<T:Serialize>(class:JobClass,source:&T)->Result<Vec<u8>,String>{
        protocol::encode_node(source)?;
        serde_json::to_vec(&serde_json::json!({"layout":2,"kind":"royak-runtime-job-evidence-v2","job_class":class,"source":source}))
            .map_err(|_|"exact job header serialization failed".into())
    }
    fn start<T:Serialize>(&self,class:JobClass,volume:&Uid,key:String,header:&T)->Result<(),String>{
        let result=(||{
            let(bucket,maximum,count,first)=class.layout();
            let full=Self::header(class,header)?;let source=protocol::encode_node(header)?;
            self.claim(bucket,Some(volume),count)?;
            let writer=Arc::new(pages::JobWriter::new(self.dir.clone(),key.clone(),full,maximum,count)?);
            {let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
                if s.jobs.contains_key(&key){return Err("actual job already attempted; no replacement".into());}
                s.jobs.insert(key,writer.clone());}
            if first==0{writer.initialize()}else{writer.append(first,pages::exact_hash(&protocol::hash(&source))?)}
        })();self.latch(result)
    }
    fn append(&self,key:&str,kind:u16,hash:&str)->Result<(),String>{
        let result=(||self.append_existing(key,None,kind,pages::exact_hash(hash)?))();self.latch(result)
    }
    /// Same fixed IO serialization as every durable caller. Never let a
    /// healthy existing job bypass another record's monotonic global UNKNOWN.
    fn append_existing(&self,key:&str,header:Option<&[u8]>,kind:u16,hash:[u8;32])->Result<(),String>{
        let writer={let s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
            if s.failed{return Err("runtime evidence globally UNKNOWN; no existing-job append".into());}
            s.jobs.get(key).cloned().ok_or("actual pinned evidence job absent; no reconstruction")?};
        if let Some(header)=header{writer.require_header(header)?;}
        writer.append(kind,hash)
    }
    pub(super) fn begin<T:Serialize>(&self,run:&Uid,volume:&Uid,value:&T)->Result<(),String>{
        {let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
            if s.frozen||s.failed||s.group.as_ref().is_none_or(|g|g.run!=*run||!g.volumes.contains(volume)){
                return Err("previous/unknown/unreserved work; no automatic resume".into());}
            s.frozen=true;s.cold_runs.insert(run.clone(),volume.clone());}
        self.exact(Bucket::ColdRun,Some(volume),format!("run-{}.json",run.as_str()),value)
    }
    pub(super) fn receiver(&self,spec:&JobSpec,offer_sha256:&str)->Result<(),String>{
        // Current controller offers ONE volume. Future8 must precharge its
        // complete genuine group, not repeat this single-volume entry point.
        self.precharge_group(&spec.job_uid,std::slice::from_ref(&spec.owner.volume_uid))?;
        {let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;s.frozen=true;
            s.cold_jobs.insert(spec.job_uid.clone(),spec.owner.volume_uid.clone());}
        self.start(JobClass::ColdReceiver,&spec.owner.volume_uid,format!("cold-job-{}",spec.job_uid.as_str()),
            &serde_json::json!({"version":1,"spec":spec,"offer_sha256":offer_sha256,"disposition":"UNKNOWN_BEFORE_GRANT"}))
    }
    pub(super) fn register_expected(&self,expected:&ExpectedColdJob)->Result<(),String>{
        let spec=expected.spec();self.start(JobClass::ColdIssuer,&spec.owner.volume_uid,format!("cold-job-{}",spec.job_uid.as_str()),
            &serde_json::json!({"version":1,"spec":spec,"spec_sha256":expected.hash()?,"acknowledged_core":true,"restart_authority":false}))
    }
    pub(super) fn issuer(&self,expected:&ExpectedColdJob,request_sha256:&str)->Result<(),String>{
        self.append(&format!("cold-job-{}",expected.spec().job_uid.as_str()),102,request_sha256)
    }
    pub(super) fn register_init(&self,expected:&super::init::ExpectedInitJob)->Result<(),String>{
        let spec=expected.spec();self.start(JobClass::InitIssuer,&spec.owner.volume_uid,format!("init-job-{}",spec.job_uid.as_str()),
            &serde_json::json!({"version":2,"spec":spec,"spec_sha256":expected.hash()?,"acknowledged_core":true,"restart_authority":false}))
    }
    pub(super) fn issuer_init(&self,expected:&super::init::ExpectedInitJob,request:&str)->Result<(),String>{
        self.append(&format!("init-job-{}",expected.spec().job_uid.as_str()),202,request)
    }
    pub(super) fn receiver_init(&self,spec:&JobSpec)->Result<(),String>{
        self.start(JobClass::InitReceiver,&spec.owner.volume_uid,format!("init-job-{}",spec.job_uid.as_str()),
            &serde_json::json!({"version":2,"spec":spec,"disposition":"UNKNOWN_BEFORE_GRANT","restart_authority":false}))
    }
    pub(super) fn local_init(&self,owner:&super::dispatcher::distributed_init::HeldInitializationOwner,
        scope:&crate::storage_lifecycle::generation::physical::ExpectedInitScope)->Result<(),String>{
        owner.check_offer(scope)?;
        self.start(JobClass::InitLocal,&scope.owner.volume_uid,format!("init-job-{}",scope.phase_job_uid.as_str()),
            &serde_json::json!({"version":2,"scope":scope,"reference":owner.reference(),"disposition":"UNKNOWN_BEFORE_LAUNCH","restart_authority":false}))
    }
    pub(super) fn arm(&self,owner:&super::dispatcher::distributed_init::HeldInitializationOwner,
        generation:&crate::storage_lifecycle::generation::DataGeneration)->Result<(),String>{
        self.start(JobClass::InitRound,&owner.reference().volume_uid,format!("init-round-{}",generation.initialize_operation_uid.as_str()),
            &serde_json::json!({"version":2,"prepare_owner":owner.prepare().owner(),"prepare_operation_uid":owner.prepare().operation_uid(),
                "reference":owner.reference(),"generation":generation,"restart_authority":false}))
    }
    pub(super) fn phase(&self,run:&Uid,phase:&str,evidence:&str)->Result<(),String>{
        match phase{
            "INIT_RESERVED"=>self.append(&format!("init-round-{}",run.as_str()),302,evidence),
            "DETACHED_DRAINED"=>self.append(&format!("init-round-{}",run.as_str()),303,evidence),
            "PHASE_COMPLETE"=>self.append(&format!("init-job-{}",run.as_str()),202,evidence),
            "HELD"=>{
                let(remote,volume)={let s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
                    if let Some(v)=s.cold_jobs.get(run){(true,v.clone())}
                    else{(false,s.cold_runs.get(run).cloned().ok_or("actual cold run evidence absent")?)}};
                if remote{self.append(&format!("cold-job-{}",run.as_str()),102,evidence)}else{
                    pages::exact_hash(evidence)?;
                    self.exact(Bucket::ColdHeld,Some(&volume),format!("cold-held-{}.json",run.as_str()),
                        &serde_json::json!({"version":1,"run":run,"phase":phase,"evidence_sha256":evidence}))
                }
            }
            _=>Err("unregistered phase has no precharged evidence sidepath".into())
        }
    }
    pub(super) fn attach_admission(&self,expected:&super::mount::parent::ExpectedAttachJob,
        purpose:protocol::attachment::Purpose,binding:&str)->Result<(),String>{
        let scope=expected.scope();expected.require_live()?;
        scope.validate()?;let key=format!("attach-job-{}",scope.phase_job_uid.as_str());
        let header=serde_json::json!({"version":1,"scope":scope,"session_uid":expected.session_uid(),"disposition":"UNKNOWN_BEFORE_PERMISSION","restart_authority":false});
        let exists={let s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
            if s.failed{return Err("runtime evidence globally UNKNOWN; no attach admission".into());}
            s.jobs.contains_key(&key)};
        if !exists{self.start(JobClass::AttachIssuer,&scope.owner.volume_uid,key.clone(),&header)?;}
        let kind=match purpose{
            protocol::attachment::Purpose::PhaseGrant=>401,
            protocol::attachment::Purpose::PhaseBoundary(boundary)=>410+match boundary{
                protocol::attachment::AttachBoundary::Start=>0,protocol::attachment::AttachBoundary::Identity=>1,
                protocol::attachment::AttachBoundary::Program=>2,protocol::attachment::AttachBoundary::Read=>3,
                protocol::attachment::AttachBoundary::AnchorBind=>4,protocol::attachment::AttachBoundary::AnchorPrivate=>5,
                protocol::attachment::AttachBoundary::MountExt4=>6,protocol::attachment::AttachBoundary::MakePrivate=>7,
                protocol::attachment::AttachBoundary::Complete=>8,
                protocol::attachment::AttachBoundary::InventoryRead=>9},
            protocol::attachment::Purpose::PhaseReport=>430,protocol::attachment::Purpose::MountedCommit=>431,
            protocol::attachment::Purpose::MountedCommitConfirm=>432};
        let result=(||{
            let exact_header=Self::header(JobClass::AttachIssuer,&header)?;
            self.append_existing(&key,Some(&exact_header),kind,pages::exact_hash(binding)?)
        })();self.latch(result)
    }
    pub(super) fn attach_reservation<T:Serialize>(&self,operation:&Uid,source:&T)->Result<(),String>{
        self.exact(Bucket::Reservation,None,format!("attach-reservation-{}.json",operation.as_str()),
            &serde_json::json!({"version":1,"operation":operation,"source":source,"disposition":"UNKNOWN_BEFORE_ACTUAL_CORE_RESERVATION","restart_authority":false}))
    }
    pub(super) fn attach_outcome(&self,scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope,actual:&[u8])->Result<(),String>{
        scope.validate()?;let outcome:serde_json::Value=protocol::decode_node(actual)?;
        self.exact(Bucket::Outcome,None,format!("attach-outcome-{}.json",scope.round_uid.as_str()),
            &serde_json::json!({"version":1,"round":scope.round_uid,"job":scope.phase_job_uid,"outcome":outcome,"restart_authority":false,"ready_authority":false}))
    }
    pub(super) fn reserve_consumer_plan(&self,source_sha256:&str,containers:usize,materializations:usize)->Result<ConsumerEvidenceBudget,String>{
        pages::exact_hash(source_sha256)?;
        if containers==0||containers>128||materializations>containers{return Err("invalid actual consumer DATA counts".into());}
        let slots=containers.checked_mul(4).and_then(|n|materializations.checked_mul(2).and_then(|m|n.checked_add(m))).ok_or("consumer count overflow")?;
        let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
        if s.failed||s.group.is_none()||s.consumer.is_some(){return Err("consumer plan attempted/UNKNOWN/unreserved; no retry".into());}
        if s.entries.checked_add(slots).is_none_or(|n|n>FILES){return Err("consumer budget exceeds remaining512 BEFORE first consumer effect; earlier storage effects retained".into());}
        let root=Arc::new(ConsumerRoot{source:source_sha256.into(),containers,materializations,slots,terminal:None,
            state:Mutex::new(ConsumerState{operation:None,remaining:slots,actions:BTreeMap::new(),failed:false})});
        s.entries+=slots;s.consumer=Some(root.clone());Ok(ConsumerEvidenceBudget{root})
    }
    pub(super) fn consumer_admission_record<T:Serialize>(&self,budget:&ConsumerEvidenceBudget,operation:&Uid,action:&Uid,value:&T)->Result<(),String>{
        self.consumer_record(budget,operation,action,false,value)
    }
    pub(super) fn consumer_outcome_record<T:Serialize>(&self,budget:&ConsumerEvidenceBudget,operation:&Uid,action:&Uid,value:&T)->Result<(),String>{
        self.consumer_record(budget,operation,action,true,value)
    }
    fn consumer_record<T:Serialize>(&self,budget:&ConsumerEvidenceBudget,operation:&Uid,action:&Uid,outcome:bool,value:&T)->Result<(),String>{
        let result=(||{
            {let s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
                if s.failed||!s.consumer.as_ref().is_some_and(|r|Arc::ptr_eq(r,&budget.root)){return Err("not SAME rooted consumer budget".into());}}
            {let mut s=budget.root.state.lock().map_err(|_|"consumer budget poisoned")?;
                let wrong=if outcome{s.actions.get(action)!=Some(&false)}
                    else{s.actions.contains_key(action)||s.actions.len()>=2*budget.root.containers+budget.root.materializations};
                if s.failed||s.remaining==0||s.operation.as_ref().is_some_and(|op|op!=operation)||wrong{
                    return Err("consumer evidence replay/order/changed operation/UNKNOWN".into());}
                s.operation=Some(operation.clone());s.remaining-=1;s.actions.insert(action.clone(),outcome);s.failed=true;}
            // The FIRST admitted effect fsyncs this full exact plan reservation
            // in its own already-charged record. No extra uncharged budget file.
            let name=format!("consumer-{}-{}.json",action.as_str(),if outcome{"outcome"}else{"admission"});
            let raw=protocol::encode_node(&serde_json::json!({"layout":2,"kind":"royak-runtime-consumer-evidence-v2",
                "plan_source_sha256":budget.root.source,"containers":budget.root.containers,"materializations":budget.root.materializations,
                "total_precharged_files":budget.root.slots,"operation":operation,"action":action,"source":value,"restart_authority":false}))?;
            let record=Arc::new(pages::ExactRecord::new(self.dir.clone(),name.clone(),raw)?);
            {let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
                if s.exact.contains_key(&name){return Err("consumer evidence already attempted".into());}
                s.exact.insert(name,record.clone());}
            record.write_once()?;
            budget.root.state.lock().map_err(|_|"consumer budget poisoned")?.failed=false;Ok(())
        })();
        if result.is_err(){budget.root.state.lock().unwrap_or_else(|p|p.into_inner()).failed=true;}
        self.latch(result)
    }
}

#[cfg(test)]
#[path="native_runtime_journal_tests.rs"]
mod group_tests;
#[cfg(test)]
mod tests {
    #[test]
    fn restart_history_is_never_an_authority_constructor() {
        let fresh = vec!["lock".to_string(), "runtime-owner.json".to_string()];
        assert!(!super::has_history(&fresh));
        for old in [
            "run-a.json",
            "issuer-a.json",
            "receiver-a.json",
            "phase-complete.json",
            "unknown",
        ] {
            let mut entries = fresh.clone();
            entries.push(old.to_string());
            assert!(super::has_history(&entries));
        }
    }
}

