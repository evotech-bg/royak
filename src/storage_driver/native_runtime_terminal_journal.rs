//! Closed terminal evidence classes, reserved with launch BEFORE first Create.
//! This is resource accounting, never Core/FD/physical effect authority.
use super::*;
use std::sync::atomic::{AtomicBool,Ordering};

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord,Serialize)]
pub(in crate::storage_driver::native_runtime) enum TerminalRecordKind {ProcessPin,SignalAdmission,SignalOutcome,RootAdmission,RootOutcome,
    DetachingAdmission,DetachingOutcome,OfflineSummary,DetachedAdmission,DetachedOutcome}
impl TerminalRecordKind {
    fn maximum(self,c:usize,v:usize)->usize{match self{
        Self::ProcessPin|Self::SignalAdmission|Self::SignalOutcome=>c,
        Self::RootAdmission|Self::RootOutcome=>1,
        Self::OfflineSummary=>3*v,_=>v}}
    fn label(self)->&'static str{match self{Self::ProcessPin=>"process-pin",Self::SignalAdmission=>"signal-admission",
        Self::SignalOutcome=>"signal-outcome",Self::RootAdmission=>"root-admission",Self::RootOutcome=>"root-outcome",
        Self::DetachingAdmission=>"detaching-admission",Self::DetachingOutcome=>"detaching-outcome",
        Self::OfflineSummary=>"offline-summary",Self::DetachedAdmission=>"detached-admission",Self::DetachedOutcome=>"detached-outcome"}}
}
pub(super) fn complete_consumer_slots(c:usize,m:usize,v:usize)->Result<usize,String>{
    if !(1..=128).contains(&c)||m>c||v!=1{return Err("terminal producer requires exact one-volume bounded actual plan".into());}
    if c.checked_mul(3).and_then(|n|n.checked_add(m)).is_none_or(|n|n>384){
        return Err("complete launch/signal action history exceeds unchanged384 BEFORE Create".into());}
    c.checked_mul(7).and_then(|n|m.checked_mul(2).and_then(|x|n.checked_add(x)))
        .and_then(|n|v.checked_mul(13).and_then(|x|n.checked_add(x)))
        .and_then(|n|n.checked_add(2)).ok_or("complete consumer terminal count overflow".into())
}
struct TerminalState {operation:Option<Uid>,failed:bool,counts:BTreeMap<TerminalRecordKind,usize>,
    attempted:BTreeSet<(TerminalRecordKind,Uid)>,jobs:BTreeMap<Uid,Arc<pages::JobWriter>>}
pub(super) struct TerminalRoot {uid:Uid,source:String,containers:usize,volumes:usize,state:Mutex<TerminalState>}
/// Non-serde/non-Clone. SAME root is held by Journal's original consumer root.
pub(in crate::storage_driver::native_runtime) struct TerminalEvidenceBudget {root:Arc<TerminalRoot>}
impl TerminalEvidenceBudget {
    pub(in crate::storage_driver::native_runtime) fn source_sha256(&self)->&str{&self.root.source}
    pub(super) fn uid(&self)->&Uid{&self.root.uid}
}
impl ConsumerEvidenceBudget {
    pub(in crate::storage_driver::native_runtime) fn terminal(&self)->Result<Arc<TerminalEvidenceBudget>,String>{
        let root=self.root.terminal.as_ref().cloned().ok_or("old launch-only budget has no precharged terminal authority")?;
        Ok(Arc::new(TerminalEvidenceBudget{root}))
    }
}
impl Journal {
    pub(in crate::storage_driver::native_runtime) fn reserve_terminal_consumer_plan(&self,source:&str,c:usize,m:usize,v:usize)
        ->Result<ConsumerEvidenceBudget,String>{
        pages::exact_hash(source)?;let slots=complete_consumer_slots(c,m,v)?;
        let launch=c.checked_mul(4).and_then(|n|m.checked_mul(2).and_then(|x|n.checked_add(x))).ok_or("launch count overflow")?;
        let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
        if s.failed||s.group.is_none()||s.consumer.is_some(){return Err("complete consumer/terminal budget already attempted/UNKNOWN/unreserved".into());}
        if s.entries.checked_add(slots).is_none_or(|n|n>FILES){return Err("complete consumer+terminal budget exceeds512 BEFORE Create; storage retained".into());}
        let terminal=Arc::new(TerminalRoot {uid:Uid::new(),source:source.into(),containers:c,volumes:v,
            state:Mutex::new(TerminalState{operation:None,failed:false,counts:BTreeMap::new(),attempted:BTreeSet::new(),jobs:BTreeMap::new()})});
        let root=Arc::new(ConsumerRoot{source:source.into(),containers:c,materializations:m,slots,terminal:Some(terminal),
            state:Mutex::new(ConsumerState{operation:None,remaining:launch,actions:BTreeMap::new(),failed:false})});
        s.entries+=slots;s.consumer=Some(root.clone());Ok(ConsumerEvidenceBudget{root})
    }
    fn require_terminal_root(&self,budget:&TerminalEvidenceBudget)->Result<(),String>{
        let state=self.state.lock().map_err(|_|"runtime journal poisoned")?;
        if state.failed||!state.consumer.as_ref().and_then(|c|c.terminal.as_ref()).is_some_and(|t|Arc::ptr_eq(t,&budget.root)){
            return Err("global evidence UNKNOWN or not SAME precharged terminal root".into());
        }Ok(())
    }
    pub(in crate::storage_driver::native_runtime) fn terminal_record<T:Serialize>(&self,budget:&TerminalEvidenceBudget,operation:&Uid,
        kind:TerminalRecordKind,key:&Uid,value:&T)->Result<(),String>{
        let result=(||{
            self.require_terminal_root(budget)?;
            {let mut s=budget.root.state.lock().map_err(|_|"terminal budget poisoned")?;
                if s.failed||s.operation.as_ref().is_some_and(|uid|uid!=operation)
                    ||s.attempted.contains(&(kind,key.clone())){return Err("terminal evidence failed/replayed/changed operation".into());}
                let count=s.counts.get(&kind).copied().unwrap_or(0);
                if count>=kind.maximum(budget.root.containers,budget.root.volumes){return Err("closed terminal record class exhausted".into());}
                for (outcome,admission) in [(TerminalRecordKind::SignalOutcome,TerminalRecordKind::SignalAdmission),
                    (TerminalRecordKind::RootOutcome,TerminalRecordKind::RootAdmission),
                    (TerminalRecordKind::DetachingOutcome,TerminalRecordKind::DetachingAdmission),
                    (TerminalRecordKind::DetachedOutcome,TerminalRecordKind::DetachedAdmission)] {
                    if kind==outcome&&!s.attempted.contains(&(admission,key.clone())){return Err("terminal outcome has no actual original admission".into());}
                }
                s.operation=Some(operation.clone());s.counts.insert(kind,count+1);
                s.attempted.insert((kind,key.clone()));s.failed=true;}
            let name=format!("terminal-{}-{}.json",kind.label(),key.as_str());
            let raw=protocol::encode_node(&serde_json::json!({"layout":3,"kind":"royak-terminal-data-v1",
                "budget":budget.root.uid,"source_sha256":budget.root.source,"operation":operation,
                "record_kind":kind,"record_key":key,"facts":value,"restart_authority":false}))?;
            let record=Arc::new(pages::ExactRecord::new(self.dir.clone(),name.clone(),raw)?);
            {let mut s=self.state.lock().map_err(|_|"runtime journal poisoned")?;
                if s.failed||s.exact.contains_key(&name){return Err("terminal exact record already exists/globalfailed".into());}
                s.exact.insert(name,record.clone());}
            record.write_once()?;
            budget.root.state.lock().map_err(|_|"terminal budget poisoned")?.failed=false;Ok(())
        })();
        if result.is_err(){budget.root.state.lock().unwrap_or_else(|p|p.into_inner()).failed=true;}
        self.latch(result)
    }
    /// Header supplied ONLY by the genuine registered terminal node producer,
    /// never a public input. It still cannot grant an effect.
    pub(in crate::storage_driver::native_runtime) fn terminal_node_header<T:Serialize>(&self,budget:&TerminalEvidenceBudget,
        operation:&Uid,node_job:&Uid,header:&T)->Result<(),String>{
        let result=(||{
            self.require_terminal_root(budget)?;
            let raw=protocol::encode_node(header)?;
            let writer=Arc::new(pages::JobWriter::new(self.dir.clone(),format!("terminal-node-{}",node_job.as_str()),raw,512,2)?);
            {let mut s=budget.root.state.lock().map_err(|_|"terminal budget poisoned")?;
                if s.failed||s.operation.as_ref().is_some_and(|uid|uid!=operation)||s.jobs.len()>=3*budget.root.volumes||s.jobs.contains_key(node_job){
                    return Err("terminal node header duplicate/full/UNKNOWN".into());}
                s.operation=Some(operation.clone());s.jobs.insert(node_job.clone(),writer.clone());}
            writer.initialize()
        })();self.latch(result)
    }
    pub(in crate::storage_driver::native_runtime) fn terminal_node_append(&self,budget:&TerminalEvidenceBudget,node_job:&Uid,
        kind:u16,binding:&str)->Result<(),String>{
        let result=(||{
            self.require_terminal_root(budget)?;
            let writer={let s=budget.root.state.lock().map_err(|_|"terminal node budget poisoned")?;
                if s.failed{return Err("terminal evidence UNKNOWN".into());}
                s.jobs.get(node_job).cloned().ok_or("terminal node lacks original pre-effect header")?};
            writer.append(kind,pages::exact_hash(binding)?)
        })();self.latch(result)
    }
    pub(in crate::storage_driver::native_runtime) fn terminal_healthy(&self,budget:&TerminalEvidenceBudget)->Result<(),String>{
        self.require_terminal_root(budget)?;
        if budget.root.state.lock().map_err(|_|"terminal budget poisoned")?.failed{return Err("terminal evidence UNKNOWN".into());}
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn complete_terminal_budget_counts_every_closed_runtime_class_before_create(){
        assert_eq!(complete_consumer_slots(1,0,1).unwrap(),22);
        assert_eq!(49+5+complete_consumer_slots(1,0,1).unwrap(),76);
        assert_eq!(complete_consumer_slots(1,1,1).unwrap(),24);
        assert_eq!(TerminalRecordKind::OfflineSummary.maximum(1,1),3);
    }
    #[test] fn data_ceiling_does_not_claim_terminal_physical_or_file_capacity(){
        assert_eq!(complete_consumer_slots(128,0,1).unwrap(),911);
        assert!(complete_consumer_slots(128,128,1).is_err());
        for (c,m,v) in [(0,0,1),(129,0,1),(1,2,1),(1,0,2)]{assert!(complete_consumer_slots(c,m,v).is_err());}
        assert!(54+complete_consumer_slots(63,0,1).unwrap()<=512);
        assert!(54+complete_consumer_slots(64,0,1).unwrap()>512);
    }
}
