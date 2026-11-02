//! Readonly actual same-book roots. Never a serialized owner list or a new
//! registry: canonical Assignment/PodWriter and existing book remain sole roots.
use super::*;
fn same_actual_members<T>(left:&[Arc<T>],right:&[Arc<T>])->bool{
    left.len()==right.len()&&left.iter().zip(right).all(|(a,b)|Arc::ptr_eq(a,b))
}

pub(in crate::storage_driver) struct SameGroupInventoryRoots {
    book:Arc<MountBook>,round:Uid,boot:BootId,
    owners:Vec<Arc<AttachOwner>>,commitment:String,
}
impl SameGroupInventoryRoots {
    pub(in crate::storage_driver) fn members(&self)->&[Arc<AttachOwner>]{&self.owners}
    pub(in crate::storage_driver) fn commitment(&self)->&str{&self.commitment}
    pub(in crate::storage_driver) fn require_current(&self,current:&parent::VerifiedAttachParent)->Result<(),String>{
        current.require_live()?;
        if !Arc::ptr_eq(current.root_book(),&self.book)||!Arc::ptr_eq(current.actual_store(),self.book.world())
            ||current.scope().round_uid!=self.round||self.boot!=BootId::current()?||self.book.boot!=self.boot
            ||self.book.invalid.load(Ordering::Acquire){return Err("owned inventory lost SAME actual book/round/boot/world".into());}
        {
            let state=self.book.state.try_lock().map_err(|_|"owned inventory original book busy/poisoned")?;
            if state.unknown.is_some()||state.commit.is_some()||state.current.as_ref()!=Some(&self.round)
                ||state.owners.len()!=self.owners.len()||self.owners.is_empty()||self.owners.len()>8{
                return Err("owned inventory group changed/committing/UNKNOWN; no adoption".into());}
            let current=state.owners.values().cloned().collect::<Vec<_>>();
            if !same_actual_members(&self.owners,&current){return Err("owned inventory actual Arc membership changed".into());}
        } // NEVER hold book mutex through member/source/FD or network IO.
        for owner in &self.owners{owner.require_inventory_group_member(current)?;}
        if group_commitment(&self.owners)?!=self.commitment{return Err("owned inventory immutable scope commitment changed".into());}
        current.require_live()
    }
}
#[cfg(test)]mod tests{
    use super::*;
    #[test]fn v7_same_book_membership_uses_same_actual_arcs_not_equal_copied_data(){
        let a=Arc::new(1);let b=Arc::new(2);let expected=vec![a.clone(),b.clone()];
        assert!(same_actual_members(&expected,&[a.clone(),b.clone()]));
        assert!(!same_actual_members(&expected,&[Arc::new(1),b.clone()]));assert!(!same_actual_members(&expected,&[b,a.clone()]));
        assert!(!same_actual_members(&expected,&[a]));
    }
    #[test]fn v7_snapshot_source_drops_book_guard_before_member_io_or_fresh_permission(){
        let source=include_str!("native_runtime_mount_inventory.rs");
        let body=source.split("fn require_current(").nth(1).unwrap().split("fn group_commitment(").next().unwrap();
        let release=body.find("NEVER hold book mutex").unwrap();let io=body.find("owner.require_inventory_group_member").unwrap();
        assert!(release<io);assert!(!body[..release].contains(".probe.lock("));
        assert!(body.contains("state.commit.is_some()"));assert!(body.contains("state.current.as_ref()!=Some(&self.round)"));
    }
}
fn group_commitment(owners:&[Arc<AttachOwner>])->Result<String,String>{
    // Full exact scopes, never truncated. FD/kernel identity is checked by
    // actual member probes separately; this digest is not their constructor.
    let scopes=owners.iter().map(|o|o.scope()).collect::<Vec<_>>();
    Ok(super::super::digest(&serde_json::to_vec(&scopes).map_err(|_|"actual inventory group scope encoding")?))
}
impl MountBook {
    pub(in crate::storage_driver) fn released_slot_for_owned_inventory(&self,current:&parent::VerifiedAttachParent)
        ->Result<Arc<crate::storage_driver::dispatcher::distributed_init::ReleasedInitializationSlot>,String>{
        current.require_live()?;
        if !std::ptr::eq(self,Arc::as_ptr(current.root_book()))||!Arc::ptr_eq(&self.world,current.actual_store())
            ||self.boot!=current.scope().phase_boot||self.invalid.load(Ordering::Acquire){return Err("not SAME original v7 initialized book/world/boot".into());}
        let state=self.state.lock().map_err(|_|"actual original init slot book poisoned")?;
        if state.unknown.is_some(){return Err("actual original init slot book UNKNOWN".into());}
        let(generation,slot)=state.released_slots.get(&current.scope().owner.volume_uid).ok_or("no genuine retained per-volume initialization slot")?;
        if generation!=&current.scope().generation.uid{return Err("retained init slot generation differs (not dataset substitution)".into());}
        Ok(slot.clone())
    }
    pub(in crate::storage_driver) fn same_group_inventory(self:&Arc<Self>,current:&parent::VerifiedAttachParent)
        ->Result<SameGroupInventoryRoots,String>{
        current.require_live()?;
        if !Arc::ptr_eq(current.root_book(),self)||!Arc::ptr_eq(current.actual_store(),&self.world)
            ||self.invalid.load(Ordering::Acquire)||self.boot!=BootId::current()?{
            return Err("inventory roots require SAME actual live Watch book".into());}
        let owners={
            let state=self.state.try_lock().map_err(|_|"inventory actual book busy/poisoned")?;
            if state.unknown.is_some()||state.commit.is_some()||state.current.as_ref()!=Some(&current.scope().round_uid)
                ||state.owners.is_empty()||state.owners.len()>8||!state.owners.contains_key(&current.scope().owner.volume_uid){
                return Err("inventory needs bounded exact current precommit group; no other-round/history fallback".into());}
            state.owners.values().cloned().collect::<Vec<_>>()
        };
        let commitment=group_commitment(&owners)?;
        let roots=SameGroupInventoryRoots{book:self.clone(),round:current.scope().round_uid.clone(),boot:self.boot.clone(),owners,commitment};
        roots.require_current(current)?;Ok(roots)
    }
}
