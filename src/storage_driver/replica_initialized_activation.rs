//! Private initialized-only companion. Never Mode::Online broadening, blank
//! metadata reconciliation, adoption or a public caller-supplied context.
use super::*;
use crate::storage_driver::dispatcher::attachment::VerifiedAttachPhase;
use crate::storage_lifecycle::generation::VirginReplicaRef;
#[cfg(test)]
pub(in crate::storage_driver) fn maximal_inventory_plan_data(cfg:&Config,scope:&crate::storage_lifecycle::pod_attachment::ExpectedAttachScope)->Value{
    let peers=std::array::from_fn(|i|Peer{node_uid:scope.replicas[i].node_uid.clone(),node_id:i as u8,
        hostname:format!("{}{}","h".repeat(62),i),address:std::net::Ipv4Addr::new(10,77,0,(i+1)as u8),
        public_key:format!("{}{}=","A".repeat(42),["E","I","M"][i]),vg_name:cfg.vg_name.clone()});
    let plan=Plan{version:1,cluster_id:cfg.cluster_id.clone(),pool_uid:cfg.pool_uid.clone(),volume_uid:scope.owner.volume_uid.clone(),
        operation_uid:scope.generation.prepare_operation_uid.clone(),minor:32767,port:59999,interface:"i".repeat(15),shared_secret:"f".repeat(48),peers};
    plan.validate(cfg).unwrap();plan.runtime_wire().unwrap()
    // Closed DATA only; no inherited job, current IO/FD/session authority.
}
/// Protected retained replica DATA, not a capability constructor.
pub(in crate::storage_driver) fn inventory_minor(cfg:&Config,fact:&VirginReplicaRef)->Result<u32,String>{
    let dir=Dir::open(&cfg.journal_path(),false)?;
    let raw=dir.read(&format!("replica-{}.json",fact.volume_uid.as_str()))?.ok_or("same-book replica history absent")?;
    let envelope:Envelope=serde_json::from_slice(&raw).map_err(|_|"same-book replica envelope corrupt")?;
    let plan=&envelope.record.plan;let record=load(&dir,plan)?.ok_or("protected exact same-book replica disappeared")?;
    plan.validate(cfg)?;
    if envelope.version!=1||plan.volume_uid!=fact.volume_uid||plan.operation_uid!=fact.prepare_operation_uid
        ||plan.runtime_hash()?!=fact.plan_sha256||record.lv_uuid!=fact.lv_uuid||record.allocation_nonce!=fact.allocation_nonce
        ||record.device_uuid.as_ref()!=Some(&fact.drbd_device_uuid)||record.stage==Stage::MetadataIntent
        ||record.stage==Stage::OfflineIntent{
        return Err("same-book initialized replica plan/incarnation differs".into());}
    Ok(plan.minor as u32)
}
pub(in crate::storage_driver) fn activate(cfg:&Config,plan:&Plan,permit:&VerifiedAttachPhase)->Result<(),String>{
    use crate::storage_lifecycle::pod_attachment::AttachPhase;
    let inventory=permit.owned_inventory().ok_or("initialized-only activation requires actual profile7 context")?;
    if permit.scope().phase!=AttachPhase::ActivateReplica{return Err("not initialized-only activation phase".into());}
    plan.validate(cfg)?;permit.checkpoint()?;
    // Preserve BOTH ordinary activation backing observations: one before the
    // pool lock, one under the exact existing lock, each actual profile7.
    lvm::owned_inventory::inspect_owned(inventory,cfg)?;
    let(dir,_lock,pool,allocation,lv)=lvm::owned_inventory::prepared_context_owned(inventory,cfg,&plan.volume_uid)?;
    if pool.drbd_module_version.as_ref().is_none_or(|v|!v.starts_with("9."))
        ||allocation.request.operation_uid!=plan.operation_uid{return Err("initialized activation DRBD9/allocation differs".into());}
    let mut record=load(&dir,plan)?.ok_or("initialized activation has no actual prior replica")?;
    let fact=permit.scope().generation.virgin_replicas.iter().find(|f|f.node_uid==cfg.node_uid).ok_or("local initialized fact absent")?;
    if record.stage!=Stage::Offline||record.lv_uuid!=fact.lv_uuid||lv.uuid!=fact.lv_uuid
        ||record.allocation_nonce!=fact.allocation_nonce||record.device_uuid.as_ref()!=Some(&fact.drbd_device_uuid)
        ||status(plan)?.is_some()||dir.read(&config_name(plan))?.as_deref()!=Some(plan.config(allocation.request.exposed_bytes()?).as_bytes()){
        return Err("activation requires exact existing initialized Offline/config; never repair/adopt/retry".into());}
    lvm::verify_unheld(&lv)?;transport(cfg,plan)?;
    verify_superblock(cfg,plan,&lv,&fact.drbd_device_uuid)?;
    let before=metadata(cfg,plan)?;
    let original=permit.scope().initial_lineage.offline.iter().find(|v|v.replica.node_uid==cfg.node_uid).ok_or("actual offline lineage absent")?;
    if before.0!=fact.drbd_device_uuid||before.1!=original.drbd_current_uuid{return Err("initialized offline UUID lineage changed".into());}
    let guard=guard::Guard::new(cfg,plan,&record.allocation_nonce)?;
    permit.checkpoint()?;record.stage=Stage::OnlineIntent;save(&dir,&record)?;
    guard.ensure(cfg,&dir)?;adm(cfg,plan,"apply-al")?;
    if metadata(cfg,plan)?.0!=fact.drbd_device_uuid{return Err("initialized activity-log replay changed backend identity".into());}
    permit.checkpoint()?;adm(cfg,plan,"up")?;
    let state=status(plan)?.ok_or("initialized activation outcome UNKNOWN")?;
    secondary(cfg,plan,allocation.request.capacity_bytes,&state)?;kernel_config(cfg,plan,&lv)?;guard.verify()?;
    permit.checkpoint()?;record.stage=Stage::Online;save(&dir,&record)?;permit.checkpoint()
}
