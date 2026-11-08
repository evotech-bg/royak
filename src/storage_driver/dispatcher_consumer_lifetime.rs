//! A distinct long-lived source lifetime, not renewal of the attach round.
//! Only a genuine READY book can collect these actual owner references.
use super::*;
use crate::storage_driver::native_runtime::mount::consumer::VerifiedReadyMountSet;

/// Nonblocking PURE identity fence for DATA admission/current-Core scratch.
/// It cannot wait for a probe doing fixed-IO work under a World/commit lock.
pub(crate) fn require_ready_owner_now(witness:&RootedMountWitness,owner:&Arc<AttachOwner>)->Result<(),String>{
    if !Arc::ptr_eq(&witness.owner,owner){return Err("READY source is not the same actual root owner".into());}
    let state=owner.resources.try_lock().map_err(|_|"READY resources busy/poisoned; no admission")?;
    if state.unknown||state.quarantined||owner.cancelled.load(Ordering::Acquire)
        || admission_mode(state.volume_lease.is_some(),state.global.is_some(),state.global_safety.is_some())!=AdmissionMode::MountedLifetime{
        return Err("READY long-lived mounted ownership unavailable".into());
    }
    drop(state);
    let probe=owner.probe.try_lock().map_err(|_|"READY probe busy/poisoned; no admission")?;
    let installed=probe.installed()?;
    if installed.scope().mount_ref!=witness.reference || installed.evidence_uid()!=&witness.evidence_uid
        || installed.evidence_sha256()!=witness.evidence_sha256{
        return Err("READY source evidence differs from same installed owner".into());
    }
    Ok(())
}

pub(crate) struct RootedConsumerMountWitness {
    original:RootedMountWitness,
    ready:Arc<VerifiedReadyMountSet>,
}
impl RootedConsumerMountWitness {
    pub(crate) fn from_ready_group(ready:Arc<VerifiedReadyMountSet>,actual:&RootedMountWitness)
        ->Result<Arc<Self>,String>{
        ready.require_witness(actual)?;
        actual.require_same_root(&actual.owner)?;
        Ok(Arc::new(Self {ready,original:RootedMountWitness {owner:actual.owner.clone(),
            reference:actual.reference.clone(),evidence_uid:actual.evidence_uid.clone(),
            evidence_sha256:actual.evidence_sha256.clone(),filesystem_uuid:actual.filesystem_uuid.clone()}}))
    }
    pub(crate) fn reference(&self)->&ManagedMountRef{&self.original.reference}
    /// PURE negative lifetime checks. Never consult/revive old attach time.
    pub(crate) fn require_lifetime_current(&self)->Result<(),String>{
        self.ready.require_current()?;
        self.original.require_same_root(&self.original.owner)
    }
    /// Existing fixed IO only, outside World/book/session locks. A successful
    /// reobservation supplies NO Create/Start permission.
    pub(crate) fn reobserve_for_consumer(&self,deadline:Instant)->Result<(),String>{
        let result=(||{
            if Instant::now()>=deadline{return Err("original consumer action expired".into());}
            self.require_lifetime_current()?;
            {
                let probe=self.original.owner.probe.lock().map_err(|_|"consumer mount probe poisoned")?;
                probe.installed()?.reobserve(deadline)?;
            }
            self.require_lifetime_current()?;
            if Instant::now()>=deadline{return Err("consumer observation completed late".into());}
            Ok(())
        })();
        if result.is_err(){self.original.owner.invalidate_round();}
        result
    }
    pub(crate) fn source_for_consumer(self:&Arc<Self>,deadline:Instant)->Result<VerifiedManagedSource,String>{
        self.reobserve_for_consumer(deadline)?;
        let (path,observation)={
            let probe=self.original.owner.probe.lock().map_err(|_|"consumer source probe poisoned")?;
            let installed=probe.installed()?;
            if installed.scope().mount_ref!=self.original.reference
                || installed.evidence_uid()!=&self.original.evidence_uid
                || installed.evidence_sha256()!=self.original.evidence_sha256{
                return Err("consumer source differs from actual installed mount".into());
            }
            (installed.observation().target.clone(),installed.observation().clone())
        };
        self.require_lifetime_current()?;
        Ok(VerifiedManagedSource {witness:self.clone(),path,observation})
    }
}
/// Not serde/Clone/default and has no public path/FD/scalar constructor.
/// The same actual owner keeps original protected observation descriptors.
pub(crate) struct VerifiedManagedSource {
    witness:Arc<RootedConsumerMountWitness>,
    path:String,
    observation:crate::storage_lifecycle::pod_attachment::MountObservation,
}
impl VerifiedManagedSource {
    pub(crate) fn reference(&self)->&ManagedMountRef{self.witness.reference()}
    pub(crate) fn observation(&self)->&crate::storage_lifecycle::pod_attachment::MountObservation{&self.observation}
    /// This getter is DATA for the closed typed adapter, never raw Docker
    /// permission. All legacy/raw reserved-bind paths continue to refuse it.
    pub(crate) fn published_path(&self)->&str{&self.path}
    pub(crate) fn reobserve(&self,deadline:Instant)->Result<(),String>{
        self.witness.reobserve_for_consumer(deadline)
    }
    pub(crate) fn connect(&self,deadline:Instant)->Result<crate::docker::ManagedConsumerConnection,String>{
        self.witness.require_lifetime_current()?;
        let connection={
            let probe=self.witness.original.owner.probe.lock().map_err(|_|"consumer daemon probe poisoned")?;
            probe.installed()?.consumer_connection(deadline)?
        };
        self.witness.require_lifetime_current()?;
        connection.validate(deadline)?;
        Ok(connection)
    }
}
