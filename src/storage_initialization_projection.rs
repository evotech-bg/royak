//! Init-specific identity projection. No byte/JSON constructor for an intent;
//! only an inherited verified v2 initializer capability can reconstruct it.
use super::*;
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Projection {
    version: u32,
    volume: Volume,
    storage_class: crate::reconcile::StoredStorageClass,
    pv: crate::reconcile::StoredPV,
    pvc: crate::reconcile::StoredPVC,
    namespace_identities: std::collections::BTreeMap<String, Uid>,
}
impl InitializationIntent {
    /// A live accepted phase session + actual applied Core, never an offered
    /// DTO or stored JSON, is the receiver-side intent producer.
    pub(crate) fn from_accepted_distributed_receiver(
        session: &crate::storage_remote_protocol::ReceiverSession,
        observed: &crate::raft_node::storage_remote_core::CoreObservation,
    ) -> Result<Self, String> {
        let spec = session.accepted_init_spec()?;
        let scope = spec.initialization.as_ref().ok_or("accepted init session has no exact phase scope")?;
        scope.validate()?;
        let target=scope.generation.virgin_replicas.iter().find(|fact|fact.node_uid==scope.target_node_uid
            && fact.node_boot_id==scope.target_boot).ok_or("accepted phase target lineage absent")?;
        let volume = observed.volume();
        let generation = volume.data_generation().ok_or("receiver Core lacks committed generation")?.clone();
        let intent = Self {owner:volume.owner().clone(),generation,capacity_bytes:volume.capacity_bytes()};
        let revision=observed.revision();
        let expected=&scope.issuer_revision;
        if spec.version!=2 || spec.kind!=crate::storage_remote_protocol::JobKind::InitializeVirginGeneration
            || !intent.matches(volume) || scope.owner!=*intent.owner() || scope.generation!=*intent.generation()
            || spec.owner!=scope.owner || spec.operation_uid!=*intent.operation_uid()
            || spec.dataset_uid.as_ref()!=Some(&intent.generation().uid)
            || spec.issuer_node_uid!=scope.issuer_node_uid || spec.issuer_boot!=scope.issuer_boot
            || spec.issuer_revision!=scope.issuer_revision || spec.target_node_uid!=scope.target_node_uid
            || spec.job_uid!=scope.phase_job_uid || spec.plan_sha256!=target.plan_sha256
            || spec.maximum_duration_ms>scope.remaining_budget_ms || spec.maximum_duration_ms==0
            || spec.target_boot!=scope.target_boot || observed.local_node_uid()!=Some(&scope.target_node_uid)
            || observed.actual_boot()!=&scope.target_boot
            || spec.directory_sha256!=scope.directory_sha256
            || observed.directory_commitment()!=Some(scope.directory_sha256.as_str())
            || spec.scope_sha256!=scope.scope_sha256 || observed.scope_sha256()!=scope.scope_sha256
            || revision.term!=expected.term || revision.leader_raft_id!=expected.leader_raft_id
            || revision.membership_sha256!=expected.membership_sha256 || revision.applied_index<expected.applied_index
            || revision.applied_term<expected.applied_term || revision.desired_generation<expected.desired_generation
            || revision.applied_term==expected.applied_term && revision.applied_leader_raft_id!=expected.applied_leader_raft_id
        { return Err("accepted distributed phase is not exact current Core owner/generation/scope/node/boot".into()); }
        Ok(intent)
    }

    /// Separate capsule-v4 path. The legacy v2 initializer-only producer below
    /// and its checker remain unchanged. This factory requires the distinct
    /// inherited distributed-phase checker, not an allow-follower switch.
    pub(crate) fn from_verified_distributed_native_helper(
        capability: &crate::storage_driver::dispatcher::VerifiedNativeAuthority,
    ) -> Result<(Arc<RwLock<DesiredWorld>>, Self), String> {
        let scope=capability.distributed_initialization_scope()?;
        scope.validate()?;
        let p:Projection=serde_json::from_slice(capability.projection_bytes())
            .map_err(|_|"invalid inherited distributed initialization projection")?;
        let owner=p.volume.owner().clone();
        let intent=Self {owner:owner.clone(),generation:p.volume.data_generation()
            .ok_or("distributed projection has no committed generation")?.clone(),capacity_bytes:p.volume.capacity_bytes()};
        if p.version!=2 || !intent.matches(&p.volume) || !capability.matches_distributed_initialization(&intent)
            || scope.owner!=owner || scope.generation!=*intent.generation()
            || scope.target_boot!=crate::storage_boot::BootId::current()? {
            return Err("inherited capsule-v4 scope/phase/node/boot differs from committed projection".into());
        }
        let required=if owner.namespace==crate::store::DEFAULT_NS {1} else {2};
        if p.namespace_identities.len()!=required || !p.namespace_identities.contains_key(crate::store::DEFAULT_NS)
            || p.namespace_identities.get(&owner.namespace)!=Some(&owner.namespace_uid) {
            return Err("distributed initializer namespace projection changed".into());
        }
        let mut world=DesiredWorld::new();
        world.cluster_id=owner.cluster_id.clone();
        world.namespaces=p.namespace_identities.keys().cloned().collect();
        world.storage_classes.insert(p.storage_class.name.clone(),p.storage_class);
        world.pvs.insert(p.pv.name.clone(),p.pv);
        world.pvcs.insert(crate::store::obj_key(&owner.namespace,&owner.claim_name),p.pvc);
        world.storage_identities=serde_json::from_value(serde_json::json!({"version":1,"namespaces":p.namespace_identities,
            "claims":{crate::store::obj_key(&owner.namespace,&owner.claim_name):{"uid":&owner.claim_uid,"namespace_uid":&owner.namespace_uid}},
            "volumes":{&owner.pv_name:&owner.volume_uid},"lifecycle":{"version":1,"volumes":{owner.volume_uid.as_str():p.volume}}}))
            .map_err(|_|"invalid distributed inherited identity graph")?;
        world.storage_identities.validate(&world.to_state())?;
        Ok((Arc::new(RwLock::new(world)),intent))
    }

    pub(crate) fn export_native_projection(
        &self,
        world: &Arc<RwLock<DesiredWorld>>,
    ) -> Result<Vec<u8>, String> {
        let w = world
            .try_read()
            .map_err(|_| "actual initialization world busy or unavailable")?;
        let volume = w
            .storage_identities
            .lifecycle
            .get(&self.owner.volume_uid)
            .filter(|v| self.matches(v))
            .ok_or("initialization operation is not actual current owner")?;
        w.storage_identities.validate(&w.to_state())?;
        let pv = w
            .pvs
            .get(&self.owner.pv_name)
            .ok_or("initializer PV absent")?;
        let pvc = w
            .pvcs
            .get(&crate::store::obj_key(
                &self.owner.namespace,
                &self.owner.claim_name,
            ))
            .ok_or("initializer PVC absent")?;
        let storage_class = w
            .storage_classes
            .get(&pv.storage_class)
            .ok_or("initializer storage class absent")?;
        let mut namespaces = std::collections::BTreeMap::new();
        for name in [crate::store::DEFAULT_NS, &self.owner.namespace] {
            namespaces.insert(
                name.to_string(),
                w.storage_identities
                    .namespaces
                    .get(name)
                    .ok_or("initializer namespace identity absent")?
                    .clone(),
            );
        }
        serde_json::to_vec(&Projection {
            version: 2,
            volume: volume.clone(),
            storage_class: storage_class.clone(),
            pv: pv.clone(),
            pvc: pvc.clone(),
            namespace_identities: namespaces,
        })
        .map_err(|_| "cannot encode exact initializer identity projection".into())
    }
    pub(crate) fn from_verified_native_helper(
        capability: &crate::storage_driver::dispatcher::VerifiedNativeAuthority,
    ) -> Result<(Arc<RwLock<DesiredWorld>>, Self), String> {
        let p: Projection = serde_json::from_slice(capability.projection_bytes())
            .map_err(|_| "invalid inherited initializer projection")?;
        let owner = p.volume.owner().clone();
        let generation = p
            .volume
            .data_generation()
            .ok_or("initializer projection has no committed logical dataset")?
            .clone();
        let intent = Self {
            owner: owner.clone(),
            generation,
            capacity_bytes: p.volume.capacity_bytes(),
        };
        if p.version != 2
            || !intent.matches(&p.volume)
            || !capability.matches_initialization(&intent)
        {
            return Err(
                "initializer projection is not exact v2 kind/dataset/node/boot/operation".into(),
            );
        }
        let required = if owner.namespace == crate::store::DEFAULT_NS {
            1
        } else {
            2
        };
        if p.namespace_identities.len() != required
            || !p
                .namespace_identities
                .contains_key(crate::store::DEFAULT_NS)
            || p.namespace_identities.get(&owner.namespace) != Some(&owner.namespace_uid)
        {
            return Err("initializer namespace identity projection changed".into());
        }
        let mut w = DesiredWorld::new();
        w.cluster_id = owner.cluster_id.clone();
        w.namespaces = p.namespace_identities.keys().cloned().collect();
        w.storage_classes
            .insert(p.storage_class.name.clone(), p.storage_class);
        w.pvs.insert(p.pv.name.clone(), p.pv);
        w.pvcs.insert(
            crate::store::obj_key(&owner.namespace, &owner.claim_name),
            p.pvc,
        );
        w.storage_identities=serde_json::from_value(serde_json::json!({"version":1,"namespaces":p.namespace_identities,
            "claims":{crate::store::obj_key(&owner.namespace,&owner.claim_name):{"uid":&owner.claim_uid,"namespace_uid":&owner.namespace_uid}},
            "volumes":{&owner.pv_name:&owner.volume_uid},"lifecycle":{"version":1,"volumes":{owner.volume_uid.as_str():p.volume}}}))
            .map_err(|_|"invalid inherited initializer identity graph")?;
        w.storage_identities.validate(&w.to_state())?;
        Ok((Arc::new(RwLock::new(w)), intent))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn init_projection_contains_only_actual_default_and_owner_uids_and_dataset() {
        let (world, intent) = super::super::model_initialization_for_authority_tests();
        let raw = intent.export_native_projection(&world).unwrap();
        let p: Projection = serde_json::from_slice(&raw).unwrap();
        assert_eq!(p.version, 2);
        assert_eq!(
            p.volume.data_generation().unwrap().uid,
            intent.generation().uid
        );
        assert_eq!(p.namespace_identities.len(), 2);
        assert_eq!(
            p.namespace_identities[crate::store::DEFAULT_NS],
            world.read().unwrap().storage_identities.namespaces[crate::store::DEFAULT_NS]
        );
        assert_eq!(
            p.namespace_identities[&intent.owner().namespace],
            intent.owner().namespace_uid
        );
        let text = String::from_utf8(raw).unwrap();
        for forbidden in ["configmaps", "secrets", "auth", "roles", "sessions"] {
            assert!(!text.contains(&format!("\"{forbidden}\"")));
        }
    }
    #[test]
    fn initialization_projection_refuses_changed_namespace_graph_without_fabrication() {
        let (world, intent) = super::super::model_initialization_for_authority_tests();
        world
            .write()
            .unwrap()
            .storage_identities
            .namespaces
            .insert(intent.owner().namespace.clone(), Uid::new());
        assert!(intent.export_native_projection(&world).is_err());
    }
}
