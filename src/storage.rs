//! Storage admission primitives. No disk operations occur during admission.

/// Deliberately bounded quantity grammar: positive integral bytes with optional
/// decimal K..E or binary Ki..Ei suffix. Fractions, exponent notation and zero
/// are refused, not rounded. This is not full Kubernetes Quantity conformance.
pub fn capacity_bytes(value: &str) -> Result<u64, String> {
    let split = value.bytes().position(|b| !b.is_ascii_digit()).unwrap_or(value.len());
    let (digits, suffix) = value.split_at(split);
    let n = digits.parse::<u64>().map_err(|_| format!("invalid storage capacity {value:?}: expected a positive integer"))?;
    let factor = match suffix {
        "" => 1,
        "K" => 1_000, "M" => 1_000_000, "G" => 1_000_000_000,
        "T" => 1_000_000_000_000, "P" => 1_000_000_000_000_000, "E" => 1_000_000_000_000_000_000,
        "Ki" => 1 << 10, "Mi" => 1 << 20, "Gi" => 1 << 30,
        "Ti" => 1 << 40, "Pi" => 1 << 50, "Ei" => 1 << 60,
        _ => return Err(format!("unsupported storage capacity {value:?}: use integral bytes, K..E or Ki..Ei")),
    };
    n.checked_mul(factor).filter(|bytes| *bytes > 0)
        .ok_or_else(|| format!("storage capacity {value:?} is zero or overflows u64"))
}

pub fn access_mode(spec: &serde_yaml::Value) -> Result<String, String> {
    let Some(value) = spec.get("accessModes") else { return Ok("ReadWriteOnce".into()) };
    let modes = value.as_sequence().filter(|m| m.len() == 1)
        .ok_or("storage requires exactly one accessModes entry")?;
    match modes[0].as_str() {
        Some(mode @ ("ReadWriteOnce" | "ReadOnlyMany" | "ReadWriteMany")) => Ok(mode.into()),
        _ => Err("unsupported storage access mode".into()),
    }
}

pub fn string_field(spec: &serde_yaml::Value, path: &[&str], default: &str) -> Result<String, String> {
    let mut current = spec;
    for key in path {
        let Some(next) = current.get(*key) else {
            if current.is_mapping() { return Ok(default.into()); }
            return Err(format!("storage field {} must be a string", path.join(".")));
        };
        current = next;
    }
    current.as_str().map(String::from)
        .ok_or_else(|| format!("storage field {} must be a string", path.join(".")))
}

/// Validate a two-way binding before a path can enter a workload plan. This also
/// refuses unsafe/inconsistent legacy state loaded from disk.
pub fn bound_volume<'a>(world: &'a crate::reconcile::DesiredWorld, ns: &str, name: &str)
    -> Result<&'a crate::reconcile::StoredPV, String> {
    use crate::reconcile::PVStatus;
    let key = crate::store::obj_key(ns, name);
    let claim = world.pvcs.get(&key).ok_or_else(|| format!("volume: persistentvolumeclaim {name:?} not found in namespace {ns:?}"))?;
    let pv_name = claim.bound_pv.as_ref().ok_or_else(|| format!("volume: persistentvolumeclaim {name:?} is not bound"))?;
    let pv = world.pvs.get(pv_name).ok_or_else(|| format!("volume: pv {pv_name:?} missing"))?;
    if world.storage_classes.get(&pv.storage_class).is_some_and(|sc|sc.provisioner==crate::storage_lifecycle::PROVISIONER) {
        return Err("managed volume requires a verified per-pod driver attachment; workload mount adapter is not enabled yet".into());
    }
    if claim.namespace != ns || claim.name != name || pv.status != PVStatus::Bound
        || pv.bound_to.as_deref() != Some(key.as_str()) || pv.storage_class != claim.storage_class
        || pv.access_mode != claim.access_mode || capacity_bytes(&pv.capacity)? < capacity_bytes(&claim.requested)?
        || !crate::reconcile::validate_path(&pv.host_path) {
        return Err("volume: inconsistent or unsafe claim/PV binding; refusing to mount".into());
    }
    Ok(pv)
}

/// Observation only: never a mount, writer or runtime-effect capability.
/// Unsupported runtimes may keep their existing legacy behavior only after
/// resolving every PVC source against the CURRENT namespace and identity graph.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UnsupportedRuntimeStorage {
    Managed,
    Unresolved,
    ProvenLegacy,
}

pub(crate) fn observe_unsupported_runtime_storage(
    world: &crate::reconcile::DesiredWorld,
    namespace: &str,
    init: &[crate::reconcile::StoredContainer],
    containers: &[crate::reconcile::StoredContainer],
) -> UnsupportedRuntimeStorage {
    use UnsupportedRuntimeStorage::{Managed, ProvenLegacy, Unresolved};
    let claims: Vec<_> = init.iter().chain(containers).flat_map(|c| &c.volumes)
        .filter_map(|(source, _)| source.strip_prefix("pvc:")).collect();
    if claims.is_empty() {
        // Bare vct: is the existing legacy scratch contract. Explicit native
        // template classes are refused BEFORE that lowering loses the spec.
        return ProvenLegacy;
    }
    // Pure metadata validation, including namespace/claim/PV UID uniqueness and
    // lifecycle ownership. This does not observe a kernel or mint authority.
    if world.storage_identities.validate(&world.to_state()).is_err() {
        return Unresolved;
    }
    let mut result = ProvenLegacy;
    for name in claims {
        let observed = observe_runtime_claim(world, namespace, name);
        if observed == Unresolved { return Unresolved; }
        if observed == Managed { result = Managed; }
    }
    result
}

fn observe_runtime_claim(
    world: &crate::reconcile::DesiredWorld,
    namespace: &str,
    name: &str,
) -> UnsupportedRuntimeStorage {
    use UnsupportedRuntimeStorage::{Managed, ProvenLegacy, Unresolved};
    if !crate::store::is_dns_subdomain(name) { return Unresolved; }
    let ids = &world.storage_identities;
    let Some(namespace_uid) = ids.namespaces.get(namespace) else { return Unresolved };
    let key = crate::store::obj_key(namespace, name);
    let Some(claim) = world.pvcs.get(&key) else { return Unresolved };
    let Some(identity) = ids.claims.get(&key) else { return Unresolved };
    if claim.namespace != namespace || claim.name != name || &identity.namespace_uid != namespace_uid {
        return Unresolved;
    }
    if capacity_bytes(&claim.requested).is_err() { return Unresolved; }
    let native = if claim.storage_class.is_empty() {
        // Existing static PV/PVC bindings may intentionally have NO class.
        // This is only a candidate legacy observation: the exact bound PV,
        // public path, identity graph and absence of lifecycle are checked below.
        // Do not invent a StorageClass/default or infer any backend capability.
        false
    } else {
        // A NONEMPTY unknown class is never the classless legacy contract.
        let Some(class) = world.storage_classes.get(&claim.storage_class) else { return Unresolved };
        let native = class.provisioner == crate::storage_lifecycle::PROVISIONER;
        if class.name != claim.storage_class
            || !matches!(class.reclaim_policy.as_str(), "Retain" | "Delete")
            || (!native && class.provisioner != "royak/host-path")
            || (native && (!class.host_path_prefix.is_empty() || claim.access_mode != "ReadWriteOnce"))
        {
            return Unresolved;
        }
        native
    };
    let Some(pv_name) = &claim.bound_pv else {
        // A current native Pending claim is still native, NOT permission to
        // substitute a fresh runtime disk. An unbound legacy claim is unknown.
        return if native { Managed } else { Unresolved };
    };
    let Some(pv) = world.pvs.get(pv_name) else { return Unresolved };
    let Some(volume_uid) = ids.volumes.get(pv_name) else { return Unresolved };
    if pv.name != *pv_name || pv.storage_class != claim.storage_class
        || pv.status != crate::reconcile::PVStatus::Bound
        || pv.bound_to.as_deref() != Some(key.as_str())
        || pv.access_mode != claim.access_mode
        || capacity_bytes(&pv.capacity).ok().zip(capacity_bytes(&claim.requested).ok())
            .is_none_or(|(capacity, requested)| capacity < requested)
    {
        return Unresolved;
    }
    match ids.lifecycle.get(volume_uid) {
        Some(volume) if native => {
            let owner = volume.owner();
            if owner.cluster_id != world.cluster_id || owner.namespace != namespace
                || owner.claim_name != name || owner.pv_name != *pv_name
                || owner.namespace_uid != *namespace_uid || owner.claim_uid != identity.uid
                || owner.volume_uid != *volume_uid || !pv.host_path.is_empty()
                || matches!(volume.phase(), crate::storage_lifecycle::Phase::Released
                    | crate::storage_lifecycle::Phase::Deleted)
            { Unresolved } else { Managed }
        }
        // A lifecycle-bearing dataset cannot be reclassified legacy by changing
        // a class/path. Missing native lifecycle likewise never permits fallback.
        Some(_) => Unresolved,
        None if native => Unresolved,
        None => if bound_volume(world, namespace, name).is_ok()
            && crate::host_access::validate_public_path(&pv.host_path).is_ok() {
                ProvenLegacy
            } else {
                Unresolved
            },
    }
}

/// The old vct: representation has no StorageClass/claim identity. Refuse an
/// explicit native/unknown class before losing that information; no default
/// class, per-ordinal claim or native mount is synthesized here.
pub(crate) fn require_legacy_template_class(
    world: &crate::reconcile::DesiredWorld,
    template: &crate::spec::VolumeClaimTemplate,
) -> Result<(), String> {
    let Some(value) = template.spec.as_ref().and_then(|spec| spec.get("storageClassName")) else {
        return Ok(());
    };
    let name = value.as_str().filter(|name| !name.is_empty())
        .ok_or("volumeClaimTemplate has an unresolved explicit storageClassName")?;
    let class = world.storage_classes.get(name)
        .ok_or("volumeClaimTemplate explicit storage class is unknown; native template support is not enabled")?;
    if class.name != name || class.provisioner != "royak/host-path" {
        return Err("native volumeClaimTemplates are not supported; use an explicit current PVC".into());
    }
    Ok(())
}


#[cfg(test)]
mod unsupported_runtime_storage_tests {
    use super::*;
    use crate::reconcile::{DesiredWorld, StoredContainer};

    fn apply(world: &mut DesiredWorld, kind: &str, namespace: &str, name: &str,
        spec: serde_json::Value) {
        let resource = serde_json::from_value(serde_json::json!({
            "kind":kind,"metadata":{"name":name,"namespace":namespace},"spec":spec
        })).unwrap();
        world.apply(&resource).unwrap();
    }
    fn world() -> DesiredWorld {
        let mut world = DesiredWorld::new();
        apply(&mut world,"StorageClass","","native",serde_json::json!({
            "provisioner":crate::storage_lifecycle::PROVISIONER,"reclaimPolicy":"Retain"}));
        apply(&mut world,"StorageClass","","legacy",serde_json::json!({
            "provisioner":"royak/host-path","hostPathPrefix":"/srv/royak-legacy-observation",
            "reclaimPolicy":"Retain"}));
        for (name,class) in [("data","native"),("old","legacy")] {
            apply(&mut world,"PersistentVolumeClaim","a",name,serde_json::json!({
                "storageClassName":class,"resources":{"requests":{"storage":"64Mi"}}}));
        }
        world
    }
    fn source(source: &str) -> StoredContainer {
        serde_json::from_value(serde_json::json!({
            "name":"main","image":"busybox:1.36","env":[],"env_from_configmaps":[],
            "env_from_secrets":[],"volumes":[[source,"/data"]]
        })).unwrap()
    }
    fn observed(world: &DesiredWorld, source_name: &str) -> UnsupportedRuntimeStorage {
        observe_unsupported_runtime_storage(world,"a",&[],&[source(source_name)])
    }

    #[test]
    fn current_native_pending_lifecycle_is_managed_not_legacy() {
        let world=world();
        let pv=world.pvcs["a/data"].bound_pv.as_ref().unwrap();
        let volume=world.storage_identities.lifecycle.for_pv(&world.storage_identities,pv).unwrap();
        assert_eq!(volume.phase(),crate::storage_lifecycle::Phase::PendingProvision);
        assert_eq!(observed(&world,"pvc:data"),UnsupportedRuntimeStorage::Managed);
    }
    #[test]
    fn current_unbound_native_claim_is_managed_but_unbound_legacy_is_unresolved() {
        let mut world=DesiredWorld::new();
        apply(&mut world,"StorageClass","","native",serde_json::json!({
            "provisioner":crate::storage_lifecycle::PROVISIONER,"reclaimPolicy":"Retain"}));
        apply(&mut world,"StorageClass","","legacy",serde_json::json!({
            "provisioner":"royak/host-path","hostPathPrefix":"/srv/royak-legacy-observation"}));
        // Observation-only Pending claim DATA, not any backend or capability.
        for (name,class) in [("data","native"),("old","legacy")] {
            world.pvcs.insert(format!("default/{name}"),crate::reconcile::StoredPVC {
                name:name.into(),namespace:"default".into(),storage_class:class.into(),
                requested:"64Mi".into(),access_mode:"ReadWriteOnce".into(),bound_pv:None,
            });
        }
        world.synchronize_storage_identities().unwrap();
        assert_eq!(observe_unsupported_runtime_storage(&world,"default",&[],&[source("pvc:data")]),
            UnsupportedRuntimeStorage::Managed);
        assert_eq!(observe_unsupported_runtime_storage(&world,"default",&[],&[source("pvc:old")]),
            UnsupportedRuntimeStorage::Unresolved);
    }
    #[test]
    fn missing_foreign_or_recreated_namespace_claim_never_becomes_legacy() {
        let mut world=world();
        assert_eq!(observed(&world,"pvc:missing"),UnsupportedRuntimeStorage::Unresolved);
        assert_eq!(observe_unsupported_runtime_storage(&world,"b",&[],&[source("pvc:data")]),
            UnsupportedRuntimeStorage::Unresolved);
        world.storage_identities.namespaces.insert("a".into(),crate::storage_identity::Uid::new());
        assert_eq!(observed(&world,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
    }
    #[test]
    fn missing_class_pv_uid_and_native_lifecycle_are_unresolved() {
        let original=world();
        let mut missing=original.clone();missing.storage_classes.remove("native");
        assert_eq!(observed(&missing,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
        let pv=original.pvcs["a/data"].bound_pv.as_ref().unwrap();
        let mut missing=original.clone();missing.pvs.remove(pv);
        assert_eq!(observed(&missing,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
        let mut missing=original.clone();missing.storage_identities.volumes.remove(pv);
        assert_eq!(observed(&missing,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
        let mut missing=original.clone();missing.storage_identities.lifecycle=Default::default();
        assert_eq!(observed(&missing,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
    }
    #[test]
    fn conflicting_pv_binding_class_and_lifecycle_cannot_downgrade_to_legacy() {
        let original=world();let pv=original.pvcs["a/data"].bound_pv.as_ref().unwrap();
        let mut wrong=original.clone();wrong.pvs.get_mut(pv).unwrap().bound_to=Some("b/data".into());
        assert_eq!(observed(&wrong,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
        let mut wrong=original.clone();wrong.pvcs.get_mut("a/data").unwrap().storage_class="legacy".into();
        assert_eq!(observed(&wrong,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
        let mut wrong=original.clone();
        wrong.storage_classes.get_mut("native").unwrap().provisioner="royak/host-path".into();
        assert_eq!(observed(&wrong,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
    }
    #[test]
    fn native_init_and_main_are_both_checked_and_unresolved_dominates() {
        let world=world();
        assert_eq!(observe_unsupported_runtime_storage(&world,"a",&[source("pvc:data")],
            &[source("emptydir:main")]),UnsupportedRuntimeStorage::Managed);
        assert_eq!(observe_unsupported_runtime_storage(&world,"a",&[source("emptydir:init")],
            &[source("pvc:data")]),UnsupportedRuntimeStorage::Managed);
        assert_eq!(observe_unsupported_runtime_storage(&world,"a",&[source("pvc:data")],
            &[source("pvc:missing")]),UnsupportedRuntimeStorage::Unresolved);
    }
    #[test]
    fn proven_bound_legacy_and_unmanaged_sources_keep_existing_observation() {
        let world=world();
        assert_eq!(observed(&world,"pvc:old"),UnsupportedRuntimeStorage::ProvenLegacy);
        for source_name in ["emptydir:x","cmv:config","sev:secret","vct:legacy","/srv/legacy"] {
            assert_eq!(observed(&world,source_name),UnsupportedRuntimeStorage::ProvenLegacy);
        }
        assert_eq!(observe_unsupported_runtime_storage(&world,"a",&[],&[]),
            UnsupportedRuntimeStorage::ProvenLegacy);
    }

    fn classless_world() -> DesiredWorld {
        let mut world=DesiredWorld::new();
        apply(&mut world,"PersistentVolume","","static-old",serde_json::json!({
            "capacity":{"storage":"64Mi"},"storageClassName":"",
            "hostPath":{"path":"/srv/royak-static-observation"}}));
        apply(&mut world,"PersistentVolumeClaim","a","old",serde_json::json!({
            "storageClassName":"","resources":{"requests":{"storage":"64Mi"}}}));
        world
    }
    #[test]
    fn classless_static_legacy_requires_exact_bound_public_path_and_identity() {
        let world=classless_world();let before=serde_json::to_value(world.to_state()).unwrap();
        assert_eq!(world.pvcs["a/old"].storage_class,"");
        assert_eq!(world.pvs["static-old"].storage_class,"");
        assert!(world.storage_classes.get("").is_none());
        assert!(bound_volume(&world,"a","old").is_ok());
        assert_eq!(observed(&world,"pvc:old"),UnsupportedRuntimeStorage::ProvenLegacy);
        assert_eq!(before,serde_json::to_value(world.to_state()).unwrap());
        let mut wrong=world.clone();wrong.pvcs.get_mut("a/old").unwrap().bound_pv=None;
        assert_eq!(observed(&wrong,"pvc:old"),UnsupportedRuntimeStorage::Unresolved);
        let mut wrong=world.clone();wrong.pvs.get_mut("static-old").unwrap().storage_class="different".into();
        assert_eq!(observed(&wrong,"pvc:old"),UnsupportedRuntimeStorage::Unresolved);
        let mut wrong=world.clone();wrong.pvs.get_mut("static-old").unwrap().bound_to=Some("b/old".into());
        assert_eq!(observed(&wrong,"pvc:old"),UnsupportedRuntimeStorage::Unresolved);
        let mut wrong=world.clone();wrong.pvs.get_mut("static-old").unwrap().host_path="/var/lib/royak/storage".into();
        assert_eq!(observed(&wrong,"pvc:old"),UnsupportedRuntimeStorage::Unresolved);
        let mut wrong=world.clone();wrong.storage_identities.volumes.remove("static-old");
        assert_eq!(observed(&wrong,"pvc:old"),UnsupportedRuntimeStorage::Unresolved);
    }
    #[test]
    fn nonempty_unknown_class_is_not_inferred_as_classless_static_legacy() {
        let mut world=classless_world();
        world.pvcs.get_mut("a/old").unwrap().storage_class="missing".into();
        world.pvs.get_mut("static-old").unwrap().storage_class="missing".into();
        // The old generic path helper alone allows this shape. The new
        // fallback classifier must still require a KNOWN nonempty class.
        assert!(bound_volume(&world,"a","old").is_ok());
        assert_eq!(observed(&world,"pvc:old"),UnsupportedRuntimeStorage::Unresolved);
    }
    #[test]
    fn clearing_native_classes_and_forging_public_path_cannot_erase_lifecycle() {
        let mut world=world();let pv=world.pvcs["a/data"].bound_pv.clone().unwrap();
        world.pvcs.get_mut("a/data").unwrap().storage_class.clear();
        let volume=world.pvs.get_mut(&pv).unwrap();
        volume.storage_class.clear();volume.host_path="/srv/forged-native-public-path".into();
        assert!(world.storage_identities.lifecycle.for_pv(&world.storage_identities,&pv).is_some());
        // Test a public-looking path as well as cleared classes: refusal must
        // retain real native identity/lifecycle history, not rely on empty path.
        assert!(bound_volume(&world,"a","data").is_ok());
        let before=serde_json::to_value(world.to_state()).unwrap();
        assert_eq!(observed(&world,"pvc:data"),UnsupportedRuntimeStorage::Unresolved);
        assert_eq!(before,serde_json::to_value(world.to_state()).unwrap());
    }
    #[test]
    fn classification_is_read_only_and_is_not_a_mount_capability() {
        let world=world();let before=serde_json::to_value(world.to_state()).unwrap();
        for name in ["pvc:data","pvc:old","pvc:missing"] {let _=observed(&world,name);}
        assert_eq!(before,serde_json::to_value(world.to_state()).unwrap());
        assert!(bound_volume(&world,"a","data").is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quantities_compare_in_bytes_without_rounding_or_overflow() {
        for (s, n) in [("1", 1), ("512Mi", 536_870_912), ("1Gi", 1_073_741_824),
            ("1G", 1_000_000_000), ("18446744073709551615", u64::MAX), ("15Ei", 15 << 60)] {
            assert_eq!(capacity_bytes(s).unwrap(), n, "{s}");
        }
        for s in ["", "0", "00Gi", "-1", "+1", " 1Gi", "1Gi ", "1.5Gi", "1e6", "1MiB", "16Ei", "18446744073709551616"] {
            assert!(capacity_bytes(s).is_err(), "{s}");
        }
    }
}
